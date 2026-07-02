#!/usr/bin/env bash
# =============================================================================
# log-monitor.sh
# ops-log-monitor — Linux Operational Log Monitor (Orchestrator)
# =============================================================================
#
# SYNOPSIS:
#   Orchestrates collection of operationally significant events from RHEL 9
#   log sources (journald, auditd). Sources each detection module, runs them
#   against a configurable time window, assembles a structured report, and
#   writes Markdown and/or JSON output suitable for tickets, audits, or
#   documentation systems.
#
# USAGE:
#   ./log-monitor.sh [OPTIONS]
#
# OPTIONS:
#   --start-time "YYYY-MM-DD HH:MM:SS"   Beginning of monitoring window
#   --end-time   "YYYY-MM-DD HH:MM:SS"   End of monitoring window
#   --config     PATH                    Path to configuration file
#   --output     PATH                    Override OUTPUT_DIR for this run
#   --quiet                              Suppress console progress output
#   --help                               Show this usage information
#
# EXAMPLES:
#   ./log-monitor.sh
#       Runs with all defaults — last 24 hours, output to configured directory.
#
#   ./log-monitor.sh --start-time "2026-06-23 00:00:00" --end-time "2026-06-30 00:00:00"
#       Generates a 7-day summary report.
#
#   ./log-monitor.sh --quiet --output /var/log/ops-log-monitor/reports
#       Suitable for invocation from cron.
#
# EXIT CODES:
#   0 = Normal (no CRIT or WARN findings)
#   1 = Warning findings present
#   2 = Critical findings present
#   3 = Fatal error — script could not complete
#
# REQUIRES:
#   Bash 4.0+, systemd-journald, root privileges recommended (see
#   REQUIRE_ROOT in linux-monitor.conf). See docs/troubleshooting.md
#   for permission-related failures.
#
# =============================================================================

set -uo pipefail
# Note: we deliberately do NOT use 'set -e'. Individual module failures are
# caught and logged explicitly so that one module's failure does not abort
# the entire run — a partial report is more useful than no report. This
# mirrors the error-isolation design used in Invoke-LogMonitor.ps1.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_VERSION="1.0.0"
RUN_START_EPOCH=$(date +%s)

# =============================================================================
# ARGUMENT PARSING
# =============================================================================

START_TIME_ARG=""
END_TIME_ARG=""
CONFIG_PATH_ARG=""
OUTPUT_PATH_ARG=""
QUIET_MODE="false"

print_usage() {
    cat <<'USAGE'
ops-log-monitor (Linux) — Operational Log Monitor

Usage: ./log-monitor.sh [OPTIONS]

Options:
  --start-time "YYYY-MM-DD HH:MM:SS"   Beginning of monitoring window
  --end-time   "YYYY-MM-DD HH:MM:SS"   End of monitoring window
  --config     PATH                    Path to configuration file
  --output     PATH                    Override OUTPUT_DIR for this run
  --quiet                              Suppress console progress output
  --help                               Show this usage information

Examples:
  ./log-monitor.sh
  ./log-monitor.sh --start-time "2026-06-23 00:00:00" --end-time "2026-06-30 00:00:00"
  ./log-monitor.sh --quiet --output /var/log/ops-log-monitor/reports
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --start-time)
            START_TIME_ARG="$2"
            shift 2
            ;;
        --end-time)
            END_TIME_ARG="$2"
            shift 2
            ;;
        --config)
            CONFIG_PATH_ARG="$2"
            shift 2
            ;;
        --output)
            OUTPUT_PATH_ARG="$2"
            shift 2
            ;;
        --quiet)
            QUIET_MODE="true"
            shift
            ;;
        --help)
            print_usage
            exit 0
            ;;
        *)
            echo "ERROR: Unknown argument: $1" >&2
            print_usage
            exit 3
            ;;
    esac
done

# =============================================================================
# LOGGING FUNCTION
# =============================================================================
#
# Shared with all modules via the log_message function name (modules call
# it directly since they are sourced into this script's process, rather
# than via a passed function reference as PowerShell scriptblocks allow).
# =============================================================================

declare -a RUN_WARNINGS=()

log_message() {
    local level="$1"
    local source="$2"
    local message="$3"

    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local log_line="[${timestamp}] [${level}] [${source}] ${message}"

    if [[ -n "${LOG_FILE_PATH:-}" ]]; then
        local log_dir
        log_dir=$(dirname "${LOG_FILE_PATH}")
        [[ -d "$log_dir" ]] || mkdir -p "$log_dir" 2>/dev/null
        printf '%s\n' "$log_line" >> "${LOG_FILE_PATH}" 2>/dev/null
    fi

    if [[ "${QUIET_MODE}" != "true" ]]; then
        case "$level" in
            ERROR) printf '\033[31m%s\033[0m\n' "$log_line" ;;  # red
            WARN)  printf '\033[33m%s\033[0m\n' "$log_line" ;;  # yellow
            *)     printf '%s\n' "$log_line" ;;
        esac
    fi

    if [[ "$level" == "WARN" || "$level" == "ERROR" ]]; then
        RUN_WARNINGS+=("[${level}] [${source}] ${message}")
    fi
}

echo "ops-log-monitor (Linux) v${SCRIPT_VERSION} — starting run at $(date '+%Y-%m-%d %H:%M:%S')"

# =============================================================================
# STEP 1 — LOAD CONFIGURATION
# =============================================================================

if [[ -n "$CONFIG_PATH_ARG" ]]; then
    CONFIG_PATH="$CONFIG_PATH_ARG"
else
    LOCAL_CONFIG="${SCRIPT_DIR}/config/linux-monitor.conf.local"
    DEFAULT_CONFIG="${SCRIPT_DIR}/config/linux-monitor.conf"

    if [[ -f "$LOCAL_CONFIG" ]]; then
        CONFIG_PATH="$LOCAL_CONFIG"
        echo "Using local configuration override: ${CONFIG_PATH}"
    else
        CONFIG_PATH="$DEFAULT_CONFIG"
    fi
fi

if [[ ! -f "$CONFIG_PATH" ]]; then
    echo "FATAL: Configuration file not found at: ${CONFIG_PATH}" >&2
    echo "Expected location: ./config/linux-monitor.conf" >&2
    exit 3
fi

# Source the configuration file. All variables defined in it (OUTPUT_DIR,
# MONITORING_WINDOW_HOURS, MODULE_*_ENABLED, thresholds, arrays, etc.)
# become directly available in this script's scope, including to any
# module sourced afterward — bash does not require an explicit hashtable
# hand-off the way the PowerShell orchestrator constructs $Config, since
# sourced variables are already shared across the process.
# shellcheck source=/dev/null
if ! source "$CONFIG_PATH"; then
    echo "FATAL: Failed to source configuration file: ${CONFIG_PATH}" >&2
    exit 3
fi

# Apply command-line overrides on top of file-based configuration.
[[ -n "$OUTPUT_PATH_ARG" ]] && OUTPUT_DIR="$OUTPUT_PATH_ARG"

# Resolve log file path relative to script directory if not absolute.
if [[ "${LOG_FILE}" != /* ]]; then
    LOG_FILE_PATH="${SCRIPT_DIR}/${LOG_FILE}"
else
    LOG_FILE_PATH="${LOG_FILE}"
fi

# -----------------------------------------------------------------------------
# Rotate execution log if it exceeds the configured maximum size.
# -----------------------------------------------------------------------------
if [[ -f "$LOG_FILE_PATH" ]]; then
    log_size_bytes=$(stat -c%s "$LOG_FILE_PATH" 2>/dev/null || echo "0")
    if [[ "$log_size_bytes" -ge "${MAX_LOG_SIZE_BYTES}" ]]; then
        mv -f "$LOG_FILE_PATH" "${LOG_FILE_PATH}.bak"
    fi
fi

log_message "INFO" "Orchestrator" "Configuration loaded from: ${CONFIG_PATH}"
log_message "INFO" "Orchestrator" "Script version: ${SCRIPT_VERSION} | Config version: ${MONITOR_VERSION}"

# =============================================================================
# STEP 2 — RESOLVE MONITORING WINDOW
# =============================================================================

if [[ -n "$END_TIME_ARG" ]]; then
    WINDOW_END_EPOCH=$(date -d "$END_TIME_ARG" "+%s" 2>/dev/null)
    if [[ -z "$WINDOW_END_EPOCH" ]]; then
        log_message "ERROR" "Orchestrator" "Could not parse --end-time value: '${END_TIME_ARG}'. Expected format: YYYY-MM-DD HH:MM:SS"
        exit 3
    fi
else
    WINDOW_END_EPOCH=$(date +%s)
fi

if [[ -n "$START_TIME_ARG" ]]; then
    WINDOW_START_EPOCH=$(date -d "$START_TIME_ARG" "+%s" 2>/dev/null)
    if [[ -z "$WINDOW_START_EPOCH" ]]; then
        log_message "ERROR" "Orchestrator" "Could not parse --start-time value: '${START_TIME_ARG}'. Expected format: YYYY-MM-DD HH:MM:SS"
        exit 3
    fi
else
    WINDOW_START_EPOCH=$(( WINDOW_END_EPOCH - (MONITORING_WINDOW_HOURS * 3600) ))
fi

if [[ "$WINDOW_START_EPOCH" -ge "$WINDOW_END_EPOCH" ]]; then
    log_message "ERROR" "Orchestrator" "Start time must be earlier than end time. Aborting."
    exit 3
fi

WINDOW_START_ISO=$(date -u -d "@${WINDOW_START_EPOCH}" "+%Y-%m-%dT%H:%M:%SZ")
WINDOW_END_ISO=$(date -u -d "@${WINDOW_END_EPOCH}" "+%Y-%m-%dT%H:%M:%SZ")

# Export window variables so they are available to sourced modules without
# needing to be explicitly passed — consistent with bash's natural scoping
# but documented clearly here since modules rely on this contract.
export WINDOW_START_EPOCH WINDOW_END_EPOCH WINDOW_START_ISO WINDOW_END_ISO

window_hours=$(( (WINDOW_END_EPOCH - WINDOW_START_EPOCH) / 3600 ))
log_message "INFO" "Orchestrator" "Monitoring window: ${WINDOW_START_ISO} to ${WINDOW_END_ISO} (~${window_hours} hours)"

# =============================================================================
# STEP 3 — PRE-FLIGHT CHECKS
# =============================================================================

log_message "INFO" "Orchestrator" "Running pre-flight checks"

# -----------------------------------------------------------------------------
# Check 1: Root privileges.
# -----------------------------------------------------------------------------
if [[ "$(id -u)" -ne 0 ]]; then
    if [[ "${REQUIRE_ROOT}" == "true" ]]; then
        log_message "ERROR" "Orchestrator" "This script must be run as root (REQUIRE_ROOT=true in config). Privilege and Kernel modules require read access to /var/log/audit/audit.log. Run with sudo or as root."
        exit 3
    else
        log_message "WARN" "Orchestrator" "Not running as root. REQUIRE_ROOT=false allows continuing, but Privilege and Kernel modules may produce incomplete results due to permission restrictions on /var/log/audit/audit.log."
    fi
else
    log_message "INFO" "Orchestrator" "Running as root — OK"
fi

# -----------------------------------------------------------------------------
# Check 2: Required commands available.
# journalctl is mandatory — without it, four of five modules cannot function.
# Other commands are checked per-module at runtime since their absence
# degrades specific modules rather than blocking the entire run.
# -----------------------------------------------------------------------------
if ! command -v journalctl >/dev/null 2>&1; then
    log_message "ERROR" "Orchestrator" "journalctl not found. This framework requires systemd-journald, which is standard on RHEL 9. Aborting."
    exit 3
fi
log_message "INFO" "Orchestrator" "journalctl available — OK"

# -----------------------------------------------------------------------------
# Check 3: journald persistent storage.
# Warn (not fail) if persistent storage appears unconfigured, since the
# monitoring window may exceed what an in-memory-only journal can provide.
# -----------------------------------------------------------------------------
if [[ ! -d /var/log/journal ]]; then
    log_message "WARN" "Orchestrator" "/var/log/journal does not exist — journald may be using volatile (in-memory) storage only. Historical queries may return incomplete results. See docs/linux-log-sources.md for how to enable persistent storage."
fi

# -----------------------------------------------------------------------------
# Check 4: Output directory writability.
# -----------------------------------------------------------------------------
if [[ "$OUTPUT_DIR" != /* ]]; then
    RESOLVED_OUTPUT_DIR="${SCRIPT_DIR}/${OUTPUT_DIR}"
else
    RESOLVED_OUTPUT_DIR="$OUTPUT_DIR"
fi

if ! mkdir -p "$RESOLVED_OUTPUT_DIR" 2>/dev/null; then
    log_message "ERROR" "Orchestrator" "Could not create output directory: ${RESOLVED_OUTPUT_DIR}"
    exit 3
fi

TEST_FILE="${RESOLVED_OUTPUT_DIR}/.write-test-$$"
if ! touch "$TEST_FILE" 2>/dev/null; then
    log_message "ERROR" "Orchestrator" "Output directory is not writable: ${RESOLVED_OUTPUT_DIR}"
    exit 3
fi
rm -f "$TEST_FILE"
log_message "INFO" "Orchestrator" "Output directory writable: ${RESOLVED_OUTPUT_DIR}"

# =============================================================================
# STEP 4 — PREPARE TEMP WORKSPACE FOR MODULE OUTPUT
# =============================================================================
#
# Each module writes its events and summary to dedicated temp files. Using
# mktemp avoids collisions between concurrent runs (e.g., a manual run
# overlapping with a cron-scheduled run) and ensures cleanup on exit via
# the trap below.
# =============================================================================

WORKSPACE_DIR=$(mktemp -d -t ops-log-monitor.XXXXXX)

cleanup_workspace() {
    rm -rf "$WORKSPACE_DIR" 2>/dev/null
}
trap cleanup_workspace EXIT

export AUTH_MODULE_OUTPUT_FILE="${WORKSPACE_DIR}/auth-events.jsonl"
export AUTH_MODULE_SUMMARY_FILE="${WORKSPACE_DIR}/auth-summary.json"
export SERVICE_MODULE_OUTPUT_FILE="${WORKSPACE_DIR}/service-events.jsonl"
export SERVICE_MODULE_SUMMARY_FILE="${WORKSPACE_DIR}/service-summary.json"
export PRIVILEGE_MODULE_OUTPUT_FILE="${WORKSPACE_DIR}/privilege-events.jsonl"
export PRIVILEGE_MODULE_SUMMARY_FILE="${WORKSPACE_DIR}/privilege-summary.json"
export SYSHEALTH_MODULE_OUTPUT_FILE="${WORKSPACE_DIR}/syshealth-events.jsonl"
export SYSHEALTH_MODULE_SUMMARY_FILE="${WORKSPACE_DIR}/syshealth-summary.json"
export KERNEL_MODULE_OUTPUT_FILE="${WORKSPACE_DIR}/kernel-events.jsonl"
export KERNEL_MODULE_SUMMARY_FILE="${WORKSPACE_DIR}/kernel-summary.json"

log_message "INFO" "Orchestrator" "Workspace prepared: ${WORKSPACE_DIR}"

# =============================================================================
# STEP 5 — SOURCE AND EXECUTE MODULES
# =============================================================================
#
# Each module is sourced (loading its run_*_module function into this
# script's scope) and then invoked. Failures are caught individually using
# subshell isolation combined with explicit exit-status checks, so a single
# module's unexpected failure does not abort the remaining modules.
# =============================================================================

MODULES_DIR="${SCRIPT_DIR}/modules"

# Module execution plan, structured the same way as the PowerShell
# orchestrator's $ModuleExecutionPlan array — a single source of truth
# for which modules exist, their enable flags, and their entry points.
declare -A MODULE_ENABLE_FLAGS=(
    ["auth-events.sh"]="MODULE_AUTH_ENABLED"
    ["service-events.sh"]="MODULE_SERVICE_ENABLED"
    ["privilege-events.sh"]="MODULE_PRIVILEGE_ENABLED"
    ["system-health-events.sh"]="MODULE_SYSTEM_HEALTH_ENABLED"
    ["kernel-events.sh"]="MODULE_KERNEL_ENABLED"
)

declare -A MODULE_FUNCTIONS=(
    ["auth-events.sh"]="run_auth_module"
    ["service-events.sh"]="run_service_module"
    ["privilege-events.sh"]="run_privilege_module"
    ["system-health-events.sh"]="run_system_health_module"
    ["kernel-events.sh"]="run_kernel_module"
)

declare -A MODULE_RESULT_KEYS=(
    ["auth-events.sh"]="Authentication"
    ["service-events.sh"]="Services"
    ["privilege-events.sh"]="Privilege"
    ["system-health-events.sh"]="SystemHealth"
    ["kernel-events.sh"]="Kernel"
)

# Preserve execution order explicitly — associative array iteration order
# is not guaranteed in bash, but report readability benefits from a
# consistent, deliberate category ordering matching the Windows report.
MODULE_EXECUTION_ORDER=(
    "auth-events.sh"
    "service-events.sh"
    "privilege-events.sh"
    "system-health-events.sh"
    "kernel-events.sh"
)

declare -A EXECUTED_MODULES  # tracks which modules actually ran successfully

for module_file in "${MODULE_EXECUTION_ORDER[@]}"; do
    enable_flag="${MODULE_ENABLE_FLAGS[$module_file]}"
    function_name="${MODULE_FUNCTIONS[$module_file]}"
    result_key="${MODULE_RESULT_KEYS[$module_file]}"

    if [[ "${!enable_flag}" != "true" ]]; then
        log_message "INFO" "Orchestrator" "Module '${result_key}' is disabled in configuration — skipping"
        continue
    fi

    module_path="${MODULES_DIR}/${module_file}"

    if [[ ! -f "$module_path" ]]; then
        log_message "ERROR" "Orchestrator" "Module file not found: ${module_path} — skipping '${result_key}' section"
        continue
    fi

    log_message "INFO" "Orchestrator" "Loading and executing module: ${result_key}"

    # Source the module to load its run_*_module function definition.
    # shellcheck source=/dev/null
    if ! source "$module_path"; then
        log_message "ERROR" "Orchestrator" "Failed to source module file: ${module_path} — skipping '${result_key}' section"
        continue
    fi

    # Invoke the module's entry function. We do not use a subshell here
    # because the module needs access to log_message and the exported
    # window variables already in this process's environment. Instead,
    # we rely on 'set -uo pipefail' without '-e' (set at script top) so
    # that an error inside the function does not silently abort the whole
    # orchestrator — the module functions themselves use '|| true' and
    # explicit error capture internally for the same reason.
    if "$function_name"; then
        EXECUTED_MODULES["$module_file"]=1
        log_message "INFO" "Orchestrator" "Module '${result_key}' completed successfully"
    else
        log_message "ERROR" "Orchestrator" "Module '${result_key}' (${function_name}) exited with a non-zero status — section may be incomplete"
        RUN_WARNINGS+=("Module '${result_key}' exited with non-zero status")
    fi
done

# =============================================================================
# STEP 6 — GATHER SYSTEM INFORMATION (OPTIONAL)
# =============================================================================

SYSINFO_HOSTNAME=""
SYSINFO_OS_VERSION=""
SYSINFO_KERNEL_VERSION=""
SYSINFO_UPTIME=""
SYSINFO_LAST_BOOT=""

if [[ "${REPORT_INCLUDE_SYSTEM_INFO}" == "true" ]]; then
    log_message "INFO" "Orchestrator" "Collecting system information for report header"

    SYSINFO_HOSTNAME=$(hostname 2>/dev/null || echo "unknown")
    SYSINFO_KERNEL_VERSION=$(uname -r 2>/dev/null || echo "unknown")

    if [[ -f /etc/os-release ]]; then
        SYSINFO_OS_VERSION=$(grep -E "^PRETTY_NAME=" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
    fi
    [[ -z "$SYSINFO_OS_VERSION" ]] && SYSINFO_OS_VERSION="unknown"

    SYSINFO_UPTIME=$(uptime -p 2>/dev/null || echo "unknown")

    if command -v who >/dev/null 2>&1; then
        SYSINFO_LAST_BOOT=$(who -b 2>/dev/null | awk '{$1=$2=""; print $0}' | xargs)
    fi
    [[ -z "$SYSINFO_LAST_BOOT" ]] && SYSINFO_LAST_BOOT="unknown"
fi

# =============================================================================
# STEP 7 — ASSEMBLE REPORT
# =============================================================================

log_message "INFO" "Orchestrator" "Assembling final report"

REPORT_TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
REPORT_HOSTNAME="${SYSINFO_HOSTNAME:-$(hostname 2>/dev/null || echo unknown)}"
REPORT_BASE_NAME="${REPORT_FILENAME_PREFIX}-${REPORT_HOSTNAME}-${REPORT_TIMESTAMP}"

# -----------------------------------------------------------------------------
# Read each module's summary file and accumulate totals. Summary files are
# small, single-line JSON objects written deterministically by each module,
# so we extract fields with sed rather than introducing a jq dependency,
# consistent with the project's no-external-dependency requirement.
# -----------------------------------------------------------------------------
TOTAL_EVENTS=0
TOTAL_CRIT=0
TOTAL_WARN=0

declare -A CATEGORY_TOTAL CATEGORY_CRIT CATEGORY_WARN CATEGORY_INFO

for module_file in "${MODULE_EXECUTION_ORDER[@]}"; do
    result_key="${MODULE_RESULT_KEYS[$module_file]}"
    [[ -z "${EXECUTED_MODULES[$module_file]:-}" ]] && continue

    summary_var="${result_key^^}_SUMMARY_FILE_PATH"
    case "$module_file" in
        auth-events.sh)            summary_file="$AUTH_MODULE_SUMMARY_FILE" ;;
        service-events.sh)         summary_file="$SERVICE_MODULE_SUMMARY_FILE" ;;
        privilege-events.sh)       summary_file="$PRIVILEGE_MODULE_SUMMARY_FILE" ;;
        system-health-events.sh)   summary_file="$SYSHEALTH_MODULE_SUMMARY_FILE" ;;
        kernel-events.sh)          summary_file="$KERNEL_MODULE_SUMMARY_FILE" ;;
    esac

    [[ ! -f "$summary_file" ]] && continue

    summary_content=$(cat "$summary_file")

    cat_total=$(printf '%s' "$summary_content" | sed -n 's/.*"total_events":\([0-9]*\).*/\1/p')
    cat_crit=$(printf '%s' "$summary_content" | sed -n 's/.*"crit_count":\([0-9]*\).*/\1/p')
    cat_warn=$(printf '%s' "$summary_content" | sed -n 's/.*"warn_count":\([0-9]*\).*/\1/p')
    cat_info=$(printf '%s' "$summary_content" | sed -n 's/.*"info_count":\([0-9]*\).*/\1/p')

    CATEGORY_TOTAL["$result_key"]="${cat_total:-0}"
    CATEGORY_CRIT["$result_key"]="${cat_crit:-0}"
    CATEGORY_WARN["$result_key"]="${cat_warn:-0}"
    CATEGORY_INFO["$result_key"]="${cat_info:-0}"

    TOTAL_EVENTS=$(( TOTAL_EVENTS + ${cat_total:-0} ))
    TOTAL_CRIT=$(( TOTAL_CRIT + ${cat_crit:-0} ))
    TOTAL_WARN=$(( TOTAL_WARN + ${cat_warn:-0} ))
done

OVERALL_STATUS="NORMAL"
[[ "$TOTAL_WARN" -gt 0 ]] && OVERALL_STATUS="WARNING"
[[ "$TOTAL_CRIT" -gt 0 ]] && OVERALL_STATUS="CRITICAL"

# -----------------------------------------------------------------------------
# Render Markdown report.
# -----------------------------------------------------------------------------
render_markdown_report() {
    local md_path="$1"

    {
        echo "# Operational Log Monitor Report"
        echo ""
        echo "**Status:** ${OVERALL_STATUS}"
        echo "**Hostname:** ${REPORT_HOSTNAME}"
        echo "**Report Generated:** $(date '+%Y-%m-%d %H:%M:%S')"
        echo "**Monitoring Window:** ${WINDOW_START_ISO} to ${WINDOW_END_ISO}"
        echo "**Total Events:** ${TOTAL_EVENTS} | **CRIT:** ${TOTAL_CRIT} | **WARN:** ${TOTAL_WARN}"
        echo ""

        if [[ "${REPORT_INCLUDE_SYSTEM_INFO}" == "true" ]]; then
            echo "## System Information"
            echo ""
            echo "| Field | Value |"
            echo "|---|---|"
            echo "| OS Version | ${SYSINFO_OS_VERSION} |"
            echo "| Kernel Version | ${SYSINFO_KERNEL_VERSION} |"
            echo "| Uptime | ${SYSINFO_UPTIME} |"
            echo "| Last Boot | ${SYSINFO_LAST_BOOT} |"
            echo ""
        fi

        echo "## Summary by Category"
        echo ""
        echo "| Category | Total | CRIT | WARN | INFO |"
        echo "|---|---|---|---|---|"
        for module_file in "${MODULE_EXECUTION_ORDER[@]}"; do
            result_key="${MODULE_RESULT_KEYS[$module_file]}"
            [[ -z "${EXECUTED_MODULES[$module_file]:-}" ]] && continue
            echo "| ${result_key} | ${CATEGORY_TOTAL[$result_key]:-0} | ${CATEGORY_CRIT[$result_key]:-0} | ${CATEGORY_WARN[$result_key]:-0} | ${CATEGORY_INFO[$result_key]:-0} |"
        done
        echo ""

        for module_file in "${MODULE_EXECUTION_ORDER[@]}"; do
            result_key="${MODULE_RESULT_KEYS[$module_file]}"
            [[ -z "${EXECUTED_MODULES[$module_file]:-}" ]] && continue

            echo "## ${result_key}"
            echo ""

            case "$module_file" in
                auth-events.sh)            events_file="$AUTH_MODULE_OUTPUT_FILE" ;;
                service-events.sh)         events_file="$SERVICE_MODULE_OUTPUT_FILE" ;;
                privilege-events.sh)       events_file="$PRIVILEGE_MODULE_OUTPUT_FILE" ;;
                system-health-events.sh)   events_file="$SYSHEALTH_MODULE_OUTPUT_FILE" ;;
                kernel-events.sh)          events_file="$KERNEL_MODULE_OUTPUT_FILE" ;;
            esac

            if [[ ! -s "$events_file" ]]; then
                echo "No events found in this category during the monitoring window."
                echo ""
                continue
            fi

            echo "| Time | Severity | Description |"
            echo "|---|---|---|"
            while IFS= read -r json_line; do
                [[ -z "$json_line" ]] && continue
                local time_val severity_val desc_val
                time_val=$(printf '%s' "$json_line" | sed -n 's/.*"time_created":"\([^"]*\)".*/\1/p')
                severity_val=$(printf '%s' "$json_line" | sed -n 's/.*"severity":"\([^"]*\)".*/\1/p')
                desc_val=$(printf '%s' "$json_line" | sed -n 's/.*"description":"\([^"]*\)".*/\1/p')
                # Escape any pipe characters that survived into the description
                # so they do not break the Markdown table structure.
                desc_val="${desc_val//|/\\|}"
                echo "| ${time_val} | ${severity_val} | ${desc_val} |"
            done < "$events_file"
            echo ""
        done

        if [[ ${#RUN_WARNINGS[@]} -gt 0 ]]; then
            echo "## Execution Notes"
            echo ""
            echo "The following non-fatal issues occurred during report generation:"
            echo ""
            for w in "${RUN_WARNINGS[@]}"; do
                echo "- ${w}"
            done
            echo ""
        fi

        echo "---"
        echo ""
        echo "*Generated by ${MONITOR_DESCRIPTION} v${MONITOR_VERSION} (${SCRIPT_VERSION}) — ops-log-monitor*"
    } > "$md_path"
}

# -----------------------------------------------------------------------------
# Render JSON report. Combines each module's JSON Lines output into a single
# JSON document with a stable schema matching the Windows JSON output shape,
# so downstream tooling can treat both platforms' reports consistently.
# -----------------------------------------------------------------------------
render_json_report() {
    local json_path="$1"

    {
        echo "{"
        echo "  \"reportMetadata\": {"
        echo "    \"hostname\": \"${REPORT_HOSTNAME}\","
        echo "    \"generatedAt\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
        echo "    \"windowStart\": \"${WINDOW_START_ISO}\","
        echo "    \"windowEnd\": \"${WINDOW_END_ISO}\","
        echo "    \"overallStatus\": \"${OVERALL_STATUS}\","
        echo "    \"totalEvents\": ${TOTAL_EVENTS},"
        echo "    \"critCount\": ${TOTAL_CRIT},"
        echo "    \"warnCount\": ${TOTAL_WARN},"
        echo "    \"scriptVersion\": \"${SCRIPT_VERSION}\","
        echo "    \"configVersion\": \"${MONITOR_VERSION}\""
        echo "  },"
        echo "  \"systemInfo\": {"
        echo "    \"osVersion\": \"${SYSINFO_OS_VERSION}\","
        echo "    \"kernelVersion\": \"${SYSINFO_KERNEL_VERSION}\","
        echo "    \"uptime\": \"${SYSINFO_UPTIME}\","
        echo "    \"lastBoot\": \"${SYSINFO_LAST_BOOT}\""
        echo "  },"
        echo "  \"categories\": {"

        local first_category=true
        for module_file in "${MODULE_EXECUTION_ORDER[@]}"; do
            result_key="${MODULE_RESULT_KEYS[$module_file]}"
            [[ -z "${EXECUTED_MODULES[$module_file]:-}" ]] && continue

            [[ "$first_category" == false ]] && echo ","
            first_category=false

            case "$module_file" in
                auth-events.sh)            events_file="$AUTH_MODULE_OUTPUT_FILE" ;;
                service-events.sh)         events_file="$SERVICE_MODULE_OUTPUT_FILE" ;;
                privilege-events.sh)       events_file="$PRIVILEGE_MODULE_OUTPUT_FILE" ;;
                system-health-events.sh)   events_file="$SYSHEALTH_MODULE_OUTPUT_FILE" ;;
                kernel-events.sh)          events_file="$KERNEL_MODULE_OUTPUT_FILE" ;;
            esac

            printf '    "%s": {\n' "$result_key"
            printf '      "totalEvents": %s,\n' "${CATEGORY_TOTAL[$result_key]:-0}"
            printf '      "critCount": %s,\n' "${CATEGORY_CRIT[$result_key]:-0}"
            printf '      "warnCount": %s,\n' "${CATEGORY_WARN[$result_key]:-0}"
            printf '      "infoCount": %s,\n' "${CATEGORY_INFO[$result_key]:-0}"
            printf '      "events": [\n'

            if [[ -s "$events_file" ]]; then
                local first_event=true
                while IFS= read -r json_line; do
                    [[ -z "$json_line" ]] && continue
                    [[ "$first_event" == false ]] && printf ',\n'
                    first_event=false
                    printf '        %s' "$json_line"
                done < "$events_file"
                printf '\n'
            fi

            printf '      ]\n'
            printf '    }'
        done

        echo ""
        echo "  }"
        echo "}"
    } > "$json_path"
}

WRITTEN_FILES=()

if [[ "${OUTPUT_FORMATS}" == "markdown" || "${OUTPUT_FORMATS}" == "both" ]]; then
    MD_PATH="${RESOLVED_OUTPUT_DIR}/${REPORT_BASE_NAME}.md"
    render_markdown_report "$MD_PATH"
    WRITTEN_FILES+=("$MD_PATH")
    log_message "INFO" "Orchestrator" "Markdown report written: ${MD_PATH}"
fi

if [[ "${OUTPUT_FORMATS}" == "json" || "${OUTPUT_FORMATS}" == "both" ]]; then
    JSON_PATH="${RESOLVED_OUTPUT_DIR}/${REPORT_BASE_NAME}.json"
    render_json_report "$JSON_PATH"
    WRITTEN_FILES+=("$JSON_PATH")
    log_message "INFO" "Orchestrator" "JSON report written: ${JSON_PATH}"
fi

# =============================================================================
# STEP 8 — FINAL SUMMARY
# =============================================================================

RUN_END_EPOCH=$(date +%s)
RUN_DURATION=$(( RUN_END_EPOCH - RUN_START_EPOCH ))

log_message "INFO" "Orchestrator" "Run complete in ${RUN_DURATION} seconds"
log_message "INFO" "Orchestrator" "Overall status: ${OVERALL_STATUS} | Total events: ${TOTAL_EVENTS} | CRIT: ${TOTAL_CRIT} | WARN: ${TOTAL_WARN}"

echo ""
echo "============================================================="
echo " ops-log-monitor run complete"
echo "============================================================="
echo " Status:        ${OVERALL_STATUS}"
echo " Total events:  ${TOTAL_EVENTS}"
echo " CRIT / WARN:   ${TOTAL_CRIT} / ${TOTAL_WARN}"
echo " Duration:      ${RUN_DURATION}s"
echo " Reports:"
for f in "${WRITTEN_FILES[@]}"; do
    echo "   - ${f}"
done
echo "============================================================="

# Exit code reflects overall severity, consistent with the Windows
# orchestrator's exit code scheme, for cron/monitoring integration.
case "$OVERALL_STATUS" in
    CRITICAL) exit 2 ;;
    WARNING)  exit 1 ;;
    *)        exit 0 ;;
esac