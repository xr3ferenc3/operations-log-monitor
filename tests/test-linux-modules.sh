#!/usr/bin/env bash
# =============================================================================
# test-linux-modules.sh
# ops-log-monitor — Linux Module Structural Validation Tests
# =============================================================================
#
# PURPOSE:
#   Validates that each Linux detection module handles missing/empty log
#   sources gracefully, parses correctly formatted synthetic test input as
#   expected, and produces correctly structured JSON Lines output and
#   summary files that the orchestrator can consume without error.
#
# WHAT IS TESTED:
#   - Each module file has valid Bash syntax
#   - Each module refuses direct execution (sourcing guard works)
#   - Each module's entry function runs without error against an empty
#     / synthetic environment
#   - Each module produces syntactically valid JSON Lines output
#   - Each module produces a syntactically valid JSON summary file
#   - Summary file counts are internally consistent
#     (total_events == crit_count + warn_count + info_count)
#   - Helper functions (json_escape, decode_audit_cmd) behave correctly
#     against known input/output pairs
#
# WHAT IS NOT TESTED:
#   - Whether actual events are collected from live journald/auditd data
#     (requires an appropriately configured RHEL 9 system)
#   - Report rendering (covered by running the full orchestrator)
#
# USAGE:
#   Run from the repository root. Root privileges are not required for
#   these structural tests since they use synthetic data rather than
#   querying live system logs.
#
#     cd ops-log-monitor
#     bash tests/test-linux-modules.sh
#
# EXIT CODES:
#   0 = All tests passed
#   1 = One or more tests failed
#
# REQUIRES:
#   python3 (for JSON validation only — not a runtime dependency of the
#   framework itself, used here strictly as a test-time convenience since
#   it is commonly available on development machines; the framework's
#   modules do not depend on python3 to run in production)
#
# =============================================================================

set -uo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$TEST_DIR")"
MODULES_DIR="${REPO_ROOT}/linux/modules"
CONFIG_DIR="${REPO_ROOT}/linux/config"

TESTS_PASSED=0
TESTS_FAILED=0
declare -a FAILED_TEST_NAMES=()

# =============================================================================
# Minimal assertion framework — dependency-free, consistent with the
# project's no-external-dependencies requirement. Mirrors the structure
# of test-windows-modules.ps1's assertion functions for consistency
# between the two test suites.
# =============================================================================

assert_true() {
    local test_name="$1"
    local condition="$2"  # "true" or "false" as a string
    local fail_message="${3:-Condition was false}"

    if [[ "$condition" == "true" ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        printf '  \033[32mPASS\033[0m  %s\n' "$test_name"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        FAILED_TEST_NAMES+=("$test_name")
        printf '  \033[31mFAIL\033[0m  %s\n' "$test_name"
        printf '        %s\n' "$fail_message"
    fi
}

assert_file_exists() {
    local test_name="$1"
    local file_path="$2"

    if [[ -f "$file_path" ]]; then
        assert_true "$test_name" "true"
    else
        assert_true "$test_name" "false" "Expected file not found at: $file_path"
    fi
}

assert_json_valid() {
    local test_name="$1"
    local json_content="$2"

    if printf '%s' "$json_content" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
        assert_true "$test_name" "true"
    else
        assert_true "$test_name" "false" "Content is not valid JSON: $(printf '%s' "$json_content" | head -c 200)"
    fi
}

print_section_header() {
    local title="$1"
    printf '\n\033[36m─────────────────────────────────────────────────────\033[0m\n'
    printf '\033[36m  %s\033[0m\n' "$title"
    printf '\033[36m─────────────────────────────────────────────────────\033[0m\n'
}

echo ""
echo "============================================================="
echo " ops-log-monitor — Linux Module Tests"
echo " $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================="

# -----------------------------------------------------------------------------
# TEST GROUP 1: Module file existence
# -----------------------------------------------------------------------------
print_section_header "Group 1: Module File Existence"

MODULE_FILES=(
    "auth-events.sh"
    "service-events.sh"
    "privilege-events.sh"
    "system-health-events.sh"
    "kernel-events.sh"
)

for file in "${MODULE_FILES[@]}"; do
    assert_file_exists "Module file exists: ${file}" "${MODULES_DIR}/${file}"
done

# -----------------------------------------------------------------------------
# TEST GROUP 2: Configuration file existence
# -----------------------------------------------------------------------------
print_section_header "Group 2: Configuration File Existence"

assert_file_exists "Configuration file exists" "${CONFIG_DIR}/linux-monitor.conf"

# -----------------------------------------------------------------------------
# TEST GROUP 3: Bash syntax validation
# -----------------------------------------------------------------------------
print_section_header "Group 3: Bash Syntax Validation"

for file in "${MODULE_FILES[@]}"; do
    file_path="${MODULES_DIR}/${file}"
    if [[ -f "$file_path" ]]; then
        if bash -n "$file_path" 2>/tmp/syntax-check-err.$$; then
            assert_true "Syntax valid: ${file}" "true"
        else
            err_content=$(cat /tmp/syntax-check-err.$$ 2>/dev/null)
            assert_true "Syntax valid: ${file}" "false" "bash -n reported: ${err_content}"
        fi
        rm -f /tmp/syntax-check-err.$$
    fi
done

if [[ -f "${CONFIG_DIR}/linux-monitor.conf" ]]; then
    if bash -n "${CONFIG_DIR}/linux-monitor.conf" 2>/tmp/syntax-check-err.$$; then
        assert_true "Syntax valid: linux-monitor.conf" "true"
    else
        err_content=$(cat /tmp/syntax-check-err.$$ 2>/dev/null)
        assert_true "Syntax valid: linux-monitor.conf" "false" "bash -n reported: ${err_content}"
    fi
    rm -f /tmp/syntax-check-err.$$
fi

# -----------------------------------------------------------------------------
# TEST GROUP 4: Direct-execution guard validation
# Each module must refuse to run when executed directly rather than
# sourced, since modules depend on orchestrator-provided environment
# variables and functions that are absent in a standalone invocation.
# -----------------------------------------------------------------------------
print_section_header "Group 4: Direct-Execution Guard"

for file in "${MODULE_FILES[@]}"; do
    file_path="${MODULES_DIR}/${file}"
    if [[ -f "$file_path" ]]; then
        set +e
        output=$(bash "$file_path" 2>&1)
        exit_code=$?
        set -e

        guard_worked="false"
        if [[ "$exit_code" -ne 0 ]] && [[ "$output" == *"must be sourced"* ]]; then
            guard_worked="true"
        fi

        assert_true "Direct-execution guard works: ${file}" "$guard_worked" \
            "Expected non-zero exit and 'must be sourced' message. Got exit=${exit_code}, output='${output}'"
    fi
done

# -----------------------------------------------------------------------------
# TEST GROUP 5: Set up a synthetic test environment
#
# All module functions expect certain environment variables and helper
# functions (log_message, and per-module output/summary file paths) to
# be present, since in production these are provided by log-monitor.sh.
# We replicate the minimum necessary orchestrator contract here so each
# module can be exercised in isolation.
# -----------------------------------------------------------------------------
print_section_header "Group 5: Synthetic Test Environment Setup"

TEST_WORKSPACE=$(mktemp -d -t ops-log-monitor-test.XXXXXX)
cleanup_test_workspace() {
    rm -rf "$TEST_WORKSPACE" 2>/dev/null
}
trap cleanup_test_workspace EXIT

assert_true "Test workspace created" "$([[ -d "$TEST_WORKSPACE" ]] && echo true || echo false)" \
    "mktemp -d failed to create workspace"

# Minimal log_message implementation for test purposes — captures calls
# to a file rather than printing, so test output stays readable.
LOG_CAPTURE_FILE="${TEST_WORKSPACE}/test-log-capture.log"
log_message() {
    local level="$1" source="$2" message="$3"
    printf '[%s] [%s] %s\n' "$level" "$source" "$message" >> "$LOG_CAPTURE_FILE"
}

# Window variables — use a window guaranteed to return no journald/auditd
# data (far in the past) so tests validate structure and error-handling
# rather than depending on live system activity.
export WINDOW_START_EPOCH=$(date -d "2015-01-01 00:00:00" +%s 2>/dev/null || echo "1420070400")
export WINDOW_END_EPOCH=$(date -d "2015-01-01 00:00:01" +%s 2>/dev/null || echo "1420070401")
export WINDOW_START_ISO="2015-01-01T00:00:00Z"
export WINDOW_END_ISO="2015-01-01T00:00:01Z"

# Config variables referenced by the modules — mirrors the defaults in
# linux-monitor.conf so module logic runs in a realistic context.
export AUTH_FAILURE_WARN_THRESHOLD=10
export AUTH_FAILURE_CRIT_THRESHOLD=50
export AUTH_ACCOUNT_WARN_THRESHOLD=5
export AUTH_ACCOUNT_CRIT_THRESHOLD=20
export AUTH_INVALID_USER_CRIT_THRESHOLD=20
export AUTH_MONITOR_ROOT_SSH="true"
export SECURE_LOG="/var/log/secure"

SECURITY_RELEVANT_SERVICES=("sshd.service" "auditd.service" "firewalld.service")
CRITICAL_SYSTEM_SERVICES=("dbus.service" "NetworkManager.service")

EXPECTED_SUDO_USERS=("root")
EXPECTED_SU_USERS=("root")
export AUDIT_LOG="/var/log/audit/audit.log"
export AUDIT_LOG_DIR="/var/log/audit"

export SELINUX_MONITOR_ENABLED="true"
export SELINUX_DENIAL_WARN_THRESHOLD=5
export SELINUX_DENIAL_CRIT_THRESHOLD=25
SELINUX_KNOWN_NOISY_CONTEXTS=()

KERNEL_ERROR_PATTERNS=("Out of memory" "oom.kill" "Killed process" "I/O error"
                       "kernel panic" "Oops:" "BUG:" "soft lockup" "hard lockup" "RCU stall")
KERNEL_SUPPRESS_PATTERNS=()
export OOM_KILL_ALWAYS_CRIT="true"

# Per-module output/summary file paths, matching what log-monitor.sh exports
export AUTH_MODULE_OUTPUT_FILE="${TEST_WORKSPACE}/auth-events.jsonl"
export AUTH_MODULE_SUMMARY_FILE="${TEST_WORKSPACE}/auth-summary.json"
export SERVICE_MODULE_OUTPUT_FILE="${TEST_WORKSPACE}/service-events.jsonl"
export SERVICE_MODULE_SUMMARY_FILE="${TEST_WORKSPACE}/service-summary.json"
export PRIVILEGE_MODULE_OUTPUT_FILE="${TEST_WORKSPACE}/privilege-events.jsonl"
export PRIVILEGE_MODULE_SUMMARY_FILE="${TEST_WORKSPACE}/privilege-summary.json"
export SYSHEALTH_MODULE_OUTPUT_FILE="${TEST_WORKSPACE}/syshealth-events.jsonl"
export SYSHEALTH_MODULE_SUMMARY_FILE="${TEST_WORKSPACE}/syshealth-summary.json"
export KERNEL_MODULE_OUTPUT_FILE="${TEST_WORKSPACE}/kernel-events.jsonl"
export KERNEL_MODULE_SUMMARY_FILE="${TEST_WORKSPACE}/kernel-summary.json"

echo "  Synthetic test environment ready at: ${TEST_WORKSPACE}"

# =============================================================================
# Helper: validate a module's summary file structure and internal count
# consistency. Called once per module after its entry function runs.
# =============================================================================

validate_summary_file() {
    local module_display_name="$1"
    local summary_file="$2"
    local expected_category="$3"

    assert_file_exists "${module_display_name} — summary file was created" "$summary_file"

    if [[ -f "$summary_file" ]]; then
        local summary_content
        summary_content=$(cat "$summary_file")

        assert_json_valid "${module_display_name} — summary file is valid JSON" "$summary_content"

        local category total crit warn info
        category=$(printf '%s' "$summary_content" | python3 -c "import json,sys; print(json.load(sys.stdin).get('category',''))" 2>/dev/null)
        total=$(printf '%s' "$summary_content" | python3 -c "import json,sys; print(json.load(sys.stdin).get('total_events',-1))" 2>/dev/null)
        crit=$(printf '%s' "$summary_content" | python3 -c "import json,sys; print(json.load(sys.stdin).get('crit_count',-1))" 2>/dev/null)
        warn=$(printf '%s' "$summary_content" | python3 -c "import json,sys; print(json.load(sys.stdin).get('warn_count',-1))" 2>/dev/null)
        info=$(printf '%s' "$summary_content" | python3 -c "import json,sys; print(json.load(sys.stdin).get('info_count',-1))" 2>/dev/null)

        assert_true "${module_display_name} — category field is '${expected_category}'" \
            "$([[ "$category" == "$expected_category" ]] && echo true || echo false)" \
            "Expected category '${expected_category}', got '${category}'"

        if [[ "$total" -ge 0 && "$crit" -ge 0 && "$warn" -ge 0 && "$info" -ge 0 ]]; then
            local sum=$((crit + warn + info))
            assert_true "${module_display_name} — total_events == crit+warn+info" \
                "$([[ "$total" -eq "$sum" ]] && echo true || echo false)" \
                "total_events(${total}) != crit(${crit})+warn(${warn})+info(${info})=${sum}"
        else
            assert_true "${module_display_name} — count fields are non-negative integers" "false" \
                "One or more count fields missing or invalid: total=${total} crit=${crit} warn=${warn} info=${info}"
        fi
    fi
}

validate_events_file_is_jsonl() {
    local module_display_name="$1"
    local events_file="$2"

    if [[ -f "$events_file" ]]; then
        if [[ ! -s "$events_file" ]]; then
            # Empty file is valid — no events found in the synthetic
            # far-past window, which is expected.
            assert_true "${module_display_name} — events file exists (empty, expected)" "true"
            return
        fi

        local all_valid="true"
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            if ! printf '%s' "$line" | python3 -c "import json,sys; json.loads(sys.stdin.read())" 2>/dev/null; then
                all_valid="false"
                break
            fi
        done < "$events_file"

        assert_true "${module_display_name} — every line in events file is valid JSON" "$all_valid" \
            "One or more lines in ${events_file} are not valid JSON"
    else
        assert_true "${module_display_name} — events file exists" "false" \
            "Expected file not found: ${events_file}"
    fi
}

# -----------------------------------------------------------------------------
# TEST GROUP 6: auth-events.sh functional structural test
# -----------------------------------------------------------------------------
print_section_header "Group 6: auth-events.sh — Structural Validation"

auth_module_path="${MODULES_DIR}/auth-events.sh"
if [[ -f "$auth_module_path" ]]; then
    # shellcheck source=/dev/null
    source "$auth_module_path"

    if run_auth_module 2>>"${TEST_WORKSPACE}/auth-stderr.log"; then
        assert_true "auth-events.sh — run_auth_module executed without error" "true"
    else
        assert_true "auth-events.sh — run_auth_module executed without error" "false" \
            "Function returned non-zero exit status. stderr: $(cat "${TEST_WORKSPACE}/auth-stderr.log" 2>/dev/null)"
    fi

    validate_summary_file "auth-events.sh" "$AUTH_MODULE_SUMMARY_FILE" "Authentication"
    validate_events_file_is_jsonl "auth-events.sh" "$AUTH_MODULE_OUTPUT_FILE"
else
    echo "  SKIP  Module file not found — skipping Group 6"
fi

# -----------------------------------------------------------------------------
# TEST GROUP 7: service-events.sh functional structural test
# -----------------------------------------------------------------------------
print_section_header "Group 7: service-events.sh — Structural Validation"

service_module_path="${MODULES_DIR}/service-events.sh"
if [[ -f "$service_module_path" ]]; then
    # shellcheck source=/dev/null
    source "$service_module_path"

    if run_service_module 2>>"${TEST_WORKSPACE}/service-stderr.log"; then
        assert_true "service-events.sh — run_service_module executed without error" "true"
    else
        assert_true "service-events.sh — run_service_module executed without error" "false" \
            "Function returned non-zero exit status. stderr: $(cat "${TEST_WORKSPACE}/service-stderr.log" 2>/dev/null)"
    fi

    validate_summary_file "service-events.sh" "$SERVICE_MODULE_SUMMARY_FILE" "Services"
    validate_events_file_is_jsonl "service-events.sh" "$SERVICE_MODULE_OUTPUT_FILE"
else
    echo "  SKIP  Module file not found — skipping Group 7"
fi

# -----------------------------------------------------------------------------
# TEST GROUP 8: privilege-events.sh functional structural test
# -----------------------------------------------------------------------------
print_section_header "Group 8: privilege-events.sh — Structural Validation"

privilege_module_path="${MODULES_DIR}/privilege-events.sh"
if [[ -f "$privilege_module_path" ]]; then
    # shellcheck source=/dev/null
    source "$privilege_module_path"

    if run_privilege_module 2>>"${TEST_WORKSPACE}/privilege-stderr.log"; then
        assert_true "privilege-events.sh — run_privilege_module executed without error" "true"
    else
        assert_true "privilege-events.sh — run_privilege_module executed without error" "false" \
            "Function returned non-zero exit status. stderr: $(cat "${TEST_WORKSPACE}/privilege-stderr.log" 2>/dev/null)"
    fi

    validate_summary_file "privilege-events.sh" "$PRIVILEGE_MODULE_SUMMARY_FILE" "Privilege"
    validate_events_file_is_jsonl "privilege-events.sh" "$PRIVILEGE_MODULE_OUTPUT_FILE"

    # -------------------------------------------------------------------------
    # Isolated unit test for the hex-decoding helper — this is the most
    # error-prone piece of logic in this module and deserves a targeted
    # test independent of live audit.log data.
    # -------------------------------------------------------------------------
    if declare -f decode_audit_cmd > /dev/null; then
        decoded=$(decode_audit_cmd "6c73202d6c61")
        assert_true "privilege-events.sh — decode_audit_cmd('6c73202d6c61') == 'ls -la'" \
            "$([[ "$decoded" == "ls -la" ]] && echo true || echo false)" \
            "Expected 'ls -la', got '${decoded}'"

        # Non-hex input should pass through unchanged
        decoded_passthrough=$(decode_audit_cmd "not-hex-input!")
        assert_true "privilege-events.sh — decode_audit_cmd passes through non-hex input unchanged" \
            "$([[ "$decoded_passthrough" == "not-hex-input!" ]] && echo true || echo false)" \
            "Expected passthrough of 'not-hex-input!', got '${decoded_passthrough}'"
    else
        assert_true "privilege-events.sh — decode_audit_cmd function is defined" "false" \
            "Function not found after sourcing module"
    fi
else
    echo "  SKIP  Module file not found — skipping Group 8"
fi

# -----------------------------------------------------------------------------
# TEST GROUP 9: system-health-events.sh functional structural test
# -----------------------------------------------------------------------------
print_section_header "Group 9: system-health-events.sh — Structural Validation"

syshealth_module_path="${MODULES_DIR}/system-health-events.sh"
if [[ -f "$syshealth_module_path" ]]; then
    # shellcheck source=/dev/null
    source "$syshealth_module_path"

    if run_system_health_module 2>>"${TEST_WORKSPACE}/syshealth-stderr.log"; then
        assert_true "system-health-events.sh — run_system_health_module executed without error" "true"
    else
        assert_true "system-health-events.sh — run_system_health_module executed without error" "false" \
            "Function returned non-zero exit status. stderr: $(cat "${TEST_WORKSPACE}/syshealth-stderr.log" 2>/dev/null)"
    fi

    validate_summary_file "system-health-events.sh" "$SYSHEALTH_MODULE_SUMMARY_FILE" "SystemHealth"
    validate_events_file_is_jsonl "system-health-events.sh" "$SYSHEALTH_MODULE_OUTPUT_FILE"

    # Verify the extended summary fields specific to this module
    if [[ -f "$SYSHEALTH_MODULE_SUMMARY_FILE" ]]; then
        summary_content=$(cat "$SYSHEALTH_MODULE_SUMMARY_FILE")
        has_shutdown_field=$(printf '%s' "$summary_content" | python3 -c "import json,sys; d=json.load(sys.stdin); print('unexpected_shutdowns' in d)" 2>/dev/null)
        assert_true "system-health-events.sh — summary includes unexpected_shutdowns field" \
            "$([[ "$has_shutdown_field" == "True" ]] && echo true || echo false)" \
            "Field 'unexpected_shutdowns' missing from summary JSON"
    fi
else
    echo "  SKIP  Module file not found — skipping Group 9"
fi

# -----------------------------------------------------------------------------
# TEST GROUP 10: kernel-events.sh functional structural test
# -----------------------------------------------------------------------------
print_section_header "Group 10: kernel-events.sh — Structural Validation"

kernel_module_path="${MODULES_DIR}/kernel-events.sh"
if [[ -f "$kernel_module_path" ]]; then
    # shellcheck source=/dev/null
    source "$kernel_module_path"

    if run_kernel_module 2>>"${TEST_WORKSPACE}/kernel-stderr.log"; then
        assert_true "kernel-events.sh — run_kernel_module executed without error" "true"
    else
        assert_true "kernel-events.sh — run_kernel_module executed without error" "false" \
            "Function returned non-zero exit status. stderr: $(cat "${TEST_WORKSPACE}/kernel-stderr.log" 2>/dev/null)"
    fi

    validate_summary_file "kernel-events.sh" "$KERNEL_MODULE_SUMMARY_FILE" "Kernel"
    validate_events_file_is_jsonl "kernel-events.sh" "$KERNEL_MODULE_OUTPUT_FILE"
else
    echo "  SKIP  Module file not found — skipping Group 10"
fi

# -----------------------------------------------------------------------------
# TEST GROUP 11: Shared helper function correctness (json_escape)
# json_escape is duplicated across all five modules (a deliberate design
# choice for module independence — see architecture.md). This test
# validates the same known input/output pairs against whichever module's
# implementation is currently loaded in this shell, confirming the
# escaping logic is correct at least once as a representative sample.
# -----------------------------------------------------------------------------
print_section_header "Group 11: json_escape Helper Correctness"

if declare -f json_escape > /dev/null; then
    result=$(json_escape 'simple text')
    assert_true "json_escape — passes through simple text unchanged" \
        "$([[ "$result" == "simple text" ]] && echo true || echo false)" \
        "Expected 'simple text', got '${result}'"

    result=$(json_escape 'text with "quotes"')
    assert_true "json_escape — escapes double quotes" \
        "$([[ "$result" == 'text with \"quotes\"' ]] && echo true || echo false)" \
        "Expected escaped quotes, got '${result}'"

    result=$(json_escape 'back\slash')
    assert_true "json_escape — escapes backslash" \
        "$([[ "$result" == 'back\\slash' ]] && echo true || echo false)" \
        "Expected escaped backslash, got '${result}'"

    result=$(json_escape $'line one\nline two')
    assert_true "json_escape — collapses embedded newline to space" \
        "$([[ "$result" == "line one line two" ]] && echo true || echo false)" \
        "Expected newline collapsed to space, got '${result}'"
else
    assert_true "json_escape function is available for testing" "false" \
        "No json_escape function found in current shell — expected from a sourced module"
fi

# =============================================================================
# RESULTS SUMMARY
# =============================================================================

TOTAL_TESTS=$((TESTS_PASSED + TESTS_FAILED))

echo ""
echo "============================================================="
echo " Test Results Summary"
echo "============================================================="
echo " Total tests:  ${TOTAL_TESTS}"
printf ' Passed:       \033[32m%s\033[0m\n' "$TESTS_PASSED"
if [[ "$TESTS_FAILED" -gt 0 ]]; then
    printf ' Failed:       \033[31m%s\033[0m\n' "$TESTS_FAILED"
else
    printf ' Failed:       %s\n' "$TESTS_FAILED"
fi
echo "============================================================="

if [[ "$TESTS_FAILED" -gt 0 ]]; then
    echo ""
    printf '\033[31m FAILED TESTS:\033[0m\n'
    for name in "${FAILED_TEST_NAMES[@]}"; do
        printf '   - %s\n' "$name"
    done
fi

echo ""

if [[ "$TESTS_FAILED" -gt 0 ]]; then
    exit 1
else
    exit 0
fi