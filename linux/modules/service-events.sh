#!/usr/bin/env bash
# =============================================================================
# service-events.sh
# ops-log-monitor — Linux Service Event Module
# =============================================================================
#
# PURPOSE:
#   Detects systemd unit failures, unexpected service state changes, and
#   units currently in failed state. Combines journal log analysis (what
#   happened during the window) with live systemctl state (what is failed
#   right now) to catch both transient and persistent failures.
#
# CALLED BY:
#   log-monitor.sh (orchestrator), via: source service-events.sh; run_service_module
#
# INPUTS (environment variables expected to be set by the orchestrator):
#   WINDOW_START_EPOCH, WINDOW_END_EPOCH, WINDOW_START_ISO, WINDOW_END_ISO
#   SECURITY_RELEVANT_SERVICES (array), CRITICAL_SYSTEM_SERVICES (array)
#
# OUTPUT:
#   JSON Lines events written to $SERVICE_MODULE_OUTPUT_FILE
#   Summary JSON written to $SERVICE_MODULE_SUMMARY_FILE
#
#   Each event line has the structure:
#   {
#     "time_created": "ISO8601",
#     "event_type": "unit_failed|start_failure|currently_failed|persistent_failure",
#     "severity": "CRIT|WARN|INFO",
#     "unit_name": "string",
#     "is_security_relevant": true|false,
#     "description": "string"
#   }
#
# REQUIRED PREREQUISITES:
#   systemd as init system (guaranteed on RHEL 9)
#   journald accessible for the user running the script
#
# =============================================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "ERROR: service-events.sh is a module and must be sourced by log-monitor.sh, not executed directly." >&2
    echo "Usage: bash linux/log-monitor.sh" >&2
    exit 1
fi

# -----------------------------------------------------------------------------
# run_service_module
#
# Main entry point. Called by orchestrator after sourcing this file.
# -----------------------------------------------------------------------------
run_service_module() {
    log_message "INFO" "Services" "Module started. Window: ${WINDOW_START_ISO} to ${WINDOW_END_ISO}"

    local total_events=0
    local crit_count=0
    local warn_count=0
    local info_count=0
    local -a module_errors=()

    : > "${SERVICE_MODULE_OUTPUT_FILE}"

    # Build a lookup string for security-relevant and critical services.
    # Bash associative arrays provide O(1) membership testing, used the
    # same way the HashSet pattern is used in the PowerShell modules.
    declare -A security_relevant_set
    for svc in "${SECURITY_RELEVANT_SERVICES[@]}"; do
        security_relevant_set["$svc"]=1
    done

    declare -A critical_system_set
    for svc in "${CRITICAL_SYSTEM_SERVICES[@]}"; do
        critical_system_set["$svc"]=1
    done

    # Track stop counts per unit for crash loop detection, consistent with
    # the approach used in Get-ServiceEvents.ps1.
    declare -A stop_counts

    json_escape() {
        local input="$1"
        input="${input//\\/\\\\}"
        input="${input//\"/\\\"}"
        input="${input//$'\t'/\\t}"
        input="${input//$'\n'/ }"
        input="${input//$'\r'/}"
        printf '%s' "$input"
    }

    write_event() {
        local time_created="$1"
        local event_type="$2"
        local severity="$3"
        local unit_name="$4"
        local is_security_relevant="$5"
        local description="$6"

        unit_name=$(json_escape "$unit_name")
        description=$(json_escape "$description")

        printf '{"time_created":"%s","event_type":"%s","severity":"%s","unit_name":"%s","is_security_relevant":%s,"description":"%s"}\n' \
            "$time_created" "$event_type" "$severity" "$unit_name" "$is_security_relevant" "$description" \
            >> "${SERVICE_MODULE_OUTPUT_FILE}"

        total_events=$((total_events + 1))
        case "$severity" in
            CRIT) crit_count=$((crit_count + 1)) ;;
            WARN) warn_count=$((warn_count + 1)) ;;
            INFO) info_count=$((info_count + 1)) ;;
        esac
    }

    # -------------------------------------------------------------------------
    # STEP 1: Query journald for systemd unit failure messages within window.
    #
    # systemd itself logs unit failures under the "systemd" identifier. We
    # grep for the specific phrases systemd uses when a unit fails to start,
    # enters failed state, or fails with a non-zero exit/signal/timeout result.
    # -------------------------------------------------------------------------
    log_message "INFO" "Services" "Querying journald for systemd unit failure messages"

    local systemd_log
    if ! systemd_log=$(journalctl --no-pager \
                                   --since="@${WINDOW_START_EPOCH}" \
                                   --until="@${WINDOW_END_EPOCH}" \
                                   --identifier=systemd \
                                   --output=short-iso 2>&1); then
        local err_msg="journalctl query for systemd identifier failed: ${systemd_log}"
        log_message "ERROR" "Services" "$err_msg"
        module_errors+=("$err_msg")
        systemd_log=""
    fi

    local line_count
    line_count=$(printf '%s\n' "$systemd_log" | grep -c . || true)
    log_message "INFO" "Services" "Retrieved ${line_count} systemd log lines"

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        local line_timestamp
        line_timestamp=$(printf '%s' "$line" | awk '{print $1}')

        # --- Unit failed to start ---
        if [[ "$line" =~ Failed\ to\ start\ ([^\.]+\.[a-z]+) ]]; then
            local unit_name="${BASH_REMATCH[1]}"
            local is_sec_relevant="false"
            local severity="WARN"

            if [[ -n "${security_relevant_set[$unit_name]:-}" ]]; then
                is_sec_relevant="true"
                severity="CRIT"
            fi
            if [[ -n "${critical_system_set[$unit_name]:-}" ]]; then
                severity="CRIT"
            fi

            write_event "$line_timestamp" "start_failure" "$severity" "$unit_name" "$is_sec_relevant" \
                "Unit '$unit_name' failed to start"

        # --- Unit entered failed state ---
        elif [[ "$line" =~ ([a-zA-Z0-9_@.-]+\.[a-z]+):\ Failed\ with\ result\ \'([a-z-]+)\' ]]; then
            local unit_name="${BASH_REMATCH[1]}"
            local fail_result="${BASH_REMATCH[2]}"
            local is_sec_relevant="false"
            local severity="WARN"

            if [[ -n "${security_relevant_set[$unit_name]:-}" ]]; then
                is_sec_relevant="true"
                severity="CRIT"
            fi
            if [[ -n "${critical_system_set[$unit_name]:-}" ]]; then
                severity="CRIT"
            fi

            # Track for crash loop detection — count each distinct failure
            # event per unit.
            stop_counts["$unit_name"]=$(( ${stop_counts["$unit_name"]:-0} + 1 ))

            local result_explanation
            case "$fail_result" in
                exit-code) result_explanation="process exited with non-zero status" ;;
                signal)    result_explanation="process was killed by a signal (possible crash or OOM kill)" ;;
                timeout)   result_explanation="unit did not start within its configured timeout" ;;
                *)         result_explanation="result: $fail_result" ;;
            esac

            write_event "$line_timestamp" "unit_failed" "$severity" "$unit_name" "$is_sec_relevant" \
                "Unit '$unit_name' entered failed state — $result_explanation"

        # --- Unit entered failed state (alternate message format) ---
        elif [[ "$line" =~ ([a-zA-Z0-9_@.-]+\.[a-z]+).*entered\ failed\ state ]]; then
            local unit_name="${BASH_REMATCH[1]}"
            local is_sec_relevant="false"
            local severity="WARN"

            if [[ -n "${security_relevant_set[$unit_name]:-}" ]]; then
                is_sec_relevant="true"
                severity="CRIT"
            fi
            if [[ -n "${critical_system_set[$unit_name]:-}" ]]; then
                severity="CRIT"
            fi

            stop_counts["$unit_name"]=$(( ${stop_counts["$unit_name"]:-0} + 1 ))

            write_event "$line_timestamp" "unit_failed" "$severity" "$unit_name" "$is_sec_relevant" \
                "Unit '$unit_name' entered failed state"
        fi
    done <<< "$systemd_log"

    # -------------------------------------------------------------------------
    # STEP 2: Crash loop detection.
    #
    # A unit that failed three or more times within the monitoring window is
    # reported as a synthetic CRIT event summarizing the pattern, consistent
    # with the approach used in Get-ServiceEvents.ps1 for Windows Event 7036.
    # -------------------------------------------------------------------------
    local crash_loop_threshold=3

    for unit_name in "${!stop_counts[@]}"; do
        local fail_count="${stop_counts[$unit_name]}"
        if [[ "$fail_count" -ge "$crash_loop_threshold" ]]; then
            local is_sec_relevant="false"
            if [[ -n "${security_relevant_set[$unit_name]:-}" ]]; then
                is_sec_relevant="true"
            fi

            write_event "${WINDOW_END_ISO}" "crash_loop" "CRIT" "$unit_name" "$is_sec_relevant" \
                "Unit '$unit_name' failed ${fail_count} times within the monitoring window — crash loop detected"

            log_message "WARN" "Services" "Crash loop detected: '$unit_name' failed ${fail_count} times"
        fi
    done

    # -------------------------------------------------------------------------
    # STEP 3: Query current systemd unit state for units presently in failed
    # state. This is a live state check, not a log query, and catches units
    # that failed before the monitoring window began but remain unaddressed —
    # a "persistent failure" that may not generate new journal entries.
    # -------------------------------------------------------------------------
    log_message "INFO" "Services" "Querying current systemd failed unit state"

    local failed_units_raw
    if ! failed_units_raw=$(systemctl list-units --state=failed --no-legend --no-pager 2>&1); then
        local err_msg="systemctl list-units query failed: ${failed_units_raw}"
        log_message "ERROR" "Services" "$err_msg"
        module_errors+=("$err_msg")
        failed_units_raw=""
    fi

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        # Output format: "unit.service  loaded failed failed  Description text"
        local unit_name
        unit_name=$(printf '%s' "$line" | awk '{print $1}')

        [[ -z "$unit_name" ]] && continue

        # If this unit already appeared in our journal-based events above for
        # this window, it is not a "persistent" failure from before the
        # window — it is already correctly represented. Skip duplicates.
        if [[ -n "${stop_counts[$unit_name]:-}" ]]; then
            continue
        fi

        local is_sec_relevant="false"
        local severity="WARN"
        if [[ -n "${security_relevant_set[$unit_name]:-}" ]]; then
            is_sec_relevant="true"
            severity="CRIT"
        fi
        if [[ -n "${critical_system_set[$unit_name]:-}" ]]; then
            severity="CRIT"
        fi

        write_event "${WINDOW_END_ISO}" "persistent_failure" "$severity" "$unit_name" "$is_sec_relevant" \
            "Unit '$unit_name' is currently in failed state but did not generate a failure event within this monitoring window — failure predates the window and remains unresolved"
    done <<< "$failed_units_raw"

    # -------------------------------------------------------------------------
    # STEP 4: Write summary file consumed by the orchestrator.
    # -------------------------------------------------------------------------
    local errors_json="[]"
    if [[ ${#module_errors[@]} -gt 0 ]]; then
        errors_json="["
        local first=true
        for err in "${module_errors[@]}"; do
            local escaped_err
            escaped_err=$(json_escape "$err")
            if [[ "$first" == true ]]; then
                errors_json+="\"${escaped_err}\""
                first=false
            else
                errors_json+=",\"${escaped_err}\""
            fi
        done
        errors_json+="]"
    fi

    cat > "${SERVICE_MODULE_SUMMARY_FILE}" <<EOF
{"category":"Services","total_events":${total_events},"crit_count":${crit_count},"warn_count":${warn_count},"info_count":${info_count},"errors":${errors_json}}
EOF

    log_message "INFO" "Services" "Module complete. Total: ${total_events} CRIT: ${crit_count} WARN: ${warn_count} INFO: ${info_count}"
}