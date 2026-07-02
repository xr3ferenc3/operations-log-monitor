#!/usr/bin/env bash
# =============================================================================
# kernel-events.sh
# ops-log-monitor — Linux Kernel and SELinux Event Module
# =============================================================================
#
# PURPOSE:
#   Detects SELinux AVC (Access Vector Cache) denials from auditd and kernel
#   warnings/errors (oops, BUG, panic, lockups) from journald. AVC denials
#   indicate a process attempted an action its security policy does not
#   permit — a significant signal in a correctly configured environment.
#   Kernel oops/BUG/panic indicators signal kernel-level instability.
#
# CALLED BY:
#   log-monitor.sh (orchestrator), via: source kernel-events.sh; run_kernel_module
#
# INPUTS (environment variables expected to be set by the orchestrator):
#   WINDOW_START_EPOCH, WINDOW_END_EPOCH, WINDOW_START_ISO, WINDOW_END_ISO
#   SELINUX_MONITOR_ENABLED, SELINUX_DENIAL_WARN_THRESHOLD,
#   SELINUX_DENIAL_CRIT_THRESHOLD, SELINUX_KNOWN_NOISY_CONTEXTS (array)
#   KERNEL_ERROR_PATTERNS (array), KERNEL_SUPPRESS_PATTERNS (array)
#   AUDIT_LOG
#
# OUTPUT:
#   JSON Lines events written to $KERNEL_MODULE_OUTPUT_FILE
#   Summary JSON written to $KERNEL_MODULE_SUMMARY_FILE
#
#   Each event line has the structure:
#   {
#     "time_created": "ISO8601",
#     "event_type": "avc_denial|kernel_oops|kernel_bug|kernel_warning|kernel_panic",
#     "severity": "CRIT|WARN|INFO",
#     "source_context": "string",
#     "description": "string"
#   }
#
# REQUIRED PREREQUISITES:
#   SELinux in enforcing or permissive mode (not disabled) for AVC detection
#   auditd running and /var/log/audit/audit.log readable for AVC detection
#   journald accessible for kernel warning/error detection
#
# =============================================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "ERROR: kernel-events.sh is a module and must be sourced by log-monitor.sh, not executed directly." >&2
    echo "Usage: bash linux/log-monitor.sh" >&2
    exit 1
fi

# -----------------------------------------------------------------------------
# run_kernel_module
# -----------------------------------------------------------------------------
run_kernel_module() {
    log_message "INFO" "Kernel" "Module started. Window: ${WINDOW_START_ISO} to ${WINDOW_END_ISO}"

    local total_events=0
    local crit_count=0
    local warn_count=0
    local info_count=0
    local -a module_errors=()

    : > "${KERNEL_MODULE_OUTPUT_FILE}"

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
        local source_context="$4"
        local description="$5"

        source_context=$(json_escape "$source_context")
        description=$(json_escape "$description")

        printf '{"time_created":"%s","event_type":"%s","severity":"%s","source_context":"%s","description":"%s"}\n' \
            "$time_created" "$event_type" "$severity" "$source_context" "$description" \
            >> "${KERNEL_MODULE_OUTPUT_FILE}"

        total_events=$((total_events + 1))
        case "$severity" in
            CRIT) crit_count=$((crit_count + 1)) ;;
            WARN) warn_count=$((warn_count + 1)) ;;
            INFO) info_count=$((info_count + 1)) ;;
        esac
    }

    # -------------------------------------------------------------------------
    # STEP 1: SELinux AVC denial detection.
    #
    # Skipped entirely if SELinux is disabled — disabled SELinux generates
    # no AVC records regardless of activity, so querying for them would
    # produce a misleading empty section rather than an explained absence.
    # -------------------------------------------------------------------------
    if [[ "${SELINUX_MONITOR_ENABLED}" == "true" ]]; then
        local selinux_mode
        selinux_mode=$(getenforce 2>/dev/null || echo "Unknown")

        if [[ "$selinux_mode" == "Disabled" ]]; then
            log_message "INFO" "Kernel" "SELinux is Disabled on this system — AVC denial monitoring skipped (no AVC records are generated when SELinux is disabled)"
        elif [[ "$selinux_mode" == "Unknown" ]]; then
            local err_msg="Could not determine SELinux mode via getenforce — AVC denial monitoring skipped"
            log_message "WARN" "Kernel" "$err_msg"
            module_errors+=("$err_msg")
        else
            log_message "INFO" "Kernel" "SELinux mode: ${selinux_mode} — querying AVC denials"

            if [[ ! -r "${AUDIT_LOG}" ]]; then
                local err_msg="${AUDIT_LOG} is not readable — AVC denial detection requires auditd running with a readable audit log"
                log_message "WARN" "Kernel" "$err_msg"
                module_errors+=("$err_msg")
            else
                # Build the known-noisy-context lookup for suppression marking.
                declare -A noisy_context_set
                for ctx in "${SELINUX_KNOWN_NOISY_CONTEXTS[@]}"; do
                    noisy_context_set["$ctx"]=1
                done

                local avc_records
                avc_records=$(grep "type=AVC" "${AUDIT_LOG}" 2>/dev/null | \
                    awk -v start="${WINDOW_START_EPOCH}" -v end="${WINDOW_END_EPOCH}" '
                    {
                        if (match($0, /audit\(([0-9]+)\.[0-9]+:/, arr)) {
                            ts = arr[1] + 0
                            if (ts >= start && ts <= end) {
                                print $0
                            }
                        }
                    }' 2>/dev/null || true)

                # Track denial counts per source context for threshold evaluation.
                declare -A denials_by_scontext
                local -a avc_event_data=()  # buffer for two-pass severity assignment

                while IFS= read -r record; do
                    [[ -z "$record" ]] && continue

                    local epoch_ts iso_ts
                    epoch_ts=$(printf '%s' "$record" | sed -n 's/.*audit(\([0-9]*\)\..*/\1/p')
                    iso_ts=$(date -u -d "@${epoch_ts}" "+%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || printf '%s' "${WINDOW_END_ISO}")

                    # Extract the denied permission, e.g. "denied { read write }"
                    local denied_perm
                    denied_perm=$(printf '%s' "$record" | sed -n 's/.*denied[[:space:]]*{[[:space:]]*\([a-z_ ]*\)}.*/\1/p' | xargs)
                    [[ -z "$denied_perm" ]] && denied_perm="unknown"

                    # Extract the process name (comm field).
                    local proc_comm
                    proc_comm=$(printf '%s' "$record" | sed -n 's/.*comm="\([^"]*\)".*/\1/p')
                    [[ -z "$proc_comm" ]] && proc_comm="unknown"

                    # Extract source context (scontext) and target context (tcontext).
                    local scontext tcontext tclass
                    scontext=$(printf '%s' "$record" | sed -n 's/.*scontext=\([^[:space:]]*\).*/\1/p')
                    tcontext=$(printf '%s' "$record" | sed -n 's/.*tcontext=\([^[:space:]]*\).*/\1/p')
                    tclass=$(printf '%s' "$record" | sed -n 's/.*tclass=\([a-z_]*\).*/\1/p')

                    # Extract permissive flag — 0 means the action was blocked
                    # (enforcing), 1 means it was allowed but logged (permissive).
                    local permissive_flag
                    permissive_flag=$(printf '%s' "$record" | sed -n 's/.*permissive=\([01]\).*/\1/p')

                    denials_by_scontext["$scontext"]=$(( ${denials_by_scontext["$scontext"]:-0} + 1 ))

                    local is_noisy="false"
                    [[ -n "${noisy_context_set[$scontext]:-}" ]] && is_noisy="true"

                    local enforcement_note="BLOCKED (enforcing)"
                    [[ "$permissive_flag" == "1" ]] && enforcement_note="ALLOWED (permissive mode — logged only)"

                    local description="SELinux denied '$proc_comm' [$scontext] permission '$denied_perm' on $tclass object [$tcontext] — $enforcement_note"

                    # Store as a pipe-delimited record for the second pass,
                    # where final severity is assigned based on accumulated
                    # per-context counts.
                    avc_event_data+=("${iso_ts}|${scontext}|${is_noisy}|${description}")
                done <<< "$avc_records"

                # -----------------------------------------------------------
                # Second pass: assign severity based on per-context denial
                # counts now that the full window has been processed, mirroring
                # the two-pass threshold pattern used in auth-events.sh.
                # -----------------------------------------------------------
                for entry in "${avc_event_data[@]}"; do
                    IFS='|' read -r iso_ts scontext is_noisy description <<< "$entry"

                    local context_count="${denials_by_scontext[$scontext]:-0}"
                    local severity="INFO"

                    if [[ "$is_noisy" == "true" ]]; then
                        # Known-noisy contexts are always INFO regardless of
                        # count — these are documented policy gaps under
                        # active remediation, not new findings.
                        severity="INFO"
                        description="${description} [KNOWN NOISY CONTEXT — see SELINUX_KNOWN_NOISY_CONTEXTS in config]"
                    elif [[ "$context_count" -ge "${SELINUX_DENIAL_CRIT_THRESHOLD}" ]]; then
                        severity="CRIT"
                    elif [[ "$context_count" -ge "${SELINUX_DENIAL_WARN_THRESHOLD}" ]]; then
                        severity="WARN"
                    fi

                    write_event "$iso_ts" "avc_denial" "$severity" "$scontext" "$description"
                done

                local total_avc_count=${#avc_event_data[@]}
                log_message "INFO" "Kernel" "Processed ${total_avc_count} AVC denial records across $(echo "${!denials_by_scontext[@]}" | wc -w) distinct source contexts"
            fi
        fi
    else
        log_message "INFO" "Kernel" "SELinux monitoring disabled in configuration — skipping AVC denial detection"
    fi

    # -------------------------------------------------------------------------
    # STEP 2: Kernel warning/error detection from journald --dmesg.
    #
    # Applies the configurable KERNEL_ERROR_PATTERNS list against kernel
    # messages, then filters out anything matching KERNEL_SUPPRESS_PATTERNS
    # to eliminate known-benign noise specific to this environment.
    # -------------------------------------------------------------------------
    log_message "INFO" "Kernel" "Querying kernel messages for warnings, oops, BUG, and panic indicators"

    local kernel_log
    if ! kernel_log=$(journalctl --no-pager \
                                  --since="@${WINDOW_START_EPOCH}" \
                                  --until="@${WINDOW_END_EPOCH}" \
                                  --dmesg \
                                  --priority=warning \
                                  --output=short-iso 2>&1); then
        local err_msg="journalctl --dmesg --priority=warning query failed: ${kernel_log}"
        log_message "ERROR" "Kernel" "$err_msg"
        module_errors+=("$err_msg")
        kernel_log=""
    fi

    # Build a single extended-regex alternation from the configured error
    # patterns for an efficient single-pass grep, rather than looping the
    # pattern list against every line individually.
    local error_pattern_regex
    error_pattern_regex=$(IFS='|'; echo "${KERNEL_ERROR_PATTERNS[*]}")

    local matched_lines
    if [[ -n "$kernel_log" && -n "$error_pattern_regex" ]]; then
        matched_lines=$(printf '%s\n' "$kernel_log" | grep -iE "$error_pattern_regex" || true)
    else
        matched_lines=""
    fi

    # Apply suppression patterns to filter out known-benign matches.
    if [[ -n "$matched_lines" && ${#KERNEL_SUPPRESS_PATTERNS[@]} -gt 0 ]]; then
        local suppress_pattern_regex
        suppress_pattern_regex=$(IFS='|'; echo "${KERNEL_SUPPRESS_PATTERNS[*]}")
        matched_lines=$(printf '%s\n' "$matched_lines" | grep -ivE "$suppress_pattern_regex" || true)
    fi

    local matched_count
    matched_count=$(printf '%s\n' "$matched_lines" | grep -c . || true)
    log_message "INFO" "Kernel" "Found ${matched_count} kernel warning/error lines after suppression filtering"

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        local line_timestamp
        line_timestamp=$(printf '%s' "$line" | awk '{print $1}')

        # Classify by specific indicator for accurate event_type and severity.
        # Order matters: panic and BUG are checked before generic WARNING.
        if [[ "$line" =~ [Kk]ernel\ panic ]]; then
            write_event "$line_timestamp" "kernel_panic" "CRIT" "kernel" \
                "Kernel panic detected — unrecoverable kernel error, system halted or rebooted. This is the most severe kernel-level event possible."

        elif [[ "$line" =~ BUG: ]]; then
            write_event "$line_timestamp" "kernel_bug" "CRIT" "kernel" \
                "Kernel BUG assertion triggered — indicates a serious kernel-level inconsistency. System stability cannot be guaranteed after this point until rebooted."

        elif [[ "$line" =~ Oops: ]]; then
            write_event "$line_timestamp" "kernel_oops" "CRIT" "kernel" \
                "Kernel oops detected — a recoverable kernel bug occurred but the system continued running. Investigate the associated call trace; reboot may be warranted."

        elif [[ "$line" =~ general\ protection\ fault ]]; then
            write_event "$line_timestamp" "kernel_oops" "CRIT" "kernel" \
                "General protection fault detected — CPU detected an invalid memory access at the kernel level."

        elif [[ "$line" =~ soft\ lockup ]]; then
            write_event "$line_timestamp" "kernel_warning" "CRIT" "kernel" \
                "Soft lockup detected — a CPU was unresponsive for an extended period. Investigate for runaway processes or driver issues."

        elif [[ "$line" =~ hard\ lockup ]]; then
            write_event "$line_timestamp" "kernel_warning" "CRIT" "kernel" \
                "Hard lockup detected — a CPU stopped responding to interrupts entirely. Strong indicator of imminent system failure."

        elif [[ "$line" =~ RCU\ stall ]]; then
            write_event "$line_timestamp" "kernel_warning" "WARN" "kernel" \
                "RCU stall detected — a CPU did not check in with the kernel's RCU subsystem in time. Can indicate CPU starvation or scheduling problems."

        elif [[ "$line" =~ WARNING: ]]; then
            write_event "$line_timestamp" "kernel_warning" "WARN" "kernel" \
                "Kernel WARNING logged — may or may not indicate an active problem; review the full message for context."

        elif [[ "$line" =~ Out\ of\ memory|oom.kill|Killed\ process ]]; then
            # OOM messages also match the storage/health error pattern set
            # and are primarily handled in system-health-events.sh. We skip
            # them here to avoid duplicate reporting across modules.
            continue

        elif [[ "$line" =~ I/O\ error|Buffer\ I/O|blk_update_request|EXT4-fs|XFS|ata.*error|SCSI\ error|nvme.*error ]]; then
            # Disk/filesystem errors are the responsibility of
            # system-health-events.sh. Skip here for the same reason.
            continue

        else
            # Matched the broad error pattern list but did not match a
            # specific known classification above (e.g., a generic
            # "Call Trace:" line accompanying an oops reported separately).
            # Report at WARN with the raw matched text for administrator review.
            local truncated_line="$line"
            if [[ ${#truncated_line} -gt 200 ]]; then
                truncated_line="${truncated_line:0:200}...(truncated)"
            fi
            write_event "$line_timestamp" "kernel_warning" "WARN" "kernel" \
                "Kernel message matched error pattern list: $truncated_line"
        fi
    done <<< "$matched_lines"

    # -------------------------------------------------------------------------
    # STEP 3: Write summary file consumed by the orchestrator.
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

    cat > "${KERNEL_MODULE_SUMMARY_FILE}" <<EOF
{"category":"Kernel","total_events":${total_events},"crit_count":${crit_count},"warn_count":${warn_count},"info_count":${info_count},"errors":${errors_json}}
EOF

    log_message "INFO" "Kernel" "Module complete. Total: ${total_events} CRIT: ${crit_count} WARN: ${warn_count} INFO: ${info_count}"
}