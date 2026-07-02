#!/usr/bin/env bash
# =============================================================================
# privilege-events.sh
# ops-log-monitor — Linux Privilege Event Module
# =============================================================================
#
# PURPOSE:
#   Detects sudo and su executions, including unauthorized attempts, by
#   querying auditd's audit.log as the primary authoritative source with
#   journald as a fallback when auditd is not running. Flags activity by
#   accounts outside the configured expected administrator list.
#
# CALLED BY:
#   log-monitor.sh (orchestrator), via: source privilege-events.sh; run_privilege_module
#
# INPUTS (environment variables expected to be set by the orchestrator):
#   WINDOW_START_EPOCH, WINDOW_END_EPOCH, WINDOW_START_ISO, WINDOW_END_ISO
#   EXPECTED_SUDO_USERS (array), EXPECTED_SU_USERS (array)
#   AUDIT_LOG, AUDIT_LOG_DIR
#
# OUTPUT:
#   JSON Lines events written to $PRIVILEGE_MODULE_OUTPUT_FILE
#   Summary JSON written to $PRIVILEGE_MODULE_SUMMARY_FILE
#
#   Each event line has the structure:
#   {
#     "time_created": "ISO8601",
#     "event_type": "sudo_exec|sudo_denied|su_attempt|sudoers_change",
#     "severity": "CRIT|WARN|INFO",
#     "account": "string",
#     "command": "string",
#     "description": "string"
#   }
#
# REQUIRED PREREQUISITES:
#   auditd running with sudo/su execve rules loaded (preferred, full detail)
#   OR journald with sudo logging via syslog (fallback, reduced detail)
#   See docs/threat-model.md for required auditd rules.
#
# =============================================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "ERROR: privilege-events.sh is a module and must be sourced by log-monitor.sh, not executed directly." >&2
    echo "Usage: bash linux/log-monitor.sh" >&2
    exit 1
fi

# -----------------------------------------------------------------------------
# run_privilege_module
# -----------------------------------------------------------------------------
run_privilege_module() {
    log_message "INFO" "Privilege" "Module started. Window: ${WINDOW_START_ISO} to ${WINDOW_END_ISO}"

    local total_events=0
    local crit_count=0
    local warn_count=0
    local info_count=0
    local -a module_errors=()

    : > "${PRIVILEGE_MODULE_OUTPUT_FILE}"

    declare -A expected_sudo_set
    for user in "${EXPECTED_SUDO_USERS[@]}"; do
        expected_sudo_set["$user"]=1
    done

    declare -A expected_su_set
    for user in "${EXPECTED_SU_USERS[@]}"; do
        expected_su_set["$user"]=1
    done

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
        local account="$4"
        local command="$5"
        local description="$6"

        account=$(json_escape "$account")
        command=$(json_escape "$command")
        description=$(json_escape "$description")

        printf '{"time_created":"%s","event_type":"%s","severity":"%s","account":"%s","command":"%s","description":"%s"}\n' \
            "$time_created" "$event_type" "$severity" "$account" "$command" "$description" \
            >> "${PRIVILEGE_MODULE_OUTPUT_FILE}"

        total_events=$((total_events + 1))
        case "$severity" in
            CRIT) crit_count=$((crit_count + 1)) ;;
            WARN) warn_count=$((warn_count + 1)) ;;
            INFO) info_count=$((info_count + 1)) ;;
        esac
    }

    # -------------------------------------------------------------------------
    # Helper: decode a hex-encoded command string from an auditd USER_CMD
    # record. auditd encodes command arguments containing special characters
    # as a continuous hex string (e.g., 6c73202d6c61 = "ls -la"). We detect
    # whether the cmd field is hex-encoded (all hex digits, even length) and
    # decode it; otherwise we use it as-is, since auditd does not hex-encode
    # commands that contain no special characters.
    # -------------------------------------------------------------------------
    decode_audit_cmd() {
        local raw="$1"

        # Hex-encoded strings consist solely of hex digit pairs.
        if [[ "$raw" =~ ^[0-9A-Fa-f]+$ ]] && [[ $(( ${#raw} % 2 )) -eq 0 ]]; then
            local decoded=""
            local i
            for (( i=0; i<${#raw}; i+=2 )); do
                local hex_pair="${raw:i:2}"
                # printf %b with \x interprets the hex byte. This correctly
                # reconstructs the original command string byte by byte.
                decoded+=$(printf "\\x${hex_pair}")
            done
            printf '%s' "$decoded"
        else
            printf '%s' "$raw"
        fi
    }

    local auditd_available=false
    local auditd_data_found=false

    # -------------------------------------------------------------------------
    # STEP 1: Check whether auditd is running and audit.log is readable.
    # This determines whether we use the high-detail auditd path or fall
    # back to the lower-detail journald path.
    # -------------------------------------------------------------------------
    if systemctl is-active --quiet auditd 2>/dev/null && [[ -r "${AUDIT_LOG}" ]]; then
        auditd_available=true
        log_message "INFO" "Privilege" "auditd is active and ${AUDIT_LOG} is readable — using auditd as primary source"
    else
        log_message "WARN" "Privilege" "auditd is not active or ${AUDIT_LOG} is not readable — falling back to journald (reduced detail, no working directory or full argument capture)"
        module_errors+=("auditd unavailable or audit.log unreadable — privilege detail limited to journald sudo logging")
    fi

    # -------------------------------------------------------------------------
    # STEP 2: Primary path — parse auditd USER_CMD records for sudo execution.
    #
    # auditd records use epoch timestamps embedded in the msg=audit(EPOCH.MS:ID)
    # field. We filter records within our window using awk for numeric epoch
    # comparison, which is more reliable than string-matching ISO timestamps
    # against the audit log's native format.
    # -------------------------------------------------------------------------
    if [[ "$auditd_available" == true ]]; then
        log_message "INFO" "Privilege" "Parsing auditd USER_CMD records for sudo execution"

        local sudo_records
        sudo_records=$(grep "type=USER_CMD" "${AUDIT_LOG}" 2>/dev/null | \
            awk -v start="${WINDOW_START_EPOCH}" -v end="${WINDOW_END_EPOCH}" '
            {
                # Extract epoch timestamp from msg=audit(EPOCH.MS:SERIAL)
                if (match($0, /audit\(([0-9]+)\.[0-9]+:/, arr)) {
                    ts = arr[1] + 0
                    if (ts >= start && ts <= end) {
                        print $0
                    }
                }
            }' 2>/dev/null || true)

        if [[ -n "$sudo_records" ]]; then
            auditd_data_found=true
        fi

        while IFS= read -r record; do
            [[ -z "$record" ]] && continue

            # Extract epoch timestamp for the event time.
            local epoch_ts
            epoch_ts=$(printf '%s' "$record" | sed -n 's/.*audit(\([0-9]*\)\..*/\1/p')
            local iso_ts
            iso_ts=$(date -u -d "@${epoch_ts}" "+%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || printf '%s' "${WINDOW_END_ISO}")

            # Extract uid (the account that ran sudo). auditd records uid as
            # a numeric ID in the raw log; we resolve it to a username.
            local uid
            uid=$(printf '%s' "$record" | sed -n 's/.*[^a]uid=\([0-9]*\).*/\1/p')
            local account
            account=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1)
            [[ -z "$account" ]] && account="uid:${uid}"

            # Extract and decode the command from the hex-encoded cmd field.
            local raw_cmd
            raw_cmd=$(printf '%s' "$record" | sed -n "s/.*cmd=\([0-9A-Fa-f]*\).*/\1/p")
            local command="unknown"
            if [[ -n "$raw_cmd" ]]; then
                command=$(decode_audit_cmd "$raw_cmd")
            fi

            # Extract success/failure result.
            local result
            result=$(printf '%s' "$record" | sed -n 's/.*res=\([a-z]*\).*/\1/p')

            local is_expected="false"
            [[ -n "${expected_sudo_set[$account]:-}" ]] && is_expected="true"

            if [[ "$result" == "success" ]]; then
                local severity="INFO"
                [[ "$is_expected" == "false" ]] && severity="WARN"

                local note=""
                [[ "$is_expected" == "false" ]] && note=" — account not in expected sudo users list"

                write_event "$iso_ts" "sudo_exec" "$severity" "$account" "$command" \
                    "sudo command executed by '$account': $command$note"
            else
                # Failed sudo attempt — always at least WARN; CRIT if the
                # account is not expected to use sudo at all.
                local severity="WARN"
                [[ "$is_expected" == "false" ]] && severity="CRIT"

                write_event "$iso_ts" "sudo_denied" "$severity" "$account" "$command" \
                    "sudo command DENIED for '$account': $command — authorization failure"
            fi
        done <<< "$sudo_records"

        # ---------------------------------------------------------------------
        # Parse su attempts from USER_AUTH records within the window.
        # ---------------------------------------------------------------------
        log_message "INFO" "Privilege" "Parsing auditd USER_AUTH records for su attempts"

        local su_records
        su_records=$(grep -E "type=USER_AUTH" "${AUDIT_LOG}" 2>/dev/null | \
            grep -i "exe=\"/usr/bin/su\"" | \
            awk -v start="${WINDOW_START_EPOCH}" -v end="${WINDOW_END_EPOCH}" '
            {
                if (match($0, /audit\(([0-9]+)\.[0-9]+:/, arr)) {
                    ts = arr[1] + 0
                    if (ts >= start && ts <= end) {
                        print $0
                    }
                }
            }' 2>/dev/null || true)

        while IFS= read -r record; do
            [[ -z "$record" ]] && continue

            local epoch_ts iso_ts
            epoch_ts=$(printf '%s' "$record" | sed -n 's/.*audit(\([0-9]*\)\..*/\1/p')
            iso_ts=$(date -u -d "@${epoch_ts}" "+%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || printf '%s' "${WINDOW_END_ISO}")

            local uid account
            uid=$(printf '%s' "$record" | sed -n 's/.*[^a]uid=\([0-9]*\).*/\1/p')
            account=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1)
            [[ -z "$account" ]] && account="uid:${uid}"

            local result
            result=$(printf '%s' "$record" | sed -n 's/.*res=\([a-z]*\).*/\1/p')

            local is_expected="false"
            [[ -n "${expected_su_set[$account]:-}" ]] && is_expected="true"

            if [[ "$result" == "success" ]]; then
                local severity="INFO"
                [[ "$is_expected" == "false" ]] && severity="WARN"
                write_event "$iso_ts" "su_attempt" "$severity" "$account" "su" \
                    "su authentication succeeded for '$account'"
            else
                write_event "$iso_ts" "su_attempt" "WARN" "$account" "su" \
                    "su authentication FAILED for '$account'"
            fi
        done <<< "$su_records"
    fi

    # -------------------------------------------------------------------------
    # STEP 3: Fallback path — parse journald sudo log messages.
    # Used either when auditd is unavailable, or as a supplementary check
    # when auditd did not yield any records (rules may not be loaded even
    # if the daemon is running).
    # -------------------------------------------------------------------------
    if [[ "$auditd_available" == false ]] || [[ "$auditd_data_found" == false ]]; then
        log_message "INFO" "Privilege" "Querying journald for sudo log messages (fallback/supplementary)"

        local sudo_log
        if ! sudo_log=$(journalctl --no-pager \
                                    --since="@${WINDOW_START_EPOCH}" \
                                    --until="@${WINDOW_END_EPOCH}" \
                                    --identifier=sudo \
                                    --output=short-iso 2>&1); then
            sudo_log=""
        fi

        while IFS= read -r line; do
            [[ -z "$line" ]] && continue

            local line_timestamp
            line_timestamp=$(printf '%s' "$line" | awk '{print $1}')

            # --- Successful sudo execution: "user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/ls" ---
            if [[ "$line" =~ ([a-zA-Z0-9._-]+)\ :\ .*COMMAND=(.+)$ ]]; then
                local account="${BASH_REMATCH[1]}"
                local command="${BASH_REMATCH[2]}"

                local is_expected="false"
                [[ -n "${expected_sudo_set[$account]:-}" ]] && is_expected="true"

                local severity="INFO"
                [[ "$is_expected" == "false" ]] && severity="WARN"

                local note=""
                [[ "$is_expected" == "false" ]] && note=" — account not in expected sudo users list"

                write_event "$line_timestamp" "sudo_exec" "$severity" "$account" "$command" \
                    "sudo command executed by '$account': $command$note (source: journald, reduced detail)"

            # --- User not in sudoers ---
            elif [[ "$line" =~ ([a-zA-Z0-9._-]+)\ is\ not\ in\ the\ sudoers\ file ]]; then
                local account="${BASH_REMATCH[1]}"
                write_event "$line_timestamp" "sudo_denied" "CRIT" "$account" "unknown" \
                    "sudo DENIED — '$account' is not in the sudoers file. This event is logged and reported to the system administrator."

            # --- Incorrect password attempts ---
            elif [[ "$line" =~ ([a-zA-Z0-9._-]+)\ :\ .*incorrect\ password\ attempt ]]; then
                local account="${BASH_REMATCH[1]}"
                write_event "$line_timestamp" "sudo_denied" "WARN" "$account" "unknown" \
                    "sudo authentication failed (incorrect password) for '$account'"

            # --- Command not allowed by sudoers policy ---
            elif [[ "$line" =~ ([a-zA-Z0-9._-]+)\ :\ command\ not\ allowed ]]; then
                local account="${BASH_REMATCH[1]}"
                write_event "$line_timestamp" "sudo_denied" "WARN" "$account" "unknown" \
                    "sudo command not allowed by policy for '$account' — user is in sudoers but lacks permission for this specific command"
            fi
        done <<< "$sudo_log"
    fi

    # -------------------------------------------------------------------------
    # STEP 4: Check for sudoers file modifications.
    #
    # Changes to /etc/sudoers or /etc/sudoers.d/ are tracked via auditd watch
    # rules (-w /etc/sudoers -p wa). This is one of the highest-value
    # detections in this module — modification of the sudoers configuration
    # is a direct path to privilege escalation persistence.
    # -------------------------------------------------------------------------
    if [[ "$auditd_available" == true ]]; then
        log_message "INFO" "Privilege" "Checking auditd for sudoers file modifications"

        local sudoers_records
        sudoers_records=$(grep -E "key=\"sudoers_change\"" "${AUDIT_LOG}" 2>/dev/null | \
            awk -v start="${WINDOW_START_EPOCH}" -v end="${WINDOW_END_EPOCH}" '
            {
                if (match($0, /audit\(([0-9]+)\.[0-9]+:/, arr)) {
                    ts = arr[1] + 0
                    if (ts >= start && ts <= end) {
                        print $0
                    }
                }
            }' 2>/dev/null || true)

        while IFS= read -r record; do
            [[ -z "$record" ]] && continue

            local epoch_ts iso_ts
            epoch_ts=$(printf '%s' "$record" | sed -n 's/.*audit(\([0-9]*\)\..*/\1/p')
            iso_ts=$(date -u -d "@${epoch_ts}" "+%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || printf '%s' "${WINDOW_END_ISO}")

            local uid account
            uid=$(printf '%s' "$record" | sed -n 's/.*[^a]uid=\([0-9]*\).*/\1/p')
            account=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1)
            [[ -z "$account" ]] && account="uid:${uid}"

            local syscall
            syscall=$(printf '%s' "$record" | sed -n 's/.*syscall=\([0-9]*\).*/\1/p')

            write_event "$iso_ts" "sudoers_change" "CRIT" "$account" "N/A" \
                "Modification detected to /etc/sudoers or /etc/sudoers.d/ by '$account' (syscall ${syscall}). This change must be verified against an approved change request immediately."
        done <<< "$sudoers_records"

        if [[ -z "$sudoers_records" ]]; then
            log_message "INFO" "Privilege" "No sudoers modifications detected — note this requires the sudoers_change auditd rule to be loaded (see docs/threat-model.md)"
        fi
    fi

    # -------------------------------------------------------------------------
    # STEP 5: Write summary file consumed by the orchestrator.
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

    cat > "${PRIVILEGE_MODULE_SUMMARY_FILE}" <<EOF
{"category":"Privilege","total_events":${total_events},"crit_count":${crit_count},"warn_count":${warn_count},"info_count":${info_count},"errors":${errors_json}}
EOF

    log_message "INFO" "Privilege" "Module complete. Total: ${total_events} CRIT: ${crit_count} WARN: ${warn_count} INFO: ${info_count}"
}