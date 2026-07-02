#!/usr/bin/env bash
# =============================================================================
# auth-events.sh
# ops-log-monitor — Linux Authentication Event Module
# =============================================================================
#
# PURPOSE:
#   Collects authentication-related events from journald (sshd, PAM) and
#   falls back to /var/log/secure if journald yields no results. Detects
#   SSH and PAM authentication failures, invalid user attempts, and direct
#   root SSH logins. Applies configurable thresholds to escalate severity.
#
# CALLED BY:
#   log-monitor.sh (orchestrator), via: source auth-events.sh; run_auth_module
#
# INPUTS (environment variables expected to be set by the orchestrator):
#   WINDOW_START_EPOCH   Unix epoch timestamp — beginning of monitoring window
#   WINDOW_END_EPOCH     Unix epoch timestamp — end of monitoring window
#   WINDOW_START_ISO     ISO 8601 timestamp — beginning of monitoring window
#   WINDOW_END_ISO       ISO 8601 timestamp — end of monitoring window
#   All variables sourced from linux-monitor.conf (AUTH_FAILURE_WARN_THRESHOLD,
#   AUTH_FAILURE_CRIT_THRESHOLD, SECURE_LOG, etc.)
#
# OUTPUT:
#   Writes structured event records to the file path given in
#   $AUTH_MODULE_OUTPUT_FILE, one JSON object per line (JSON Lines format).
#   This format avoids the complexity of building a single large JSON array
#   in bash and lets the orchestrator stream-parse results from each module.
#
#   Each line has the structure:
#   {
#     "time_created": "ISO8601",
#     "event_type": "ssh_failure|invalid_user|pam_failure|account_locked|root_ssh_login",
#     "severity": "CRIT|WARN|INFO",
#     "account": "string",
#     "source_ip": "string",
#     "description": "string"
#   }
#
#   Also writes summary counters to $AUTH_MODULE_SUMMARY_FILE as a single
#   JSON object: total_events, crit_count, warn_count, info_count, errors[]
#
# REQUIRED PREREQUISITES:
#   sshd logging to journald (default on RHEL 9)
#   journald persistent storage enabled for historical queries
#
# =============================================================================

# -----------------------------------------------------------------------------
# Guard against direct execution. This script is a module meant to be
# sourced by log-monitor.sh, not executed standalone, because it depends
# on environment variables and helper functions defined by the orchestrator.
# -----------------------------------------------------------------------------
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "ERROR: auth-events.sh is a module and must be sourced by log-monitor.sh, not executed directly." >&2
    echo "Usage: bash linux/log-monitor.sh" >&2
    exit 1
fi

# -----------------------------------------------------------------------------
# run_auth_module
#
# Main entry point for this module. Called by the orchestrator after
# sourcing this file. Expects orchestrator helper functions to be available:
#   log_message "LEVEL" "MODULE" "message"
#   write_event_json (internal use within this module)
# -----------------------------------------------------------------------------
run_auth_module() {
    log_message "INFO" "Authentication" "Module started. Window: ${WINDOW_START_ISO} to ${WINDOW_END_ISO}"

    local total_events=0
    local crit_count=0
    local warn_count=0
    local info_count=0
    local -a module_errors=()

    # Truncate the output file at the start of this run. The module appends
    # one JSON line per event as it processes them, rather than building an
    # array in memory, which keeps memory usage bounded on high-volume systems.
    : > "${AUTH_MODULE_OUTPUT_FILE}"

    # Associative arrays to track failure counts per source IP and per
    # account for threshold evaluation. Declared local to this function scope.
    declare -A failures_by_ip
    declare -A failures_by_account
    declare -A invalid_user_attempts_by_ip

    # -------------------------------------------------------------------------
    # Helper: escape a string for safe embedding inside a JSON string value.
    # Handles the characters most likely to appear in log messages: double
    # quotes, backslashes, and control characters. This is a minimal escaper
    # sufficient for the log content we process — not a full JSON library —
    # but it is deliberate and tested rather than a naive sed one-liner.
    # -------------------------------------------------------------------------
    json_escape() {
        local input="$1"
        input="${input//\\/\\\\}"   # backslash must be escaped first
        input="${input//\"/\\\"}"   # double quote
        input="${input//$'\t'/\\t}" # tab
        input="${input//$'\n'/ }"   # collapse embedded newlines to a space
        input="${input//$'\r'/}"    # strip carriage returns
        printf '%s' "$input"
    }

    # -------------------------------------------------------------------------
    # Helper: write one event as a JSON line to the module output file.
    # -------------------------------------------------------------------------
    write_event() {
        local time_created="$1"
        local event_type="$2"
        local severity="$3"
        local account="$4"
        local source_ip="$5"
        local description="$6"

        account=$(json_escape "$account")
        source_ip=$(json_escape "$source_ip")
        description=$(json_escape "$description")

        printf '{"time_created":"%s","event_type":"%s","severity":"%s","account":"%s","source_ip":"%s","description":"%s"}\n' \
            "$time_created" "$event_type" "$severity" "$account" "$source_ip" "$description" \
            >> "${AUTH_MODULE_OUTPUT_FILE}"

        total_events=$((total_events + 1))
        case "$severity" in
            CRIT) crit_count=$((crit_count + 1)) ;;
            WARN) warn_count=$((warn_count + 1)) ;;
            INFO) info_count=$((info_count + 1)) ;;
        esac
    }

    # -------------------------------------------------------------------------
    # STEP 1: Query journald for sshd messages within the monitoring window.
    #
    # We request short-iso output for deterministic, parseable timestamps.
    # --identifier=sshd restricts to the SSH daemon's own log identifier,
    # avoiding noise from other services that might log similar phrases.
    # -------------------------------------------------------------------------
    log_message "INFO" "Authentication" "Querying journald for sshd events"

    local sshd_log
    if ! sshd_log=$(journalctl --no-pager \
                                --since="@${WINDOW_START_EPOCH}" \
                                --until="@${WINDOW_END_EPOCH}" \
                                --identifier=sshd \
                                --output=short-iso 2>&1); then
        local err_msg="journalctl query for sshd failed: ${sshd_log}"
        log_message "ERROR" "Authentication" "$err_msg"
        module_errors+=("$err_msg")
        sshd_log=""
    fi

    local sshd_line_count
    sshd_line_count=$(printf '%s\n' "$sshd_log" | grep -c . || true)
    log_message "INFO" "Authentication" "Retrieved ${sshd_line_count} sshd log lines"

    # -------------------------------------------------------------------------
    # Process each sshd log line, matching against known authentication
    # message patterns. We use a single pass with a case statement on
    # extracted patterns rather than multiple separate grep passes, which
    # is more efficient for large log volumes.
    # -------------------------------------------------------------------------
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        # Extract the ISO timestamp from the start of the journalctl line.
        # short-iso format: "2026-06-30T14:32:01+0300 hostname sshd[1234]: message"
        local line_timestamp
        line_timestamp=$(printf '%s' "$line" | awk '{print $1}')

        # --- Failed password for an existing account ---
        if [[ "$line" =~ Failed\ password\ for\ ([a-zA-Z0-9._-]+)\ from\ ([0-9a-fA-F:.]+) ]]; then
            local account="${BASH_REMATCH[1]}"
            local source_ip="${BASH_REMATCH[2]}"

            failures_by_ip["$source_ip"]=$(( ${failures_by_ip["$source_ip"]:-0} + 1 ))
            failures_by_account["$account"]=$(( ${failures_by_account["$account"]:-0} + 1 ))

            # Severity assigned after full pass once counts are known —
            # placeholder INFO here, escalated in Step 4 below.
            write_event "$line_timestamp" "ssh_failure" "INFO" "$account" "$source_ip" \
                "SSH password authentication failed for account '$account' from $source_ip"

        # --- Failed password for an invalid (nonexistent) user ---
        elif [[ "$line" =~ Failed\ password\ for\ invalid\ user\ ([a-zA-Z0-9._-]+)\ from\ ([0-9a-fA-F:.]+) ]]; then
            local account="${BASH_REMATCH[1]}"
            local source_ip="${BASH_REMATCH[2]}"

            invalid_user_attempts_by_ip["$source_ip"]=$(( ${invalid_user_attempts_by_ip["$source_ip"]:-0} + 1 ))
            failures_by_ip["$source_ip"]=$(( ${failures_by_ip["$source_ip"]:-0} + 1 ))

            write_event "$line_timestamp" "invalid_user" "INFO" "$account" "$source_ip" \
                "SSH authentication attempt for nonexistent account '$account' from $source_ip"

        # --- Invalid user notification (precedes the failed password line) ---
        elif [[ "$line" =~ Invalid\ user\ ([a-zA-Z0-9._-]+)\ from\ ([0-9a-fA-F:.]+) ]]; then
            # This message often precedes "Failed password for invalid user"
            # for the same attempt. We do not double-count it as a separate
            # failure — it is already captured by the pattern above when the
            # subsequent failure line is processed. We skip it here to avoid
            # inflating failure counts for a single connection attempt.
            continue

        # --- Successful password authentication (uncommon if keys enforced) ---
        elif [[ "$line" =~ Accepted\ password\ for\ ([a-zA-Z0-9._-]+)\ from\ ([0-9a-fA-F:.]+) ]]; then
            local account="${BASH_REMATCH[1]}"
            local source_ip="${BASH_REMATCH[2]}"

            # Direct root SSH login via password is always significant —
            # PermitRootLogin should be disabled per current hardening
            # guidance. Flag regardless of prior failures.
            if [[ "$account" == "root" && "${AUTH_MONITOR_ROOT_SSH}" == "true" ]]; then
                write_event "$line_timestamp" "root_ssh_login" "CRIT" "$account" "$source_ip" \
                    "Direct root SSH login (password auth) from $source_ip — PermitRootLogin should be disabled per current hardening guidance"
            fi

            # If this account had prior failures in this window, a successful
            # login after failures is a stronger signal than either alone.
            if [[ -n "${failures_by_account[$account]:-}" ]]; then
                write_event "$line_timestamp" "ssh_success_after_failures" "WARN" "$account" "$source_ip" \
                    "Successful SSH password login for '$account' from $source_ip following ${failures_by_account[$account]} prior failures in this window — possible successful brute force"
            fi

        # --- Successful key-based authentication ---
        elif [[ "$line" =~ Accepted\ publickey\ for\ ([a-zA-Z0-9._-]+)\ from\ ([0-9a-fA-F:.]+) ]]; then
            local account="${BASH_REMATCH[1]}"
            local source_ip="${BASH_REMATCH[2]}"

            if [[ "$account" == "root" && "${AUTH_MONITOR_ROOT_SSH}" == "true" ]]; then
                write_event "$line_timestamp" "root_ssh_login" "WARN" "$account" "$source_ip" \
                    "Direct root SSH login (key auth) from $source_ip — verify this is expected and documented"
            fi

        # --- Too many authentication failures (MaxAuthTries reached) ---
        elif [[ "$line" =~ Too\ many\ authentication\ failures\ for\ ([a-zA-Z0-9._-]+) ]]; then
            local account="${BASH_REMATCH[1]}"
            write_event "$line_timestamp" "max_auth_tries_exceeded" "WARN" "$account" "unknown" \
                "SSH client for '$account' exceeded MaxAuthTries — automated tooling or scripted retry behavior"
        fi

    done <<< "$sshd_log"

    # -------------------------------------------------------------------------
    # STEP 2: Query journald for PAM authentication failures and account
    # lockouts (pam_faillock), which cover su, sudo, console login, and any
    # other PAM-aware service in addition to SSH.
    # -------------------------------------------------------------------------
    log_message "INFO" "Authentication" "Querying journald for PAM events"

    local pam_log
    if ! pam_log=$(journalctl --no-pager \
                               --since="@${WINDOW_START_EPOCH}" \
                               --until="@${WINDOW_END_EPOCH}" \
                               --identifier=sshd \
                               --identifier=su \
                               --identifier=sudo \
                               --identifier=login \
                               --output=short-iso 2>&1 | \
                   grep -E "pam_unix|pam_faillock" || true); then
        pam_log=""
    fi

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        local line_timestamp
        line_timestamp=$(printf '%s' "$line" | awk '{print $1}')

        # --- pam_faillock account lockout ---
        if [[ "$line" =~ pam_faillock.*user\ ([a-zA-Z0-9._-]+)\ .*locked\ out ]]; then
            local account="${BASH_REMATCH[1]}"
            write_event "$line_timestamp" "account_locked" "CRIT" "$account" "unknown" \
                "Account '$account' locked out by pam_faillock after repeated authentication failures"

        # --- generic PAM authentication failure (not already captured by sshd parsing above) ---
        elif [[ "$line" =~ pam_unix\(([a-zA-Z0-9_-]+)(:[a-zA-Z]+)?\).*authentication\ failure.*user=([a-zA-Z0-9._-]+) ]]; then
            local pam_service="${BASH_REMATCH[1]}"
            local account="${BASH_REMATCH[3]}"

            # Skip sshd service here — already fully handled in Step 1 with
            # source IP context that this generic PAM line does not provide.
            if [[ "$pam_service" == "sshd" ]]; then
                continue
            fi

            write_event "$line_timestamp" "pam_failure" "WARN" "$account" "local" \
                "PAM authentication failure for '$account' via $pam_service"
        fi
    done <<< "$pam_log"

    # -------------------------------------------------------------------------
    # STEP 3: Fallback to /var/log/secure if journald returned no sshd data.
    #
    # This can occur if persistent journal storage is not configured and
    # journald was restarted within the monitoring window, losing in-memory
    # entries. /var/log/secure, populated by rsyslog, may still have the data.
    # -------------------------------------------------------------------------
    if [[ "$sshd_line_count" -eq 0 && -f "${SECURE_LOG}" ]]; then
        log_message "WARN" "Authentication" "journald returned no sshd data — falling back to ${SECURE_LOG}"

        if [[ -r "${SECURE_LOG}" ]]; then
            local secure_log_failures
            secure_log_failures=$(grep "Failed password" "${SECURE_LOG}" 2>/dev/null | tail -1000 || true)

            local fallback_count=0
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                if [[ "$line" =~ Failed\ password\ for\ ([a-zA-Z0-9._-]+)\ from\ ([0-9a-fA-F:.]+) ]]; then
                    local account="${BASH_REMATCH[1]}"
                    local source_ip="${BASH_REMATCH[2]}"
                    failures_by_ip["$source_ip"]=$(( ${failures_by_ip["$source_ip"]:-0} + 1 ))
                    failures_by_account["$account"]=$(( ${failures_by_account["$account"]:-0} + 1 ))
                    fallback_count=$((fallback_count + 1))
                fi
            done <<< "$secure_log_failures"

            log_message "INFO" "Authentication" "Recovered ${fallback_count} failure events from ${SECURE_LOG} fallback"
        else
            local err_msg="${SECURE_LOG} exists but is not readable by current user — check permissions"
            log_message "ERROR" "Authentication" "$err_msg"
            module_errors+=("$err_msg")
        fi
    fi

    # -------------------------------------------------------------------------
    # STEP 4: Threshold-based severity escalation.
    #
    # Re-scan the output file, applying configured thresholds to the failure
    # counts gathered above. We rewrite the file with corrected severities
    # using a temp file and atomic rename, since bash does not support
    # in-place line editing of arbitrary JSON content safely with sed for
    # this structure.
    # -------------------------------------------------------------------------
    log_message "INFO" "Authentication" "Applying threshold-based severity escalation"

    local temp_output
    temp_output=$(mktemp)

    # Reset counters — they will be recalculated as we rewrite each line
    # with its final, threshold-adjusted severity.
    total_events=0
    crit_count=0
    warn_count=0
    info_count=0

    while IFS= read -r json_line; do
        [[ -z "$json_line" ]] && continue

        # Extract fields using grep/sed rather than a JSON parser dependency.
        # This is deliberate: the project requires no external dependencies
        # beyond Bash 4.0+ core utilities, so we parse our own known-format
        # JSON Lines output with targeted pattern extraction rather than jq.
        local event_type account source_ip severity

        event_type=$(printf '%s' "$json_line" | sed -n 's/.*"event_type":"\([^"]*\)".*/\1/p')
        account=$(printf '%s' "$json_line" | sed -n 's/.*"account":"\([^"]*\)".*/\1/p')
        source_ip=$(printf '%s' "$json_line" | sed -n 's/.*"source_ip":"\([^"]*\)".*/\1/p')
        severity=$(printf '%s' "$json_line" | sed -n 's/.*"severity":"\([^"]*\)".*/\1/p')

        # Only re-evaluate severity for event types subject to threshold logic.
        # Other event types (already correctly assigned CRIT/WARN above) pass
        # through unchanged.
        if [[ "$event_type" == "ssh_failure" || "$event_type" == "invalid_user" ]]; then
            local acct_failures="${failures_by_account[$account]:-0}"
            local ip_failures="${failures_by_ip[$source_ip]:-0}"

            if [[ "$acct_failures" -ge "${AUTH_ACCOUNT_CRIT_THRESHOLD}" ]] || \
               [[ "$ip_failures" -ge "${AUTH_FAILURE_CRIT_THRESHOLD}" ]]; then
                severity="CRIT"
            elif [[ "$acct_failures" -ge "${AUTH_ACCOUNT_WARN_THRESHOLD}" ]] || \
                 [[ "$ip_failures" -ge "${AUTH_FAILURE_WARN_THRESHOLD}" ]]; then
                severity="WARN"
            else
                severity="INFO"
            fi

            # Rewrite the severity field in the JSON line.
            json_line=$(printf '%s' "$json_line" | sed "s/\"severity\":\"[^\"]*\"/\"severity\":\"${severity}\"/")
        fi

        printf '%s\n' "$json_line" >> "$temp_output"

        total_events=$((total_events + 1))
        case "$severity" in
            CRIT) crit_count=$((crit_count + 1)) ;;
            WARN) warn_count=$((warn_count + 1)) ;;
            INFO) info_count=$((info_count + 1)) ;;
        esac
    done < "${AUTH_MODULE_OUTPUT_FILE}"

    mv "$temp_output" "${AUTH_MODULE_OUTPUT_FILE}"

    # -------------------------------------------------------------------------
    # STEP 5: Check for invalid-user enumeration bursts per source IP.
    # A high count of attempts against nonexistent usernames from one source
    # indicates username enumeration or a credential list mismatched to this
    # target, independent of the per-IP failure threshold logic above.
    # -------------------------------------------------------------------------
    for source_ip in "${!invalid_user_attempts_by_ip[@]}"; do
        local attempt_count="${invalid_user_attempts_by_ip[$source_ip]}"
        if [[ "$attempt_count" -ge "${AUTH_INVALID_USER_CRIT_THRESHOLD}" ]]; then
            write_event "${WINDOW_END_ISO}" "username_enumeration" "CRIT" "multiple" "$source_ip" \
                "Source $source_ip attempted authentication against ${attempt_count} nonexistent usernames — possible username enumeration"
        fi
    done

    # -------------------------------------------------------------------------
    # STEP 6: Write summary file consumed by the orchestrator.
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

    cat > "${AUTH_MODULE_SUMMARY_FILE}" <<EOF
{"category":"Authentication","total_events":${total_events},"crit_count":${crit_count},"warn_count":${warn_count},"info_count":${info_count},"errors":${errors_json}}
EOF

    log_message "INFO" "Authentication" "Module complete. Total: ${total_events} CRIT: ${crit_count} WARN: ${warn_count} INFO: ${info_count}"
}