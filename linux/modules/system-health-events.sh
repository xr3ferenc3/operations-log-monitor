#!/usr/bin/env bash
# =============================================================================
# system-health-events.sh
# ops-log-monitor — Linux System Health Event Module
# =============================================================================
#
# PURPOSE:
#   Detects hardware degradation and stability indicators from kernel
#   messages: disk I/O errors, filesystem errors, OOM killer invocations,
#   and unexpected (unclean) system shutdowns. These provide early warning
#   of hardware failure before it causes data loss or unplanned outages.
#
# CALLED BY:
#   log-monitor.sh (orchestrator), via: source system-health-events.sh; run_system_health_module
#
# INPUTS (environment variables expected to be set by the orchestrator):
#   WINDOW_START_EPOCH, WINDOW_END_EPOCH, WINDOW_START_ISO, WINDOW_END_ISO
#   OOM_KILL_ALWAYS_CRIT
#
# OUTPUT:
#   JSON Lines events written to $SYSHEALTH_MODULE_OUTPUT_FILE
#   Summary JSON written to $SYSHEALTH_MODULE_SUMMARY_FILE
#
#   Each event line has the structure:
#   {
#     "time_created": "ISO8601",
#     "event_type": "disk_io_error|filesystem_error|oom_kill|unexpected_shutdown",
#     "severity": "CRIT|WARN|INFO",
#     "component": "string",
#     "description": "string"
#   }
#
# REQUIRED PREREQUISITES:
#   systemd-journald running and retaining kernel messages (--dmesg)
#
# =============================================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "ERROR: system-health-events.sh is a module and must be sourced by log-monitor.sh, not executed directly." >&2
    echo "Usage: bash linux/log-monitor.sh" >&2
    exit 1
fi

# -----------------------------------------------------------------------------
# run_system_health_module
# -----------------------------------------------------------------------------
run_system_health_module() {
    log_message "INFO" "SystemHealth" "Module started. Window: ${WINDOW_START_ISO} to ${WINDOW_END_ISO}"

    local total_events=0
    local crit_count=0
    local warn_count=0
    local info_count=0
    local -a module_errors=()
    local unexpected_shutdown_count=0
    local disk_error_count=0

    : > "${SYSHEALTH_MODULE_OUTPUT_FILE}"

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
        local component="$4"
        local description="$5"

        component=$(json_escape "$component")
        description=$(json_escape "$description")

        printf '{"time_created":"%s","event_type":"%s","severity":"%s","component":"%s","description":"%s"}\n' \
            "$time_created" "$event_type" "$severity" "$component" "$description" \
            >> "${SYSHEALTH_MODULE_OUTPUT_FILE}"

        total_events=$((total_events + 1))
        case "$severity" in
            CRIT) crit_count=$((crit_count + 1)) ;;
            WARN) warn_count=$((warn_count + 1)) ;;
            INFO) info_count=$((info_count + 1)) ;;
        esac
    }

    # -------------------------------------------------------------------------
    # STEP 1: Query kernel messages (--dmesg) for storage and filesystem
    # errors within the monitoring window.
    #
    # journalctl --dmesg surfaces kernel ring buffer messages captured by
    # journald, which persist across the window even though /proc/kmsg
    # itself only holds a limited in-memory buffer. This is the correct
    # source for historical kernel message review, as opposed to running
    # `dmesg` directly, which only reflects the current boot's buffer.
    # -------------------------------------------------------------------------
    log_message "INFO" "SystemHealth" "Querying kernel messages for storage and filesystem errors"

    local kernel_log
    if ! kernel_log=$(journalctl --no-pager \
                                  --since="@${WINDOW_START_EPOCH}" \
                                  --until="@${WINDOW_END_EPOCH}" \
                                  --dmesg \
                                  --output=short-iso 2>&1); then
        local err_msg="journalctl --dmesg query failed: ${kernel_log}"
        log_message "ERROR" "SystemHealth" "$err_msg"
        module_errors+=("$err_msg")
        kernel_log=""
    fi

    local line_count
    line_count=$(printf '%s\n' "$kernel_log" | grep -c . || true)
    log_message "INFO" "SystemHealth" "Retrieved ${line_count} kernel message lines for analysis"

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        local line_timestamp
        line_timestamp=$(printf '%s' "$line" | awk '{print $1}')

        # --- Buffer I/O error — generic block-layer read/write failure ---
        if [[ "$line" =~ Buffer\ I/O\ error\ on\ dev(ice)?\ ([a-zA-Z0-9/]+) ]]; then
            local device="${BASH_REMATCH[2]}"
            disk_error_count=$((disk_error_count + 1))
            write_event "$line_timestamp" "disk_io_error" "CRIT" "$device" \
                "Buffer I/O error on device $device — possible failing disk, run smartctl diagnostics"

        # --- Block layer I/O error ---
        elif [[ "$line" =~ blk_update_request:\ I/O\ error ]]; then
            disk_error_count=$((disk_error_count + 1))
            write_event "$line_timestamp" "disk_io_error" "CRIT" "block-layer" \
                "Block layer I/O error detected — device-level read/write failure, investigate disk health immediately"

        # --- EXT4 filesystem error ---
        elif [[ "$line" =~ EXT4-fs\ error\ \(device\ ([a-zA-Z0-9]+)\) ]]; then
            local device="${BASH_REMATCH[1]}"
            disk_error_count=$((disk_error_count + 1))
            write_event "$line_timestamp" "filesystem_error" "CRIT" "$device" \
                "EXT4 filesystem error on device $device — filesystem may need fsck; schedule maintenance window"

        # --- XFS filesystem error ---
        elif [[ "$line" =~ XFS\ \(([a-zA-Z0-9]+)\).*[Ee]rror ]]; then
            local device="${BASH_REMATCH[1]}"
            disk_error_count=$((disk_error_count + 1))
            write_event "$line_timestamp" "filesystem_error" "CRIT" "$device" \
                "XFS filesystem error on device $device — filesystem may need xfs_repair; schedule maintenance window"

        # --- ATA/SATA device error ---
        elif [[ "$line" =~ (ata[0-9]+\.[0-9]+):\ error ]]; then
            local device="${BASH_REMATCH[1]}"
            disk_error_count=$((disk_error_count + 1))
            write_event "$line_timestamp" "disk_io_error" "WARN" "$device" \
                "ATA/SATA error reported on $device — monitor for recurrence, may indicate cabling or early drive failure"

        # --- SCSI error ---
        elif [[ "$line" =~ SCSI\ error:\ return\ code ]]; then
            disk_error_count=$((disk_error_count + 1))
            write_event "$line_timestamp" "disk_io_error" "WARN" "scsi" \
                "SCSI command error reported — investigate storage controller and disk health"

        # --- NVMe error ---
        elif [[ "$line" =~ (nvme[0-9]+).*[Ee]rror ]]; then
            local device="${BASH_REMATCH[1]}"
            disk_error_count=$((disk_error_count + 1))
            write_event "$line_timestamp" "disk_io_error" "CRIT" "$device" \
                "NVMe error reported on $device — check nvme smart-log for wear and health indicators"

        # --- OOM killer invocation ---
        # elif [[ "$line" =~ Out\ of\ memory:\ Killed\ process\ ([0-9]+)\ \(([^)]+)\) ]]; then
        pattern='Out of memory: Killed process ([0-9]+) \(([^)]+)\)'
        elif [[ "$line" =~ $pattern ]]; then
            local pid="${BASH_REMATCH[1]}"
            local proc_name="${BASH_REMATCH[2]}"
            local severity="WARN"
            [[ "${OOM_KILL_ALWAYS_CRIT}" == "true" ]] && severity="CRIT"

            write_event "$line_timestamp" "oom_kill" "$severity" "$proc_name" \
                "Out of Memory killer terminated process '$proc_name' (PID $pid) — system lacked sufficient memory for the current workload; review memory sizing and consider per-service limits"
        fi
    done <<< "$kernel_log"

    # -------------------------------------------------------------------------
    # STEP 2: Detect unexpected (unclean) shutdowns using journalctl's boot
    # list. We examine each boot that started within or immediately before
    # the monitoring window and check whether the PRECEDING boot ended with
    # a clean shutdown sequence. The absence of a clean shutdown message
    # before a new boot indicates a crash, power loss, or hard reset.
    # -------------------------------------------------------------------------
    log_message "INFO" "SystemHealth" "Checking boot history for unexpected shutdowns"

    local boot_list
    if ! boot_list=$(journalctl --list-boots --no-pager 2>&1); then
        local err_msg="journalctl --list-boots failed: ${boot_list}"
        log_message "ERROR" "SystemHealth" "$err_msg"
        module_errors+=("$err_msg")
        boot_list=""
    fi

    # --list-boots output format (varies slightly by systemd version):
    # IDX BOOT_ID                          FIRST_ENTRY                 LAST_ENTRY
    #  -1 a1b2c3...                        Mon 2026-06-29 08:00:00 UTC Mon 2026-06-29 23:59:00 UTC
    #   0 d4e5f6...                        Tue 2026-06-30 00:00:05 UTC Tue 2026-06-30 14:32:00 UTC
    #
    # A boot whose FIRST_ENTRY timestamp falls within our monitoring window
    # represents a system startup during the window — we check whether the
    # previous boot ended cleanly.
    while IFS= read -r boot_line; do
        [[ -z "$boot_line" ]] && continue
        [[ "$boot_line" =~ ^[[:space:]]*IDX ]] && continue  # skip header if present

        local boot_idx
        boot_idx=$(printf '%s' "$boot_line" | awk '{print $1}')

        # Skip the current boot (index 0) for "did the previous boot end
        # cleanly" analysis — we examine boot N relative to boot N-1.
        [[ "$boot_idx" == "0" ]] && continue

        # Extract the first-entry timestamp to determine if this boot
        # started within our monitoring window. We use a loose substring
        # match on the date portion since exact column parsing of
        # --list-boots output is fragile across systemd versions.
        local first_entry_date
        first_entry_date=$(printf '%s' "$boot_line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)

        [[ -z "$first_entry_date" ]] && continue

        local boot_epoch
        boot_epoch=$(date -d "$first_entry_date" "+%s" 2>/dev/null || echo "0")

        if [[ "$boot_epoch" -ge "$WINDOW_START_EPOCH" ]] && [[ "$boot_epoch" -le "$WINDOW_END_EPOCH" ]]; then
            # This boot started within our window. Check the PREVIOUS boot
            # (boot_idx + 1, since indices count backward from 0) for a
            # clean shutdown sequence.
            local prev_boot_idx=$((boot_idx + 1))

            local prev_boot_log
            prev_boot_log=$(journalctl --boot=-"${prev_boot_idx}" --no-pager 2>/dev/null | \
                grep -E "Reached target.*Shutdown|Stopped target.*System|Power down" || true)

            local boot_iso
            boot_iso=$(date -u -d "@${boot_epoch}" "+%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || printf '%s' "${WINDOW_START_ISO}")

            if [[ -z "$prev_boot_log" ]]; then
                unexpected_shutdown_count=$((unexpected_shutdown_count + 1))
                write_event "$boot_iso" "unexpected_shutdown" "CRIT" "system" \
                    "System boot detected without a preceding clean shutdown sequence — indicates a crash, power loss, kernel panic, or forced power-off prior to this boot. Investigate hardware and review kernel messages from immediately before the gap."
            fi
        fi
    done <<< "$boot_list"

    if [[ "$unexpected_shutdown_count" -eq 0 ]]; then
        log_message "INFO" "SystemHealth" "No unexpected shutdowns detected in boot history for this window"
    fi

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

    cat > "${SYSHEALTH_MODULE_SUMMARY_FILE}" <<EOF
{"category":"SystemHealth","total_events":${total_events},"crit_count":${crit_count},"warn_count":${warn_count},"info_count":${info_count},"errors":${errors_json},"unexpected_shutdowns":${unexpected_shutdown_count},"disk_error_count":${disk_error_count}}
EOF

    log_message "INFO" "SystemHealth" "Module complete. Total: ${total_events} CRIT: ${crit_count} WARN: ${warn_count} INFO: ${info_count} UnexpectedShutdowns: ${unexpected_shutdown_count} DiskErrors: ${disk_error_count}"
}