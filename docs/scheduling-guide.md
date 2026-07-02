# Scheduling Guide

## Purpose of This Document

This document provides step-by-step instructions for scheduling automated
report generation using Windows Task Scheduler and Linux cron or systemd
timers. A monitoring framework that requires manual invocation every day
will eventually stop being run. Scheduling is what turns this from a tool
into an operational habit.

---

## General Scheduling Principles

Before configuring a schedule, decide on a monitoring window strategy:

**Non-overlapping daily windows (recommended default):** Schedule the
script to run once per day with `MONITORING_WINDOW_HOURS = 24`, timed so
each day's window picks up exactly where the previous day's left off. This
gives complete coverage with no gaps and no duplicate events across
reports.

**Overlapping windows for redundancy:** Some environments prefer running
more frequently with a window longer than the run interval (e.g., running
every 6 hours with a 24-hour window) so that a missed run does not create
a coverage gap. This produces duplicate events across consecutive reports,
which is an acceptable tradeoff for environments where a missed scheduled
run is a realistic risk (e.g., systems that reboot for patching at
unpredictable times).

Choose the strategy that matches your environment's reliability
characteristics. The non-overlapping approach is simpler to reason about
and is the right default for most environments.

---

## Windows: Task Scheduler

### Step 1: Decide on a run-as account

The scheduled task must run under an account with permission to read the
Security event log. Three options, in order of preference:

1. **A dedicated service account** with explicit Security log read access
   granted via group membership (Event Log Readers group, plus the
   specific Security log ACL adjustment Security logs require beyond
   standard Event Log Readers membership - see
   `docs/troubleshooting.md` for the exact permission grant).
2. **The local Administrator account**, using a Group Managed Service
   Account (gMSA) if domain-joined, to avoid storing a static password.
3. **A named administrator's personal account** - not recommended for
   production use, since the schedule becomes tied to that individual's
   account lifecycle (password expiry, account lockout, departure).

### Step 2: Create the scheduled task via PowerShell

Using PowerShell to create the task (rather than the Task Scheduler GUI)
makes the configuration reviewable, version-controllable, and repeatable
across multiple servers.

```powershell
# Run this as Administrator on the target server.

$taskName        = "ops-log-monitor-daily"
$scriptPath      = "C:\ops-log-monitor\windows\Invoke-LogMonitor.ps1"
$workingDirectory = "C:\ops-log-monitor\windows"

# Action: run PowerShell with the script, in Quiet mode since console
# output is not monitored for a scheduled run. -ExecutionPolicy Bypass
# is scoped to this single invocation only, not a system-wide policy
# change - it does not weaken execution policy for any other script.
$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -Quiet" `
    -WorkingDirectory $workingDirectory

# Trigger: daily at 07:00. Adjust to align with your non-overlapping
# window strategy - if MONITORING_WINDOW_HOURS is 24, running daily at
# the same time each day produces clean, non-overlapping coverage.
$trigger = New-ScheduledTaskTrigger -Daily -At "07:00"

# Settings: allow the task to run even if the previous run is still
# executing past its expected duration (StartWhenAvailable), and do not
# stop the task if the system is briefly on battery (irrelevant for
# servers, included for laptop-based lab/test deployments).
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -DontStopOnIdleEnd `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1) `
    -RestartCount 2 `
    -RestartInterval (New-TimeSpan -Minutes 5)

# Principal: run as SYSTEM for simplicity in this example. SYSTEM has
# Security log read access by default, avoiding the credential storage
# and rotation concerns of a dedicated service account. For environments
# with stricter least-privilege requirements, substitute a dedicated
# service account here instead and grant it Security log read access
# explicitly (see docs/troubleshooting.md).
$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Description "Daily ops-log-monitor report generation for operational log review"
```

### Step 3: Verify the task

```powershell
Get-ScheduledTask -TaskName "ops-log-monitor-daily" | Get-ScheduledTaskInfo

# Trigger an immediate test run rather than waiting for the next
# scheduled time
Start-ScheduledTask -TaskName "ops-log-monitor-daily"

# Check the result after a few seconds
Start-Sleep -Seconds 10
Get-ScheduledTask -TaskName "ops-log-monitor-daily" | Get-ScheduledTaskInfo |
    Select-Object LastRunTime, LastTaskResult

# LastTaskResult of 0 indicates success. Non-zero indicates an error -
# check the script's own log file at the configured LOG_FILE path, and
# the Task Scheduler history (enabled via "Enable All Tasks History" in
# the Task Scheduler GUI's Action menu) for execution details.
```

### Step 4: Verify report output

```powershell
Get-ChildItem "C:\ops-log-monitor\windows\output\reports\" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 5
```

### Optional: Alert on CRITICAL status via exit code

`Invoke-LogMonitor.ps1` exits with code 2 when the overall report status
is CRITICAL. Wrap the scheduled task in a follow-up action, or use a
separate monitoring system that polls Task Scheduler history for
non-zero `LastTaskResult` values, to alert when this occurs without
requiring a human to manually open every report.

---

## Linux: cron

### Step 1: Decide on a run-as context

`REQUIRE_ROOT="true"` in `linux-monitor.conf` (the default) means the
script must run as root for full module coverage, particularly the
Privilege and Kernel modules, which require read access to
`/var/log/audit/audit.log`.

The standard approach is a root crontab entry, or a systemd timer running
as root (see the systemd timer section below for the more modern
alternative).

### Step 2: Create the cron entry

```bash
# Edit the root crontab
sudo crontab -e
```

Add the following line. This example runs daily at 07:00, matching the
non-overlapping window strategy described above.

```cron
# ops-log-monitor - daily operational log report
# Runs at 07:00 daily, covering the previous 24 hours (MONITORING_WINDOW_HOURS=24)
0 7 * * * /opt/ops-log-monitor/linux/log-monitor.sh --quiet >> /var/log/ops-log-monitor/cron.log 2>&1
```

**Notes on this cron entry:**

- `--quiet` suppresses the colorized console progress output, which is
  meaningless in a cron log file and adds visual noise without value.
- The script's own structured execution log (configured via `LOG_FILE` in
  `linux-monitor.conf`) is the primary place to look for execution detail
  - the redirected cron output above is a secondary safety net that
  captures anything written directly to stdout/stderr outside the
  script's own logging function, such as a fatal error before logging
  initializes.
- Use an absolute path to the script. Cron does not run with the same
  `PATH` or working directory assumptions as an interactive shell.

### Step 3: Verify the cron job is registered

```bash
sudo crontab -l
```

### Step 4: Test the script manually with the same invocation cron will use

```bash
sudo /opt/ops-log-monitor/linux/log-monitor.sh --quiet
echo "Exit code: $?"
```

Confirm this produces the same exit code and report output you expect
before relying on the scheduled execution. Testing the literal command
cron will run - including `--quiet` and the redirect - catches issues
that testing an interactive invocation would miss (e.g., a script that
behaves differently when stdin is not a terminal).

### Step 5: Verify report output

```bash
ls -lht /opt/ops-log-monitor/output/reports/ | head -5
```

---

## Linux: systemd Timer (Recommended Alternative to cron)

systemd timers provide better logging integration (visible via
`journalctl`), more flexible scheduling, and built-in handling of missed
runs (e.g., if the system was powered off at the scheduled time) compared
to traditional cron. This is the current best-practice approach on RHEL 9
and is recommended over cron for new deployments, though cron remains
fully supported and simpler for administrators already comfortable with it.

### Step 1: Create the service unit

```bash
sudo tee /etc/systemd/system/ops-log-monitor.service > /dev/null <<'EOF'
[Unit]
Description=ops-log-monitor daily report generation
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/ops-log-monitor/linux/log-monitor.sh --quiet
User=root
# Hardening: this service does not need a shell, network access beyond
# DNS resolution for hostname lookups, or write access outside its own
# output and log directories. ProtectSystem=strict combined with explicit
# ReadWritePaths follows current systemd hardening guidance.
ProtectSystem=strict
ReadWritePaths=/opt/ops-log-monitor/output /opt/ops-log-monitor/logs
NoNewPrivileges=false
# NoNewPrivileges remains false because the script itself requires root
# for audit.log access; this is not a privilege escalation concern since
# the unit already runs as root by design (REQUIRE_ROOT=true).

[Install]
WantedBy=multi-user.target
EOF
```

### Step 2: Create the timer unit

```bash
sudo tee /etc/systemd/system/ops-log-monitor.timer > /dev/null <<'EOF'
[Unit]
Description=Daily timer for ops-log-monitor

[Timer]
OnCalendar=*-*-* 07:00:00
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
EOF
```

**Notes on timer configuration:**

- `Persistent=true` ensures that if the system was powered off at the
  scheduled time, the timer fires as soon as possible after the system
  comes back up, rather than silently waiting for the next scheduled
  occurrence. This directly addresses the missed-run risk that the
  "overlapping windows" strategy described earlier exists to mitigate -
  with `Persistent=true`, the simpler non-overlapping strategy is safe to
  use even on systems with unpredictable reboot schedules.
- `RandomizedDelaySec=300` adds up to 5 minutes of random jitter, useful
  when this configuration is deployed identically across many servers via
  configuration management, to avoid every server in a fleet generating
  its report at the exact same second and creating a thundering-herd
  effect on shared storage or logging infrastructure.

### Step 3: Enable and start the timer

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ops-log-monitor.timer
```

### Step 4: Verify the timer is scheduled

```bash
systemctl list-timers ops-log-monitor.timer

# Expected output shows NEXT (next scheduled run) and LEFT (time remaining)
```

### Step 5: Trigger an immediate test run

```bash
sudo systemctl start ops-log-monitor.service

# Check status and exit code
systemctl status ops-log-monitor.service

# Review full execution output via journald - this is the advantage
# systemd timers have over cron: structured, queryable logs without
# manually redirecting output to a file
journalctl -u ops-log-monitor.service --since "10 minutes ago"
```

### Step 6: Verify report output

```bash
ls -lht /opt/ops-log-monitor/output/reports/ | head -5
```

---

## Choosing Between cron and systemd Timers

| Consideration | cron | systemd timer |
|---|---|---|
| Familiarity | Nearly universal sysadmin knowledge | Requires comfort with systemd unit files |
| Logging | Manual redirect required | Automatic via journald |
| Missed-run handling | None - a missed run is simply skipped | `Persistent=true` catches up after downtime |
| Dependency management | None | Can depend on other systemd units (e.g., `After=network-online.target`) |
| Current RHEL guidance | Fully supported, simpler | Recommended for new deployments |

Either is a correct choice operationally. systemd timers are presented as
the recommended default for new deployments because they integrate better
with the rest of a RHEL 9 system's logging and dependency management - not
because cron is deprecated or inferior for this use case.

---

## Running an Ad Hoc Longer-Window Report

Outside the regular daily schedule, you will sometimes want a longer-window
report - for example, the weekly review described in
`docs/interpreting-reports.md`, or an investigation spanning several days.

**Windows:**

```powershell
.\windows\Invoke-LogMonitor.ps1 `
    -StartTime (Get-Date).AddDays(-7) `
    -EndTime (Get-Date) `
    -OutputPath "C:\ops-log-monitor\output\weekly-reports"
```

**Linux:**

```bash
sudo /opt/ops-log-monitor/linux/log-monitor.sh \
    --start-time "$(date -d '7 days ago' '+%Y-%m-%d %H:%M:%S')" \
    --end-time "$(date '+%Y-%m-%d %H:%M:%S')" \
    --output /opt/ops-log-monitor/output/weekly-reports
```

Both examples write to a separate output directory from the daily
scheduled reports, keeping ad hoc and routine reports organized separately
without one schedule's configuration affecting the other.