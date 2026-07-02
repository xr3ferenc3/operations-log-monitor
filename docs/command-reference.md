# Command Reference

## Purpose of This Document

This document is a concise quick-reference for every parameter, argument,
and common invocation pattern for both the Windows and Linux
implementations of `ops-log-monitor`. It is designed to be used as a
lookup document rather than read from top to bottom - if you need to know
what a specific parameter does, or how to construct a specific type of
invocation, this is the right document.

For operational interpretation guidance, see `docs/interpreting-reports.md`.
For scheduling configuration, see `docs/scheduling-guide.md`.
For module configuration and extension, see `docs/customization-guide.md`.

-

## Windows: `Invoke-LogMonitor.ps1`

### Location

```
windows\Invoke-LogMonitor.ps1
```

### Syntax

```powershell
.\Invoke-LogMonitor.ps1 [[-StartTime] <DateTime>] [[-EndTime] <DateTime>]
                         [[-ConfigPath] <String>] [[-OutputPath] <String>]
                         [-Quiet]
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-|-|-|-|-|
| `-StartTime` | DateTime | No | `(now) - MONITORING_WINDOW_HOURS` | Beginning of the event query window |
| `-EndTime` | DateTime | No | Current time | End of the event query window |
| `-ConfigPath` | String | No | `.\config\windows-monitor.conf.ps1` | Path to configuration file. Local override (`.conf.local.ps1`) is preferred automatically if it exists |
| `-OutputPath` | String | No | `OUTPUT_DIR` from config | Override the output directory for this run only |
| `-Quiet` | Switch | No | Off | Suppress console progress output. Errors and the final summary are still written to the console |

### Exit Codes

| Code | Meaning |
|-|-|
| 0 | NORMAL - no CRIT or WARN findings in the report |
| 1 | WARNING - one or more WARN-level findings present, no CRIT |
| 2 | CRITICAL - one or more CRIT-level findings present |
| 1 (also) | Script startup error - check console output for the specific error message |

### Common Invocations

#### Default run (last 24 hours, all defaults)

```powershell
.\Invoke-LogMonitor.ps1
```

#### Specify an exact time window

```powershell
.\Invoke-LogMonitor.ps1 -StartTime "2026-06-29 07:00:00" -EndTime "2026-06-30 07:00:00"
```

#### Last 7 days (weekly summary)

```powershell
.\Invoke-LogMonitor.ps1 -StartTime (Get-Date).AddDays(-7) -EndTime (Get-Date)
```

#### Last 1 hour (interactive investigation)

```powershell
.\Invoke-LogMonitor.ps1 -StartTime (Get-Date).AddMinutes(-60) -EndTime (Get-Date)
```

#### Scheduled/unattended run (suppress console, custom output directory)

```powershell
.\Invoke-LogMonitor.ps1 -Quiet -OutputPath "C:\Monitoring\Reports"
```

#### Use a specific configuration file

```powershell
.\Invoke-LogMonitor.ps1 -ConfigPath "C:\CustomConfig\windows-monitor.conf.ps1"
```

#### Use a local override configuration (automatic - no parameter needed)

```powershell
# If windows-monitor.conf.local.ps1 exists in .\config\, it is
# automatically preferred over windows-monitor.conf.ps1 without
# specifying -ConfigPath explicitly.
.\Invoke-LogMonitor.ps1
```

#### Check exit code explicitly

```powershell
.\Invoke-LogMonitor.ps1 -Quiet
switch ($LASTEXITCODE) {
    0 { Write-Host "Report status: NORMAL" -ForegroundColor Green }
    1 { Write-Host "Report status: WARNING" -ForegroundColor Yellow }
    2 { Write-Host "Report status: CRITICAL" -ForegroundColor Red }
}
```

#### Run a specific time window and open the Markdown report immediately

```powershell
$result = .\Invoke-LogMonitor.ps1 -StartTime (Get-Date).AddDays(-1) -EndTime (Get-Date) -OutputPath $env:TEMP
Get-ChildItem $env:TEMP -Filter "ops-log-monitor-*.md" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1 |
    Invoke-Item
```

### Verifying Audit Policy Prerequisites

Before relying on report output, verify the required audit policy settings
are configured. Run in an elevated PowerShell session:

```powershell
# Check all audit policy subcategories at once
auditpol /get /category:* | Select-String -Pattern "Logon|Account Management|Privilege Use|Object Access"

# Check a specific subcategory
auditpol /get /subcategory:"Logon"
auditpol /get /subcategory:"Sensitive Privilege Use"
auditpol /get /subcategory:"Other Object Access Events"

# Check current Security event log size
Get-WinEvent -ListLog Security | Select-Object LogName, MaximumSizeInBytes, RecordCount
Get-WinEvent -ListLog System   | Select-Object LogName, MaximumSizeInBytes, RecordCount

# Increase Security log size if below the recommended 200MB minimum
# (requires Administrator privileges)
wevtutil set-log Security /ms:209715200
```

### Useful Companion Commands for Windows Log Investigation

These commands are not part of `ops-log-monitor` itself but are frequently
used alongside it when investigating a finding from a report.

```powershell
# Query specific event IDs manually to see full event detail
Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4624
    StartTime = (Get-Date).AddHours(-24)
} | Select-Object TimeCreated, Id, Message | Format-List

# Find all events from a specific user in the Security log
Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    StartTime = (Get-Date).AddDays(-1)
} | Where-Object { $_.Message -match "mreyes" } |
    Select-Object TimeCreated, Id, Message | Format-List

# List all currently running scheduled tasks with their run-as accounts
Get-ScheduledTask |
    Select-Object TaskName, TaskPath,
        @{N="Principal";E={$_.Principal.UserId}},
        @{N="Action";E={$_.Actions.Execute}} |
    Sort-Object TaskPath

# Check current local group membership
Get-LocalGroupMember -Group "Administrators"
Get-LocalGroupMember -Group "Remote Desktop Users"

# Review current local user account status
Get-LocalUser | Select-Object Name, Enabled, LastLogon,
    PasswordExpires, PasswordLastSet, PasswordRequired |
    Format-Table -AutoSize
```

-

## Linux: `log-monitor.sh`

### Location

```
linux/log-monitor.sh
```

### Syntax

```bash
./log-monitor.sh [-start-time "YYYY-MM-DD HH:MM:SS"]
                  [-end-time   "YYYY-MM-DD HH:MM:SS"]
                  [-config     PATH]
                  [-output     PATH]
                  [-quiet]
                  [-help]
```

### Arguments

| Argument | Required | Default | Description |
|-|-|-|-|
| `-start-time` | No | `(now) - MONITORING_WINDOW_HOURS` | Beginning of the event query window. Accepts any format understood by `date -d` |
| `-end-time` | No | Current time | End of the event query window |
| `-config` | No | `./config/linux-monitor.conf` | Path to configuration file. Local override (`.conf.local`) is preferred automatically if it exists |
| `-output` | No | `OUTPUT_DIR` from config | Override the output directory for this run only |
| `-quiet` | No | Off | Suppress colorized console progress output |
| `-help` | No | - | Print usage information and exit 0 |

### Exit Codes

| Code | Meaning |
|-|-|
| 0 | NORMAL - no CRIT or WARN findings |
| 1 | WARNING - one or more WARN-level findings, no CRIT |
| 2 | CRITICAL - one or more CRIT-level findings |
| 3 | Fatal error - script could not complete (configuration not found, output directory not writable, journalctl not available, etc.) |

### Common Invocations

#### Default run (last 24 hours, all defaults)

```bash
sudo ./linux/log-monitor.sh
```

#### Specify an exact time window

```bash
sudo ./linux/log-monitor.sh \
    -start-time "2026-06-29 07:00:00" \
    -end-time   "2026-06-30 07:00:00"
```

#### Last 7 days (weekly summary)

```bash
sudo ./linux/log-monitor.sh \
    -start-time "$(date -d '7 days ago' '+%Y-%m-%d %H:%M:%S')" \
    -end-time   "$(date '+%Y-%m-%d %H:%M:%S')"
```

#### Last 1 hour (interactive investigation)

```bash
sudo ./linux/log-monitor.sh \
    -start-time "$(date -d '1 hour ago' '+%Y-%m-%d %H:%M:%S')" \
    -end-time   "$(date '+%Y-%m-%d %H:%M:%S')"
```

#### Scheduled/unattended run

```bash
sudo /opt/ops-log-monitor/linux/log-monitor.sh -quiet \
    -output /var/log/ops-log-monitor/reports
```

#### Use a local override configuration (automatic - no argument needed)

```bash
# If linux-monitor.conf.local exists in ./config/, it is automatically
# preferred over linux-monitor.conf without specifying -config.
sudo ./linux/log-monitor.sh
```

#### Check exit code explicitly

```bash
sudo ./linux/log-monitor.sh -quiet
EXIT_CODE=$?
case $EXIT_CODE in
    0) echo "Report status: NORMAL" ;;
    1) echo "Report status: WARNING" ;;
    2) echo "Report status: CRITICAL" ;;
    3) echo "FATAL: Script did not complete - check execution log" ;;
esac
```

#### Parse JSON output for a specific field with Python

```bash
# Extract all CRIT events from the Authentication category
python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
for event in data['categories']['Authentication']['events']:
    if event.get('severity') == 'CRIT':
        print(event['time_created'], event['description'])
" /path/to/report.json
```

### Verifying Prerequisites

```bash
# Verify journald persistent storage is enabled
ls -ld /var/log/journal/ 2>/dev/null && echo "Persistent journal OK" || \
    echo "WARNING: /var/log/journal does not exist - journal may be volatile only"

# Check journal retention and disk usage
journalctl -disk-usage
journalctl -verify

# Verify auditd is running and audit log is accessible
systemctl status auditd -no-pager
ls -lh /var/log/audit/audit.log

# Verify required auditd rules are loaded
auditctl -l

# Verify SELinux mode (Enforcing recommended; Permissive records but
# does not block; Disabled produces no AVC records)
getenforce

# Check journal retention for the monitoring window
journalctl -since "7 days ago" -until now -no-pager | wc -l
```

### Useful Companion Commands for Linux Log Investigation

```bash
# Query journald for a specific user's sudo activity directly
journalctl -identifier=sudo -since "24 hours ago" | grep "mreyes"

# Query journald for a specific unit's full history
journalctl -u sshd.service -since "24 hours ago" -no-pager

# View AVC denials since yesterday
ausearch -m AVC -start yesterday -end now 2>/dev/null | head -40

# Summarize all AVC denials in the audit log
aureport -avc -start yesterday -end now 2>/dev/null

# Check current pam_faillock status for a specific account
faillock -user mreyes

# List current systemd failed units
systemctl list-units -state=failed -no-pager

# Review recent authentication events from /var/log/secure
grep -E "Accepted|Failed|Invalid" /var/log/secure | tail -20

# Check current sudoers configuration for unexpected entries
visudo -c && cat /etc/sudoers
ls -la /etc/sudoers.d/

# Check recently modified files in audit-related directories
find /etc/audit/ /var/log/audit/ -newer /etc/fstab -ls 2>/dev/null
```

-

## Output File Naming Convention

Both platforms use the same filename pattern for generated reports:

```
{REPORT_FILENAME_PREFIX}-{HOSTNAME}-{YYYYMMDD}-{HHMMSS}.{ext}
```

**Example (Windows):**

```
ops-log-monitor-WEB-PROD-03-20260630-070014.md
ops-log-monitor-WEB-PROD-03-20260630-070014.json
```

**Example (Linux):**

```
ops-log-monitor-db-prod-02-20260630-070008.md
ops-log-monitor-db-prod-02-20260630-070008.json
```

The timestamp in the filename reflects when the report was *generated*,
not the start or end of the monitoring window. The monitoring window is
recorded in the report header and JSON metadata.

This naming convention means that:

- Reports from multiple runs accumulate without overwriting each other
- Files sort chronologically by filename without metadata inspection
- Hostname in the filename allows reports from multiple systems to be
  stored in the same directory and distinguished without opening each file

-

## Finding the Most Recent Report

**Windows (PowerShell):**

```powershell
Get-ChildItem ".\output\reports\" -Filter "*.md" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1 -ExpandProperty FullName
```

**Linux (Bash):**

```bash
ls -t output/reports/*.md 2>/dev/null | head -1
```

-

## Comparing Reports Across Dates

To compare CRIT counts between two JSON reports:

```bash
python3 - <<'EOF'
import json, glob, sys, os

report_files = sorted(glob.glob("output/reports/*.json"))[-7:]
for path in report_files:
    with open(path) as f:
        data = json.load(f)
    meta = data.get("reportMetadata", {})
    name = os.path.basename(path)
    print(f"{meta.get('windowStart','?')} | {meta.get('overallStatus','?'):8} | "
          f"CRIT:{meta.get('critCount',0):3} WARN:{meta.get('warnCount',0):3} | {name}")
EOF
```

This produces a one-line summary per report, suitable for spotting trends
across a week of daily runs without opening each report individually.