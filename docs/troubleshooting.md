# Troubleshooting

## Purpose of This Document

This document covers common failures when running `ops-log-monitor` on
both Windows and Linux - why they occur, how to confirm the diagnosis, and
how to resolve them. It is structured so you can search for a specific
symptom or error message and go directly to the relevant section.

Every failure mode described here was identified during development and
testing of the framework. None are hypothetical.

---

## Windows Troubleshooting

---

### W-01: Access Denied Querying the Security Event Log

**Symptom:**
The Authentication or Privilege module reports an error similar to:

```
[ERROR] [Authentication] Failed to query Event ID 4625:
The caller does not have the required access rights.
```

Or PowerShell throws:

```
Get-WinEvent : The caller does not have the required access rights
```

**Cause:**
The Security event log has stricter access controls than the System and
Application logs. The Event Log Readers built-in group does not receive
Security log access by default - an additional explicit ACL grant is
required. Running as a standard user or a non-administrative service
account without this grant produces this error.

**Diagnosis:**

```powershell
# Check what groups the current user belongs to
[Security.Principal.WindowsIdentity]::GetCurrent().Groups |
    ForEach-Object { $_.Translate([Security.Principal.NTAccount]) }

# Check whether the current process has Administrator rights
([Security.Principal.WindowsPrincipal]
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

**Resolution:**
Option 1 (simplest): Run the script as a local Administrator or from an
elevated PowerShell session.

```powershell
# Start PowerShell as Administrator, then run the script
.\Invoke-LogMonitor.ps1
```

Option 2 (preferred for scheduled/service use): Add the run-as account to
the built-in Administrators group, or grant it explicit Security log read
access. The Security log requires a SACL grant in addition to the Security
descriptor, which the Event Log Readers group alone does not provide:

```powershell
# Grant Security log read access to a specific account or group.
# Replace DOMAIN\svc-logmonitor with your actual service account name.
# This command modifies the Security event log's security descriptor
# and persists across reboots.
$logSd = (Get-WinEvent -ListLog Security).SecurityDescriptor
$sid = (New-Object Security.Principal.NTAccount("DOMAIN\svc-logmonitor")).Translate(
    [Security.Principal.SecurityIdentifier]).Value
wevtutil set-log Security /ca:"$logSd(A;;0x1;;;$sid)"
```

Option 3 (SYSTEM account): The Task Scheduler configuration in
`docs/scheduling-guide.md` uses SYSTEM as the run-as account for this
reason - SYSTEM has Security log read access by default.

---

### W-02: Modules Return Empty Results Despite Known Activity

**Symptom:**
A module completes without errors but reports zero events, even though
you know the relevant activity occurred on the system during the
monitoring window.

**Cause:**
Almost always an audit policy misconfiguration. If the required audit
policy subcategory is set to No Auditing, Windows does not generate the
events - there is nothing in the log for the module to find. An empty
module result is indistinguishable from a correctly configured module
with no relevant activity during the window, which is why verifying audit
policy is a mandatory first step when a module behaves unexpectedly.

**Diagnosis:**

```powershell
# Check the audit policy subcategories required by each module
auditpol /get /subcategory:"Logon"
auditpol /get /subcategory:"User Account Management"
auditpol /get /subcategory:"Security Group Management"
auditpol /get /subcategory:"Sensitive Privilege Use"
auditpol /get /subcategory:"Special Logon"
auditpol /get /subcategory:"Other Object Access Events"

# Each should show Success and Failure (or at minimum Success for
# event types that only have success variants)
```

**Resolution:**

Configure the required subcategories as described in
`docs/threat-model.md`:

```powershell
# Configure Logon auditing (required for Event IDs 4624, 4625, 4740)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Configure Security Group Management (required for 4728, 4732, 4756)
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable

# Configure Sensitive Privilege Use (required for 4672, 4673)
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable

# Configure Other Object Access Events (required for 4698, 4699, 4702)
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

After enabling the subcategory, generate a test event of the relevant
type (e.g., a deliberate failed logon), then verify it appears in
Event Viewer before relying on the module's output.

**Important note on Basic vs. Advanced Audit Policy:**
Avoid mixing the legacy Basic Audit Policy settings (configurable via
`secpol.msc` under Local Policies > Audit Policy) with the Advanced Audit
Policy subcategory settings (`auditpol /set`). Mixing the two can produce
unpredictable results where one setting silently overrides the other.
Use Advanced Audit Policy (`auditpol`) exclusively, as documented in
`docs/windows-event-ids.md`.

---

### W-03: Events Exist in the Log But Are Outside the Monitoring Window

**Symptom:**
You can see relevant events in Event Viewer that you expected to appear
in the report, but the report does not include them. The events timestamp
falls within what you believe the monitoring window should cover.

**Cause:**
Three common causes:

1. **Time zone mismatch:** Event Viewer displays event times in the local
   time zone by default, while `Get-WinEvent` returns times in the local
   time zone of the machine running the script. If you are viewing events
   from a remote machine with a different time zone, the displayed time
   may not match the query window.

2. **Window boundary:** The event timestamp falls exactly at or outside
   the window boundary (StartTime/EndTime). The filter is inclusive on
   both ends but precision matters - an event at 07:00:01 is inside a
   window ending at 07:00:00.

3. **NTP drift:** If the system clock has drifted significantly (hours
   rather than seconds), events may be logged with incorrect timestamps
   that fall outside the expected window.

**Diagnosis:**

```powershell
# Confirm the system time and time zone
Get-Date
[System.TimeZoneInfo]::Local.DisplayName

# Check NTP sync status
w32tm /query /status

# Query the event manually with explicit timestamps to confirm it exists
Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4625
    StartTime = [DateTime]"2026-06-29 00:00:00"
    EndTime   = [DateTime]"2026-06-30 23:59:59"
} | Select-Object -First 5 TimeCreated, Id | Format-Table
```

**Resolution:**
For time zone issues, use explicit `-StartTime` and `-EndTime` parameters
with timestamps that account for the offset. For NTP drift, configure
Windows Time Service (`w32tm /config /syncfromflags:domhier /update`,
or `w32tm /config /manualpeerlist:"time.server.example" /syncfromflags:manual`
for standalone systems) and resync (`w32tm /resync`).

---

### W-04: Event Log Has Overwritten Events for the Requested Window

**Symptom:**
The report covers a shorter period than requested. For example, a 24-hour
window is requested but the oldest event in any category is only 4 hours
old, and the report execution note warns about log size.

**Cause:**
The Security event log maximum size is too small for the volume of events
generated on this system within the monitoring window. When the log is
full, Windows overwrites the oldest events. The pre-flight check in the
orchestrator compares the configured log size against the recommended
minimums and surfaces this as a warning, but it cannot retroactively
recover overwritten events.

**Diagnosis:**

```powershell
Get-WinEvent -ListLog Security |
    Select-Object LogName, MaximumSizeInBytes, FileSize, RecordCount |
    Format-Table

# Determine the oldest event in the Security log
Get-WinEvent -LogName Security -Oldest |
    Select-Object -First 1 TimeCreated
```

**Resolution:**

```powershell
# Increase the Security log maximum size to 200 MB (recommended minimum
# for this framework's 24-hour monitoring window on production servers)
wevtutil set-log Security /maxsize:209715200  # 200 MB in bytes
wevtutil set-log System   /maxsize:52428800   # 50 MB
wevtutil set-log Application /maxsize:52428800 # 50 MB
```

For environments with high audit volume or compliance requirements, also
consider configuring Windows Event Forwarding to a central collector,
so local log overwriting does not permanently lose events.

---

### W-05: PowerShell Execution Policy Prevents the Script from Running

**Symptom:**

```
File cannot be loaded because running scripts is disabled on this system.
```

**Cause:**
The system's PowerShell execution policy is set to Restricted or
AllSigned, which prevents unsigned scripts from running.

**Diagnosis:**

```powershell
Get-ExecutionPolicy
Get-ExecutionPolicy -List  # shows policy at all scopes
```

**Resolution:**
For a single run, use the `-ExecutionPolicy Bypass` flag scoped to that
invocation only - this does not permanently change the system policy:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\Invoke-LogMonitor.ps1"
```

For a scheduled task, use the same flag in the task action's argument
string, as shown in `docs/scheduling-guide.md`.

For a persistent change at the LocalMachine scope (requires Administrator
and should be reviewed against organizational policy):

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
```

---

## Linux Troubleshooting

---

### L-01: Permission Denied Reading `/var/log/audit/audit.log`

**Symptom:**
The Privilege module reports:

```
[WARN] [Privilege] auditd is not active or /var/log/audit/audit.log
is not readable - falling back to journald (reduced detail)
```

Or a direct read attempt fails:

```bash
cat /var/log/audit/audit.log
cat: /var/log/audit/audit.log: Permission denied
```

**Cause:**
`/var/log/audit/audit.log` is owned by root and readable only by root
(mode 600 by default on RHEL 9). Running the script as a non-root user
without `REQUIRE_ROOT="false"` in the configuration will hit this
restriction.

**Diagnosis:**

```bash
ls -la /var/log/audit/audit.log
id
whoami
```

**Resolution:**
Run the script as root. For scheduled execution, this means the cron
entry or systemd timer must run as root, as documented in
`docs/scheduling-guide.md`. This is the recommended configuration and
is enforced by `REQUIRE_ROOT="true"` in `linux-monitor.conf`.

If running as non-root is a hard requirement in your environment:

```bash
# Add the service account to the 'adm' group, which has read access
# to most system logs but NOT to /var/log/audit/ by default
usermod -aG adm svc-logmonitor

# For audit.log specifically, an ACL grant is required since the
# standard group permission is not sufficient
setfacl -m u:svc-logmonitor:r /var/log/audit/audit.log

# Verify
getfacl /var/log/audit/audit.log
sudo -u svc-logmonitor cat /var/log/audit/audit.log | head -1
```

Note that `setfacl` ACLs on `/var/log/audit/audit.log` may be reset
when auditd rotates the log file. A more robust non-root approach is
to configure auditd to write to a secondary file with relaxed
permissions, or to use audisp (the audit dispatcher) to forward records
to a world-readable log, though these are environment-specific
configurations outside the scope of this framework.

---

### L-02: journald Returns No Data for the Requested Window

**Symptom:**
Multiple modules return zero events, including modules that should have
routine activity (Authentication, Services). The execution log shows
journalctl commands completing successfully but returning no output.

**Cause:**
Two common causes:

1. **Volatile journal storage:** If `/var/log/journal/` does not exist,
   journald uses volatile in-memory storage (`/run/log/journal/`). In-memory
   journal data is lost at every reboot, and may also have been truncated
   if journald was restarted during the monitoring window. A window that
   spans a reboot will have a gap in journal data.

2. **Clock skew:** If the system clock jumped significantly (e.g., after
   an NTP resync correcting a large drift), the `--since` and `--until`
   timestamps passed to journalctl may not align with the timestamps of
   journal entries written before the correction.

**Diagnosis:**

```bash
# Check whether persistent journal storage is configured
ls -ld /var/log/journal/ 2>/dev/null && echo "Persistent OK" || echo "Volatile only"

# Check journal disk usage and available range
journalctl --disk-usage
journalctl --list-boots --no-pager

# Test a direct journalctl query for the relevant window
journalctl --no-pager \
    --since="$(date -d '24 hours ago' '+%Y-%m-%d %H:%M:%S')" \
    --until="$(date '+%Y-%m-%d %H:%M:%S')" \
    --identifier=sshd \
    --output=short-iso | head -5

# Check system clock accuracy
timedatectl status
chronyc tracking 2>/dev/null || ntpstat 2>/dev/null || echo "Neither chrony nor ntpstat available"
```

**Resolution:**
To enable persistent journal storage:

```bash
# Create the persistent journal directory
mkdir -p /var/log/journal

# Set appropriate ownership
systemd-tmpfiles --create --prefix /var/log/journal

# Restart journald to begin writing to persistent storage
systemctl restart systemd-journald

# Verify
journalctl --disk-usage
ls -lh /var/log/journal/
```

For clock skew, ensure chronyd is running and synchronized:

```bash
systemctl enable --now chronyd
chronyc makestep    # Force immediate clock adjustment
timedatectl status  # Confirm synchronized
```

---

### L-03: auditd Rules Are Not Loaded

**Symptom:**
The Privilege module queries auditd but returns no sudo or su events,
even though sudo was used during the monitoring window. auditd appears
to be running.

**Cause:**
auditd can be running without the required audit rules being loaded.
Without the specific rules for monitoring sudo and su execve calls, those
events are not captured in audit.log even though auditd is active.

**Diagnosis:**

```bash
# Confirm auditd is running
systemctl status auditd --no-pager

# List currently loaded rules
auditctl -l

# If only "-a never,task" or no rules appear, the required rules
# are not loaded. Check the rules files:
ls -la /etc/audit/rules.d/
cat /etc/audit/audit.rules
```

**Resolution:**
Create the required rules file. As root:

```bash
cat > /etc/audit/rules.d/ops-log-monitor.rules <<'EOF'
# Monitor sudo executions
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k sudo_exec
-a always,exit -F arch=b32 -S execve -F path=/usr/bin/sudo -k sudo_exec

# Monitor su executions
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/su -k su_exec
-a always,exit -F arch=b32 -S execve -F path=/usr/bin/su -k su_exec

# Monitor changes to sudoers
-w /etc/sudoers -p wa -k sudoers_change
-w /etc/sudoers.d/ -p wa -k sudoers_change
EOF

# Load the rules without restarting auditd
augenrules --load

# Verify the rules are now loaded
auditctl -l | grep -E "sudo_exec|su_exec|sudoers_change"
```

Generate a test sudo command and verify it appears in audit.log:

```bash
sudo ls /root 2>/dev/null
grep "type=USER_CMD" /var/log/audit/audit.log | tail -3
```

---

### L-04: SELinux AVC Denial Detection Returns No Results

**Symptom:**
The Kernel module reports either:
- "SELinux is Disabled on this system - AVC denial monitoring skipped"
- No AVC denial events, even though you know policy violations occurred

**Cause (Disabled):**
SELinux is set to Disabled in `/etc/selinux/config`. Disabling SELinux
is a common shortcut that removes an important security control. No AVC
records are generated when SELinux is disabled - there is nothing for
the module to detect.

**Cause (no results despite expected violations):**
auditd may not be running, or the audit log may not contain AVC records.
When auditd is not running, AVC denials go to `/var/log/messages` with
reduced structure rather than to `/var/log/audit/audit.log`. The module
does not currently parse `/var/log/messages` for AVC records.

**Diagnosis:**

```bash
# Check current SELinux mode (runtime)
getenforce

# Check configured SELinux mode (persists after reboot)
cat /etc/selinux/config | grep ^SELINUX=

# Check whether AVC records exist in the audit log
grep "type=AVC" /var/log/audit/audit.log | tail -5

# Check whether AVC records appear in messages instead (indicates
# auditd was not running when the denial occurred)
grep "avc:.*denied" /var/log/messages 2>/dev/null | tail -5
```

**Resolution (Disabled → Permissive for testing):**
Do not change SELinux from Disabled to Enforcing directly - this can
cause boot failures on systems that have accumulated many unlabeled files.
Go through Permissive first:

```bash
# Set permissive mode at runtime (takes effect immediately, no reboot)
setenforce 0

# Set permissive mode persistently (for the next boot)
sed -i 's/^SELINUX=disabled/SELINUX=permissive/' /etc/selinux/config

# Reboot to allow SELinux to label the filesystem
# Then test in permissive mode before switching to enforcing
```

For the no-results-despite-violations case, ensure auditd is running
before expecting AVC records in `/var/log/audit/audit.log`:

```bash
systemctl enable --now auditd
```

---

### L-05: `date -d` Cannot Parse the Time Format

**Symptom:**
The orchestrator exits with:

```
[ERROR] [Orchestrator] Could not parse --start-time value: '2026/06/29 07:00:00'.
Expected format: YYYY-MM-DD HH:MM:SS
```

**Cause:**
`date -d` on RHEL 9 (GNU date) accepts many formats, but the
`--start-time` and `--end-time` arguments are validated strictly by the
orchestrator using `date -d` and checking for a non-empty result. Formats
using `/` instead of `-` as date separators, or ISO 8601 `T`-separated
timestamps without a timezone suffix, may fail depending on locale and
`date` version.

**Diagnosis:**

```bash
# Test whether your format is accepted by GNU date
date -d "2026/06/29 07:00:00" "+%s" && echo "Format OK" || echo "Format not accepted"
date -d "2026-06-29T07:00:00" "+%s" && echo "Format OK" || echo "Format not accepted"

# The format that always works with this framework
date -d "2026-06-29 07:00:00" "+%s" && echo "Format OK"
```

**Resolution:**
Use the documented format: `YYYY-MM-DD HH:MM:SS` with a space separator
between date and time. This format is unambiguous and consistently
accepted by GNU date across all RHEL 9 locale settings.

```bash
sudo ./linux/log-monitor.sh \
    --start-time "2026-06-29 07:00:00" \
    --end-time   "2026-06-30 07:00:00"
```

---

### L-06: Script Reports `REQUIRE_ROOT=true` but Running Under sudo Fails

**Symptom:**

```
[ERROR] [Orchestrator] This script must be run as root (REQUIRE_ROOT=true
in config).
```

...even though you ran the script with `sudo`.

**Cause:**
Typically caused by the script being invoked via a path that sudo cannot
resolve, or a sudoers configuration that strips the `SETENV` flag and
does not preserve the expected environment. Less commonly, a shell
function named `log-monitor` shadows the script, causing the wrong binary
to be invoked.

**Diagnosis:**

```bash
# Verify what id reports when running the script under sudo
sudo bash -c 'id && echo "Working as expected"'

# Verify the script is being invoked from the correct path
which ./linux/log-monitor.sh 2>/dev/null || echo "Not in PATH - use explicit path"
sudo bash /opt/ops-log-monitor/linux/log-monitor.sh --help
```

**Resolution:**
Use the full path to `bash` with the script path as an argument, rather
than relying on the shebang line when sudo's PATH is restricted:

```bash
sudo bash /opt/ops-log-monitor/linux/log-monitor.sh
```

Or ensure the deploying user has a sudoers rule that allows running the
script explicitly, rather than relying on general sudo access:

```bash
# In /etc/sudoers.d/ops-log-monitor:
svc-logmonitor ALL=(root) NOPASSWD: /opt/ops-log-monitor/linux/log-monitor.sh
```

---

## Both Platforms

---

### B-01: Report Shows NORMAL Status but You Expected Findings

**Symptom:**
The report status is NORMAL with zero CRIT and WARN events, but you know
something suspicious or operationally significant happened on the system
during the monitoring window.

**Diagnosis approach - work from log source to report output:**

1. **Confirm the event exists in the raw log** (bypassing the framework):

   Windows:
```powershell
   Get-WinEvent -LogName Security -MaxEvents 100 |
       Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-24) } |
       Select-Object TimeCreated, Id |
       Format-Table
```

   Linux:
```bash
   journalctl --no-pager --since="24 hours ago" --identifier=sshd | tail -20
   grep "type=USER_CMD" /var/log/audit/audit.log | tail -10
```

2. **If the event exists in the raw log:** The module is collecting it
   but the severity threshold is placing it at INFO rather than WARN.
   Check the threshold configuration against the actual event count -
   if the count is below the WARN threshold, the event is correctly
   classified. Lower the threshold if your environment justifies it.

3. **If the event does not exist in the raw log:** The problem is at the
   log source layer, not the framework layer. Check audit policy (Windows)
   or auditd rules (Linux). Refer to W-02 or L-03 above.

4. **If you are unsure which layer the problem is at:** Enable verbose
   logging by removing `--quiet` from the invocation and reviewing the
   full execution log output. Each module logs how many raw events it
   retrieved before filtering - "Retrieved 0 sshd log lines" is a
   fundamentally different diagnosis than "Retrieved 847 sshd log lines"
   when zero events appear in the report.

---

### B-02: Report Generation Succeeds but Output Files Are Missing

**Symptom:**
The script runs to completion and reports success in the console, but no
`.md` or `.json` files appear in the expected output directory.

**Cause:**
`OUTPUT_DIR` in the configuration resolves to a different path than
expected - commonly because the value is relative and the script was
invoked from a different working directory than the repository root.

**Diagnosis:**

Windows:
```powershell
$config = . ".\windows\config\windows-monitor.conf.ps1" ; $OUTPUT_DIR
# If blank, the dot-source did not work - check working directory
Get-Location
```

Linux:
```bash
source linux/config/linux-monitor.conf
echo "$OUTPUT_DIR"
echo "Resolved: $(pwd)/$OUTPUT_DIR"
ls -lhd "$(pwd)/$OUTPUT_DIR" 2>/dev/null || echo "Directory does not exist at resolved path"
```

**Resolution:**
Set `OUTPUT_DIR` to an absolute path in the configuration file (or local
override) rather than a relative path. Absolute paths are unambiguous
regardless of where the script is invoked from:

Windows: `$OUTPUT_DIR = "C:\ops-log-monitor\output\reports"`

Linux: `OUTPUT_DIR="/opt/ops-log-monitor/output/reports"`