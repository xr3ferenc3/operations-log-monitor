# Incident Escalation Checklist

**System:** _________________________________ &nbsp;&nbsp; **Date:** _____________

**Incident Start (estimated):** _____________ &nbsp;&nbsp; **Detected By:** _____________

**Investigator:** _________________________________ &nbsp;&nbsp; **Ticket Number:** _____________

**Report Files Referenced:**

- _________________________________
- _________________________________
- _________________________________

---

## Purpose

This checklist guides an administrator through using `ops-log-monitor`
report output as evidence-collection and timeline-construction tools
during an active incident. It is designed to be started as soon as a
potential incident is identified from a daily review, an alert from
another system, or a direct user report.

Complete this checklist in order. Steps are sequenced to build a factual
timeline before drawing conclusions - a common mistake in incident
investigation is committing to a narrative too early and then selectively
reading evidence to confirm it. This checklist is designed to prevent
that.

Attach this completed checklist, all referenced report files, and any
additional log extracts to the incident ticket before escalating.
Evidence not documented in the ticket may as well not exist once the
incident is closed and memory fades.

---

## Section 1: Incident Identification

---

**Step 1.1 - Record how the incident was identified**

Select the initial detection method and record details:

- [ ] CRIT finding in daily `ops-log-monitor` report
- [ ] WARN finding in report - escalated due to correlation or recurrence
- [ ] User or system owner reported a problem
- [ ] Alert from another monitoring system (specify): _____________
- [ ] Discovered during routine maintenance or log review
- [ ] Other: _________________________________

**Detection details:**

_________________________________
_________________________________

---

**Step 1.2 - Record the initial finding that triggered this checklist**

Copy the exact event description from the report that initiated this
investigation:

```
Time:        _________________________________
Category:    _________________________________
Severity:    _________________________________
Description: _________________________________
             _________________________________
```

---

**Step 1.3 - Identify which system(s) are involved**

- [ ] Single system - hostname: _________________________________
- [ ] Multiple systems - list: _________________________________
- [ ] Unknown at this stage

**System role (web server, database server, file server, etc.):**
_________________________________

**System criticality (production / staging / development):**
_________________________________

---

## Section 2: Immediate Containment Assessment

Before collecting evidence, assess whether immediate containment is
required. Do not let evidence collection delay containment if the
incident is active.

---

**Step 2.1 - Is malicious activity potentially still in progress?**

Indicators that an incident may be active rather than historical:

- A suspicious account is currently logged on
- A recently created scheduled task or cron job is set to run in the
  near future
- A service is currently in an unexpected state resulting from the
  suspected activity
- A process associated with the suspected activity is currently running

- [ ] Activity appears historical - continue to evidence collection
- [ ] Activity may be ongoing - complete Step 2.2 before continuing

---

**Step 2.2 - Immediate containment actions (if active incident)**

Document every action taken. An undocumented containment action can
corrupt evidence or make the timeline impossible to reconstruct.

| Time | Action Taken | Taken By |
|---|---|---|
| | | |
| | | |
| | | |

**Containment actions may include:**

- Disabling the suspected account (do NOT delete it - deletion destroys
  audit trail)
- Isolating the system from the network (coordinate with your incident
  response plan before doing this - isolation may also destroy in-memory
  evidence if the system reboots)
- Terminating a specific process
- Revoking a recently granted permission or group membership

```powershell
# Windows: disable an account without deleting it
Disable-LocalUser -Name "mreyes"

# Windows: document the account state at time of disable
Get-LocalUser -Name "mreyes" | Format-List
```

```bash
# Linux: lock an account without deleting it
usermod -L mreyes
passwd -l mreyes

# Linux: document the account state
getent passwd mreyes
groups mreyes
```

---

## Section 3: Evidence Collection from Report Output

---

**Step 3.1 - Collect the full report for the window covering the incident**

If the incident began near the boundary of a daily report window,
generate an extended-window report to ensure full coverage:

```powershell
# Windows: generate a 48-hour window centered on the incident time
.\windows\Invoke-LogMonitor.ps1 `
    -StartTime "YYYY-MM-DD HH:MM:SS" `
    -EndTime   "YYYY-MM-DD HH:MM:SS" `
    -OutputPath "C:\Incident-Evidence\TICKET-NUMBER"
```

```bash
# Linux: generate a 48-hour window centered on the incident time
sudo ./linux/log-monitor.sh \
    --start-time "YYYY-MM-DD HH:MM:SS" \
    --end-time   "YYYY-MM-DD HH:MM:SS" \
    --output /var/log/incident-evidence/TICKET-NUMBER
```

**Extended report generated:** Yes / No

**Report file path:** _________________________________

---

**Step 3.2 - Extract the Authentication section findings**

Review the Authentication section of the extended report. Record:

**Account(s) involved in authentication events:**
_________________________________

**Source IP(s) involved:**
_________________________________

**First authentication event for the involved account(s):**

```
Time:    _________________________________
Type:    _________________________________
Result:  _________________________________
```

**Last authentication event for the involved account(s):**

```
Time:    _________________________________
Type:    _________________________________
Result:  _________________________________
```

**Account lockout events (if any):** _________________________________

---

**Step 3.3 - Extract the Privilege section findings**

Review the Privilege section. Record:

**Were any group membership changes made?**

- [ ] No
- [ ] Yes - groups modified: _________________________________
        By account: _____________ At time: _____________

**Were any high-risk privileges exercised?**

- [ ] No
- [ ] Yes - privilege: _________________ Account: _________________ Process: _________________

**Were any sudo commands executed by the involved account(s)?**

- [ ] No
- [ ] Yes - commands: _________________________________

**Were any sudoers modifications detected?**

- [ ] No
- [ ] Yes - at time: _____________ by account: _____________

---

**Step 3.4 - Extract the Scheduled Tasks / Kernel section findings**

Review the ScheduledTasks section (Windows) or Kernel section (Linux)
for persistence mechanisms created during the incident window.

**Were any scheduled tasks created or modified?**

- [ ] No
- [ ] Yes - task name: _________________________ at time: _____________
        Action/command: _________________________________
        Created by: _________________________________

**Were any cron jobs or systemd timers created (Linux)?**

- [ ] No
- [ ] Yes - details: _________________________________

**Were any SELinux AVC denials generated by the involved process?**

- [ ] No / Not applicable
- [ ] Yes - source context: _________________________________
        Target context: _________________________________

---

**Step 3.5 - Extract the Services section findings**

**Were any services stopped, crashed, or failed during the incident window?**

- [ ] No
- [ ] Yes - service: _________________________ at time: _____________

**Is the service currently running?**

- [ ] Yes
- [ ] No - still in failed state

**Were any security-relevant services affected?**

- [ ] No
- [ ] Yes - service(s): _________________________________
  This may indicate an attempt to disable defensive controls before
  or during the incident.

---

**Step 3.6 - Extract the System Health section findings**

**Were any unexpected shutdowns or reboots recorded?**

- [ ] No
- [ ] Yes - at time: _____________ type: _____________

**Were any disk errors or OOM kills recorded?**

- [ ] No
- [ ] Yes - details: _________________________________

---

## Section 4: Timeline Construction

Using the findings from Section 3, construct a chronological timeline
of events. List each significant event in time order. A complete
timeline is the most important artifact produced by an incident
investigation - it tells the story in sequence rather than by category.

| Time (UTC) | Category | Event | Source |
|---|---|---|---|
| | | | |
| | | | |
| | | | |
| | | | |
| | | | |
| | | | |
| | | | |
| | | | |

**Earliest suspicious event in the timeline:**

```
Time:     _________________________________
Event:    _________________________________
```

**Estimated incident start time (may differ from detection time):**
_________________________________

---

## Section 5: Supplementary Evidence Collection

`ops-log-monitor` report output is structured and organized but does not
capture every event on the system. Collect supplementary evidence from
the native log sources to fill gaps in the timeline.

---

**Step 5.1 - Windows supplementary evidence**

```powershell
# Full logon/logoff history for the involved account in the incident window
Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = @(4624, 4625, 4634, 4647)
    StartTime = [DateTime]"INCIDENT-START"
    EndTime   = [DateTime]"INCIDENT-END"
} | Where-Object { $_.Message -match "ACCOUNT-NAME" } |
    Select-Object TimeCreated, Id, Message |
    Export-Csv "C:\Incident-Evidence\TICKET-NUMBER\logon-history.csv" -NoTypeInformation

# Current scheduled task state (what tasks exist RIGHT NOW)
Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } |
    Select-Object TaskName, TaskPath,
        @{N="Principal";E={$_.Principal.UserId}},
        @{N="Action";E={$_.Actions.Execute}},
        @{N="LastRun";E={(Get-ScheduledTaskInfo $_.TaskName).LastRunTime}} |
    Export-Csv "C:\Incident-Evidence\TICKET-NUMBER\scheduled-tasks-now.csv" -NoTypeInformation

# All group membership changes for the incident window
Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = @(4728, 4732, 4756, 4729, 4733, 4757)
    StartTime = [DateTime]"INCIDENT-START"
    EndTime   = [DateTime]"INCIDENT-END"
} | Select-Object TimeCreated, Id, Message |
    Format-List | Out-File "C:\Incident-Evidence\TICKET-NUMBER\group-changes.txt"

# PowerShell command history if transcript logging is enabled
Get-Content "C:\Windows\System32\WindowsPowerShell\v1.0\*transcript*" `
    -ErrorAction SilentlyContinue | Out-File `
    "C:\Incident-Evidence\TICKET-NUMBER\ps-transcripts.txt"
```

**Windows evidence collection completed:** Yes / No / Partial

**Notes:** _________________________________

---

**Step 5.2 - Linux supplementary evidence**

```bash
TICKET="TICKET-NUMBER"
INCIDENT_START="YYYY-MM-DD HH:MM:SS"
INCIDENT_END="YYYY-MM-DD HH:MM:SS"
ACCOUNT="mreyes"
EVIDENCE_DIR="/var/log/incident-evidence/${TICKET}"
mkdir -p "$EVIDENCE_DIR"

# Full SSH session history for the involved account
journalctl --no-pager \
    --since="$INCIDENT_START" \
    --until="$INCIDENT_END" \
    --identifier=sshd \
    --output=short-iso > "${EVIDENCE_DIR}/sshd-sessions.log"

# All sudo commands from the involved account via auditd
ausearch --start "${INCIDENT_START}" --end "${INCIDENT_END}" \
    --message USER_CMD --raw 2>/dev/null | \
    grep -i "uid.*$(id -u $ACCOUNT 2>/dev/null || echo $ACCOUNT)" \
    > "${EVIDENCE_DIR}/sudo-commands.log" || true

# Current sudoers configuration snapshot
cp /etc/sudoers "${EVIDENCE_DIR}/sudoers-now.txt"
cp -r /etc/sudoers.d/ "${EVIDENCE_DIR}/sudoers.d-now/" 2>/dev/null || true

# All AVC denials for the incident window
ausearch --start "${INCIDENT_START}" --end "${INCIDENT_END}" \
    --message AVC --raw 2>/dev/null \
    > "${EVIDENCE_DIR}/avc-denials.log" || true

# Current crontab state
crontab -l -u root > "${EVIDENCE_DIR}/root-crontab-now.txt" 2>/dev/null || true
ls -la /etc/cron.d/ > "${EVIDENCE_DIR}/cron.d-listing.txt" 2>/dev/null || true

# Current systemd timer state
systemctl list-timers --all --no-pager \
    > "${EVIDENCE_DIR}/systemd-timers-now.txt"

# Bash history for the involved account (may have been cleared - capture
# what remains and note if the file is empty or suspiciously short)
cp "/home/${ACCOUNT}/.bash_history" \
   "${EVIDENCE_DIR}/bash_history-${ACCOUNT}.txt" 2>/dev/null || \
   echo "No bash_history found for ${ACCOUNT}" > \
   "${EVIDENCE_DIR}/bash_history-${ACCOUNT}.txt"

wc -l "${EVIDENCE_DIR}/bash_history-${ACCOUNT}.txt"
echo "Note: an unusually short or empty bash_history may indicate deliberate clearing - itself a finding."
```

**Linux evidence collection completed:** Yes / No / Partial

**Notes:** _________________________________

---

## Section 6: Impact Assessment

---

**Step 6.1 - What resources did the involved account(s) access?**

_________________________________
_________________________________

---

**Step 6.2 - Was any data accessed that should not have been?**

- [ ] No evidence of unauthorized data access
- [ ] Possible unauthorized data access - details: _________________________________
- [ ] Confirmed unauthorized data access - details: _________________________________

---

**Step 6.3 - Were any persistent changes made to the system?**

Persistent changes survive a reboot and may still be present on the system
even after the initial activity is stopped. Check each:

- [ ] New user accounts created
- [ ] Existing accounts added to privileged groups
- [ ] Scheduled tasks or cron jobs created
- [ ] Sudoers modified
- [ ] SSH authorized_keys modified
- [ ] New services installed
- [ ] Software installed or modified
- [ ] Firewall rules changed
- [ ] Files written to persistent locations

**Details of persistent changes found:**

_________________________________
_________________________________

---

**Step 6.4 - What is the estimated scope?**

- [ ] Contained to this one system
- [ ] May extend to other systems - list: _________________________________
- [ ] Unknown - cross-system investigation required

---

## Section 7: Escalation Decision

---

**Step 7.1 - Does this incident require escalation beyond the local team?**

Escalation criteria - check all that apply:

- [ ] Confirmed unauthorized access to the system
- [ ] Evidence of lateral movement to other systems
- [ ] Unauthorized data access confirmed or probable
- [ ] Malware or attacker tooling identified
- [ ] Incident involves a privileged or administrative account
- [ ] Evidence of log tampering or evidence destruction
- [ ] Regulatory or compliance implications (PCI, HIPAA, SOX, etc.)
- [ ] Incident is ongoing and containment is not yet achieved

**Escalation required:** Yes / No / Unclear

**Escalated to:** _________________________________

**Escalation time:** _________________________________

---

## Section 8: Resolution and Lessons Learned

Complete this section after the incident is closed, not during active
investigation.

---

**Step 8.1 - Root cause**

_________________________________
_________________________________

---

**Step 8.2 - How was the incident detected?**

- [ ] Detected by `ops-log-monitor` CRIT finding on the day of the incident
- [ ] Detected by `ops-log-monitor` WARN finding - delay of _______ days
- [ ] Detected by another mechanism - describe: _________________________________
- [ ] Not detected by `ops-log-monitor` - reason: _________________________________

---

**Step 8.3 - Would earlier detection have been possible?**

- [ ] No - detection timing was optimal given the framework's capabilities
- [ ] Yes - describe what change would have detected it earlier:

_________________________________
_________________________________

---

**Step 8.4 - Configuration changes recommended as a result of this incident**

| Change | Justification | Owner | Due Date |
|---|---|---|---|
| | | | |
| | | | |

---

**Step 8.5 - Final sign-off**

**Incident closed:** Yes / No **Closure time:** _____________

**Investigator signature:** _________________________________ **Date:** _____________

**Manager or security team sign-off:** _________________________________ **Date:** _____________