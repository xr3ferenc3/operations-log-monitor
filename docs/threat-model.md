# Threat Model

## Purpose of This Document

This document defines what `ops-log-monitor` can detect, what it cannot
detect, what assumptions it makes about the environment it operates in, and
what it should not be relied upon to replace.

Every monitoring tool has a detection boundary. Understanding that boundary
is not a weakness - it is a prerequisite for using any tool responsibly.
An administrator who understands what their monitoring cannot see is more
effective than one who assumes their tools see everything.

This document is written for administrators who are evaluating whether this
framework meets their operational needs, planning a monitoring strategy around
it, or explaining its capabilities to a manager or auditor.

---

## Threat Categories This Framework Addresses

### 1. Credential-Based Attacks

**What it detects:**
- Repeated authentication failures against local accounts (brute force
  indicators)
- Account lockouts resulting from repeated failures
- Successful authentications that immediately follow a series of failures
  (possible successful brute force)
- Authentication events occurring outside defined business hours
- SSH authentication failures on Linux systems
- PAM authentication failures for non-SSH services

**How it detects it:**
Windows: Event IDs 4625 (logon failure), 4740 (account lockout), and 4624
(successful logon) are queried from the Security event log. Failures are
counted per account and per source. Threshold crossings are flagged.

Linux: SSH failures are extracted from journald and /var/log/secure. PAM
failures are extracted from journald. Failure counts per source IP and
per username are tracked within the monitoring window.

**Limitations:**
- Slow credential attacks that stay below the failure threshold within the
  monitoring window will not be flagged
- Attacks using valid credentials obtained through phishing or other means
  produce no authentication failures and will not be detected here
- This framework monitors local accounts only. Domain accounts on systems
  joined to Active Directory generate authentication events on domain
  controllers, not on the local system

---

### 2. Unauthorized Privilege Use

**What it detects:**
- Special privilege assignment at logon (Windows Event ID 4672), which
  indicates a user logged on with administrative or sensitive privileges
- Sensitive privilege use during a session (Windows Event ID 4673)
- Membership changes to privileged local groups: Administrators (4728),
  Remote Desktop Users (4732), and similar groups (4756)
- sudo command executions on Linux, including the command run and the
  user who ran it
- Failed sudo attempts (user attempted sudo but was not authorized)
- su attempts and their outcomes

**How it detects it:**
Windows: Security event log queries for privilege-related event IDs.
Group membership change events include the account that was added or
removed and the account that made the change.

Linux: sudo executions are extracted from journald and /var/log/secure.
auditd records are used where available for more complete sudo coverage.

**Limitations:**
- A legitimate administrator using their own credentials to perform
  authorized administrative work will generate the same events as an
  attacker who has compromised that administrator's credentials. This
  framework records the event. It cannot determine intent.
- On Linux systems where auditd is not running, sudo coverage depends
  entirely on journald. If journald has been tampered with, coverage
  is incomplete.
- Privilege use by accounts that are already in the Administrators group
  or sudoers is expected and will appear in reports. Volume and timing
  are the indicators, not the events themselves.

---

### 3. Service and Application Failures

**What it detects:**
- Services that crashed or stopped unexpectedly (Windows Event IDs 7034,
  7036; systemd unit entered failed state)
- Services that failed to start at system boot (Windows Event ID 7000;
  systemd units that failed during boot)
- Application crashes with crash dump generation (Windows Event IDs
  1000, 1001)
- Services that were stopped and restarted in an unusual sequence

**How it detects it:**
Windows: System and Application event log queries for service control
manager events and Windows Error Reporting events.

Linux: journalctl queries filtering for units in failed state and
units that did not start cleanly.

**Limitations:**
- A service that is functioning incorrectly but has not crashed will
  not appear in this category. Application-level errors that do not
  produce Windows events or systemd journal entries are invisible to
  this framework.
- Service failures caused by dependency failures (a service failed
  because a service it depends on failed first) are reported as
  individual failures. The root cause relationship is not automatically
  identified.

---

### 4. Scheduled Task and Cron Manipulation

**What it detects (Windows):**
- Scheduled task creation (Event ID 4698)
- Scheduled task modification (Event ID 4702)
- Scheduled task deletion (Event ID 4699)
- Tasks created or modified by non-administrative accounts

**What it detects (Linux):**
- New files appearing in /etc/cron.d, /etc/cron.hourly, /etc/cron.daily,
  /etc/cron.weekly, /etc/cron.monthly during the monitoring window
- Systemd timer unit creation events in the journal

**Why this matters:**
Scheduled tasks and cron jobs are a common persistence mechanism used by
attackers after gaining initial access. Creating a scheduled task that
executes a payload is one of the first things many attackers do after
establishing a foothold.

**Limitations:**
- This framework detects task creation and modification events. It does
  not analyze the content of the task action to determine whether it is
  malicious. A newly created task running PowerShell from an unusual
  path is flagged the same way as a newly created task running a
  legitimate backup script.
- On Linux, detection of cron file changes depends on file modification
  timestamps, which can be manipulated.
- Scheduled tasks or cron jobs that were created before the monitoring
  window are not reported, even if they are malicious. Baseline review
  is a separate operational concern covered in the customization guide.

---

### 5. System Health Degradation

**What it detects:**
- Unexpected system shutdowns and reboots (Windows Event ID 6008;
  Linux kernel panic indicators in the journal)
- Disk I/O errors and filesystem errors (Windows Disk and NTFS event
  sources; Linux kernel storage error messages in journald)
- OOM (Out of Memory) killer invocations on Linux
- Hardware error events reported by the operating system

**Why this matters:**
Hardware failures give advance warning before causing data loss or
outages. Disk errors appearing in logs days or weeks before a disk
failure are common. This framework surfaces those warnings so
administrators can act before failure occurs.

**Limitations:**
- This framework reports events that the operating system has already
  logged. If a hardware failure is severe enough to prevent the OS from
  logging, it will not be detected here.
- Disk errors reported by the OS do not always indicate imminent failure.
  A single reallocated sector is different from continuous read errors.
  The report records what happened; the administrator must interpret the
  severity.

---

### 6. Kernel and Policy Violations (Linux)

**What it detects:**
- SELinux AVC denials from /var/log/audit/audit.log
- Kernel warnings and errors from journald
- Kernel oops indicators

**Why this matters:**
SELinux AVC denials indicate that a process attempted an action that its
security policy does not permit. In a correctly configured system, AVC
denials are rare. A burst of AVC denials from an unexpected process is
a significant indicator of either a misconfiguration or an attempt to
operate outside expected process boundaries.

**Limitations:**
- AVC denials on a newly deployed system or after a package update are
  commonly caused by policy gaps, not attacks. Context is required to
  interpret them correctly.
- This framework requires auditd to be running and /var/log/audit/audit.log
  to be populated. If auditd is not running, SELinux denial detection
  is not available.

---

## What This Framework Does Not Detect

Understanding detection gaps is as important as understanding detection
capabilities. The following threat categories are outside the scope of
this framework.

### Network-based threats

This framework does not monitor network traffic, firewall logs, or
connection state. Port scans, network reconnaissance, lateral movement
over the network, and data exfiltration over the network are not detected.

Network monitoring requires dedicated tooling such as firewall log
aggregation, IDS/IPS, or network flow analysis. Those tools operate at
a different layer than this framework.

### File system integrity

This framework does not monitor file modifications, hash changes, or
unexpected file creation in sensitive directories (beyond the cron
directories noted above). File integrity monitoring requires dedicated
tooling such as AIDE on Linux or a Windows FIM solution.

### Memory-resident threats

Attacks that operate entirely in memory without writing files or creating
scheduled tasks, and without generating authentication events or service
failures, are not detectable by log analysis alone. These threats require
endpoint detection and response (EDR) tooling.

### Cross-system correlation

This framework monitors one system at a time. It cannot detect attack
patterns that span multiple systems, such as an attacker who fails
authentication on three different servers using three different accounts
within a short window. Cross-system correlation requires centralized log
aggregation.

### Log tampering

If an attacker with administrative access clears the Windows Event Log
or deletes journal entries, this framework will not detect the events
that were cleared. Windows generates Event ID 1102 (audit log cleared)
when the Security log is cleared by an administrator, which this framework
does monitor. However, an attacker with sufficient access can defeat log-
based detection.

The appropriate response to this limitation is defense in depth: forward
logs to a remote syslog server or SIEM so that clearing the local log
does not destroy the evidence.

### Real-time alerting

This framework produces reports on demand or on a schedule. It does not
provide real-time alerting. An attack that completes in minutes will not
be detected until the next report is generated.

Real-time alerting requires either a SIEM or a dedicated alerting layer
built on top of this framework. The scheduling guide covers how to run
reports at short intervals as a partial mitigation.

---

## Assumptions

This framework makes the following assumptions about the environment it
operates in. If these assumptions do not hold, results may be incomplete
or misleading.

### Windows assumptions

| Assumption | Consequence if false |
|---|---|
| Advanced Audit Policy is configured to log the required event IDs | Events will not exist in the log; modules will return empty results |
| The Security event log is large enough to retain events for the monitoring window | Old events will have been overwritten; the report will cover a shorter window than requested |
| The script runs under an account with permission to read the Security event log | Authentication and privilege modules will fail with access denied errors |
| System time is synchronized | Timestamps in reports will be inaccurate; after-hours detection will produce false results |

### Linux assumptions

| Assumption | Consequence if false |
|---|---|
| systemd-journald is running and retaining logs | Service and kernel modules will return empty or incomplete results |
| auditd is running and configured to log sudo and privilege events | Privilege module coverage will be incomplete |
| SELinux is in enforcing or permissive mode (not disabled) | Kernel module will report no AVC denials regardless of activity |
| The script runs as root or a user with read access to /var/log/audit/ | Privilege and kernel modules will fail with permission errors |
| System time is synchronized via chronyd or ntpd | Timestamps will be inaccurate |

---

## Audit Policy Requirements (Windows)

The following audit policy categories must be enabled for the Windows
modules to collect their intended events. These settings are configured
in Local Security Policy under Security Settings → Advanced Audit Policy
Configuration.

| Audit Category | Subcategory | Setting Required |
|---|---|---|
| Account Logon | Audit Logon | Success and Failure |
| Account Management | Audit User Account Management | Success and Failure |
| Account Management | Audit Security Group Management | Success and Failure |
| Logon/Logoff | Audit Logon | Success and Failure |
| Privilege Use | Audit Sensitive Privilege Use | Success and Failure |
| System | Audit Security State Change | Success and Failure |
| Object Access | Audit Other Object Access Events | Success (for scheduled tasks) |

To verify current audit policy settings:

```powershell
auditpol /get /category:*
```

*Mastering Windows Server 2022* (Krause, Chapter on Security) covers
audit policy configuration in detail. The subcategory settings above
follow current Microsoft guidance, which provides more granular control
than the legacy basic audit policy settings the book also references.
Current best practice is to use Advanced Audit Policy exclusively and
not mix it with basic audit policy settings, as mixing can produce
unpredictable results.

---

## auditd Requirements (Linux)

The following auditd rules are required for complete privilege event
coverage on Linux. These rules should be present in /etc/audit/rules.d/.

```bash
# Monitor sudo executions
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k sudo_exec

# Monitor su executions
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/su -k su_exec

# Monitor changes to sudoers
-w /etc/sudoers -p wa -k sudoers_change
-w /etc/sudoers.d/ -p wa -k sudoers_change
```

To verify auditd is running and rules are loaded:

```bash
systemctl status auditd
auditctl -l
```

*RHCSA Red Hat Enterprise Linux 9 Certification Study Guide* (Jang) covers
auditd configuration and rule syntax. The rule format above follows current
RHEL 9 auditd documentation.

---

## Risk Acceptance Statement

This framework is a visibility tool, not a prevention tool. It improves
the speed at which administrators can detect and investigate operational
problems and security events. It does not prevent attacks, enforce policy,
or respond to incidents automatically.

Organizations that require real-time detection, cross-system correlation,
or automated response should implement this framework as a supplement to,
not a replacement for, appropriate security infrastructure.

The value of this framework is proportional to how consistently and
promptly its output is reviewed. A report that is generated but not read
provides no operational benefit.