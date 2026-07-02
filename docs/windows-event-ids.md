# Windows Event ID Reference

## Purpose of This Document

This document explains every Windows Event ID monitored by
`ops-log-monitor`. For each event it covers:

- What triggers the event
- What the event means operationally
- What a benign instance looks like
- What a suspicious instance looks like
- How the framework uses the event in its report
- What audit policy subcategory must be enabled to generate the event

This document is intended as a reference for administrators who want to
understand why a specific event appears in a report and what to do with it.
It is also useful when investigating alerts and when explaining findings to
non-technical stakeholders.

---

## Prerequisites

All events described in this document require Advanced Audit Policy to be
configured correctly. The `docs/threat-model.md` lists the required
subcategories. Events that are not enabled in audit policy will not appear
in the event log regardless of what activity occurs on the system.

To verify that a specific subcategory is enabled:

```powershell
auditpol /get /subcategory:"Logon"
auditpol /get /subcategory:"User Account Management"
```

If the setting shows **No Auditing**, the event log will contain no events
for that subcategory.

---

## Authentication Events

---

### Event ID 4624 - An account was successfully logged on

**Log:** Security
**Audit subcategory:** Logon/Logoff → Audit Logon → Success

**What triggers it:**
Generated every time an account successfully authenticates to the local
system. This includes interactive logons at the console, remote desktop
sessions, network logons (file share access), service logons, and batch
logons (scheduled tasks).

**Logon types included in this event:**

| Logon Type | Description |
|---|---|
| 2 | Interactive (console) |
| 3 | Network (file share, mapped drive) |
| 4 | Batch (scheduled task) |
| 5 | Service (service account startup) |
| 7 | Unlock (screen unlock) |
| 10 | RemoteInteractive (Remote Desktop) |
| 11 | CachedInteractive (cached credentials) |

**What a benign instance looks like:**
Type 10 (Remote Desktop) logon for a known administrator account during
business hours from a known IP address. Type 5 service logons for service
accounts during system startup.

**What a suspicious instance looks like:**
Any logon type for a known account occurring outside business hours without
a prior change request. A Type 10 logon from an IP address not associated
with the administrator's known workstations. A successful Type 3 logon
immediately following multiple Event ID 4625 failures for the same account
(possible successful brute force).

**How the framework uses it:**
The framework does not report every 4624 event. It uses 4624 selectively:
to identify successful logons that follow a series of 4625 failures for
the same account within the monitoring window, and to identify logons
outside defined business hours for interactive logon types (2 and 10).

---

### Event ID 4625 - An account failed to log on

**Log:** Security
**Audit subcategory:** Logon/Logoff → Audit Logon → Failure

**What triggers it:**
Generated every time an authentication attempt fails. The event includes
the account name that was attempted, the source workstation name, the
source IP address, the logon type, and a failure reason code.

**Common failure reason codes:**

| Code | Meaning |
|---|---|
| 0xC000006A | Incorrect password for valid account |
| 0xC0000064 | Account name does not exist |
| 0xC000006D | Generic logon failure |
| 0xC000006F | Account restricted by logon hours |
| 0xC0000070 | Account restricted to specific workstations |
| 0xC0000071 | Password has expired |
| 0xC0000072 | Account disabled |
| 0xC0000234 | Account locked out |

**What a benign instance looks like:**
A single 4625 event for a user account with reason code 0xC000006A followed
by a successful 4624 shortly after - the user mistyped their password once.
A 4625 with reason code 0xC0000064 for an account name that does not exist -
a user typed the wrong username.

**What a suspicious instance looks like:**
Multiple 4625 events in rapid succession against the same account from the
same source IP - automated brute force attempt. Multiple 4625 events
against different account names from the same source IP - username
enumeration followed by password spraying. Any 4625 events against
administrative account names (Administrator, admin, sysadmin) from
external IP addresses.

**How the framework uses it:**
The framework counts 4625 events per account and per source IP within the
monitoring window. Counts exceeding the configured threshold are reported
as WARN. Accounts that are subsequently locked out (4740) after repeated
failures are reported as CRIT.

---

### Event ID 4740 - A user account was locked out

**Log:** Security
**Audit subcategory:** Account Management → Audit User Account Management → Success

**What triggers it:**
Generated when an account is locked out due to exceeding the bad password
threshold defined in the account lockout policy. The event identifies the
locked account, the system that observed the bad password attempts, and
the caller that enforced the lockout.

**What a benign instance looks like:**
A single lockout for a user account after the user entered their password
incorrectly several times - common after password changes or when a user
has an old password cached on a mobile device or mapped drive.

**What a suspicious instance looks like:**
Multiple lockout events for multiple different accounts within a short
window - password spraying attack. A lockout event for an administrative
account - targeted attack against a privileged account. A lockout that
the user has no knowledge of - could indicate an automated attack
running with their credentials.

**How the framework uses it:**
Every 4740 event is reported as CRIT regardless of volume. Account lockouts
always require administrative review to determine whether they are caused
by user error, a stale credential, or an active attack.

---

## Privilege Events

---

### Event ID 4672 - Special privileges assigned to new logon

**Log:** Security
**Audit subcategory:** Privilege Use → Audit Special Logon → Success

**What triggers it:**
Generated every time an account logs on with one or more sensitive or
administrative privileges. The event lists which privileges were assigned.
Common privileges that trigger this event include SeDebugPrivilege,
SeBackupPrivilege, SeTakeOwnershipPrivilege, and SeSecurityPrivilege.
Any account in the local Administrators group will generate this event
at every logon.

**What a benign instance looks like:**
A 4672 event immediately following a 4624 event for a known administrator
account - the administrator logged on normally. SYSTEM and LOCAL SERVICE
accounts generating 4672 at boot - normal system behavior.

**What a suspicious instance looks like:**
A 4672 event for an account that is not expected to hold administrative
privileges - possible privilege escalation. A 4672 event for a service
account that does not require administrative privileges to operate -
the service may be configured with excessive privilege.

**How the framework uses it:**
The framework reports 4672 events for accounts that are not in a configured
list of expected administrative accounts. Expected administrative accounts
are defined in the configuration file. Any 4672 for an unlisted account
is reported as WARN.

---

### Event ID 4673 - A privileged service was called

**Log:** Security
**Audit subcategory:** Privilege Use → Audit Sensitive Privilege Use → Success and Failure

**What triggers it:**
Generated when a process calls a Windows service that requires a specific
privilege, and the account either holds or is denied that privilege. The
event includes the process name, the account, and the specific privilege
that was exercised or denied.

**What a benign instance looks like:**
Backup software calling SeBackupPrivilege to read files regardless of
NTFS permissions - expected behavior for backup operations.

**What a suspicious instance looks like:**
An unexpected process calling SeDebugPrivilege - SeDebug allows a process
to read and write to the memory of other processes and is used by debugging
tools and by malware that performs process injection. Any process calling
SeTcbPrivilege (act as part of the operating system) from a non-system
context.

**How the framework uses it:**
The framework reports 4673 events for high-risk privileges (SeDebugPrivilege,
SeTcbPrivilege, SeLoadDriverPrivilege) when called by processes that are not
on the configured expected process list. These are reported as WARN or CRIT
depending on the privilege involved.

---

### Event ID 4728 - A member was added to a security-enabled global group

**Log:** Security
**Audit subcategory:** Account Management → Audit Security Group Management → Success

**What triggers it:**
Generated when an account is added to a global security group. On standalone
systems and workgroup servers, the most operationally relevant instance of
this event involves the local Administrators group (which generates 4732,
not 4728 - see below). On domain-joined systems this event covers domain
global groups.

**How the framework uses it:**
Monitored on domain-joined systems. Every group membership addition is
reported as WARN because group membership changes require change management
documentation in most operational environments.

---

### Event ID 4732 - A member was added to a security-enabled local group

**Log:** Security
**Audit subcategory:** Account Management → Audit Security Group Management → Success

**What triggers it:**
Generated when an account is added to a local security group. This is the
event that fires when a user is added to the local Administrators group,
the local Remote Desktop Users group, or any other local group.

**What a benign instance looks like:**
A 4732 event for the Remote Desktop Users group when an administrator
deliberately grants a user remote access, documented in a change request.

**What a suspicious instance looks like:**
A 4732 event for the Administrators group for any account that is not
expected to be an administrator - privilege escalation. A 4732 event that
occurs outside business hours without a corresponding change request.
A 4732 event where the subject account (the account that made the change)
is the same as the member account (the account added) - self-escalation.

**How the framework uses it:**
Every 4732 event involving the local Administrators group or Remote Desktop
Users group is reported as CRIT. Every 4732 event involving any other local
group is reported as WARN.

---

### Event ID 4756 - A member was added to a security-enabled universal group

**Log:** Security
**Audit subcategory:** Account Management → Audit Security Group Management → Success

**What triggers it:**
Generated when an account is added to a universal security group. Relevant
primarily on domain-joined systems. Operationally similar to 4728 and 4732.

**How the framework uses it:**
Monitored and reported as WARN for all instances, consistent with the
approach to 4728 events.

---

## Service Events

---

### Event ID 7000 - The service failed to start

**Log:** System
**Source:** Service Control Manager
**Audit subcategory:** No audit policy required - System log event

**What triggers it:**
Generated during system startup when the Service Control Manager attempts
to start a service and the start attempt fails. The event includes the
service name and a description of the failure reason.

**What a benign instance looks like:**
A service that depends on a network resource failing to start at boot
because the network was not yet available. A service that is configured
to start automatically but whose executable path no longer exists after
a software uninstall.

**What a suspicious instance looks like:**
A previously healthy service failing to start after a system change -
the change may have affected the service's binary or configuration. A
service that never fails to start suddenly failing - possible binary
replacement or permission change.

**How the framework uses it:**
Every 7000 event is reported as WARN. If the same service generates 7000
events in multiple consecutive monitoring windows, the framework reports
it as CRIT and notes the recurrence.

---

### Event ID 7034 - A service terminated unexpectedly

**Log:** System
**Source:** Service Control Manager
**Audit subcategory:** No audit policy required - System log event

**What triggers it:**
Generated when a service that was running stops without being deliberately
stopped by an administrator or the system. The event includes the service
name and the number of times this has happened.

**What a benign instance looks like:**
A service that crashes due to a known bug during a specific operation -
may occur repeatedly until the software is updated.

**What a suspicious instance looks like:**
A security-related service (antivirus, event log service, firewall service)
terminating unexpectedly - possible attempt to disable a defensive control.
Any service termination that cannot be correlated with a known software bug
or recent configuration change.

**How the framework uses it:**
Every 7034 event is reported as WARN. Security-relevant services (defined
in the configuration file) generating 7034 events are reported as CRIT.

---

### Event ID 7036 - A service entered a state

**Log:** System
**Source:** Service Control Manager
**Audit subcategory:** No audit policy required - System log event

**What triggers it:**
Generated every time a service changes state: running to stopped, stopped
to running. This event is extremely common during normal operations. The
framework uses it selectively rather than reporting every instance.

**How the framework uses it:**
The framework does not report every 7036 event. It uses 7036 to identify
services that entered a stopped state without a preceding planned shutdown
event (Event ID 1074) and services that cycled through stopped and running
states multiple times within the monitoring window, which may indicate
a crash loop.

---

## System Health Events

---

### Event ID 6008 - The previous system shutdown was unexpected

**Log:** System
**Source:** EventLog
**Audit subcategory:** No audit policy required - System log event

**What triggers it:**
Generated at boot when Windows determines that the previous shutdown was
not a clean shutdown. This indicates a system crash, power loss, or
forced power-off.

**What a benign instance looks like:**
A 6008 event following a known power outage documented by facilities.

**What a suspicious instance looks like:**
A 6008 event with no corresponding facilities report or known maintenance
window - possible hardware failure, kernel panic, or deliberate forced
shutdown. Repeated 6008 events over multiple monitoring windows - ongoing
hardware instability.

**How the framework uses it:**
Every 6008 event is reported as CRIT. Unexpected shutdowns always require
investigation to determine cause.

---

### Event ID 1000 - Application error

**Log:** Application
**Source:** Application Error
**Audit subcategory:** No audit policy required - Application log event

**What triggers it:**
Generated when an application crashes and the crash is caught by Windows
Error Reporting. The event includes the application name, version,
faulting module, and exception code.

**What a benign instance looks like:**
A known application with a documented bug crashing in a predictable way.

**What a suspicious instance looks like:**
A crash in a security-relevant application (antivirus scanner, event log
service, firewall management service). A crash in a process that does not
normally crash, particularly if it coincides with other suspicious events.
Repeated crashes of the same process with different faulting modules -
possible exploitation attempts causing unstable behavior.

**How the framework uses it:**
The framework reports 1000 events for processes on the configured
security-relevant process list as CRIT. All other 1000 events are
reported as WARN.

---

### Event ID 1001 - Application error (crash dump)

**Log:** Application
**Source:** Windows Error Reporting
**Audit subcategory:** No audit policy required - Application log event

**What triggers it:**
Generated when Windows Error Reporting completes collection of a crash
dump for an application that generated Event ID 1000. Appears alongside
1000 events. Includes the path where the crash dump was saved.

**How the framework uses it:**
Reported alongside the corresponding 1000 event. The crash dump path is
included in the report so investigators know where to find the dump file
for deeper analysis.

---

## Scheduled Task Events

---

### Event ID 4698 - A scheduled task was created

**Log:** Security
**Audit subcategory:** Object Access → Audit Other Object Access Events → Success

**What triggers it:**
Generated when a new scheduled task is created through Task Scheduler,
schtasks.exe, PowerShell, or the COM API. The event includes the task
name, task content (XML), and the account that created it.

**What a benign instance looks like:**
A scheduled task created by a software installer during application setup.
A task created by an administrator to run a maintenance script, documented
in a change request.

**What a suspicious instance looks like:**
A scheduled task created by a non-administrative account. A task that
runs from a temp directory, user profile directory, or other unusual
path. A task whose action is encoded (Base64 PowerShell) or uses
environmental variables to obscure the actual command. A task created
outside business hours by an account that is not expected to create tasks.

**How the framework uses it:**
Every 4698 event is reported as WARN. Tasks created by non-administrative
accounts are reported as CRIT. The task XML content is included in the
report so the administrator can evaluate the action without querying
Task Scheduler separately.

---

### Event ID 4699 - A scheduled task was deleted

**Log:** Security
**Audit subcategory:** Object Access → Audit Other Object Access Events → Success

**What triggers it:**
Generated when a scheduled task is deleted. The event includes the task
name and the account that deleted it.

**What a suspicious instance looks like:**
A scheduled task created recently (appearing in 4698 events in a recent
monitoring window) being deleted shortly after - possible attacker
cleaning up evidence of persistence. A task with an operational name
(backup, maintenance) being deleted without a corresponding change request.

**How the framework uses it:**
Every 4699 event is reported as WARN. The framework notes if the deleted
task was created within the same monitoring window (indicating rapid
creation and deletion) and reports that combination as CRIT.

---

### Event ID 4702 - A scheduled task was updated

**Log:** Security
**Audit subcategory:** Object Access → Audit Other Object Access Events → Success

**What triggers it:**
Generated when an existing scheduled task's properties are modified. The
event includes both the old and new task XML, allowing comparison.

**What a suspicious instance looks like:**
Modification of a long-standing legitimate scheduled task to change its
action, run-as account, or trigger - possible hijacking of an existing
trusted task to execute an attacker-controlled payload.

**How the framework uses it:**
Every 4702 event is reported as WARN. The report includes the task name
and the modifying account so the administrator can cross-reference with
change management records.

---

## Quick Reference Table

| Event ID | Log | Category | Default Severity |
|---|---|---|---|
| 4624 | Security | Authentication | INFO (selective) |
| 4625 | Security | Authentication | WARN / CRIT |
| 4740 | Security | Authentication | CRIT |
| 4672 | Security | Privilege | WARN (unlisted accounts) |
| 4673 | Security | Privilege | WARN / CRIT |
| 4728 | Security | Privilege | WARN |
| 4732 | Security | Privilege | WARN / CRIT |
| 4756 | Security | Privilege | WARN |
| 7000 | System | Services | WARN |
| 7034 | System | Services | WARN / CRIT |
| 7036 | System | Services | INFO (selective) |
| 6008 | System | System Health | CRIT |
| 1000 | Application | System Health | WARN / CRIT |
| 1001 | Application | System Health | WARN |
| 4698 | Security | Scheduled Tasks | WARN / CRIT |
| 4699 | Security | Scheduled Tasks | WARN |
| 4702 | Security | Scheduled Tasks | WARN |

---

## Source Material Notes

Event ID definitions in this document are derived from:

- *Mastering Windows Server 2022* (Krause) - audit policy configuration,
  Security event log architecture, and event category overview
- Current Microsoft documentation at learn.microsoft.com - authoritative
  event ID descriptions, XML schemas, and audit subcategory mappings

Where the book references basic audit policy settings (Account Logon,
Account Management, Logon Events), this document maps those to the
corresponding Advanced Audit Policy subcategories, which is current
best practice. Basic and Advanced audit policy settings should not be
mixed on the same system.

The failure reason codes for Event ID 4625 come from Microsoft's
authentication error documentation, which is more complete than the
coverage in the book.