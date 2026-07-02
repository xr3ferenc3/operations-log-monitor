# Interpreting Reports

## Purpose of This Document

This document is an operational guide for reading and acting on
`ops-log-monitor` report output. It is written for the administrator who
has just received a report - either from a scheduled run, a manual
investigation, or a ticket attachment - and needs to know what to do with
it.

Generating a report is the easy part. Interpreting it correctly, deciding
what deserves escalation, and avoiding both alert fatigue and missed
incidents is where operational judgment matters. This document teaches
that judgment.

---

## Start With the Header, Not the Tables

Every report begins with a status line:

```
**Status:** CRITICAL
**Total Events:** 23 | **CRIT:** 5 | **WARN:** 9
```

Before reading a single event row, answer three questions from the header
alone:

1. **What is the overall status?** NORMAL, WARNING, or CRITICAL. This tells
   you whether you can finish your coffee first or need to act now.
2. **What is the monitoring window?** A report covering 24 hours after a
   long weekend will look different from one covering a quiet Tuesday
   afternoon. Context changes interpretation.
3. **How many CRIT events are there?** A report with 1 CRIT event needs a
   different response than one with 12. Volume itself is a signal.

Do not skip to the event tables before grounding yourself in this summary.
Reading event-by-event without the header context leads to either
under-reacting to a serious pattern or over-reacting to an isolated event.

---

## Reading the Category Summary Table

```
| Category | Total | CRIT | WARN | INFO |
|---|---|---|---|---|
| Authentication | 9 | 2 | 4 | 3 |
| Services | 4 | 1 | 2 | 1 |
```

This table is your triage map. Scan it before reading any category in
detail. Ask:

- **Which category has the most CRIT events?** Start there.
- **Is there a category with zero events?** This is not necessarily good
  news - check whether the module is actually functioning. An
  Authentication category showing zero events on a system with active
  users is more concerning than one showing nine events with two CRIT,
  because it likely means the audit policy is misconfigured rather than
  that nothing happened. Cross-reference against `docs/troubleshooting.md`
  if a category that should have activity shows none.
- **Are CRIT counts clustered in one category or spread across several?**
  A single category with all the CRIT findings often points to one root
  cause (a single compromised account, one failing disk). CRIT findings
  spread across several categories - authentication failures AND privilege
  escalation AND scheduled task creation - is a stronger indicator of an
  active, multi-stage incident rather than isolated unrelated issues.

---

## Severity Levels - What They Actually Mean

The framework assigns three severity levels. Understanding what each one
represents operationally - not just technically - is essential to using
the report correctly.

### CRIT

**Operational meaning:** This requires action before the next scheduled
report run, not "when convenient."

CRIT findings are not necessarily confirmed incidents. Many CRIT findings
turn out to be false positives or expected activity that was not yet added
to an exception list. But every CRIT finding deserves a deliberate decision
- either "I investigated, this is fine, here is why" or "this needs
escalation" - not silence.

If you find yourself routinely ignoring CRIT findings from a specific
source without investigation, that is a signal the threshold or exception
list needs tuning, not a signal to keep ignoring them. See
`docs/customization-guide.md` for threshold and exception adjustment.

### WARN

**Operational meaning:** This deserves review during your normal working
hours, with no immediate action required, but should not be ignored
indefinitely.

WARN findings accumulate. A single WARN finding for an unexpected account
running sudo once is unremarkable. The same account appearing in WARN
findings every day for a week is itself worth investigating, even though
no single day's report would have escalated it to CRIT.

### INFO

**Operational meaning:** This is recorded for completeness and audit trail
purposes. No action is expected.

INFO findings exist primarily for two reasons: to provide a complete record
when a ticket or audit needs the full picture, not just the flagged items,
and to make patterns visible when reviewed in aggregate across multiple
reports even though no single INFO event is independently significant.

Do not spend operational time reviewing INFO findings individually during
routine report review. Use them when investigating a specific incident
where you need full context, or when reviewing a longer time window (weekly
or monthly) where INFO-level patterns become meaningful.

---

## Common Patterns and What They Mean

### Pattern: A service account locked out, followed by no further activity

```
WARN | Logon failure (RemoteInteractive) for 'svc-backup' from 10.0.4.22
WARN | Logon failure (RemoteInteractive) for 'svc-backup' from 10.0.4.22
... (3 more)
CRIT | Account 'svc-backup' was locked out.
```

**Most likely cause:** A scheduled task or service configuration still
references an old password after a credential rotation. The source IP is
internal and consistent across attempts - this is a configuration problem,
not an attack.

**What to check:** Find what runs as `svc-backup` from `10.0.4.22` (check
Scheduled Tasks, IIS application pools, or Windows services configured with
that account) and update its stored credential.

**What would make this look different if it were an attack:** Source IP
changing between attempts, the account also appearing in unexpected logon
type events (interactive console rather than service/batch), or lockouts
across multiple unrelated accounts in the same window (password spraying
rather than one stale credential).

### Pattern: After-hours logon preceded by failures, on an external IP

```
CRIT | After-hours RemoteInteractive logon for 'mreyes' from 203.0.113.44
      - PRECEDED BY FAILURES IN THIS WINDOW
```

**Most likely cause:** Either a legitimate but poorly-documented after-
hours access (the user forgot their password and tried a few times before
succeeding from home), or a credential compromise where an attacker
guessed or obtained the password and is now using it.

**What to check first:** Contact the account owner directly - not via
email, which the attacker could also access if compromised - and ask if
they logged on at that time from that location. This single question
resolves most instances of this pattern quickly.

**If the account owner did not log on:** Treat as a confirmed compromise.
Disable the account immediately, force a password reset, and review what
that account did during the session using the Privilege and ScheduledTasks
sections of subsequent reports, plus a manual Event Viewer review for the
full session activity.

### Pattern: SeDebugPrivilege used by an unexpected process or account

```
CRIT | HIGH-RISK PRIVILEGE USE: 'CORP\mreyes' exercised SeDebugPrivilege
      via process 'powershell.exe'
```

**Most likely cause:** This is one of the findings that should rarely have
an innocent explanation. SeDebugPrivilege grants the ability to read and
write the memory of any process on the system, including `lsass.exe`,
where Windows caches authentication material. Legitimate uses are narrow:
debugging tools, certain backup software, and specific administrative
utilities.

**What to check:** What was `powershell.exe` actually doing at that
timestamp? Check PowerShell transcript logs if enabled, or the
ScheduledTasks and Services sections of the same report for related
activity at a similar time. Treat this as a probable credential-dumping
attempt (tools like Mimikatz require this exact privilege) until proven
otherwise.

**This is one of the few findings in this framework that warrants
immediate escalation even before full investigation is complete.**

### Pattern: A new SELinux AVC denial appears after a package update

```
WARN | SELinux denied 'httpd' [system_u:system_r:httpd_t:s0] permission
      'read' on file object [unconfined_u:object_r:admin_home_t:s0]
```

**Most likely cause:** A file was placed in a location with an SELinux
context that does not match what the service's policy expects - commonly
after manually copying files into a web root rather than using a package
manager or `restorecon`.

**What to check:** Run `restorecon -Rv /path/to/affected/directory` to
restore the expected SELinux context, then confirm the denial does not
recur in the next report. If the file legitimately needs a non-default
context (uncommon but possible), use `semanage fcontext` to define a
persistent rule rather than repeatedly running `restorecon`.

**When this pattern is more concerning:** If the source process (`comm`)
is not one you recognize, or if the target context is something sensitive
like `shadow_t` or `passwd_file_t`, this could indicate an exploitation
attempt being blocked by SELinux rather than a benign policy gap. The
`permissive=0` flag confirms SELinux actively blocked the action - if it
were `permissive=1`, the action was allowed and logged only, which is a
different and more urgent situation if that process should not have been
able to perform that action at all.

### Pattern: A sudoers file modification

```
CRIT | Modification detected to /etc/sudoers or /etc/sudoers.d/ by
      'mreyes' (syscall 2). This change must be verified against an
      approved change request immediately.
```

**This finding should never be dismissed without verification, regardless
of who made the change.** Sudoers modifications are one of the most direct
paths to privilege escalation persistence on a Linux system. Even when made
by a legitimate administrator, sudoers changes should go through change
management.

**What to check:** Compare against your change management system for a
matching approved request. If found, document the correlation and close
as expected. If not found, treat as an unauthorized change: review the
current contents of `/etc/sudoers` and `/etc/sudoers.d/` immediately for
unexpected grants, and investigate how the modifying account gained the
access needed to make this change in the first place.

---

## What a Clean Report Looks Like

```
**Status:** NORMAL
**Total Events:** 6 | **CRIT:** 0 | **WARN:** 0

| Category | Total | CRIT | WARN | INFO |
|---|---|---|---|---|
| Authentication | 4 | 0 | 0 | 4 |
| Services | 0 | 0 | 0 | 0 |
| Privilege | 2 | 0 | 0 | 2 |
| SystemHealth | 0 | 0 | 0 | 0 |
| ScheduledTasks | 0 | 0 | 0 | 0 |
```

A NORMAL status with low INFO-only event counts in Authentication and
Privilege, and zero events elsewhere, is what a quiet, healthy day looks
like on a well-managed system. Do not interpret an empty report as the
tool malfunctioning - confirm via the Execution Notes section (if present)
that no module errors occurred, and otherwise accept that nothing
noteworthy happened.

A report with zero events across every single category, every single day,
indefinitely, is itself worth periodic verification - confirm audit policy
and auditd rules remain correctly configured, since a silently broken
detection pipeline produces the same "clean" report as a genuinely quiet
system. See `docs/troubleshooting.md` for verification steps.

---

## Building a Review Rhythm

A report that is generated but never reviewed provides no operational
value. The following rhythm is a reasonable starting point for most
environments; adjust based on your organization's risk tolerance and team
size.

**Daily (5–10 minutes per system):**
Review the status header and category summary table. Investigate any CRIT
finding the same day. Note WARN findings but defer detailed review unless
a pattern is already apparent.

**Weekly (30 minutes per system or system group):**
Generate or review a 7-day window report (see `docs/scheduling-guide.md`
for how to run an ad hoc longer-window report). Look for WARN findings
that recurred across multiple days - these often reveal slow-developing
issues that no single day's CRIT threshold would catch.

**Monthly:**
Review the `EXPECTED_ADMIN_ACCOUNTS`, `EXPECTED_SUDO_USERS`, and similar
exception lists in the configuration files. Accounts change roles, leave
the organization, or have their access revoked - these lists need to stay
current or the severity classification logic degrades over time. Cross-
reference against `checklists/daily-review-checklist.md` and your
organization's account review process.

---

## When to Escalate Beyond This Framework

This framework is a visibility tool, not an incident response platform.
Escalate to your organization's formal incident response process when:

- A CRIT finding is confirmed (not just flagged) as unauthorized activity
- Multiple CRIT findings across categories appear correlated in time,
  suggesting a multi-stage incident in progress
- Evidence of log tampering appears (Event ID 1102 on Windows, gaps in
  journald boot history on Linux) - see `docs/threat-model.md` for the
  limitations this framework has against an attacker with log-clearing
  access
- You are uncertain whether a finding represents a genuine incident and
  the uncertainty itself carries meaningful risk if wrong

This framework is designed to get you to the right question quickly. It is
not designed to answer every question on its own.