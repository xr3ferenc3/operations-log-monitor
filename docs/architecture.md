# Architecture

## Purpose of This Document

This document explains how `ops-log-monitor` is designed, why it is designed
that way, and how its components fit together. It is written for administrators
who want to understand the framework before using it, extending it, or
adapting it for their own environment.

Understanding the architecture helps you:

- Trust what the reports tell you and understand their limitations
- Modify thresholds and modules with confidence
- Troubleshoot failures at the right layer
- Extend the framework without breaking existing functionality

---

## The Problem This Framework Solves

Every Windows Server and RHEL system generates continuous log data. The
information needed to detect authentication attacks, service failures,
privilege abuse, and hardware problems is present in those logs by default.
No additional agents or commercial tools are required to collect it.

The problem is volume and format. A busy server can generate thousands of
event log entries or journal lines per day. No administrator reviews raw logs
daily in a production environment. The signal is buried in noise.

The conventional solution is a SIEM - a Security Information and Event
Management platform that aggregates, correlates, and alerts on log data.
SIEMs are effective but require dedicated infrastructure, licensing, ongoing
tuning, and specialized knowledge to operate. They are out of reach for many
environments and out of scope for individual server administration.

This framework occupies the space between raw log review (impractical) and
a full SIEM deployment (expensive and complex). It extracts the events that
matter most from each platform's native log sources, organizes them into
operational categories, and produces a structured summary that an
administrator can review in minutes rather than hours.

---

## Design Principles

### Native tooling only

Every component uses tooling that ships with the operating system. PowerShell
5.1 is present on every Windows Server 2022 installation. Bash 4.0, journalctl,
and ausearch are present on every RHEL 9 installation. No additional software
is required to run this framework.

This is an operational decision, not a philosophical one. Tools that require
installation create deployment barriers. In a real environment, getting
approval to install third-party software on production servers takes time and
sometimes never happens. Tools that work out of the box get used.

### Separate implementations for each platform

Windows and Linux have fundamentally different logging architectures.

Windows uses a structured binary Event Log system. Events have numeric IDs,
defined providers, structured XML payloads, and are queryable using .NET
classes and PowerShell cmdlets. The query model is built around event IDs and
log channel names.

Linux logging is more heterogeneous. systemd-journald provides structured
binary journal data queryable via journalctl. The audit subsystem writes to
/var/log/audit/audit.log in its own structured text format. Traditional
syslog-style logs in /var/log/ use unstructured text. Different distributions
use different log file locations for the same events.

Forcing these two architectures into a unified interface would require either
accepting a lowest-common-denominator design that does both poorly, or
building an abstraction layer that obscures the operational logic and makes
the code harder to understand, trust, and modify.

Separate implementations written well demonstrate deeper platform knowledge
than a unified wrapper written superficially.

### Modular event collection

Each event category is collected by a dedicated module rather than one
monolithic script. This decision has operational consequences:

- A failure in one module does not prevent other modules from running
- A new event category can be added without touching existing modules
- Each module can be tested independently
- An administrator can disable a specific module without modifying script logic

### Structured output in two formats

Every report is produced in both Markdown and JSON.

Markdown is optimized for human consumption. An administrator can read it in
a terminal, attach it to a helpdesk ticket, paste it into a wiki, or email it
to a manager without any transformation.

JSON is optimized for machine consumption. A downstream script can parse it
to extract specific fields, populate a dashboard, or trigger an alert. The
JSON structure is consistent across runs so that parsers do not break when
report content changes.

### Configuration separated from logic

All tunable parameters live in configuration files, not in the scripts.
Thresholds, output paths, business hours, and module enable/disable flags are
all defined in the config files. This means an administrator can adapt the
framework to their environment without modifying or understanding the script
logic.

The config files are the only files most administrators will ever need to edit.

---

## Component Map

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Administrator                                │
│                                                                     │
│   Runs Invoke-LogMonitor.ps1        Runs log-monitor.sh             │
│   (Windows)                         (Linux)                         │
└───────────────────┬─────────────────────────┬───────────────────────┘
                    │                         │
                    ▼                         ▼
┌───────────────────────────┐   ┌─────────────────────────────────┐
│  windows-monitor.conf.ps1 │   │      linux-monitor.conf         │
│  (Configuration)          │   │      (Configuration)            │
└───────────┬───────────────┘   └──────────────┬──────────────────┘
            │                                  │
            ▼                                  ▼
┌───────────────────────────┐   ┌─────────────────────────────────┐
│   Invoke-LogMonitor.ps1   │   │        log-monitor.sh           │
│   (Orchestrator)          │   │        (Orchestrator)           │
└───────────┬───────────────┘   └──────────────┬──────────────────┘
            │                                  │
            │  loads and calls                 │  sources and calls
            ▼                                  ▼
┌───────────────────────────┐   ┌─────────────────────────────────┐
│  Windows Modules          │   │  Linux Modules                  │
│                           │   │                                 │
│  Get-AuthenticationEvents │   │  auth-events.sh                 │
│  Get-ServiceEvents        │   │  service-events.sh              │
│  Get-PrivilegeEvents      │   │  privilege-events.sh            │
│  Get-SystemHealthEvents   │   │  system-health-events.sh        │
│  Get-ScheduledTaskEvents  │   │  kernel-events.sh               │
└───────────┬───────────────┘   └──────────────┬──────────────────┘
            │                                  │
            │  query                           │  query
            ▼                                  ▼
┌───────────────────────────┐   ┌─────────────────────────────────┐
│  Windows Log Sources      │   │  Linux Log Sources              │
│                           │   │                                 │
│  Security Event Log       │   │  systemd-journald               │
│  System Event Log         │   │  /var/log/audit/audit.log       │
│  Application Event Log    │   │  /var/log/secure                │
│  TaskScheduler/Operational│   │  /var/log/messages              │
└───────────┬───────────────┘   └──────────────┬──────────────────┘
            │                                  │
            │  structured objects              │  structured text
            ▼                                  ▼
┌───────────────────────────────────────────────────────────────────┐
│                      Report Assembler                             │
│              (inside each orchestrator script)                    │
│                                                                   │
│   Collects module output → organizes by category → writes report  │
└───────────────────────────┬───────────────────────────────────────┘
                            │
                            ▼
┌───────────────────────────────────────────────────────────────────┐
│                         Output                                    │
│                                                                   │
│   report-HOSTNAME-YYYYMMDD-HHMMSS.md    (human-readable)          │
│   report-HOSTNAME-YYYYMMDD-HHMMSS.json  (machine-readable)        │
└───────────────────────────────────────────────────────────────────┘
```

---

## Data Flow

### Step 1 - Invocation

The administrator runs the orchestrator script with optional parameters
specifying the time window, output path, and which modules to run.
If no parameters are provided, defaults from the configuration file are used.

### Step 2 - Configuration load

The orchestrator loads the configuration file. Configuration values establish
the operating context for the entire run: time window boundaries, output
directory, business hours definition, and per-module enable/disable flags.

### Step 3 - Module execution

The orchestrator calls each enabled module in sequence. Each module is
responsible for exactly one event category. Modules query their respective
log sources, apply category-specific filtering, and return structured data
to the orchestrator.

Modules do not write output directly. They return data. This separation means
the output format can change without touching the modules, and modules can be
tested independently of the report format.

### Step 4 - Report assembly

The orchestrator collects all module output and passes it to the report
assembly section. The report assembler organizes the data into sections,
calculates summary statistics, applies severity indicators, and renders the
final report in both Markdown and JSON formats.

### Step 5 - Output

Reports are written to the configured output directory with filenames
that include the hostname and a timestamp. This naming convention means
reports from multiple runs accumulate without overwriting each other and
can be sorted chronologically by filename.

---

## Event Category Design

The five event categories monitored by each platform were chosen to cover
the most operationally significant classes of events that occur regularly
on production systems.

| Category | What It Covers | Why It Matters |
|---|---|---|
| Authentication | Logon failures, lockouts, after-hours access | Credential attacks, account abuse, unauthorized access |
| Services | Service failures, unexpected state changes | Application health, reliability, availability |
| Privilege | Privilege assignment, admin group changes, sudo use | Privilege escalation, insider threat, change audit |
| System Health | Disk errors, crashes, unexpected shutdowns | Hardware failure early warning, stability |
| Scheduled Tasks / Kernel | Task creation/deletion (Windows), kernel errors and SELinux denials (Linux) | Persistence detection, kernel stability, policy violations |

These categories are not exhaustive. They represent the events most likely
to require administrative attention in a typical week. The customization
guide explains how to add additional categories.

---

## Report Structure

Both the Markdown and JSON reports follow the same logical structure:

```
Report Header
├── Hostname
├── Report generated timestamp
├── Time window covered
└── Summary (total events by category and severity)

Authentication Section
├── Summary statistics
└── Event table (time, source, description, severity)

Services Section
├── Summary statistics
└── Event table

Privilege Section
├── Summary statistics
└── Event table

System Health Section
├── Summary statistics
└── Event table

Scheduled Tasks / Kernel Section
├── Summary statistics
└── Event table

Footer
├── Script version
└── Configuration file used
```

The JSON output mirrors this structure as nested objects, making it
straightforward to extract any section programmatically.

---

## Severity Levels

Each event is assigned one of three severity levels by the module that
collects it.

| Level | Meaning | Example |
|---|---|---|
| `INFO` | Expected or low-significance event worth recording | Successful logon during business hours |
| `WARN` | Unusual event that warrants review but is not necessarily a problem | Three consecutive logon failures from one account |
| `CRIT` | Event that requires prompt administrative attention | Account lockout, service crash, SELinux denial |

Severity levels are determined by the module logic and the thresholds defined
in the configuration file. Changing a threshold changes which level an event
is assigned. This allows the framework to be tuned to the noise level of a
specific environment without modifying script logic.

---

## Extending the Framework

### Adding a new Windows module

1. Create a new file in `windows/modules/` named `Get-<CategoryName>Events.ps1`
2. Follow the same function signature and return object structure as existing
   modules (documented in `docs/customization-guide.md`)
3. Add an enable/disable flag for the new module in `windows-monitor.conf.ps1`
4. Add a call to the new module in the module execution section of
   `Invoke-LogMonitor.ps1`
5. Add a section handler in the report assembly section of
   `Invoke-LogMonitor.ps1`

### Adding a new Linux module

1. Create a new file in `linux/modules/` named `<category>-events.sh`
2. Follow the same output structure as existing modules
3. Add an enable/disable flag in `linux-monitor.conf`
4. Add a source and call in `log-monitor.sh`
5. Add a section handler in the report assembly section of `log-monitor.sh`

The `docs/customization-guide.md` provides complete worked examples for both
platforms.

---

## What This Framework Is Not

This framework is not a SIEM. It does not:

- Correlate events across multiple systems
- Provide real-time alerting
- Store historical event data beyond what the OS retains in its logs
- Detect sophisticated multi-stage attacks that require cross-system correlation
- Replace audit logging infrastructure

It is a structured summary layer on top of the logs that already exist on
every server. Its value is in making those logs reviewable by a human
administrator in a reasonable amount of time, and in producing output that
can be attached to tickets, audits, and incident reports.

The `docs/threat-model.md` describes the detection capabilities and
limitations in operational detail.

---

## Source Material

The event category selections and log source references in this framework
draw from the following:

- *Mastering Windows Server 2022* by Jordan Krause - Windows Event Log
  architecture, audit policy configuration, and Security log event categories
- *RHCSA Red Hat Enterprise Linux 9 Certification Study Guide* by Michael J.
  Jang - journald configuration, auditd architecture, SELinux audit logging,
  and systemd unit management
- Current Microsoft documentation for Windows Security auditing event IDs,
  supplementing the book where event ID coverage is incomplete
- Current Red Hat documentation for RHEL 9 journald and auditd configuration,
  supplementing the book where log path and format details differ from earlier
  RHEL versions