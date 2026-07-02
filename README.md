# ops-log-monitor

A cross-platform operational log monitoring framework for Windows Server
2022 and Red Hat Enterprise Linux 9. Extracts operationally significant
events from native log sources - Windows Event Logs, systemd-journald,
and auditd - and produces structured daily reports in Markdown and JSON
format suitable for attaching to helpdesk tickets, audits, and
documentation systems.

No external agents. No commercial tooling. No cloud infrastructure.
Every component uses capabilities that ship with the operating system.

---

## What Problem This Solves

Every Windows Server and RHEL system generates continuous log data
containing early warning of authentication attacks, service failures,
privilege abuse, and hardware degradation. The information is there by
default. The problem is volume: a busy server generates thousands of
entries per day. No administrator reviews raw logs daily in a production
environment.

This framework extracts the events that matter most, organizes them into
operational categories, applies configurable severity thresholds, and
produces a report an administrator can review in five minutes rather than
five hours. It occupies the space between raw log review (impractical)
and a full SIEM deployment (expensive and complex).

---

## Monitored Event Categories

| Category | Windows Source | Linux Source |
|---|---|---|
| Authentication | Security log (4625, 4740, 4624) | journald (sshd, PAM), /var/log/secure |
| Services | System log (7034, 7000, 7036), Application log (1000, 1001) | journald (systemd), systemctl |
| Privilege | Security log (4672, 4673, 4728, 4732, 4756) | auditd (USER_CMD, USER_AUTH, sudoers_change), journald (sudo) |
| System Health | System log (6008, disk/NTFS/WHEA providers) | journald --dmesg (storage errors, OOM kills, boot gaps) |
| Scheduled Tasks / Kernel | Security log (4698, 4699, 4702) | auditd (AVC denials), journald --dmesg (kernel oops, BUG, panic) |

---

## Sample Report Output

**Status:** CRITICAL
**Hostname:** WEB-PROD-03
**Monitoring Window:** 2026-06-29 07:00:00 to 2026-06-30 07:00:00
**Total Events:** 23 | **CRIT:** 5 | **WARN:** 9

| Category | Total | CRIT | WARN | INFO |
|---|---|---|---|---|
| Authentication | 9 | 2 | 4 | 3 |
| Services | 4 | 1 | 2 | 1 |
| Privilege | 5 | 1 | 3 | 1 |
| SystemHealth | 2 | 1 | 1 | 0 |
| ScheduledTasks | 3 | 0 | 2 | 1 |

See [`output/sample-windows-report.md`](output/sample-windows-report.md)
and [`output/sample-linux-report.md`](output/sample-linux-report.md) for
complete report examples from both platforms.

---

## Repository Structure

```
ops-log-monitor/
├── windows/
│   ├── Invoke-LogMonitor.ps1          # Orchestrator - main entry point
│   ├── modules/
│   │   ├── Get-AuthenticationEvents.ps1
│   │   ├── Get-ServiceEvents.ps1
│   │   ├── Get-PrivilegeEvents.ps1
│   │   ├── Get-SystemHealthEvents.ps1
│   │   └── Get-ScheduledTaskEvents.ps1
│   └── config/
│       └── windows-monitor.conf.ps1   # All tunable parameters
│
├── linux/
│   ├── log-monitor.sh                 # Orchestrator - main entry point
│   ├── modules/
│   │   ├── auth-events.sh
│   │   ├── service-events.sh
│   │   ├── privilege-events.sh
│   │   ├── system-health-events.sh
│   │   └── kernel-events.sh
│   └── config/
│       └── linux-monitor.conf         # All tunable parameters
│
├── output/
│   ├── sample-windows-report.md
│   ├── sample-windows-report.json
│   ├── sample-linux-report.md
│   └── sample-linux-report.json
│
├── docs/
│   ├── architecture.md                # Design rationale and component map
│   ├── threat-model.md                # Detection scope and limitations
│   ├── windows-event-ids.md           # Reference for every monitored Event ID
│   ├── linux-log-sources.md           # Reference for every monitored log source
│   ├── interpreting-reports.md        # Operational guide for reading reports
│   ├── customization-guide.md         # Threshold tuning and module extension
│   ├── scheduling-guide.md            # Task Scheduler, cron, systemd timer setup
│   ├── command-reference.md           # All parameters and common invocations
│   └── troubleshooting.md             # 12 documented failure modes and resolutions
│
├── checklists/
│   ├── daily-review-checklist.md      # Structured daily review procedure
│   └── incident-escalation-checklist.md  # Evidence collection during incidents
│
└── tests/
    ├── test-windows-modules.ps1       # Structural validation, no live data needed
    └── test-linux-modules.sh          # Structural validation, no live data needed
```

---

## Requirements

### Windows

| Requirement | Details |
|---|---|
| Operating System | Windows Server 2022 (also compatible with Windows Server 2019 and Windows 10/11) |
| PowerShell | 5.1 or later (included with Windows Server 2022) |
| Privileges | Local Administrator or Event Log Readers + explicit Security log ACL |
| Audit Policy | Advanced Audit Policy subcategories configured (see Prerequisites) |
| Disk Space | Minimal - reports are text files typically under 100 KB each |

### Linux

| Requirement | Details |
|---|---|
| Operating System | RHEL 9 (also compatible with Rocky Linux 9, AlmaLinux 9, RHEL 8) |
| Shell | Bash 4.0 or later (included with all RHEL 9 installations) |
| Privileges | Root recommended (required for /var/log/audit/audit.log access) |
| systemd-journald | Must be running; persistent storage recommended |
| auditd | Required for full Privilege and Kernel module coverage |
| SELinux | Enforcing or Permissive for AVC denial detection |

---

## Quick Start

### Windows

```powershell
# 1. Clone the repository
git clone https://github.com/YOUR-USERNAME/ops-log-monitor.git
cd ops-log-monitor

# 2. Verify audit policy is configured (see Prerequisites section below)
auditpol /get /subcategory:"Logon"

# 3. Run your first report (last 24 hours)
.\windows\Invoke-LogMonitor.ps1

# 4. Review the output
Get-ChildItem .\output\reports\ | Sort-Object LastWriteTime -Descending | Select-Object -First 2
```

### Linux

```bash
# 1. Clone the repository
git clone https://github.com/YOUR-USERNAME/ops-log-monitor.git
cd ops-log-monitor

# 2. Verify prerequisites
systemctl status auditd
getenforce

# 3. Run your first report (last 24 hours)
sudo bash linux/log-monitor.sh

# 4. Review the output
ls -lt output/reports/ | head -5
```

---

## Prerequisites

### Windows: Audit Policy

The Security event log only contains events that audit policy is
configured to generate. Without the correct subcategories enabled, modules
will return empty results for those event types rather than producing
errors. Verify and configure from an elevated PowerShell session:

```powershell
# Verify current settings
auditpol /get /category:*

# Configure required subcategories
auditpol /set /subcategory:"Logon"                      /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management"    /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management"  /success:enable /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use"    /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon"              /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

See [`docs/windows-event-ids.md`](docs/windows-event-ids.md) for the
specific event IDs each subcategory enables and why each one matters.
See [`docs/threat-model.md`](docs/threat-model.md) for the full audit
policy requirement table.

### Linux: auditd Rules

The Privilege module relies on auditd rules to capture sudo and su
executions at the kernel audit level. Without these rules, the module
falls back to journald with reduced detail (no working directory, no
hex-decoded argument capture). Load the required rules as root:

```bash
cat > /etc/audit/rules.d/ops-log-monitor.rules <<'EOF'
# Monitor sudo executions
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k sudo_exec
-a always,exit -F arch=b32 -S execve -F path=/usr/bin/sudo -k sudo_exec

# Monitor su executions
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/su -k su_exec
-a always,exit -F arch=b32 -S execve -F path=/usr/bin/su -k su_exec

# Monitor sudoers modifications
-w /etc/sudoers    -p wa -k sudoers_change
-w /etc/sudoers.d/ -p wa -k sudoers_change
EOF

augenrules --load
auditctl -l | grep -E "sudo_exec|su_exec|sudoers_change"
```

### Linux: journald Persistent Storage

```bash
# Enable persistent journal storage if not already active
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal
systemctl restart systemd-journald

# Verify
journalctl --disk-usage
```

---

## Configuration

All tunable parameters live in the configuration files - the module and
orchestrator scripts do not need to be modified for routine customization.

**Windows:** `windows/config/windows-monitor.conf.ps1`
**Linux:** `linux/config/linux-monitor.conf`

Key parameters:

| Parameter | Default | Purpose |
|---|---|---|
| `MONITORING_WINDOW_HOURS` | 24 | Hours of log history to cover per run |
| `AUTH_FAILURE_WARN_THRESHOLD` | 5 (Win) / 10 (Lin) | Failures before WARN |
| `AUTH_FAILURE_CRIT_THRESHOLD` | 20 (Win) / 50 (Lin) | Failures before CRIT |
| `EXPECTED_ADMIN_ACCOUNTS` | Administrator, admin | Accounts expected to hold admin privileges |
| `EXPECTED_SUDO_USERS` | root | Accounts expected to use sudo |
| `BUSINESS_HOURS_START` | 7 | Start of business day for after-hours detection |
| `BUSINESS_HOURS_END` | 19 | End of business day for after-hours detection |
| `OUTPUT_FORMATS` | both | Markdown, JSON, or both |
| `MODULE_*_ENABLED` | true | Enable/disable individual detection categories |

To customize without touching tracked files:

```powershell
# Windows
Copy-Item windows\config\windows-monitor.conf.ps1 `
          windows\config\windows-monitor.conf.local.ps1
# Edit the .local copy - it is automatically preferred if it exists
```

```bash
# Linux
cp linux/config/linux-monitor.conf linux/config/linux-monitor.conf.local
# Edit the .local copy - automatically preferred if it exists
```

See [`docs/customization-guide.md`](docs/customization-guide.md) for
threshold tuning guidance, expected account list maintenance, and worked
examples for adding new detection modules.

---

## Scheduling Automated Reports

### Windows: Task Scheduler

```powershell
# Run as Administrator - creates a daily 07:00 scheduled task running as SYSTEM
$action   = New-ScheduledTaskAction -Execute "powershell.exe" `
              -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$((Resolve-Path '.\windows\Invoke-LogMonitor.ps1').Path)`" -Quiet" `
              -WorkingDirectory ((Resolve-Path '.\windows').Path)
$trigger  = New-ScheduledTaskTrigger -Daily -At "07:00"
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "ops-log-monitor-daily" `
    -Action $action -Trigger $trigger -Settings $settings -Principal $principal
```

### Linux: systemd Timer (Recommended)

```bash
sudo tee /etc/systemd/system/ops-log-monitor.service > /dev/null <<'EOF'
[Unit]
Description=ops-log-monitor daily report generation

[Service]
Type=oneshot
ExecStart=/opt/ops-log-monitor/linux/log-monitor.sh --quiet
User=root
EOF

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

sudo systemctl daemon-reload
sudo systemctl enable --now ops-log-monitor.timer
systemctl list-timers ops-log-monitor.timer
```

See [`docs/scheduling-guide.md`](docs/scheduling-guide.md) for complete
scheduling instructions including cron, run-as account guidance, and
verification steps.

---

## Running the Tests

```powershell
# Windows - no elevated privileges required
.\tests\test-windows-modules.ps1
```

```bash
# Linux - no root privileges required
bash tests/test-linux-modules.sh
```

Both test suites run against a synthetic far-past time window and do not
require live event log data. They validate module structure, output schema
consistency, and critical helper function correctness.

---

## Documentation

| Document | Purpose |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Design rationale, component map, data flow |
| [`docs/threat-model.md`](docs/threat-model.md) | Detection scope, limitations, audit policy requirements |
| [`docs/windows-event-ids.md`](docs/windows-event-ids.md) | Every monitored Event ID: what triggers it, benign vs. suspicious |
| [`docs/linux-log-sources.md`](docs/linux-log-sources.md) | Every monitored log source: location, format, prerequisites |
| [`docs/interpreting-reports.md`](docs/interpreting-reports.md) | How to read and act on report output operationally |
| [`docs/customization-guide.md`](docs/customization-guide.md) | Threshold tuning, exception lists, adding new modules |
| [`docs/scheduling-guide.md`](docs/scheduling-guide.md) | Task Scheduler, cron, systemd timer configuration |
| [`docs/command-reference.md`](docs/command-reference.md) | All parameters, arguments, and common invocations |
| [`docs/troubleshooting.md`](docs/troubleshooting.md) | 12 documented failure modes with diagnosis and resolution |

---

## Severity Levels

| Level | Operational Meaning |
|---|---|
| `CRIT` | Requires action before the next scheduled report run |
| `WARN` | Review during normal working hours; do not ignore indefinitely |
| `INFO` | Recorded for completeness; no action expected |

Exit codes match severity for integration with Task Scheduler and
monitoring systems: `0` = NORMAL, `1` = WARNING, `2` = CRITICAL.

---

## Design Decisions

**No external dependencies.** Every component uses PowerShell 5.1 and
Bash 4.0 - available on every target platform with no installation steps.
Tools that require installation create deployment barriers that reduce
actual use.

**Separate implementations per platform.** Windows Event Log and Linux
journald/auditd have different architectures, query models, and data
formats. A unified abstraction layer would require a lowest-common-
denominator design that does both poorly. Separate implementations done
well demonstrate deeper platform knowledge than a wrapper done
superficially.

**Modular collection, centralized rendering.** Modules collect and return
structured data. The orchestrator renders reports. This separation means
output formats can change without touching collection logic, and modules
can be tested independently of report rendering.

**Configuration separated from logic.** All tunable parameters - thresholds,
expected accounts, business hours, output paths - live in configuration
files. No script modification is required for routine customization.

**Dual output formats.** Markdown for immediate human readability (attach
to a ticket, paste into a wiki). JSON for machine readability (parse with
a downstream script, populate a dashboard). Both produced on every run.

See [`docs/architecture.md`](docs/architecture.md) for the full design
rationale.

---

## What This Is Not

This framework is not a SIEM. It does not correlate events across multiple
systems, provide real-time alerting, or replace audit logging
infrastructure. It is a structured summary layer on top of logs that
already exist on every server. Its value is in making those logs
reviewable by a human administrator in a reasonable amount of time.

See [`docs/threat-model.md`](docs/threat-model.md) for a complete
description of detection capabilities and their boundaries.

---

## License

MIT - see [`LICENSE`](LICENSE)

---

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md) for version history.