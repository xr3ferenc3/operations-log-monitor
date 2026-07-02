# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).  
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## Version Numbering Policy

| Component | Meaning |
|---|---|
| Major (X.0.0) | Breaking change to report schema, script interface, or config format |
| Minor (0.X.0) | New event category, new module, new output format, or new platform support |
| Patch (0.0.X) | Bug fix, documentation correction, threshold adjustment, or compatibility fix |

A change is considered breaking if it would require an administrator to modify
an existing scheduled task, cron job, config file, or downstream parser in
order to continue using the tool without interruption.

---

## [1.0.0] - 2025-07-01

### Added

**Project foundation**
- Repository structure, LICENSE, .gitignore, and this CHANGELOG

**Windows implementation**
- `Invoke-LogMonitor.ps1` - main entry point for Windows log monitoring
- `Get-AuthenticationEvents.ps1` - monitors logon failures, lockouts, and
  after-hours logons (Event IDs 4625, 4740, 4624)
- `Get-ServiceEvents.ps1` - monitors service failures and unexpected state
  changes (Event IDs 7034, 7036, 7000)
- `Get-PrivilegeEvents.ps1` - monitors privilege assignment and sensitive
  group membership changes (Event IDs 4672, 4673, 4728, 4732, 4756)
- `Get-SystemHealthEvents.ps1` - monitors disk errors, application crashes,
  and unexpected shutdowns (Event IDs 6008, 1000, 1001)
- `Get-ScheduledTaskEvents.ps1` - monitors scheduled task creation,
  modification, and deletion (Event IDs 4698, 4702, 4699)
- `windows-monitor.conf.ps1` - configurable parameters for the Windows
  implementation

**Linux implementation**
- `log-monitor.sh` - main entry point for Linux log monitoring
- `auth-events.sh` - monitors SSH failures, PAM failures, and failed
  privilege escalation attempts
- `service-events.sh` - monitors systemd unit failures and unexpected
  service state changes
- `privilege-events.sh` - monitors sudo executions and su attempts via
  auditd and journald
- `system-health-events.sh` - monitors disk I/O errors, OOM killer
  invocations, and filesystem errors
- `kernel-events.sh` - monitors kernel warnings, SELinux AVC denials,
  and kernel oops indicators
- `linux-monitor.conf` - configurable parameters for the Linux
  implementation

**Sample outputs**
- `sample-windows-report.md` - representative Markdown report output
- `sample-windows-report.json` - representative JSON report output
- `sample-linux-report.md` - representative Markdown report output
- `sample-linux-report.json` - representative JSON report output

**Documentation**
- `docs/architecture.md` - design rationale and component overview
- `docs/threat-model.md` - what the framework detects and what it does not
- `docs/windows-event-ids.md` - reference for every monitored Event ID
- `docs/linux-log-sources.md` - reference for every monitored log source
- `docs/interpreting-reports.md` - operational guide for reading reports
- `docs/customization-guide.md` - how to modify thresholds and add modules
- `docs/scheduling-guide.md` - how to schedule automated report generation
- `docs/command-reference.md` - complete parameter and usage reference
- `docs/troubleshooting.md` - common failures and their resolutions

**Operational checklists**
- `checklists/daily-review-checklist.md` - structured daily log review
  procedure
- `checklists/incident-escalation-checklist.md` - log evidence collection
  during active incidents

**Tests**
- `tests/test-windows-modules.ps1` - structural validation for Windows
  module output
- `tests/test-linux-modules.sh` - structural validation for Linux module
  output

---

## Unreleased

Nothing currently staged for the next release.

---

## Versioning Notes for Maintainers

When preparing a release:

1. Move all items from **Unreleased** into a new dated version block.
2. Assign the correct semantic version based on the nature of the changes.
3. Update the version number in `README.md` if it is referenced there.
4. Tag the release in Git: