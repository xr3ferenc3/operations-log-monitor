# operations-log-monitor
Operations Log Monitor - Collection, Parsing, and Operational Summary Framework, Collects, normalize, and summarize operational log data from Windows Event Logs and Linux system journals into structured daily/weekly summaries that administrators can act on without a SIEM.


ops-log-monitor/
│
├── README.md
├── CHANGELOG.md
├── LICENSE
├── .gitignore
│
├── windows/
│   ├── Invoke-LogMonitor.ps1
│   ├── modules/
│   │   ├── Get-AuthenticationEvents.ps1
│   │   ├── Get-ServiceEvents.ps1
│   │   ├── Get-PrivilegeEvents.ps1
│   │   ├── Get-SystemHealthEvents.ps1
│   │   └── Get-ScheduledTaskEvents.ps1
│   └── config/
│       └── windows-monitor.conf.ps1
│
├── linux/
│   ├── log-monitor.sh
│   ├── modules/
│   │   ├── auth-events.sh
│   │   ├── service-events.sh
│   │   ├── privilege-events.sh
│   │   ├── system-health-events.sh
│   │   └── kernel-events.sh
│   └── config/
│       └── linux-monitor.conf
│
├── output/
│   ├── sample-windows-report.md
│   ├── sample-windows-report.json
│   ├── sample-linux-report.md
│   └── sample-linux-report.json
│
├── docs/
│   ├── architecture.md
│   ├── windows-event-ids.md
│   ├── linux-log-sources.md
│   ├── interpreting-reports.md
│   ├── customization-guide.md
│   ├── scheduling-guide.md
│   ├── threat-model.md
│   ├── command-reference.md
│   └── troubleshooting.md
│
├── checklists/
│   ├── daily-review-checklist.md
│   └── incident-escalation-checklist.md
│
└── tests/
    ├── test-windows-modules.ps1
    └── test-linux-modules.sh