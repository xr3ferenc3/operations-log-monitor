# =============================================================================
# windows-monitor.conf.ps1
# ops-log-monitor - Windows Monitor Configuration
# =============================================================================
#
# PURPOSE:
#   This file defines all configurable parameters for Invoke-LogMonitor.ps1.
#   It is sourced (dot-sourced) by the main script at runtime. Every parameter
#   that an administrator is likely to need to adjust for their environment
#   lives here. The main script logic should never need to be modified for
#   routine customization.
#
# USAGE:
#   This file is not run directly. It is loaded by Invoke-LogMonitor.ps1.
#   To create a site-specific override without modifying this file:
#
#     Copy-Item windows-monitor.conf.ps1 windows-monitor.conf.local.ps1
#     # Edit the local copy
#     # The main script will load the local copy if it exists
#
#   Local override files match the pattern *.conf.local.ps1 and are excluded
#   from version control by .gitignore. This allows site-specific settings
#   to coexist with repository updates.
#
# SECTIONS:
#   1. Output settings
#   2. Monitoring window defaults
#   3. Business hours definition
#   4. Module enable/disable flags
#   5. Authentication thresholds
#   6. Expected administrative accounts
#   7. Security-relevant processes and services
#   8. Event log size verification thresholds
#   9. Report metadata
#
# =============================================================================


# -----------------------------------------------------------------------------
# SECTION 1 - Output Settings
# -----------------------------------------------------------------------------
#
# OUTPUT_DIR: Directory where reports are written. The directory will be
# created if it does not exist. Use an absolute path in production deployments
# to avoid ambiguity about where reports land when the script is run from
# different working directories or by the Task Scheduler.
#
# Relative path (suitable for development and testing):
$OUTPUT_DIR = ".\output\reports"
#
# Absolute path examples for production:
# $OUTPUT_DIR = "C:\Monitoring\Reports"
# $OUTPUT_DIR = "\\fileserver\monitoring$\reports\$env:COMPUTERNAME"

# OUTPUT_FORMATS: Which report formats to generate.
# Valid values: "Markdown", "JSON", "Both"
# "Both" is the default and is recommended for most environments.
# Markdown is human-readable and suitable for tickets and email.
# JSON is machine-readable and suitable for downstream parsing or dashboards.
$OUTPUT_FORMATS = "Both"

# REPORT_FILENAME_PREFIX: Prefix applied to all generated report filenames.
# Reports are named: PREFIX-HOSTNAME-YYYYMMDD-HHMMSS.md / .json
# Changing this prefix helps distinguish reports from different scripts or
# environments if multiple monitoring tools write to the same directory.
$REPORT_FILENAME_PREFIX = "ops-log-monitor"

# LOG_FILE: Path for the script's own execution log. This records what the
# script did, any errors encountered, and execution timing. It is separate
# from the reports the script generates. Useful for troubleshooting when
# a scheduled task is not producing expected output.
$LOG_FILE = ".\logs\windows-monitor.log"

# MAX_LOG_SIZE_MB: Maximum size of the script execution log before it is
# rotated. The previous log is renamed with a .bak extension. Only one
# generation of backup is retained.
$MAX_LOG_SIZE_MB = 10


# -----------------------------------------------------------------------------
# SECTION 2 - Monitoring Window Defaults
# -----------------------------------------------------------------------------
#
# These values define the default time window that reports cover when no
# -StartTime or -EndTime parameter is passed to Invoke-LogMonitor.ps1.
#
# MONITORING_WINDOW_HOURS: Number of hours back from the current time to
# search. The default of 24 hours is appropriate for daily scheduled runs.
# For a weekly summary, set this to 168.
#
# When the script is run on a schedule (e.g., daily at 07:00), this window
# ensures the report covers the previous 24 hours without gaps or overlaps
# between runs.
$MONITORING_WINDOW_HOURS = 24

# MONITORING_WINDOW_MAX_EVENTS: Maximum number of events to retrieve per
# event log query. This limit prevents the script from consuming excessive
# memory on systems with very high log volume. If a category consistently
# hits this limit, consider shortening the monitoring window, increasing
# the limit, or investigating why event volume is so high.
$MONITORING_WINDOW_MAX_EVENTS = 10000


# -----------------------------------------------------------------------------
# SECTION 3 - Business Hours Definition
# -----------------------------------------------------------------------------
#
# Business hours are used to identify authentication events that occur
# outside expected working hours. An interactive logon at 03:00 on a
# Tuesday warrants review even if it is not inherently malicious.
#
# These values apply to the LOCAL time on the monitored system. If your
# environment spans multiple time zones, set ENFORCE_BUSINESS_HOURS to
# $false and perform after-hours review manually.
#
# BUSINESS_HOURS_START: First hour of the business day (24-hour format, 0-23)
$BUSINESS_HOURS_START = 7

# BUSINESS_HOURS_END: Last hour of the business day (24-hour format, 0-23)
# Logons at or after this hour are considered after-hours.
$BUSINESS_HOURS_END = 19

# BUSINESS_DAYS: Days of the week considered working days.
# Uses .NET DayOfWeek enum values: Sunday=0, Monday=1, Tuesday=2,
# Wednesday=3, Thursday=4, Friday=5, Saturday=6
$BUSINESS_DAYS = @(1, 2, 3, 4, 5)  # Monday through Friday

# ENFORCE_BUSINESS_HOURS: Set to $false to disable after-hours detection
# entirely. Useful for environments with 24/7 operations where after-hours
# logons are routine and expected.
$ENFORCE_BUSINESS_HOURS = $true


# -----------------------------------------------------------------------------
# SECTION 4 - Module Enable/Disable Flags
# -----------------------------------------------------------------------------
#
# Each flag controls whether a specific event category module is executed.
# Set to $false to skip a module. Skipped modules produce no output section
# in the report. All modules are enabled by default.
#
# Reasons to disable a module:
#   - The required audit policy is not configured (module will return empty
#     results anyway, but disabling it speeds up execution and avoids
#     misleading empty sections in the report)
#   - The event category generates too much expected noise in your
#     environment and you have decided not to monitor it with this tool
#   - You are testing a specific module in isolation

$MODULE_AUTHENTICATION_ENABLED  = $true
$MODULE_SERVICES_ENABLED        = $true
$MODULE_PRIVILEGE_ENABLED       = $true
$MODULE_SYSTEM_HEALTH_ENABLED   = $true
$MODULE_SCHEDULED_TASKS_ENABLED = $true


# -----------------------------------------------------------------------------
# SECTION 5 - Authentication Thresholds
# -----------------------------------------------------------------------------
#
# These thresholds determine when authentication failure counts are escalated
# from informational to WARN or CRIT severity in the report.
#
# Setting thresholds too low generates noise (every user who mistyped a
# password appears in the report). Setting them too high misses real attacks.
# The defaults below are conservative starting points appropriate for
# environments where password spraying and brute force are realistic threats.
# Adjust based on observed baseline failure rates in your environment.

# AUTH_FAILURE_WARN_THRESHOLD: Number of failures for a single account within
# the monitoring window before the account is reported at WARN severity.
# A user who mistyped their password three times and succeeded is unlikely
# to reach this threshold. An automated attack will.
$AUTH_FAILURE_WARN_THRESHOLD = 5

# AUTH_FAILURE_CRIT_THRESHOLD: Number of failures for a single account before
# the account is reported at CRIT severity. At this level, the volume
# suggests an automated or persistent attack rather than a user error.
$AUTH_FAILURE_CRIT_THRESHOLD = 20

# AUTH_SOURCE_WARN_THRESHOLD: Number of failures originating from a single
# source IP address within the monitoring window before that source is
# reported at WARN severity. A single source generating failures against
# multiple accounts is a password spray indicator.
$AUTH_SOURCE_WARN_THRESHOLD = 10

# AUTH_SOURCE_CRIT_THRESHOLD: Number of failures from a single source before
# that source is reported at CRIT severity.
$AUTH_SOURCE_CRIT_THRESHOLD = 50

# AUTH_MONITOR_LOGON_TYPES: Which logon types are included in authentication
# monitoring. Type 2 (interactive) and Type 10 (RemoteInteractive/RDP) are
# the most operationally significant for detecting unauthorized access.
# Type 3 (network) generates high volume from normal file share access.
# Adjust based on what is meaningful in your environment.
#
# Logon type reference:
#   2  = Interactive (console)
#   3  = Network (file shares, mapped drives)
#   4  = Batch (scheduled tasks)
#   5  = Service (service startup)
#   7  = Unlock
#   10 = RemoteInteractive (RDP)
#   11 = CachedInteractive
$AUTH_MONITOR_LOGON_TYPES = @(2, 3, 10)


# -----------------------------------------------------------------------------
# SECTION 6 - Expected Administrative Accounts
# -----------------------------------------------------------------------------
#
# EXPECTED_ADMIN_ACCOUNTS: List of account names that are expected to hold
# administrative privileges on this system. Accounts in this list that
# generate Event ID 4672 (special privileges assigned at logon) are reported
# at INFO severity. Accounts NOT in this list that generate 4672 are reported
# at WARN severity because they hold unexpected administrative privileges.
#
# This list should include:
#   - The built-in Administrator account (even if renamed - use the actual
#     current name)
#   - Named administrator accounts for individuals who legitimately
#     administer this system
#   - Service accounts that require administrative privileges
#
# Account names are case-insensitive in the comparison logic.
# Do not include the domain prefix for local accounts.
# For domain accounts on domain-joined systems, include just the username.
$EXPECTED_ADMIN_ACCOUNTS = @(
    "Administrator",
    "admin"
    # Add site-specific administrator account names here:
    # "sysadmin",
    # "backup-svc",
    # "monitor-svc"
)

# EXPECTED_SERVICE_ACCOUNTS: Service accounts that are expected to log on
# with logon type 5 (service logon). Service logons from accounts not in
# this list are reported at WARN severity. SYSTEM, LOCAL SERVICE, and
# NETWORK SERVICE are always expected and do not need to be listed here.
$EXPECTED_SERVICE_ACCOUNTS = @(
    "SYSTEM",
    "LOCAL SERVICE",
    "NETWORK SERVICE"
    # Add site-specific service accounts here:
    # "svc-backup",
    # "svc-monitoring"
)

# HIGH_RISK_PRIVILEGES: Privileges whose use (Event ID 4673) is reported at
# CRIT severity regardless of which account exercises them. These privileges
# are powerful enough that any unexpected use warrants immediate review.
# SeDebugPrivilege allows reading and writing to any process's memory space
# and is the privilege most commonly sought by malware and attackers.
$HIGH_RISK_PRIVILEGES = @(
    "SeDebugPrivilege",         # Read/write any process memory
    "SeTcbPrivilege",           # Act as part of the operating system
    "SeLoadDriverPrivilege",    # Load and unload device drivers
    "SeCreateTokenPrivilege",   # Create authentication tokens
    "SeTakeOwnershipPrivilege"  # Take ownership of objects without discretionary access
)


# -----------------------------------------------------------------------------
# SECTION 7 - Security-Relevant Processes and Services
# -----------------------------------------------------------------------------
#
# SECURITY_RELEVANT_SERVICES: Services whose unexpected termination (Event ID
# 7034) is reported at CRIT severity rather than WARN. These services are
# defensive controls whose failure has direct security consequences.
# An attacker who gains sufficient privilege may attempt to stop these
# services to reduce visibility or remove protections before proceeding.
#
# Service names are the short names as they appear in the Services control
# panel or in Get-Service output, not the display names.
$SECURITY_RELEVANT_SERVICES = @(
    "EventLog",         # Windows Event Log - if this stops, audit trail stops
    "wuauserv",         # Windows Update
    "WinDefend",        # Windows Defender Antivirus
    "MpsSvc",           # Windows Firewall
    "Schedule",         # Task Scheduler
    "CryptSvc"          # Cryptographic Services
    # Add site-specific security-relevant services here:
    # "sysmon",         # Sysinternals Sysmon if deployed
    # "LanmanServer",   # Server service (file sharing)
    # "TermService"     # Remote Desktop Services
)

# SECURITY_RELEVANT_PROCESSES: Process names whose crash (Event ID 1000) is
# reported at CRIT severity. These are processes that, if crashed, could
# indicate an exploitation attempt or a significant operational impact.
$SECURITY_RELEVANT_PROCESSES = @(
    "MsMpEng.exe",      # Windows Defender engine
    "lsass.exe",        # Local Security Authority - credential store
    "svchost.exe",      # Service host process
    "services.exe",     # Service Control Manager
    "winlogon.exe"      # Windows logon process
)

# TRUSTED_TASK_PATHS: Directories from which scheduled tasks are expected
# to run executables. Tasks whose action path is NOT under one of these
# directories are reported at elevated severity. This catches tasks created
# to run scripts from temp directories, user profile directories, or other
# unusual locations - a common attacker technique.
$TRUSTED_TASK_PATHS = @(
    "C:\Windows\System32",
    "C:\Windows\SysWOW64",
    "C:\Windows\",
    "C:\Program Files\",
    "C:\Program Files (x86)\"
    # Add site-specific trusted paths here:
    # "C:\Scripts\",
    # "C:\Tools\"
)


# -----------------------------------------------------------------------------
# SECTION 8 - Event Log Size Verification
# -----------------------------------------------------------------------------
#
# The framework checks event log sizes at the start of each run to verify
# that logs are large enough to retain the requested monitoring window.
# A Security log that is too small will overwrite events before the next
# scheduled report run, creating gaps in coverage.
#
# These are minimum recommended sizes in kilobytes. If a log is smaller than
# its minimum, the report includes a configuration warning. These defaults
# follow Microsoft's guidance for production server audit log sizing.
# Mastering Windows Server 2022 (Krause) covers event log sizing in the
# context of security auditing configuration.
#
# Note: These are minimums for this framework's purposes. Environments with
# compliance requirements (PCI DSS, HIPAA, SOX) typically require much
# larger event logs or centralized log forwarding.

$EVENTLOG_MIN_SIZE_KB = @{
    "Security"    = 204800   # 200 MB - Security log receives the most writes
    "System"      = 51200    # 50 MB
    "Application" = 51200    # 50 MB
}


# -----------------------------------------------------------------------------
# SECTION 9 - Report Metadata
# -----------------------------------------------------------------------------
#
# These values appear in report headers and footers to identify the
# configuration used to generate the report. This is useful when comparing
# reports generated by different configuration versions or from different
# systems.

# MONITOR_VERSION: Version of this configuration file. Increment this when
# making significant changes to thresholds or module settings so that
# reports generated before and after a configuration change can be
# distinguished. Follow semantic versioning: MAJOR.MINOR.PATCH
$MONITOR_VERSION = "1.0.0"

# MONITOR_DESCRIPTION: Short description included in report headers.
# Useful when this framework is deployed in multiple roles and reports
# from different roles land in the same directory or ticketing system.
$MONITOR_DESCRIPTION = "Windows Server Operational Log Monitor"

# REPORT_INCLUDE_SYSTEM_INFO: Whether to include system information
# (OS version, uptime, last boot time) in the report header.
# Useful for correlating reports with specific system states but adds
# a small amount of execution time for the WMI query.
$REPORT_INCLUDE_SYSTEM_INFO = $true