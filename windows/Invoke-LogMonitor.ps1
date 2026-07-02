<#
.SYNOPSIS
    ops-log-monitor — Windows Server Operational Log Monitor

.DESCRIPTION
    Orchestrates collection of operationally significant events from Windows
    Security, System, and Application event logs. Calls each detection module,
    assembles a structured report, and writes output in Markdown and/or JSON
    format suitable for helpdesk tickets, audits, or documentation systems.

    This script does not query event logs directly. It loads configuration,
    invokes each module in sequence, collects their structured output, and
    renders the final report. All event-log query logic lives in the
    individual modules under .\modules\.

.PARAMETER StartTime
    Beginning of the monitoring window. If omitted, calculated as
    (current time - MONITORING_WINDOW_HOURS) from the configuration file.

.PARAMETER EndTime
    End of the monitoring window. If omitted, defaults to the current time.

.PARAMETER ConfigPath
    Path to the configuration file. Defaults to .\config\windows-monitor.conf.ps1
    relative to this script's location. If a file matching
    windows-monitor.conf.local.ps1 exists in the same directory, it is loaded
    instead, allowing site-specific overrides without modifying the tracked
    configuration file.

.PARAMETER OutputPath
    Override the OUTPUT_DIR setting from the configuration file for this run.

.PARAMETER Quiet
    Suppress console progress output. Errors and the final summary are still
    written to the console. Use this for unattended/scheduled execution where
    console output is not monitored.

.EXAMPLE
    .\Invoke-LogMonitor.ps1
    Runs with all defaults — last 24 hours, output to configured directory.

.EXAMPLE
    .\Invoke-LogMonitor.ps1 -StartTime (Get-Date).AddDays(-7) -EndTime (Get-Date)
    Generates a 7-day summary report.

.EXAMPLE
    .\Invoke-LogMonitor.ps1 -Quiet -OutputPath "C:\Monitoring\Reports"
    Suitable for invocation from Windows Task Scheduler.

.NOTES
    Requires: PowerShell 5.1+, read access to Security/System/Application
    event logs (typically requires local Administrator or membership in
    Event Log Readers group with additional Security log permissions).

    Run docs\troubleshooting.md if event log access errors occur.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [DateTime]$StartTime,

    [Parameter(Mandatory = $false)]
    [DateTime]$EndTime,

    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [switch]$Quiet
)

# =============================================================================
# SCRIPT INITIALIZATION
# =============================================================================

$ErrorActionPreference = "Stop"
$ScriptRoot = $PSScriptRoot
$ScriptVersion = "1.0.0"
$RunStartTime = Get-Date

# Track non-fatal issues encountered during the run so they can be surfaced
# in the report footer even if the run otherwise completes successfully.
$script:RunWarnings = [System.Collections.Generic.List[string]]::new()

# -----------------------------------------------------------------------------
# Logging function shared with all modules via scriptblock parameter.
# Writes to both the console (unless -Quiet) and the configured log file.
# Modules call this as: & $Logger "INFO" "ModuleName" "Message"
# -----------------------------------------------------------------------------
function Write-MonitorLog {
    param(
        [string]$Level,
        [string]$Source,
        [string]$Message
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "[$timestamp] [$Level] [$Source] $Message"

    # Write to log file. Append mode, create file/directory if absent.
    if ($script:LogFilePath) {
        $logDir = Split-Path $script:LogFilePath -Parent
        if ($logDir -and -not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        Add-Content -Path $script:LogFilePath -Value $logLine -ErrorAction SilentlyContinue
    }

    # Write to console unless suppressed. Color-code by level for readability.
    if (-not $Quiet) {
        switch ($Level) {
            "ERROR" { Write-Host $logLine -ForegroundColor Red }
            "WARN"  { Write-Host $logLine -ForegroundColor Yellow }
            "INFO"  { Write-Host $logLine -ForegroundColor Gray }
            default { Write-Host $logLine }
        }
    }

    if ($Level -eq "WARN" -or $Level -eq "ERROR") {
        $script:RunWarnings.Add("[$Level] [$Source] $Message")
    }
}

$Logger = { param($Level, $Source, $Message) Write-MonitorLog -Level $Level -Source $Source -Message $Message }

# =============================================================================
# STEP 1 — LOAD CONFIGURATION
# =============================================================================
#
# Configuration loading happens before logging is fully set up because the
# log file path itself comes from the configuration. We use a bootstrap
# console write for any issues prior to config load.
# =============================================================================

Write-Host "ops-log-monitor (Windows) v$ScriptVersion — starting run at $RunStartTime" -ForegroundColor Cyan

if (-not $ConfigPath) {
    # Prefer a local override file if one exists, following the pattern
    # documented in windows-monitor.conf.ps1's header comments.
    $defaultLocalConfig = Join-Path $ScriptRoot "config\windows-monitor.conf.local.ps1"
    $defaultConfig      = Join-Path $ScriptRoot "config\windows-monitor.conf.ps1"

    if (Test-Path $defaultLocalConfig) {
        $ConfigPath = $defaultLocalConfig
        Write-Host "Using local configuration override: $ConfigPath" -ForegroundColor Cyan
    }
    else {
        $ConfigPath = $defaultConfig
    }
}

if (-not (Test-Path $ConfigPath)) {
    Write-Host "FATAL: Configuration file not found at: $ConfigPath" -ForegroundColor Red
    Write-Host "Expected location: .\config\windows-monitor.conf.ps1" -ForegroundColor Red
    exit 1
}

try {
    # Dot-source the configuration file. This loads all $VARIABLE assignments
    # from the config file into the current scope, making them directly
    # accessible. We then transfer them into a hashtable so modules receive
    # a single, explicit parameter rather than relying on scope inheritance,
    # which makes the module contract clearer and easier to test.
    . $ConfigPath
}
catch {
    Write-Host "FATAL: Failed to load configuration file: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Build the configuration hashtable passed to every module.
$Config = @{
    OUTPUT_DIR                    = $OUTPUT_DIR
    OUTPUT_FORMATS                = $OUTPUT_FORMATS
    REPORT_FILENAME_PREFIX        = $REPORT_FILENAME_PREFIX
    LOG_FILE                      = $LOG_FILE
    MAX_LOG_SIZE_MB               = $MAX_LOG_SIZE_MB
    MONITORING_WINDOW_HOURS       = $MONITORING_WINDOW_HOURS
    MONITORING_WINDOW_MAX_EVENTS  = $MONITORING_WINDOW_MAX_EVENTS
    BUSINESS_HOURS_START          = $BUSINESS_HOURS_START
    BUSINESS_HOURS_END            = $BUSINESS_HOURS_END
    BUSINESS_DAYS                 = $BUSINESS_DAYS
    ENFORCE_BUSINESS_HOURS        = $ENFORCE_BUSINESS_HOURS
    MODULE_AUTHENTICATION_ENABLED = $MODULE_AUTHENTICATION_ENABLED
    MODULE_SERVICES_ENABLED       = $MODULE_SERVICES_ENABLED
    MODULE_PRIVILEGE_ENABLED      = $MODULE_PRIVILEGE_ENABLED
    MODULE_SYSTEM_HEALTH_ENABLED  = $MODULE_SYSTEM_HEALTH_ENABLED
    MODULE_SCHEDULED_TASKS_ENABLED = $MODULE_SCHEDULED_TASKS_ENABLED
    AUTH_FAILURE_WARN_THRESHOLD   = $AUTH_FAILURE_WARN_THRESHOLD
    AUTH_FAILURE_CRIT_THRESHOLD   = $AUTH_FAILURE_CRIT_THRESHOLD
    AUTH_SOURCE_WARN_THRESHOLD    = $AUTH_SOURCE_WARN_THRESHOLD
    AUTH_SOURCE_CRIT_THRESHOLD    = $AUTH_SOURCE_CRIT_THRESHOLD
    AUTH_MONITOR_LOGON_TYPES      = $AUTH_MONITOR_LOGON_TYPES
    EXPECTED_ADMIN_ACCOUNTS       = $EXPECTED_ADMIN_ACCOUNTS
    EXPECTED_SERVICE_ACCOUNTS     = $EXPECTED_SERVICE_ACCOUNTS
    HIGH_RISK_PRIVILEGES          = $HIGH_RISK_PRIVILEGES
    SECURITY_RELEVANT_SERVICES    = $SECURITY_RELEVANT_SERVICES
    SECURITY_RELEVANT_PROCESSES   = $SECURITY_RELEVANT_PROCESSES
    TRUSTED_TASK_PATHS            = $TRUSTED_TASK_PATHS
    EVENTLOG_MIN_SIZE_KB          = $EVENTLOG_MIN_SIZE_KB
    MONITOR_VERSION               = $MONITOR_VERSION
    MONITOR_DESCRIPTION           = $MONITOR_DESCRIPTION
    REPORT_INCLUDE_SYSTEM_INFO    = $REPORT_INCLUDE_SYSTEM_INFO
}

# Apply command-line overrides on top of file-based configuration.
if ($OutputPath) { $Config.OUTPUT_DIR = $OutputPath }

# Resolve the log file path relative to the script root if it is a relative path.
if (-not [System.IO.Path]::IsPathRooted($Config.LOG_FILE)) {
    $script:LogFilePath = Join-Path $ScriptRoot $Config.LOG_FILE
} else {
    $script:LogFilePath = $Config.LOG_FILE
}

# -----------------------------------------------------------------------------
# Rotate the execution log if it has exceeded the configured maximum size.
# This prevents the script's own log from growing unbounded over months of
# scheduled runs.
# -----------------------------------------------------------------------------
if (Test-Path $script:LogFilePath) {
    $logSizeMB = (Get-Item $script:LogFilePath).Length / 1MB
    if ($logSizeMB -ge $Config.MAX_LOG_SIZE_MB) {
        $backupPath = "$($script:LogFilePath).bak"
        Move-Item -Path $script:LogFilePath -Destination $backupPath -Force
    }
}

& $Logger "INFO" "Orchestrator" "Configuration loaded from: $ConfigPath"
& $Logger "INFO" "Orchestrator" "Script version: $ScriptVersion | Config version: $($Config.MONITOR_VERSION)"

# =============================================================================
# STEP 2 — RESOLVE MONITORING WINDOW
# =============================================================================

if (-not $EndTime) { $EndTime = Get-Date }
if (-not $StartTime) { $StartTime = $EndTime.AddHours(-1 * $Config.MONITORING_WINDOW_HOURS) }

if ($StartTime -ge $EndTime) {
    & $Logger "ERROR" "Orchestrator" "StartTime ($StartTime) must be earlier than EndTime ($EndTime). Aborting."
    exit 1
}

& $Logger "INFO" "Orchestrator" "Monitoring window: $StartTime to $EndTime ($([Math]::Round(($EndTime - $StartTime).TotalHours, 1)) hours)"

# =============================================================================
# STEP 3 — PRE-FLIGHT CHECKS
# =============================================================================
#
# Verify the prerequisites required for accurate, complete report generation
# before doing any expensive event log querying. Failing fast on a clear
# prerequisite issue is more useful to the administrator than a report that
# silently has empty sections.
# =============================================================================

& $Logger "INFO" "Orchestrator" "Running pre-flight checks"

# -----------------------------------------------------------------------------
# Check 1: Administrative privileges.
# Reading the Security event log requires elevated privileges in most
# environments. We do not hard-fail here because some environments grant
# Security log read access without full local admin via group membership,
# but we surface a clear warning so failures downstream are understood.
# -----------------------------------------------------------------------------
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    & $Logger "WARN" "Orchestrator" (
        "Script is not running with Administrator privileges. " +
        "Security log queries may fail with access denied errors. " +
        "See docs\troubleshooting.md for required permissions."
    )
}
else {
    & $Logger "INFO" "Orchestrator" "Running with Administrator privileges — OK"
}

# -----------------------------------------------------------------------------
# Check 2: Event log size verification.
# A log that is too small will overwrite events before the next scheduled
# run, creating coverage gaps. We check current log sizes against configured
# minimums and warn if any log is undersized.
# -----------------------------------------------------------------------------
$logSizeWarnings = [System.Collections.Generic.List[string]]::new()

foreach ($logName in $Config.EVENTLOG_MIN_SIZE_KB.Keys) {
    try {
        $logInfo = Get-WinEvent -ListLog $logName -ErrorAction Stop
        $currentMaxSizeKB = $logInfo.MaximumSizeInBytes / 1KB
        $minRequiredKB = $Config.EVENTLOG_MIN_SIZE_KB[$logName]

        if ($currentMaxSizeKB -lt $minRequiredKB) {
            $msg = "$logName event log maximum size ($([Math]::Round($currentMaxSizeKB)) KB) " +
                   "is below the recommended minimum ($minRequiredKB KB). " +
                   "Events may be overwritten before the next scheduled report run. " +
                   "Increase log size via wevtutil or Event Viewer properties."
            & $Logger "WARN" "Orchestrator" $msg
            $logSizeWarnings.Add($msg)
        }
        else {
            & $Logger "INFO" "Orchestrator" "$logName log size OK ($([Math]::Round($currentMaxSizeKB)) KB configured)"
        }
    }
    catch {
        & $Logger "WARN" "Orchestrator" "Could not verify size of '$logName' log: $($_.Exception.Message)"
    }
}

# -----------------------------------------------------------------------------
# Check 3: Output directory writability.
# Verify the output directory exists or can be created, and is writable,
# before spending time collecting events that could not be saved.
# -----------------------------------------------------------------------------
$resolvedOutputDir = if ([System.IO.Path]::IsPathRooted($Config.OUTPUT_DIR)) {
    $Config.OUTPUT_DIR
} else {
    Join-Path $ScriptRoot $Config.OUTPUT_DIR
}

try {
    if (-not (Test-Path $resolvedOutputDir)) {
        New-Item -ItemType Directory -Path $resolvedOutputDir -Force | Out-Null
        & $Logger "INFO" "Orchestrator" "Created output directory: $resolvedOutputDir"
    }

    # Verify writability with a throwaway test file.
    $testFile = Join-Path $resolvedOutputDir ".write-test-$(Get-Random).tmp"
    [System.IO.File]::WriteAllText($testFile, "test")
    Remove-Item $testFile -Force
    & $Logger "INFO" "Orchestrator" "Output directory writable: $resolvedOutputDir"
}
catch {
    & $Logger "ERROR" "Orchestrator" "Output directory is not writable: $resolvedOutputDir — $($_.Exception.Message)"
    exit 1
}

# =============================================================================
# STEP 4 — LOAD AND EXECUTE MODULES
# =============================================================================
#
# Each module is dot-sourced to load its function definition, then invoked
# with the standard parameter set. Module failures are caught individually
# so that one module's failure does not prevent the others from running —
# a partial report is more useful than no report.
# =============================================================================

$ModulesPath = Join-Path $ScriptRoot "modules"
$ModuleResults = @{}

# Module execution plan: each entry maps a config enable-flag to the module
# file name and the function name to invoke. Defining this as a structured
# list (rather than five copy-pasted blocks) keeps the orchestrator concise
# and makes adding a sixth module in the future a one-line change here.
$ModuleExecutionPlan = @(
    @{
        EnableFlag   = "MODULE_AUTHENTICATION_ENABLED"
        FileName     = "Get-AuthenticationEvents.ps1"
        FunctionName = "Get-AuthenticationEvents"
        ResultKey    = "Authentication"
    },
    @{
        EnableFlag   = "MODULE_SERVICES_ENABLED"
        FileName     = "Get-ServiceEvents.ps1"
        FunctionName = "Get-ServiceEvents"
        ResultKey    = "Services"
    },
    @{
        EnableFlag   = "MODULE_PRIVILEGE_ENABLED"
        FileName     = "Get-PrivilegeEvents.ps1"
        FunctionName = "Get-PrivilegeEvents"
        ResultKey    = "Privilege"
    },
    @{
        EnableFlag   = "MODULE_SYSTEM_HEALTH_ENABLED"
        FileName     = "Get-SystemHealthEvents.ps1"
        FunctionName = "Get-SystemHealthEvents"
        ResultKey    = "SystemHealth"
    },
    @{
        EnableFlag   = "MODULE_SCHEDULED_TASKS_ENABLED"
        FileName     = "Get-ScheduledTaskEvents.ps1"
        FunctionName = "Get-ScheduledTaskEvents"
        ResultKey    = "ScheduledTasks"
    }
)

foreach ($moduleEntry in $ModuleExecutionPlan) {
    $isEnabled = $Config[$moduleEntry.EnableFlag]

    if (-not $isEnabled) {
        & $Logger "INFO" "Orchestrator" "Module '$($moduleEntry.ResultKey)' is disabled in configuration — skipping"
        continue
    }

    $modulePath = Join-Path $ModulesPath $moduleEntry.FileName

    if (-not (Test-Path $modulePath)) {
        $msg = "Module file not found: $modulePath — skipping '$($moduleEntry.ResultKey)' section"
        & $Logger "ERROR" "Orchestrator" $msg
        continue
    }

    & $Logger "INFO" "Orchestrator" "Loading and executing module: $($moduleEntry.ResultKey)"

    try {
        # Dot-source the module file to load its function definition into
        # the current scope, then invoke the function by name.
        . $modulePath

        $moduleOutput = & $moduleEntry.FunctionName -StartTime $StartTime `
                                                     -EndTime $EndTime `
                                                     -Config $Config `
                                                     -Logger $Logger

        $ModuleResults[$moduleEntry.ResultKey] = $moduleOutput

        & $Logger "INFO" "Orchestrator" (
            "Module '$($moduleEntry.ResultKey)' completed: " +
            "$($moduleOutput.TotalEvents) events " +
            "($($moduleOutput.CritCount) CRIT, $($moduleOutput.WarnCount) WARN, $($moduleOutput.InfoCount) INFO)"
        )
    }
    catch {
        # A module-level exception does not abort the entire run. We record
        # the failure and continue with remaining modules so the report
        # still covers as much ground as possible.
        $errorMsg = "Module '$($moduleEntry.ResultKey)' failed with an unhandled exception: $($_.Exception.Message)"
        & $Logger "ERROR" "Orchestrator" $errorMsg
        $script:RunWarnings.Add($errorMsg)
    }
}

# =============================================================================
# STEP 5 — GATHER SYSTEM INFORMATION (OPTIONAL)
# =============================================================================

$SystemInfo = $null
if ($Config.REPORT_INCLUDE_SYSTEM_INFO) {
    & $Logger "INFO" "Orchestrator" "Collecting system information for report header"
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop

        $SystemInfo = [PSCustomObject]@{
            Hostname     = $env:COMPUTERNAME
            OSVersion    = $os.Caption
            OSBuild      = $os.BuildNumber
            LastBootTime = $os.LastBootUpTime
            Uptime       = (Get-Date) - $os.LastBootUpTime
            Domain       = $cs.Domain
            DomainRole   = switch ($cs.DomainRole) {
                0 { "Standalone Workstation" }
                1 { "Member Workstation" }
                2 { "Standalone Server" }
                3 { "Member Server" }
                4 { "Backup Domain Controller" }
                5 { "Primary Domain Controller" }
                default { "Unknown" }
            }
        }
    }
    catch {
        & $Logger "WARN" "Orchestrator" "Could not collect system information: $($_.Exception.Message)"
    }
}

# =============================================================================
# STEP 6 — ASSEMBLE AND WRITE REPORT
# =============================================================================

& $Logger "INFO" "Orchestrator" "Assembling final report"

$reportTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$reportBaseName  = "$($Config.REPORT_FILENAME_PREFIX)-$($env:COMPUTERNAME)-$reportTimestamp"

# Calculate overall report severity — the highest severity found across all
# modules. This drives the report header's overall status indicator.
$allCritCounts = $ModuleResults.Values | ForEach-Object { $_.CritCount }
$allWarnCounts = $ModuleResults.Values | ForEach-Object { $_.WarnCount }
$totalCrit = ($allCritCounts | Measure-Object -Sum).Sum
$totalWarn = ($allWarnCounts | Measure-Object -Sum).Sum
$totalAllEvents = ($ModuleResults.Values | ForEach-Object { $_.TotalEvents } | Measure-Object -Sum).Sum

$overallStatus = if ($totalCrit -gt 0) { "CRITICAL" }
                 elseif ($totalWarn -gt 0) { "WARNING" }
                 else { "NORMAL" }

# -----------------------------------------------------------------------------
# Render Markdown report.
# -----------------------------------------------------------------------------
function New-MarkdownReport {
    param($ModuleResults, $SystemInfo, $Config, $StartTime, $EndTime, $OverallStatus, $TotalCrit, $TotalWarn, $TotalEvents, $RunWarnings)

    $sb = [System.Text.StringBuilder]::new()

    [void]$sb.AppendLine("# Operational Log Monitor Report")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("**Status:** $OverallStatus")
    [void]$sb.AppendLine("**Hostname:** $($env:COMPUTERNAME)")
    [void]$sb.AppendLine("**Report Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$sb.AppendLine("**Monitoring Window:** $StartTime to $EndTime")
    [void]$sb.AppendLine("**Total Events:** $TotalEvents | **CRIT:** $TotalCrit | **WARN:** $TotalWarn")
    [void]$sb.AppendLine("")

    if ($SystemInfo) {
        [void]$sb.AppendLine("## System Information")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("| Field | Value |")
        [void]$sb.AppendLine("|---|---|")
        [void]$sb.AppendLine("| OS Version | $($SystemInfo.OSVersion) (Build $($SystemInfo.OSBuild)) |")
        [void]$sb.AppendLine("| Domain Role | $($SystemInfo.DomainRole) |")
        [void]$sb.AppendLine("| Domain/Workgroup | $($SystemInfo.Domain) |")
        [void]$sb.AppendLine("| Last Boot | $($SystemInfo.LastBootTime) |")
        [void]$sb.AppendLine("| Uptime | $([Math]::Round($SystemInfo.Uptime.TotalHours, 1)) hours |")
        [void]$sb.AppendLine("")
    }

    [void]$sb.AppendLine("## Summary by Category")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("| Category | Total | CRIT | WARN | INFO |")
    [void]$sb.AppendLine("|---|---|---|---|---|")
    foreach ($key in $ModuleResults.Keys) {
        $m = $ModuleResults[$key]
        [void]$sb.AppendLine("| $key | $($m.TotalEvents) | $($m.CritCount) | $($m.WarnCount) | $($m.InfoCount) |")
    }
    [void]$sb.AppendLine("")

    foreach ($key in $ModuleResults.Keys) {
        $m = $ModuleResults[$key]
        [void]$sb.AppendLine("## $key")
        [void]$sb.AppendLine("")

        if ($m.ModuleErrors.Count -gt 0) {
            [void]$sb.AppendLine("> **Module Errors Encountered:**")
            foreach ($err in $m.ModuleErrors) {
                [void]$sb.AppendLine("> - $err")
            }
            [void]$sb.AppendLine("")
        }

        if ($m.TotalEvents -eq 0) {
            [void]$sb.AppendLine("No events found in this category during the monitoring window.")
            [void]$sb.AppendLine("")
            continue
        }

        [void]$sb.AppendLine("| Time | Severity | Event ID | Description |")
        [void]$sb.AppendLine("|---|---|---|---|")
        foreach ($evt in $m.Events) {
            $timeStr = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            # Escape pipe characters in description to avoid breaking the
            # Markdown table structure.
            $descClean = $evt.Description -replace '\|', '\|'
            [void]$sb.AppendLine("| $timeStr | $($evt.Severity) | $($evt.EventId) | $descClean |")
        }
        [void]$sb.AppendLine("")
    }

    if ($RunWarnings.Count -gt 0) {
        [void]$sb.AppendLine("## Execution Notes")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("The following non-fatal issues occurred during report generation:")
        [void]$sb.AppendLine("")
        foreach ($w in $RunWarnings) {
            [void]$sb.AppendLine("- $w")
        }
        [void]$sb.AppendLine("")
    }

    [void]$sb.AppendLine("---")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("*Generated by $($Config.MONITOR_DESCRIPTION) v$($Config.MONITOR_VERSION) ($ScriptVersion) — ops-log-monitor*")

    return $sb.ToString()
}

# -----------------------------------------------------------------------------
# Render JSON report. Uses a flat, predictable schema designed for stable
# downstream parsing across report versions.
# -----------------------------------------------------------------------------
function New-JsonReport {
    param($ModuleResults, $SystemInfo, $Config, $StartTime, $EndTime, $OverallStatus, $TotalCrit, $TotalWarn, $TotalEvents, $RunWarnings)

    $jsonObject = [PSCustomObject]@{
        reportMetadata = [PSCustomObject]@{
            hostname        = $env:COMPUTERNAME
            generatedAt     = (Get-Date -Format "o")
            windowStart     = $StartTime.ToString("o")
            windowEnd       = $EndTime.ToString("o")
            overallStatus   = $OverallStatus
            totalEvents     = $TotalEvents
            critCount       = $TotalCrit
            warnCount       = $TotalWarn
            scriptVersion   = $ScriptVersion
            configVersion   = $Config.MONITOR_VERSION
        }
        systemInfo = $SystemInfo
        categories = @{}
        executionNotes = $RunWarnings
    }

    foreach ($key in $ModuleResults.Keys) {
        $m = $ModuleResults[$key]
        $jsonObject.categories[$key] = [PSCustomObject]@{
            totalEvents  = $m.TotalEvents
            critCount    = $m.CritCount
            warnCount    = $m.WarnCount
            infoCount    = $m.InfoCount
            moduleErrors = $m.ModuleErrors
            events       = $m.Events
        }
    }

    return $jsonObject | ConvertTo-Json -Depth 10
}

$writtenFiles = [System.Collections.Generic.List[string]]::new()

if ($Config.OUTPUT_FORMATS -eq "Markdown" -or $Config.OUTPUT_FORMATS -eq "Both") {
    $mdPath = Join-Path $resolvedOutputDir "$reportBaseName.md"
    $mdContent = New-MarkdownReport -ModuleResults $ModuleResults -SystemInfo $SystemInfo `
                                     -Config $Config -StartTime $StartTime -EndTime $EndTime `
                                     -OverallStatus $overallStatus -TotalCrit $totalCrit `
                                     -TotalWarn $totalWarn -TotalEvents $totalAllEvents `
                                     -RunWarnings $script:RunWarnings
    [System.IO.File]::WriteAllText($mdPath, $mdContent)
    $writtenFiles.Add($mdPath)
    & $Logger "INFO" "Orchestrator" "Markdown report written: $mdPath"
}

if ($Config.OUTPUT_FORMATS -eq "JSON" -or $Config.OUTPUT_FORMATS -eq "Both") {
    $jsonPath = Join-Path $resolvedOutputDir "$reportBaseName.json"
    $jsonContent = New-JsonReport -ModuleResults $ModuleResults -SystemInfo $SystemInfo `
                                   -Config $Config -StartTime $StartTime -EndTime $EndTime `
                                   -OverallStatus $overallStatus -TotalCrit $totalCrit `
                                   -TotalWarn $totalWarn -TotalEvents $totalAllEvents `
                                   -RunWarnings $script:RunWarnings
    [System.IO.File]::WriteAllText($jsonPath, $jsonContent)
    $writtenFiles.Add($jsonPath)
    & $Logger "INFO" "Orchestrator" "JSON report written: $jsonPath"
}

# =============================================================================
# STEP 7 — FINAL SUMMARY
# =============================================================================

$runDuration = (Get-Date) - $RunStartTime

& $Logger "INFO" "Orchestrator" "Run complete in $([Math]::Round($runDuration.TotalSeconds, 1)) seconds"
& $Logger "INFO" "Orchestrator" "Overall status: $overallStatus | Total events: $totalAllEvents | CRIT: $totalCrit | WARN: $totalWarn"

Write-Host ""
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host " ops-log-monitor run complete" -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host " Status:        $overallStatus"
Write-Host " Total events:  $totalAllEvents"
Write-Host " CRIT / WARN:   $totalCrit / $totalWarn"
Write-Host " Duration:      $([Math]::Round($runDuration.TotalSeconds, 1))s"
Write-Host " Reports:"
foreach ($f in $writtenFiles) { Write-Host "   - $f" }
Write-Host "=============================================================" -ForegroundColor Cyan

# Exit code reflects overall severity, enabling Task Scheduler or monitoring
# wrappers to take action based on exit status without parsing report content.
switch ($overallStatus) {
    "CRITICAL" { exit 2 }
    "WARNING"  { exit 1 }
    default    { exit 0 }
}