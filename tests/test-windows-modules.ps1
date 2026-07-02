# =============================================================================
# test-windows-modules.ps1
# ops-log-monitor — Windows Module Structural Validation Tests
# =============================================================================
#
# PURPOSE:
#   Validates that each Windows detection module returns a correctly
#   structured PSCustomObject that the orchestrator can consume without
#   error. Tests do not require live event log data — they run against
#   a synthetic test environment using mock objects and empty result sets.
#
# WHAT IS TESTED:
#   - Each module loads without syntax or parse errors
#   - Each module's function can be called with the standard parameter set
#   - Each module returns an object with all required properties
#   - Each module handles empty result sets without throwing exceptions
#   - Required property types are correct (DateTime, int, List, etc.)
#   - Severity count arithmetic is internally consistent
#     (TotalEvents == CritCount + WarnCount + InfoCount)
#
# WHAT IS NOT TESTED:
#   - Whether actual events are collected from live event logs
#     (requires an appropriately configured Windows system)
#   - Whether event log queries return correct data for specific scenarios
#     (covered by functional testing on a live system)
#   - Report rendering (covered by running the full orchestrator)
#
# USAGE:
#   Run from the repository root in a standard (non-elevated) PowerShell
#   session. Elevated privileges are not required because these tests do
#   not query event logs.
#
#     cd ops-log-monitor
#     .\tests\test-windows-modules.ps1
#
# EXIT CODES:
#   0 = All tests passed
#   1 = One or more tests failed
#
# =============================================================================

$ErrorActionPreference = "Stop"
$TestRoot   = $PSScriptRoot
$RepoRoot   = Split-Path $TestRoot -Parent
$ModulesDir = Join-Path $RepoRoot "windows\modules"
$ConfigDir  = Join-Path $RepoRoot "windows\config"

# =============================================================================
# Test framework — minimal, dependency-free assertion engine.
# Using a purpose-built mini-framework rather than Pester keeps the test
# suite runnable without any module installation on the target system,
# consistent with the project's no-external-dependencies requirement.
# =============================================================================

$script:TestsPassed = 0
$script:TestsFailed = 0
$script:TestResults = [System.Collections.Generic.List[PSCustomObject]]::new()

function Assert-True {
    param(
        [string]$TestName,
        [bool]$Condition,
        [string]$FailMessage = "Condition was false"
    )

    if ($Condition) {
        $script:TestsPassed++
        $script:TestResults.Add([PSCustomObject]@{
            Name   = $TestName
            Result = "PASS"
            Detail = ""
        })
        Write-Host "  PASS  $TestName" -ForegroundColor Green
    }
    else {
        $script:TestsFailed++
        $script:TestResults.Add([PSCustomObject]@{
            Name   = $TestName
            Result = "FAIL"
            Detail = $FailMessage
        })
        Write-Host "  FAIL  $TestName" -ForegroundColor Red
        Write-Host "        $FailMessage" -ForegroundColor Yellow
    }
}

function Assert-NotNull {
    param([string]$TestName, $Value, [string]$FailMessage = "Value was null or empty")
    Assert-True -TestName $TestName -Condition ($null -ne $Value) -FailMessage $FailMessage
}

function Assert-PropertyExists {
    param([string]$TestName, $Object, [string]$PropertyName)
    $exists = ($null -ne $Object) -and ($Object.PSObject.Properties.Name -contains $PropertyName)
    Assert-True -TestName $TestName `
                -Condition $exists `
                -FailMessage "Property '$PropertyName' not found on returned object"
}

function Assert-TypeMatch {
    param([string]$TestName, $Value, [type]$ExpectedType)
    $matches = ($null -ne $Value) -and ($Value -is $ExpectedType)
    Assert-True -TestName $TestName `
                -Condition $matches `
                -FailMessage "Expected type $($ExpectedType.Name), got $($Value?.GetType().Name ?? 'null')"
}

function Write-TestSectionHeader {
    param([string]$Title)
    Write-Host ""
    Write-Host "─────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "─────────────────────────────────────────────────────" -ForegroundColor Cyan
}

# =============================================================================
# Build a minimal mock configuration hashtable that satisfies every
# parameter the modules reference from $Config. Values are set to the
# same defaults as windows-monitor.conf.ps1 so module logic runs in a
# realistic configuration context even though no events will be found.
# =============================================================================

$MockConfig = @{
    MONITORING_WINDOW_MAX_EVENTS  = 1000
    AUTH_FAILURE_WARN_THRESHOLD   = 5
    AUTH_FAILURE_CRIT_THRESHOLD   = 20
    AUTH_SOURCE_WARN_THRESHOLD    = 10
    AUTH_SOURCE_CRIT_THRESHOLD    = 50
    AUTH_ACCOUNT_WARN_THRESHOLD   = 5
    AUTH_ACCOUNT_CRIT_THRESHOLD   = 20
    AUTH_MONITOR_LOGON_TYPES      = @(2, 3, 10)
    ENFORCE_BUSINESS_HOURS        = $true
    BUSINESS_HOURS_START          = 7
    BUSINESS_HOURS_END            = 19
    BUSINESS_DAYS                 = @(1, 2, 3, 4, 5)
    EXPECTED_ADMIN_ACCOUNTS       = @("Administrator", "admin")
    EXPECTED_SERVICE_ACCOUNTS     = @("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
    HIGH_RISK_PRIVILEGES          = @("SeDebugPrivilege", "SeTcbPrivilege",
                                       "SeLoadDriverPrivilege", "SeCreateTokenPrivilege",
                                       "SeTakeOwnershipPrivilege")
    SECURITY_RELEVANT_SERVICES    = @("EventLog", "WinDefend", "MpsSvc", "Schedule", "CryptSvc")
    SECURITY_RELEVANT_PROCESSES   = @("MsMpEng.exe", "lsass.exe", "services.exe", "winlogon.exe")
    TRUSTED_TASK_PATHS            = @("C:\Windows\System32", "C:\Windows\",
                                       "C:\Program Files\", "C:\Program Files (x86)\")
}

# Mock logger: captures log output without writing to disk, so tests
# do not require a writable log directory to run.
$LogCapture = [System.Collections.Generic.List[string]]::new()
$MockLogger = {
    param($Level, $Source, $Message)
    $LogCapture.Add("[$Level] [$Source] $Message")
}

# Use a time window guaranteed to return no events on any system —
# a 1-second window 10 years in the past. This exercises all module
# code paths without needing event log data to exist.
$TestEndTime   = [DateTime]"2015-01-01 00:00:01"
$TestStartTime = [DateTime]"2015-01-01 00:00:00"

# =============================================================================
# Helper: verify the standard result object structure that all modules
# must return. Called once per module with its actual return value.
# =============================================================================

function Test-StandardResultStructure {
    param(
        [string]$ModuleName,
        [PSCustomObject]$Result,
        [string]$ExpectedCategory
    )

    Write-Host ""
    Write-Host "  Structural validation for $ModuleName output:" -ForegroundColor White

    Assert-NotNull "$ModuleName — result is not null" $Result "Module returned null"
    Assert-PropertyExists "$ModuleName — has Category property" $Result "Category"
    Assert-PropertyExists "$ModuleName — has CollectedAt property" $Result "CollectedAt"
    Assert-PropertyExists "$ModuleName — has WindowStart property" $Result "WindowStart"
    Assert-PropertyExists "$ModuleName — has WindowEnd property" $Result "WindowEnd"
    Assert-PropertyExists "$ModuleName — has TotalEvents property" $Result "TotalEvents"
    Assert-PropertyExists "$ModuleName — has CritCount property" $Result "CritCount"
    Assert-PropertyExists "$ModuleName — has WarnCount property" $Result "WarnCount"
    Assert-PropertyExists "$ModuleName — has InfoCount property" $Result "InfoCount"
    Assert-PropertyExists "$ModuleName — has ModuleErrors property" $Result "ModuleErrors"
    Assert-PropertyExists "$ModuleName — has Events property" $Result "Events"

    if ($null -ne $Result) {
        Assert-True "$ModuleName — Category is '$ExpectedCategory'" `
            -Condition ($Result.Category -eq $ExpectedCategory) `
            -FailMessage "Expected '$ExpectedCategory', got '$($Result.Category)'"

        Assert-TypeMatch "$ModuleName — CollectedAt is DateTime" $Result.CollectedAt ([DateTime])
        Assert-TypeMatch "$ModuleName — WindowStart is DateTime" $Result.WindowStart ([DateTime])
        Assert-TypeMatch "$ModuleName — WindowEnd is DateTime" $Result.WindowEnd ([DateTime])

        Assert-True "$ModuleName — WindowStart matches test input" `
            -Condition ($Result.WindowStart -eq $TestStartTime) `
            -FailMessage "WindowStart mismatch"

        Assert-True "$ModuleName — WindowEnd matches test input" `
            -Condition ($Result.WindowEnd -eq $TestEndTime) `
            -FailMessage "WindowEnd mismatch"

        Assert-True "$ModuleName — TotalEvents is non-negative integer" `
            -Condition ($Result.TotalEvents -is [int] -and $Result.TotalEvents -ge 0) `
            -FailMessage "TotalEvents is not a non-negative integer"

        Assert-True "$ModuleName — CritCount is non-negative integer" `
            -Condition ($Result.CritCount -is [int] -and $Result.CritCount -ge 0) `
            -FailMessage "CritCount is not a non-negative integer"

        Assert-True "$ModuleName — WarnCount is non-negative integer" `
            -Condition ($Result.WarnCount -is [int] -and $Result.WarnCount -ge 0) `
            -FailMessage "WarnCount is not a non-negative integer"

        Assert-True "$ModuleName — InfoCount is non-negative integer" `
            -Condition ($Result.InfoCount -is [int] -and $Result.InfoCount -ge 0) `
            -FailMessage "InfoCount is not a non-negative integer"

        # Severity arithmetic consistency check.
        # This catches bugs in count accumulation logic without requiring
        # live events — if the module reports TotalEvents=5 but the sum
        # of severity buckets is 4 or 6, the counting logic is broken.
        $severitySum = $Result.CritCount + $Result.WarnCount + $Result.InfoCount
        Assert-True "$ModuleName — TotalEvents == CritCount + WarnCount + InfoCount" `
            -Condition ($Result.TotalEvents -eq $severitySum) `
            -FailMessage "TotalEvents($($Result.TotalEvents)) != CritCount($($Result.CritCount)) + WarnCount($($Result.WarnCount)) + InfoCount($($Result.InfoCount)) = $severitySum"

        # Events list type check
        Assert-True "$ModuleName — Events is a List or array type" `
            -Condition ($Result.Events -is [System.Collections.IEnumerable]) `
            -FailMessage "Events property is not enumerable"

        # ModuleErrors list type check
        Assert-True "$ModuleName — ModuleErrors is a List or array type" `
            -Condition ($Result.ModuleErrors -is [System.Collections.IEnumerable]) `
            -FailMessage "ModuleErrors property is not enumerable"
    }
}

# =============================================================================
# TEST SUITE
# =============================================================================

Write-Host ""
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host " ops-log-monitor — Windows Module Tests" -ForegroundColor Cyan
Write-Host " $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan

# -----------------------------------------------------------------------------
# TEST GROUP 1: Module file existence checks
# Validate all five module files exist before trying to load any of them.
# -----------------------------------------------------------------------------
Write-TestSectionHeader "Group 1: Module File Existence"

$moduleFiles = @(
    "Get-AuthenticationEvents.ps1",
    "Get-ServiceEvents.ps1",
    "Get-PrivilegeEvents.ps1",
    "Get-SystemHealthEvents.ps1",
    "Get-ScheduledTaskEvents.ps1"
)

foreach ($file in $moduleFiles) {
    $filePath = Join-Path $ModulesDir $file
    Assert-True "Module file exists: $file" `
        -Condition (Test-Path $filePath) `
        -FailMessage "Expected file not found at: $filePath"
}

# -----------------------------------------------------------------------------
# TEST GROUP 2: Configuration file existence
# -----------------------------------------------------------------------------
Write-TestSectionHeader "Group 2: Configuration File Existence"

$configFile = Join-Path $ConfigDir "windows-monitor.conf.ps1"
Assert-True "Configuration file exists" `
    -Condition (Test-Path $configFile) `
    -FailMessage "Expected at: $configFile"

# -----------------------------------------------------------------------------
# TEST GROUP 3: Module syntax validation
# Uses the PowerShell parser API to validate syntax without executing.
# This catches bracket mismatches, unclosed strings, and invalid tokens
# before attempting to dot-source any module.
# -----------------------------------------------------------------------------
Write-TestSectionHeader "Group 3: PowerShell Syntax Validation"

foreach ($file in $moduleFiles) {
    $filePath = Join-Path $ModulesDir $file
    if (Test-Path $filePath) {
        $parseErrors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile(
            $filePath, [ref]$null, [ref]$parseErrors
        )
        Assert-True "Syntax valid: $file" `
            -Condition ($parseErrors.Count -eq 0) `
            -FailMessage "Parse errors: $($parseErrors | ForEach-Object { $_.Message } | Join-String -Separator '; ')"
    }
}

# Also validate the config file syntax
if (Test-Path $configFile) {
    $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        $configFile, [ref]$null, [ref]$parseErrors
    )
    Assert-True "Syntax valid: windows-monitor.conf.ps1" `
        -Condition ($parseErrors.Count -eq 0) `
        -FailMessage "Parse errors: $($parseErrors | ForEach-Object { $_.Message } | Join-String -Separator '; ')"
}

# -----------------------------------------------------------------------------
# TEST GROUP 4: Authentication module structural validation
# -----------------------------------------------------------------------------
Write-TestSectionHeader "Group 4: Get-AuthenticationEvents — Structural Validation"

$authModulePath = Join-Path $ModulesDir "Get-AuthenticationEvents.ps1"
if (Test-Path $authModulePath) {
    try {
        . $authModulePath

        $authResult = Get-AuthenticationEvents `
            -StartTime  $TestStartTime `
            -EndTime    $TestEndTime `
            -Config     $MockConfig `
            -Logger     $MockLogger

        Test-StandardResultStructure -ModuleName "Get-AuthenticationEvents" `
                                     -Result $authResult `
                                     -ExpectedCategory "Authentication"

        # Authentication-specific properties
        Assert-PropertyExists "Auth — has FailuresByAccount property" $authResult "FailuresByAccount"
        Assert-PropertyExists "Auth — has FailuresBySource property" $authResult "FailuresBySource"

        Assert-True "Auth — FailuresByAccount is hashtable" `
            -Condition ($authResult.FailuresByAccount -is [hashtable]) `
            -FailMessage "FailuresByAccount is not a hashtable"

        Assert-True "Auth — FailuresBySource is hashtable" `
            -Condition ($authResult.FailuresBySource -is [hashtable]) `
            -FailMessage "FailuresBySource is not a hashtable"

    }
    catch {
        $script:TestsFailed++
        Write-Host "  FAIL  Get-AuthenticationEvents threw an unhandled exception: $($_.Exception.Message)" -ForegroundColor Red
    }
}
else {
    Write-Host "  SKIP  Module file not found — skipping Group 4" -ForegroundColor Yellow
}

# -----------------------------------------------------------------------------
# TEST GROUP 5: Service module structural validation
# -----------------------------------------------------------------------------
Write-TestSectionHeader "Group 5: Get-ServiceEvents — Structural Validation"

$serviceModulePath = Join-Path $ModulesDir "Get-ServiceEvents.ps1"
if (Test-Path $serviceModulePath) {
    try {
        . $serviceModulePath

        $serviceResult = Get-ServiceEvents `
            -StartTime  $TestStartTime `
            -EndTime    $TestEndTime `
            -Config     $MockConfig `
            -Logger     $MockLogger

        Test-StandardResultStructure -ModuleName "Get-ServiceEvents" `
                                     -Result $serviceResult `
                                     -ExpectedCategory "Services"

        Assert-PropertyExists "Services — has FailedServices property" $serviceResult "FailedServices"
        Assert-PropertyExists "Services — has CrashLoops property" $serviceResult "CrashLoops"

        Assert-True "Services — FailedServices is hashtable" `
            -Condition ($serviceResult.FailedServices -is [hashtable]) `
            -FailMessage "FailedServices is not a hashtable"

        Assert-True "Services — CrashLoops is enumerable" `
            -Condition ($serviceResult.CrashLoops -is [System.Collections.IEnumerable]) `
            -FailMessage "CrashLoops is not enumerable"

    }
    catch {
        $script:TestsFailed++
        Write-Host "  FAIL  Get-ServiceEvents threw an unhandled exception: $($_.Exception.Message)" -ForegroundColor Red
    }
}
else {
    Write-Host "  SKIP  Module file not found — skipping Group 5" -ForegroundColor Yellow
}

# -----------------------------------------------------------------------------
# TEST GROUP 6: Privilege module structural validation
# -----------------------------------------------------------------------------
Write-TestSectionHeader "Group 6: Get-PrivilegeEvents — Structural Validation"

$privModulePath = Join-Path $ModulesDir "Get-PrivilegeEvents.ps1"
if (Test-Path $privModulePath) {
    try {
        . $privModulePath

        $privResult = Get-PrivilegeEvents `
            -StartTime  $TestStartTime `
            -EndTime    $TestEndTime `
            -Config     $MockConfig `
            -Logger     $MockLogger

        Test-StandardResultStructure -ModuleName "Get-PrivilegeEvents" `
                                     -Result $privResult `
                                     -ExpectedCategory "Privilege"

        Assert-PropertyExists "Privilege — has UnexpectedAdminLogons property" $privResult "UnexpectedAdminLogons"
        Assert-PropertyExists "Privilege — has GroupChangeSummary property" $privResult "GroupChangeSummary"

        Assert-True "Privilege — UnexpectedAdminLogons is enumerable" `
            -Condition ($privResult.UnexpectedAdminLogons -is [System.Collections.IEnumerable]) `
            -FailMessage "UnexpectedAdminLogons is not enumerable"

        Assert-True "Privilege — GroupChangeSummary is hashtable" `
            -Condition ($privResult.GroupChangeSummary -is [hashtable]) `
            -FailMessage "GroupChangeSummary is not a hashtable"

    }
    catch {
        $script:TestsFailed++
        Write-Host "  FAIL  Get-PrivilegeEvents threw an unhandled exception: $($_.Exception.Message)" -ForegroundColor Red
    }
}
else {
    Write-Host "  SKIP  Module file not found — skipping Group 6" -ForegroundColor Yellow
}

# -----------------------------------------------------------------------------
# TEST GROUP 7: System health module structural validation
# -----------------------------------------------------------------------------
Write-TestSectionHeader "Group 7: Get-SystemHealthEvents — Structural Validation"

$healthModulePath = Join-Path $ModulesDir "Get-SystemHealthEvents.ps1"
if (Test-Path $healthModulePath) {
    try {
        . $healthModulePath

        $healthResult = Get-SystemHealthEvents `
            -StartTime  $TestStartTime `
            -EndTime    $TestEndTime `
            -Config     $MockConfig `
            -Logger     $MockLogger

        Test-StandardResultStructure -ModuleName "Get-SystemHealthEvents" `
                                     -Result $healthResult `
                                     -ExpectedCategory "SystemHealth"

        Assert-PropertyExists "SystemHealth — has UnexpectedShutdowns property" $healthResult "UnexpectedShutdowns"
        Assert-PropertyExists "SystemHealth — has DiskErrorCount property" $healthResult "DiskErrorCount"

        Assert-True "SystemHealth — UnexpectedShutdowns is int" `
            -Condition ($healthResult.UnexpectedShutdowns -is [int]) `
            -FailMessage "UnexpectedShutdowns is not an integer"

        Assert-True "SystemHealth — DiskErrorCount is int" `
            -Condition ($healthResult.DiskErrorCount -is [int]) `
            -FailMessage "DiskErrorCount is not an integer"

    }
    catch {
        $script:TestsFailed++
        Write-Host "  FAIL  Get-SystemHealthEvents threw an unhandled exception: $($_.Exception.Message)" -ForegroundColor Red
    }
}
else {
    Write-Host "  SKIP  Module file not found — skipping Group 7" -ForegroundColor Yellow
}

# -----------------------------------------------------------------------------
# TEST GROUP 8: Scheduled task module structural validation
# -----------------------------------------------------------------------------
Write-TestSectionHeader "Group 8: Get-ScheduledTaskEvents — Structural Validation"

$taskModulePath = Join-Path $ModulesDir "Get-ScheduledTaskEvents.ps1"
if (Test-Path $taskModulePath) {
    try {
        . $taskModulePath

        $taskResult = Get-ScheduledTaskEvents `
            -StartTime  $TestStartTime `
            -EndTime    $TestEndTime `
            -Config     $MockConfig `
            -Logger     $MockLogger

        Test-StandardResultStructure -ModuleName "Get-ScheduledTaskEvents" `
                                     -Result $taskResult `
                                     -ExpectedCategory "ScheduledTasks"

        Assert-PropertyExists "ScheduledTasks — has RapidCreateDelete property" $taskResult "RapidCreateDelete"

        Assert-True "ScheduledTasks — RapidCreateDelete is enumerable" `
            -Condition ($taskResult.RapidCreateDelete -is [System.Collections.IEnumerable]) `
            -FailMessage "RapidCreateDelete is not enumerable"

    }
    catch {
        $script:TestsFailed++
        Write-Host "  FAIL  Get-ScheduledTaskEvents threw an unhandled exception: $($_.Exception.Message)" -ForegroundColor Red
    }
}
else {
    Write-Host "  SKIP  Module file not found — skipping Group 8" -ForegroundColor Yellow
}

# -----------------------------------------------------------------------------
# TEST GROUP 9: Logger integration validation
# Verify that modules actually call the logger — a module that silently
# ignores the logger parameter would not surface execution detail in the
# orchestrator's log file, making troubleshooting significantly harder.
# -----------------------------------------------------------------------------
Write-TestSectionHeader "Group 9: Logger Integration"

Assert-True "Logger was called during module executions" `
    -Condition ($LogCapture.Count -gt 0) `
    -FailMessage "Logger was never called — modules may not be calling the Logger parameter"

$infoMessages = $LogCapture | Where-Object { $_ -like "*[INFO]*" }
Assert-True "Logger received INFO-level messages" `
    -Condition ($infoMessages.Count -gt 0) `
    -FailMessage "No INFO-level log messages found — module start/complete messages may be missing"

Write-Host "  INFO  Total log messages captured during test run: $($LogCapture.Count)" -ForegroundColor Gray

# =============================================================================
# RESULTS SUMMARY
# =============================================================================

$totalTests = $script:TestsPassed + $script:TestsFailed

Write-Host ""
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host " Test Results Summary" -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host " Total tests:  $totalTests"
Write-Host " Passed:       $($script:TestsPassed)" -ForegroundColor Green
Write-Host " Failed:       $($script:TestsFailed)" -ForegroundColor $(if ($script:TestsFailed -gt 0) { "Red" } else { "Green" })
Write-Host "=============================================================" -ForegroundColor Cyan

if ($script:TestsFailed -gt 0) {
    Write-Host ""
    Write-Host " FAILED TESTS:" -ForegroundColor Red
    $script:TestResults | Where-Object { $_.Result -eq "FAIL" } | ForEach-Object {
        Write-Host "   - $($_.Name)" -ForegroundColor Red
        if ($_.Detail) {
            Write-Host "     $($_.Detail)" -ForegroundColor Yellow
        }
    }
}

Write-Host ""

exit $(if ($script:TestsFailed -gt 0) { 1 } else { 0 })