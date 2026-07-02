# =============================================================================
# Get-ServiceEvents.ps1
# ops-log-monitor — Windows Service Event Module
# =============================================================================
#
# PURPOSE:
#   Queries the Windows System and Application event logs for service-related
#   events within a specified time window. Detects service failures, unexpected
#   terminations, crash loops, and services that failed to start at boot.
#
# CALLED BY:
#   Invoke-LogMonitor.ps1 (orchestrator)
#
# INPUTS (parameters passed by orchestrator):
#   -StartTime   [DateTime]  Beginning of the monitoring window
#   -EndTime     [DateTime]  End of the monitoring window
#   -Config      [hashtable] Configuration values from windows-monitor.conf.ps1
#   -Logger      [scriptblock] Logging function from orchestrator
#
# OUTPUT:
#   [PSCustomObject] with the following structure:
#   {
#     Category        : "Services"
#     CollectedAt     : [DateTime]
#     WindowStart     : [DateTime]
#     WindowEnd       : [DateTime]
#     TotalEvents     : [int]
#     CritCount       : [int]
#     WarnCount       : [int]
#     InfoCount       : [int]
#     ModuleErrors    : [string[]]
#     Events          : [PSCustomObject[]]
#     FailedServices  : [hashtable]  (service name -> failure count)
#     CrashLoops      : [string[]]   (services that stopped/started 3+ times)
#   }
#
#   Each event object contains:
#   {
#     TimeCreated   : [DateTime]
#     EventId       : [int]
#     Severity      : "CRIT" | "WARN" | "INFO"
#     ServiceName   : [string]
#     DisplayName   : [string]
#     State         : [string]
#     IsSecurityRelevant : [bool]
#     Description   : [string]
#   }
#
# REQUIRED AUDIT POLICY:
#   No audit policy required — System and Application logs are always active.
#   Service Control Manager events are generated regardless of audit settings.
#
# =============================================================================

function Get-ServiceEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [DateTime]$StartTime,

        [Parameter(Mandatory = $true)]
        [DateTime]$EndTime,

        [Parameter(Mandatory = $true)]
        [hashtable]$Config,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Logger
    )

    # -------------------------------------------------------------------------
    # Initialize result object. All fields populated upfront so the
    # orchestrator always receives a consistent structure, even on early exit.
    # -------------------------------------------------------------------------
    $result = [PSCustomObject]@{
        Category       = "Services"
        CollectedAt    = Get-Date
        WindowStart    = $StartTime
        WindowEnd      = $EndTime
        TotalEvents    = 0
        CritCount      = 0
        WarnCount      = 0
        InfoCount      = 0
        ModuleErrors   = [System.Collections.Generic.List[string]]::new()
        Events         = [System.Collections.Generic.List[PSCustomObject]]::new()
        FailedServices = @{}
        CrashLoops     = [System.Collections.Generic.List[string]]::new()
    }

    & $Logger "INFO" "Services" "Module started. Window: $StartTime to $EndTime"

    # -------------------------------------------------------------------------
    # Build a lookup of security-relevant services from config for O(1) checks
    # during event processing. Converting the array to a HashSet avoids
    # repeated linear searches through the config array for every event.
    # -------------------------------------------------------------------------
    $securityRelevantSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($svc in $Config.SECURITY_RELEVANT_SERVICES) {
        [void]$securityRelevantSet.Add($svc)
    }

    # -------------------------------------------------------------------------
    # STEP 1: Query Event ID 7034 — Service terminated unexpectedly.
    #
    # This is the most operationally significant service event. It fires when
    # a running service stops without being deliberately stopped. It does not
    # fire for services stopped by an administrator or during a clean shutdown.
    # -------------------------------------------------------------------------
    & $Logger "INFO" "Services" "Querying Event ID 7034 (unexpected service termination)"

    try {
        $terminationFilter = @{
            LogName      = "System"
            Id           = 7034
            StartTime    = $StartTime
            EndTime      = $EndTime
        }

        $terminationEvents = Get-WinEvent -FilterHashtable $terminationFilter `
                                          -MaxEvents $Config.MONITORING_WINDOW_MAX_EVENTS `
                                          -ErrorAction Stop

        & $Logger "INFO" "Services" "Retrieved $($terminationEvents.Count) unexpected termination events"

        foreach ($event in $terminationEvents) {
            [xml]$eventXml = $event.ToXml()

            # Event 7034 has two data fields: ServiceName and RecoveryBehavior.
            # We extract ServiceName which is always the first data element.
            $serviceNameNode = $eventXml.Event.EventData.Data |
                               Select-Object -First 1
            $serviceName = if ($serviceNameNode) {
                $serviceNameNode.'#text'
            } else { "Unknown" }

            # Track failure counts per service to detect crash loops later.
            if (-not $result.FailedServices.ContainsKey($serviceName)) {
                $result.FailedServices[$serviceName] = 0
            }
            $result.FailedServices[$serviceName]++

            $isSecurityRelevant = $securityRelevantSet.Contains($serviceName)

            # Security-relevant services terminating unexpectedly are CRIT
            # because their failure could disable a defensive control.
            # All other unexpected terminations are WARN.
            $severity = if ($isSecurityRelevant) { "CRIT" } else { "WARN" }

            $eventObj = [PSCustomObject]@{
                TimeCreated        = $event.TimeCreated
                EventId            = 7034
                Severity           = $severity
                ServiceName        = $serviceName
                DisplayName        = $serviceName
                State              = "Terminated Unexpectedly"
                IsSecurityRelevant = $isSecurityRelevant
                Description        = "Service '$serviceName' terminated unexpectedly" +
                                     $(if ($isSecurityRelevant) {
                                         " — SECURITY-RELEVANT SERVICE"
                                     } else { "" })
            }

            $result.Events.Add($eventObj)
        }
    }
    catch {
        if ($_.Exception.Message -like "*No events were found*") {
            & $Logger "INFO" "Services" "No unexpected termination events found in window"
        }
        else {
            $errorMsg = "Failed to query Event ID 7034: $($_.Exception.Message)"
            & $Logger "ERROR" "Services" $errorMsg
            $result.ModuleErrors.Add($errorMsg)
        }
    }

    # -------------------------------------------------------------------------
    # STEP 2: Query Event ID 7000 — Service failed to start.
    #
    # Generated during system startup when the Service Control Manager cannot
    # start a configured service. Differs from 7034 in that the service never
    # reached a running state — it failed on the way up.
    # -------------------------------------------------------------------------
    & $Logger "INFO" "Services" "Querying Event ID 7000 (service failed to start)"

    try {
        $startFailFilter = @{
            LogName   = "System"
            Id        = 7000
            StartTime = $StartTime
            EndTime   = $EndTime
        }

        $startFailEvents = Get-WinEvent -FilterHashtable $startFailFilter `
                                        -MaxEvents $Config.MONITORING_WINDOW_MAX_EVENTS `
                                        -ErrorAction Stop

        & $Logger "INFO" "Services" "Retrieved $($startFailEvents.Count) start failure events"

        foreach ($event in $startFailEvents) {
            [xml]$eventXml = $event.ToXml()

            # Event 7000 data fields: ServiceName, ErrorDescription
            $dataNodes   = $eventXml.Event.EventData.Data
            $serviceName = if ($dataNodes[0]) { $dataNodes[0].'#text' } else { "Unknown" }
            $errorDesc   = if ($dataNodes[1]) { $dataNodes[1].'#text' } else { "Unknown error" }

            $isSecurityRelevant = $securityRelevantSet.Contains($serviceName)
            $severity = if ($isSecurityRelevant) { "CRIT" } else { "WARN" }

            $eventObj = [PSCustomObject]@{
                TimeCreated        = $event.TimeCreated
                EventId            = 7000
                Severity           = $severity
                ServiceName        = $serviceName
                DisplayName        = $serviceName
                State              = "Failed to Start"
                IsSecurityRelevant = $isSecurityRelevant
                Description        = "Service '$serviceName' failed to start: $errorDesc"
            }

            $result.Events.Add($eventObj)
        }
    }
    catch {
        if ($_.Exception.Message -like "*No events were found*") {
            & $Logger "INFO" "Services" "No start failure events found in window"
        }
        else {
            $errorMsg = "Failed to query Event ID 7000: $($_.Exception.Message)"
            & $Logger "ERROR" "Services" $errorMsg
            $result.ModuleErrors.Add($errorMsg)
        }
    }

    # -------------------------------------------------------------------------
    # STEP 3: Query Event ID 7036 — Service entered a state (selective).
    #
    # Event 7036 fires for every service state change. We do not report all
    # of them — that would produce enormous noise. We collect them only to
    # identify crash loops: services that cycled between running and stopped
    # three or more times within the monitoring window.
    #
    # A service that crash-loops is more concerning than one that crashes once,
    # because crash loops indicate a persistent problem that recovery actions
    # are not resolving, and they can destabilize the system.
    # -------------------------------------------------------------------------
    & $Logger "INFO" "Services" "Querying Event ID 7036 (service state changes) for crash loop detection"

    try {
        $stateChangeFilter = @{
            LogName   = "System"
            Id        = 7036
            StartTime = $StartTime
            EndTime   = $EndTime
        }

        $stateChangeEvents = Get-WinEvent -FilterHashtable $stateChangeFilter `
                                          -MaxEvents $Config.MONITORING_WINDOW_MAX_EVENTS `
                                          -ErrorAction Stop

        & $Logger "INFO" "Services" "Retrieved $($stateChangeEvents.Count) state change events for analysis"

        # Count state transitions per service. Each stop event increments the
        # counter. Three or more stops within the window indicates a crash loop.
        $stopCounts = @{}

        foreach ($event in $stateChangeEvents) {
            [xml]$eventXml   = $event.ToXml()
            $dataNodes       = $eventXml.Event.EventData.Data
            $serviceName     = if ($dataNodes[0]) { $dataNodes[0].'#text' } else { "Unknown" }
            $newState        = if ($dataNodes[1]) { $dataNodes[1].'#text' } else { "Unknown" }

            # Only count "stopped" transitions, not "running" transitions.
            # We want to know how many times the service fell over, not how
            # many times it recovered.
            if ($newState -like "*stopped*") {
                if (-not $stopCounts.ContainsKey($serviceName)) {
                    $stopCounts[$serviceName] = 0
                }
                $stopCounts[$serviceName]++
            }
        }

        # Any service that stopped three or more times in the window is a
        # crash loop. Report it as a synthetic CRIT event summarizing the
        # behavior rather than individual 7036 events (which would be noisy).
        $crashLoopThreshold = 3

        foreach ($svcName in $stopCounts.Keys) {
            if ($stopCounts[$svcName] -ge $crashLoopThreshold) {
                $result.CrashLoops.Add($svcName)
                $isSecurityRelevant = $securityRelevantSet.Contains($svcName)

                $eventObj = [PSCustomObject]@{
                    TimeCreated        = $EndTime
                    EventId            = 7036
                    Severity           = "CRIT"
                    ServiceName        = $svcName
                    DisplayName        = $svcName
                    State              = "Crash Loop Detected"
                    IsSecurityRelevant = $isSecurityRelevant
                    Description        = "Service '$svcName' stopped $($stopCounts[$svcName]) " +
                                         "times within the monitoring window — crash loop detected"
                }

                $result.Events.Add($eventObj)
                & $Logger "WARN" "Services" "Crash loop detected: '$svcName' stopped $($stopCounts[$svcName]) times"
            }
        }
    }
    catch {
        if ($_.Exception.Message -like "*No events were found*") {
            & $Logger "INFO" "Services" "No service state change events found in window"
        }
        else {
            $errorMsg = "Failed to query Event ID 7036: $($_.Exception.Message)"
            & $Logger "ERROR" "Services" $errorMsg
            $result.ModuleErrors.Add($errorMsg)
        }
    }

    # -------------------------------------------------------------------------
    # STEP 4: Query Application Event IDs 1000 and 1001 (Application crashes).
    #
    # Event 1000 fires when Windows Error Reporting catches an application
    # crash. Event 1001 is the companion event confirming crash dump collection.
    # We query both in one pass and link them by the process name and time.
    # -------------------------------------------------------------------------
    & $Logger "INFO" "Services" "Querying Event IDs 1000/1001 (application crashes)"

    # Build a HashSet of security-relevant processes for O(1) lookup.
    $securityProcessSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($proc in $Config.SECURITY_RELEVANT_PROCESSES) {
        [void]$securityProcessSet.Add($proc)
    }

    try {
        $crashFilter = @{
            LogName   = "Application"
            Id        = @(1000, 1001)
            StartTime = $StartTime
            EndTime   = $EndTime
        }

        $crashEvents = Get-WinEvent -FilterHashtable $crashFilter `
                                    -MaxEvents $Config.MONITORING_WINDOW_MAX_EVENTS `
                                    -ErrorAction Stop

        & $Logger "INFO" "Services" "Retrieved $($crashEvents.Count) application crash events"

        foreach ($event in $crashEvents) {
            [xml]$eventXml = $event.ToXml()
            $dataNodes     = $eventXml.Event.EventData.Data

            if ($event.Id -eq 1000) {
                # Event 1000 data fields (in order):
                # 0: Application name
                # 1: Application version
                # 2: Application timestamp
                # 3: Fault module name
                # 4: Fault module version
                # 5: Fault module timestamp
                # 6: Exception code
                # 7: Fault offset
                # 8: Process ID
                # 9: Application start time
                # 10: Application path
                # 11: Fault module path
                $appName      = if ($dataNodes[0]) { $dataNodes[0].'#text' } else { "Unknown" }
                $appVersion   = if ($dataNodes[1]) { $dataNodes[1].'#text' } else { "Unknown" }
                $faultModule  = if ($dataNodes[3]) { $dataNodes[3].'#text' } else { "Unknown" }
                $exceptionCode = if ($dataNodes[6]) { $dataNodes[6].'#text' } else { "Unknown" }

                $isSecurityRelevant = $securityProcessSet.Contains($appName)
                $severity = if ($isSecurityRelevant) { "CRIT" } else { "WARN" }

                $eventObj = [PSCustomObject]@{
                    TimeCreated        = $event.TimeCreated
                    EventId            = 1000
                    Severity           = $severity
                    ServiceName        = $appName
                    DisplayName        = "$appName v$appVersion"
                    State              = "Crashed"
                    IsSecurityRelevant = $isSecurityRelevant
                    Description        = "Application '$appName' (v$appVersion) crashed. " +
                                         "Fault module: $faultModule. " +
                                         "Exception: $exceptionCode" +
                                         $(if ($isSecurityRelevant) {
                                             " — SECURITY-RELEVANT PROCESS"
                                         } else { "" })
                }

                $result.Events.Add($eventObj)
            }
            elseif ($event.Id -eq 1001) {
                # Event 1001: crash dump collected. Report the dump path so
                # investigators know where to find it without querying WER.
                $appName  = if ($dataNodes[0]) { $dataNodes[0].'#text' } else { "Unknown" }
                $dumpPath = if ($dataNodes.Count -gt 2) {
                    $dataNodes[2].'#text'
                } else { "Path not recorded" }

                $isSecurityRelevant = $securityProcessSet.Contains($appName)

                $eventObj = [PSCustomObject]@{
                    TimeCreated        = $event.TimeCreated
                    EventId            = 1001
                    Severity           = "INFO"
                    ServiceName        = $appName
                    DisplayName        = $appName
                    State              = "Crash Dump Collected"
                    IsSecurityRelevant = $isSecurityRelevant
                    Description        = "Crash dump collected for '$appName'. " +
                                         "Dump path: $dumpPath"
                }

                $result.Events.Add($eventObj)
            }
        }
    }
    catch {
        if ($_.Exception.Message -like "*No events were found*") {
            & $Logger "INFO" "Services" "No application crash events found in window"
        }
        else {
            $errorMsg = "Failed to query Event IDs 1000/1001: $($_.Exception.Message)"
            & $Logger "ERROR" "Services" $errorMsg
            $result.ModuleErrors.Add($errorMsg)
        }
    }

    # -------------------------------------------------------------------------
    # STEP 5: Finalize — sort events chronologically and calculate counts.
    # -------------------------------------------------------------------------
    $sortedEvents = $result.Events | Sort-Object TimeCreated
    $result.Events = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($e in $sortedEvents) { $result.Events.Add($e) }

    $result.TotalEvents = $result.Events.Count
    $result.CritCount   = ($result.Events | Where-Object { $_.Severity -eq "CRIT" }).Count
    $result.WarnCount   = ($result.Events | Where-Object { $_.Severity -eq "WARN" }).Count
    $result.InfoCount   = ($result.Events | Where-Object { $_.Severity -eq "INFO" }).Count

    & $Logger "INFO" "Services" (
        "Module complete. Total: $($result.TotalEvents) " +
        "CRIT: $($result.CritCount) " +
        "WARN: $($result.WarnCount) " +
        "INFO: $($result.InfoCount)"
    )

    return $result
}