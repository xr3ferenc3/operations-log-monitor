# =============================================================================
# Get-SystemHealthEvents.ps1
# ops-log-monitor — Windows System Health Event Module
# =============================================================================
#
# PURPOSE:
#   Queries the Windows System and Application event logs for events
#   indicating hardware degradation, unexpected shutdowns, and disk-level
#   errors. These events provide early warning of failures before they
#   cause data loss or unplanned outages.
#
# CALLED BY:
#   Invoke-LogMonitor.ps1 (orchestrator)
#
# INPUTS:
#   -StartTime   [DateTime]    Beginning of the monitoring window
#   -EndTime     [DateTime]    End of the monitoring window
#   -Config      [hashtable]   Configuration values from windows-monitor.conf.ps1
#   -Logger      [scriptblock] Logging function from orchestrator
#
# OUTPUT:
#   [PSCustomObject] with the following structure:
#   {
#     Category            : "SystemHealth"
#     CollectedAt         : [DateTime]
#     WindowStart         : [DateTime]
#     WindowEnd           : [DateTime]
#     TotalEvents         : [int]
#     CritCount           : [int]
#     WarnCount           : [int]
#     InfoCount           : [int]
#     ModuleErrors        : [string[]]
#     Events              : [PSCustomObject[]]
#     UnexpectedShutdowns : [int]
#     DiskErrorCount      : [int]
#   }
#
#   Each event object contains:
#   {
#     TimeCreated   : [DateTime]
#     EventId       : [int]
#     Severity      : "CRIT" | "WARN" | "INFO"
#     Source        : [string]
#     Component     : [string]
#     Description   : [string]
#   }
#
# REQUIRED AUDIT POLICY:
#   None. System and Application log events used here are generated
#   regardless of audit policy configuration.
#
# =============================================================================

function Get-SystemHealthEvents {
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

    $result = [PSCustomObject]@{
        Category            = "SystemHealth"
        CollectedAt         = Get-Date
        WindowStart         = $StartTime
        WindowEnd           = $EndTime
        TotalEvents         = 0
        CritCount           = 0
        WarnCount           = 0
        InfoCount           = 0
        ModuleErrors        = [System.Collections.Generic.List[string]]::new()
        Events              = [System.Collections.Generic.List[PSCustomObject]]::new()
        UnexpectedShutdowns = 0
        DiskErrorCount      = 0
    }

    & $Logger "INFO" "SystemHealth" "Module started. Window: $StartTime to $EndTime"

    function Get-XmlEventField {
        param([xml]$Xml, [string]$FieldName)
        $node = $Xml.Event.EventData.Data | Where-Object { $_.Name -eq $FieldName }
        if ($node) { return $node.'#text' } else { return "" }
    }

    # -------------------------------------------------------------------------
    # STEP 1: Query Event ID 6008 — Previous system shutdown was unexpected.
    #
    # Generated at boot when Windows detects the prior shutdown did not
    # complete cleanly. Always reported at CRIT — unexpected shutdowns always
    # warrant investigation regardless of how many occur, because each one
    # represents either a hardware problem, a kernel-level failure, or a
    # forced power-off that bypassed normal shutdown procedures.
    # -------------------------------------------------------------------------
    & $Logger "INFO" "SystemHealth" "Querying Event ID 6008 (unexpected shutdown)"

    try {
        $shutdownFilter = @{
            LogName   = "System"
            Id        = 6008
            StartTime = $StartTime
            EndTime   = $EndTime
        }

        $shutdownEvents = Get-WinEvent -FilterHashtable $shutdownFilter `
                                       -MaxEvents $Config.MONITORING_WINDOW_MAX_EVENTS `
                                       -ErrorAction Stop

        & $Logger "INFO" "SystemHealth" "Retrieved $($shutdownEvents.Count) unexpected shutdown events"

        foreach ($event in $shutdownEvents) {
            $result.UnexpectedShutdowns++

            $eventObj = [PSCustomObject]@{
                TimeCreated = $event.TimeCreated
                EventId     = 6008
                Severity    = "CRIT"
                Source      = "EventLog"
                Component   = "System"
                Description = "The previous system shutdown was unexpected. " +
                              "This indicates a crash, power loss, or forced " +
                              "power-off. Investigate hardware health and " +
                              "review events immediately preceding this entry."
            }

            $result.Events.Add($eventObj)
        }
    }
    catch {
        if ($_.Exception.Message -like "*No events were found*") {
            & $Logger "INFO" "SystemHealth" "No unexpected shutdown events found in window"
        }
        else {
            $errorMsg = "Failed to query Event ID 6008: $($_.Exception.Message)"
            & $Logger "ERROR" "SystemHealth" $errorMsg
            $result.ModuleErrors.Add($errorMsg)
        }
    }

    # -------------------------------------------------------------------------
    # STEP 2: Query disk and storage controller errors.
    #
    # Disk errors are logged by multiple sources depending on the storage
    # stack: the "disk" source for traditional disk subsystem errors, and
    # "Ntfs" for filesystem-level errors. We query both because either can
    # appear independently depending on where in the storage stack the
    # error was detected.
    #
    # We use a level-based filter (Error and Warning) combined with a
    # provider name filter rather than specific event IDs, because disk
    # error event IDs vary by storage controller driver and are less
    # standardized than Service Control Manager event IDs.
    # -------------------------------------------------------------------------
    & $Logger "INFO" "SystemHealth" "Querying disk and filesystem error events"

    try {
        # FilterHashtable does not support an OR across ProviderName values
        # combined with a level filter in a single call reliably across all
        # PowerShell versions, so we query disk-related providers separately
        # and merge results. This is more verbose but more reliable than a
        # single complex XPath filter.
        $diskProviders = @("disk", "Ntfs", "volmgr", "volsnap")
        $diskEvents = @()

        foreach ($provider in $diskProviders) {
            try {
                $providerFilter = @{
                    LogName      = "System"
                    ProviderName = $provider
                    Level        = @(1, 2, 3)  # Critical, Error, Warning
                    StartTime    = $StartTime
                    EndTime      = $EndTime
                }

                $providerEvents = Get-WinEvent -FilterHashtable $providerFilter `
                                               -MaxEvents $Config.MONITORING_WINDOW_MAX_EVENTS `
                                               -ErrorAction Stop

                $diskEvents += $providerEvents
            }
            catch {
                # A provider not present on this system is expected and not
                # an error worth logging. Only log if it's not a "no events"
                # or "provider not found" condition.
                if ($_.Exception.Message -notlike "*No events were found*" -and
                    $_.Exception.Message -notlike "*provider*") {
                    & $Logger "WARN" "SystemHealth" "Provider '$provider' query issue: $($_.Exception.Message)"
                }
            }
        }

        & $Logger "INFO" "SystemHealth" "Retrieved $($diskEvents.Count) disk/filesystem events across all providers"

        foreach ($event in $diskEvents) {
            $result.DiskErrorCount++

            # Map Windows event Level to our severity scheme.
            # Level 1 = Critical, 2 = Error, 3 = Warning, 4 = Information
            $severity = switch ($event.Level) {
                1       { "CRIT" }
                2       { "CRIT" }
                3       { "WARN" }
                default { "INFO" }
            }

            $description = $event.Message
            if ([string]::IsNullOrWhiteSpace($description)) {
                $description = "Disk/filesystem event from provider '$($event.ProviderName)' " +
                               "(Event ID $($event.Id)). No message text available — " +
                               "this can occur if the provider's message resource DLL " +
                               "is not registered on the system generating the report."
            }

            # Truncate very long messages for report readability. Full message
            # remains available via Event Viewer using the EventId and timestamp.
            if ($description.Length -gt 300) {
                $description = $description.Substring(0, 300) + "... (truncated)"
            }

            $eventObj = [PSCustomObject]@{
                TimeCreated = $event.TimeCreated
                EventId     = $event.Id
                Severity    = $severity
                Source      = $event.ProviderName
                Component   = "Storage"
                Description = $description
            }

            $result.Events.Add($eventObj)
        }
    }
    catch {
        $errorMsg = "Failed to query disk/filesystem events: $($_.Exception.Message)"
        & $Logger "ERROR" "SystemHealth" $errorMsg
        $result.ModuleErrors.Add($errorMsg)
    }

    # -------------------------------------------------------------------------
    # STEP 3: Query critical and error-level events from the System log
    # that are not already covered by the disk providers above. This catches
    # hardware errors reported by other drivers — network adapters, storage
    # controllers using vendor-specific providers, memory errors reported via
    # WHEA (Windows Hardware Error Architecture), and similar.
    #
    # WHEA-Logger is particularly important: it reports hardware errors
    # detected by the CPU and chipset, including memory ECC errors and PCIe
    # bus errors, which are strong indicators of failing hardware.
    # -------------------------------------------------------------------------
    & $Logger "INFO" "SystemHealth" "Querying WHEA hardware error events"

    try {
        $wheaFilter = @{
            LogName      = "System"
            ProviderName = "Microsoft-Windows-WHEA-Logger"
            StartTime    = $StartTime
            EndTime      = $EndTime
        }

        $wheaEvents = Get-WinEvent -FilterHashtable $wheaFilter `
                                   -MaxEvents $Config.MONITORING_WINDOW_MAX_EVENTS `
                                   -ErrorAction Stop

        & $Logger "INFO" "SystemHealth" "Retrieved $($wheaEvents.Count) WHEA hardware error events"

        foreach ($event in $wheaEvents) {
            # WHEA errors are always significant — they originate from the
            # CPU/chipset hardware error reporting mechanism, not software.
            # Any WHEA event warrants CRIT severity and hardware investigation.
            $description = $event.Message
            if ([string]::IsNullOrWhiteSpace($description)) {
                $description = "WHEA hardware error reported (Event ID $($event.Id)). " +
                               "This indicates a hardware-level fault detected by " +
                               "the CPU or chipset error reporting mechanism. " +
                               "Run full hardware diagnostics."
            }
            if ($description.Length -gt 300) {
                $description = $description.Substring(0, 300) + "... (truncated)"
            }

            $eventObj = [PSCustomObject]@{
                TimeCreated = $event.TimeCreated
                EventId     = $event.Id
                Severity    = "CRIT"
                Source      = "WHEA-Logger"
                Component   = "Hardware"
                Description = $description
            }

            $result.Events.Add($eventObj)
        }
    }
    catch {
        if ($_.Exception.Message -like "*No events were found*") {
            & $Logger "INFO" "SystemHealth" "No WHEA hardware error events found in window"
        }
        else {
            # WHEA-Logger may not exist as a provider on virtual machines or
            # systems where the kernel hardware error reporting is not active.
            # This is expected and should not be treated as a module error.
            & $Logger "INFO" "SystemHealth" "WHEA-Logger provider not available or query issue: $($_.Exception.Message)"
        }
    }

    # -------------------------------------------------------------------------
    # STEP 4: Finalize — sort events and calculate summary counts.
    # -------------------------------------------------------------------------
    $sortedEvents = $result.Events | Sort-Object TimeCreated
    $result.Events = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($e in $sortedEvents) { $result.Events.Add($e) }

    $result.TotalEvents = $result.Events.Count
    $result.CritCount   = ($result.Events | Where-Object { $_.Severity -eq "CRIT" }).Count
    $result.WarnCount   = ($result.Events | Where-Object { $_.Severity -eq "WARN" }).Count
    $result.InfoCount   = ($result.Events | Where-Object { $_.Severity -eq "INFO" }).Count

    & $Logger "INFO" "SystemHealth" (
        "Module complete. Total: $($result.TotalEvents) " +
        "CRIT: $($result.CritCount) " +
        "WARN: $($result.WarnCount) " +
        "INFO: $($result.InfoCount) " +
        "UnexpectedShutdowns: $($result.UnexpectedShutdowns) " +
        "DiskErrors: $($result.DiskErrorCount)"
    )

    return $result
}