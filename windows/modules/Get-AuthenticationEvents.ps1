# =============================================================================
# Get-AuthenticationEvents.ps1
# ops-log-monitor — Windows Authentication Event Module
# =============================================================================
#
# PURPOSE:
#   Queries the Windows Security event log for authentication-related events
#   within a specified time window. Returns structured objects representing
#   logon failures, account lockouts, and after-hours successful logons.
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
#     Category        : "Authentication"
#     CollectedAt     : [DateTime]
#     WindowStart     : [DateTime]
#     WindowEnd       : [DateTime]
#     TotalEvents     : [int]
#     CritCount       : [int]
#     WarnCount       : [int]
#     InfoCount       : [int]
#     ModuleErrors    : [string[]]
#     Events          : [PSCustomObject[]]  (see event object structure below)
#     FailuresByAccount : [hashtable]
#     FailuresBySource  : [hashtable]
#   }
#
#   Each event object contains:
#   {
#     TimeCreated   : [DateTime]
#     EventId       : [int]
#     Severity      : "CRIT" | "WARN" | "INFO"
#     Account       : [string]
#     SourceIP      : [string]
#     SourceHost    : [string]
#     LogonType     : [int]
#     LogonTypeName : [string]
#     FailureReason : [string]
#     Description   : [string]
#   }
#
# REQUIRED AUDIT POLICY:
#   Logon/Logoff > Audit Logon: Success and Failure
#   Account Management > Audit User Account Management: Success and Failure
#   Verify with: auditpol /get /subcategory:"Logon"
#
# =============================================================================

function Get-AuthenticationEvents {
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
    # Initialize the result object that will be returned to the orchestrator.
    # Pre-populating all fields ensures the orchestrator can always access
    # expected properties even if the module exits early due to an error.
    # -------------------------------------------------------------------------
    $result = [PSCustomObject]@{
        Category          = "Authentication"
        CollectedAt       = Get-Date
        WindowStart       = $StartTime
        WindowEnd         = $EndTime
        TotalEvents       = 0
        CritCount         = 0
        WarnCount         = 0
        InfoCount         = 0
        ModuleErrors      = [System.Collections.Generic.List[string]]::new()
        Events            = [System.Collections.Generic.List[PSCustomObject]]::new()
        FailuresByAccount = @{}
        FailuresBySource  = @{}
    }

    & $Logger "INFO" "Authentication" "Module started. Window: $StartTime to $EndTime"

    # -------------------------------------------------------------------------
    # Build a human-readable map of logon type codes to names.
    # This is used to make the report readable without requiring the reviewer
    # to look up logon type numbers. These codes are defined by Windows and
    # do not change between versions.
    # -------------------------------------------------------------------------
    $logonTypeNames = @{
        2  = "Interactive"
        3  = "Network"
        4  = "Batch"
        5  = "Service"
        7  = "Unlock"
        8  = "NetworkCleartext"
        9  = "NewCredentials"
        10 = "RemoteInteractive"
        11 = "CachedInteractive"
        12 = "CachedRemoteInteractive"
        13 = "CachedUnlock"
    }

    # -------------------------------------------------------------------------
    # Map Windows authentication failure substatus codes to human-readable
    # descriptions. The substatus code in Event ID 4625 is more specific than
    # the status code and tells us why the authentication failed.
    # These codes come from Microsoft's authentication error documentation.
    # -------------------------------------------------------------------------
    $failureReasonMap = @{
        "0xC000006A" = "Incorrect password"
        "0xC0000064" = "Account does not exist"
        "0xC000006D" = "Generic logon failure"
        "0xC000006F" = "Logon outside permitted hours"
        "0xC0000070" = "Logon from unauthorized workstation"
        "0xC0000071" = "Password expired"
        "0xC0000072" = "Account disabled"
        "0xC0000193" = "Account expired"
        "0xC0000224" = "Password change required"
        "0xC0000234" = "Account locked out"
        "0xC0000413" = "Authentication firewall restriction"
    }

    # -------------------------------------------------------------------------
    # STEP 1: Query Event ID 4625 (Logon Failure)
    #
    # We use Get-WinEvent with a hashtable filter rather than -FilterXML
    # because the hashtable filter is simpler to read and maintain.
    # For very large event logs, -FilterXML with XPath would be faster,
    # but the hashtable approach is readable and correct for this use case.
    # -------------------------------------------------------------------------
    & $Logger "INFO" "Authentication" "Querying Event ID 4625 (logon failures)"

    try {
        $failureFilter = @{
            LogName   = "Security"
            Id        = 4625
            StartTime = $StartTime
            EndTime   = $EndTime
        }

        # Get-WinEvent returns events newest-first by default.
        # MaxEvents limits total retrieval to prevent memory exhaustion on
        # systems with extremely high failure rates (active brute force).
        $failureEvents = Get-WinEvent -FilterHashtable $failureFilter `
                                      -MaxEvents $Config.MONITORING_WINDOW_MAX_EVENTS `
                                      -ErrorAction Stop

        & $Logger "INFO" "Authentication" "Retrieved $($failureEvents.Count) logon failure events"

        foreach ($event in $failureEvents) {
            # Extract structured fields from the event's XML payload.
            # Get-WinEvent returns events with named properties accessible
            # via the .Properties array, but XML parsing is more reliable
            # because property array indices can shift between event versions.
            [xml]$eventXml = $event.ToXml()
            $eventData = $eventXml.Event.EventData.Data

            # Helper to extract a named field from the event XML data.
            # EventData fields are stored as <Data Name="FieldName">value</Data>
            function Get-EventField {
                param([xml]$xml, [string]$fieldName)
                $node = $xml.Event.EventData.Data | Where-Object { $_.Name -eq $fieldName }
                if ($node) { return $node.'#text' } else { return "" }
            }

            $subjectAccount  = Get-EventField $eventXml "TargetUserName"
            $sourceIP        = Get-EventField $eventXml "IpAddress"
            $sourceHost      = Get-EventField $eventXml "WorkstationName"
            $logonTypeRaw    = Get-EventField $eventXml "LogonType"
            $subStatusCode   = Get-EventField $eventXml "SubStatus"

            # Convert logon type to integer for comparison against config
            $logonTypeInt = 0
            if ($logonTypeRaw -match '^\d+$') {
                $logonTypeInt = [int]$logonTypeRaw
            }

            # Skip logon types not in the configured monitoring list.
            # This prevents high-volume network logon failures (Type 3) from
            # flooding the report if Type 3 monitoring is not enabled.
            if ($Config.AUTH_MONITOR_LOGON_TYPES -notcontains $logonTypeInt) {
                continue
            }

            # Clean up placeholder values that Windows inserts when a field
            # has no meaningful value. "-" and "-\-" are common placeholders.
            if ($sourceIP -in @("-", "::1", "127.0.0.1", "")) { $sourceIP = "local" }
            if ($sourceHost -in @("-", "")) { $sourceHost = "unknown" }
            if ($subjectAccount -in @("-", "")) { $subjectAccount = "unknown" }

            # Translate the substatus hex code to a human-readable reason.
            $failureReason = "Unknown"
            if ($failureReasonMap.ContainsKey($subStatusCode)) {
                $failureReason = $failureReasonMap[$subStatusCode]
            }

            # Track failure counts per account and per source for threshold
            # evaluation after all events have been processed.
            if ($subjectAccount -ne "unknown") {
                if (-not $result.FailuresByAccount.ContainsKey($subjectAccount)) {
                    $result.FailuresByAccount[$subjectAccount] = 0
                }
                $result.FailuresByAccount[$subjectAccount]++
            }

            if ($sourceIP -ne "local") {
                if (-not $result.FailuresBySource.ContainsKey($sourceIP)) {
                    $result.FailuresBySource[$sourceIP] = 0
                }
                $result.FailuresBySource[$sourceIP]++
            }

            # Initial severity is WARN for any logon failure. Severity will
            # be upgraded to CRIT after threshold evaluation below.
            $severity = "WARN"

            $logonTypeName = if ($logonTypeNames.ContainsKey($logonTypeInt)) {
                $logonTypeNames[$logonTypeInt]
            } else {
                "Type$logonTypeInt"
            }

            $eventObj = [PSCustomObject]@{
                TimeCreated   = $event.TimeCreated
                EventId       = 4625
                Severity      = $severity
                Account       = $subjectAccount
                SourceIP      = $sourceIP
                SourceHost    = $sourceHost
                LogonType     = $logonTypeInt
                LogonTypeName = $logonTypeName
                FailureReason = $failureReason
                Description   = "Logon failure ($logonTypeName) for '$subjectAccount' from $sourceIP — $failureReason"
            }

            $result.Events.Add($eventObj)
        }
    }
    catch [System.Exception] {
        # Distinguish between "no events found" (not an error) and a genuine
        # query failure. Get-WinEvent throws a non-terminating error when no
        # events match the filter; we catch it here to handle it cleanly.
        if ($_.Exception.Message -like "*No events were found*") {
            & $Logger "INFO" "Authentication" "No logon failure events found in window"
        }
        else {
            $errorMsg = "Failed to query Event ID 4625: $($_.Exception.Message)"
            & $Logger "ERROR" "Authentication" $errorMsg
            $result.ModuleErrors.Add($errorMsg)
        }
    }

    # -------------------------------------------------------------------------
    # STEP 2: Apply threshold-based severity escalation.
    #
    # Now that all failure events have been collected and counted, we can
    # apply the configured thresholds to determine which accounts and sources
    # represent significant attack activity rather than routine user error.
    # We upgrade the severity on the individual event objects so the report
    # renders them at the correct severity level.
    # -------------------------------------------------------------------------
    & $Logger "INFO" "Authentication" "Applying threshold-based severity escalation"

    foreach ($eventObj in $result.Events | Where-Object { $_.EventId -eq 4625 }) {
        $accountFailures = $result.FailuresByAccount[$eventObj.Account]
        $sourceFailures  = $result.FailuresBySource[$eventObj.SourceIP]

        if ($accountFailures -ge $Config.AUTH_FAILURE_CRIT_THRESHOLD -or
            $sourceFailures  -ge $Config.AUTH_SOURCE_CRIT_THRESHOLD) {
            $eventObj.Severity = "CRIT"
        }
        elseif ($accountFailures -ge $Config.AUTH_FAILURE_WARN_THRESHOLD -or
                $sourceFailures  -ge $Config.AUTH_SOURCE_WARN_THRESHOLD) {
            $eventObj.Severity = "WARN"
        }
        else {
            # Below both thresholds — single or low-count failure, likely
            # user error. Report at INFO to maintain a complete record without
            # flagging it as requiring action.
            $eventObj.Severity = "INFO"
        }
    }

    # -------------------------------------------------------------------------
    # STEP 3: Query Event ID 4740 (Account Lockout)
    #
    # Lockouts are always CRIT. Every lockout requires investigation to
    # determine whether it was caused by user error (stale cached credential),
    # an automated attack, or a policy misconfiguration.
    # -------------------------------------------------------------------------
    & $Logger "INFO" "Authentication" "Querying Event ID 4740 (account lockouts)"

    try {
        $lockoutFilter = @{
            LogName   = "Security"
            Id        = 4740
            StartTime = $StartTime
            EndTime   = $EndTime
        }

        $lockoutEvents = Get-WinEvent -FilterHashtable $lockoutFilter `
                                      -MaxEvents $Config.MONITORING_WINDOW_MAX_EVENTS `
                                      -ErrorAction Stop

        & $Logger "INFO" "Authentication" "Retrieved $($lockoutEvents.Count) lockout events"

        foreach ($event in $lockoutEvents) {
            [xml]$eventXml = $event.ToXml()

            function Get-EventField2 {
                param([xml]$xml, [string]$fieldName)
                $node = $xml.Event.EventData.Data | Where-Object { $_.Name -eq $fieldName }
                if ($node) { return $node.'#text' } else { return "" }
            }

            $lockedAccount   = Get-EventField2 $eventXml "TargetUserName"
            $callerComputer  = Get-EventField2 $eventXml "CallerComputerName"

            if ($lockedAccount -in @("-", "")) { $lockedAccount = "unknown" }
            if ($callerComputer -in @("-", "")) { $callerComputer = "unknown" }

            $eventObj = [PSCustomObject]@{
                TimeCreated   = $event.TimeCreated
                EventId       = 4740
                Severity      = "CRIT"
                Account       = $lockedAccount
                SourceIP      = "N/A"
                SourceHost    = $callerComputer
                LogonType     = 0
                LogonTypeName = "N/A"
                FailureReason = "Account locked out"
                Description   = "Account '$lockedAccount' was locked out. " +
                                "Lockout observed on: $callerComputer"
            }

            $result.Events.Add($eventObj)
        }
    }
    catch {
        if ($_.Exception.Message -like "*No events were found*") {
            & $Logger "INFO" "Authentication" "No lockout events found in window"
        }
        else {
            $errorMsg = "Failed to query Event ID 4740: $($_.Exception.Message)"
            & $Logger "ERROR" "Authentication" $errorMsg
            $result.ModuleErrors.Add($errorMsg)
        }
    }

    # -------------------------------------------------------------------------
    # STEP 4: Query Event ID 4624 (Successful Logon) — selective use only.
    #
    # We do not report every successful logon. This would generate enormous
    # volume and noise. We use 4624 for two specific purposes:
    #   (a) Detect after-hours interactive logons (types 2 and 10)
    #   (b) Flag accounts that succeeded after prior failures in this window
    #       (possible successful brute force completion)
    # -------------------------------------------------------------------------
    if ($Config.ENFORCE_BUSINESS_HOURS) {
        & $Logger "INFO" "Authentication" "Querying Event ID 4624 for after-hours detection"

        try {
            $successFilter = @{
                LogName   = "Security"
                Id        = 4624
                StartTime = $StartTime
                EndTime   = $EndTime
            }

            # Only retrieve interactive and RDP logons to limit volume.
            # We filter by logon type after retrieval because Get-WinEvent
            # hashtable filters do not support EventData field filtering.
            $successEvents = Get-WinEvent -FilterHashtable $successFilter `
                                          -MaxEvents $Config.MONITORING_WINDOW_MAX_EVENTS `
                                          -ErrorAction Stop

            & $Logger "INFO" "Authentication" "Retrieved $($successEvents.Count) successful logon events for after-hours analysis"

            $interactiveTypes = @(2, 10)  # Interactive and RemoteInteractive

            foreach ($event in $successEvents) {
                [xml]$eventXml = $event.ToXml()

                function Get-EventField3 {
                    param([xml]$xml, [string]$fieldName)
                    $node = $xml.Event.EventData.Data |
                            Where-Object { $_.Name -eq $fieldName }
                    if ($node) { return $node.'#text' } else { return "" }
                }

                $logonTypeRaw  = Get-EventField3 $eventXml "LogonType"
                $targetAccount = Get-EventField3 $eventXml "TargetUserName"
                $sourceIP      = Get-EventField3 $eventXml "IpAddress"

                $logonTypeInt = 0
                if ($logonTypeRaw -match '^\d+$') {
                    $logonTypeInt = [int]$logonTypeRaw
                }

                # Skip non-interactive logon types for after-hours detection.
                # Service and network logons occur continuously and are not
                # meaningful for after-hours analysis.
                if ($interactiveTypes -notcontains $logonTypeInt) { continue }

                # Skip system accounts that legitimately log on at any hour.
                if ($targetAccount -in @("SYSTEM", "LOCAL SERVICE",
                                         "NETWORK SERVICE", "DWM-1",
                                         "UMFD-0", "UMFD-1", "-")) { continue }

                # Determine if this logon occurred outside business hours.
                $logonHour    = $event.TimeCreated.Hour
                $logonDayOfWeek = [int]$event.TimeCreated.DayOfWeek

                $isAfterHours = (
                    $Config.BUSINESS_DAYS -notcontains $logonDayOfWeek -or
                    $logonHour -lt $Config.BUSINESS_HOURS_START -or
                    $logonHour -ge $Config.BUSINESS_HOURS_END
                )

                if (-not $isAfterHours) { continue }

                # Check if this account had failures earlier in this window.
                # A success after failures on the same account is a higher
                # severity finding than an after-hours logon alone.
                $hadPriorFailures = $result.FailuresByAccount.ContainsKey($targetAccount)

                if ($sourceIP -in @("-", "::1", "127.0.0.1", "")) {
                    $sourceIP = "local"
                }

                $logonTypeName = if ($logonTypeNames.ContainsKey($logonTypeInt)) {
                    $logonTypeNames[$logonTypeInt]
                } else { "Type$logonTypeInt" }

                $severity = if ($hadPriorFailures) { "CRIT" } else { "WARN" }

                $description = if ($hadPriorFailures) {
                    "After-hours $logonTypeName logon for '$targetAccount' from $sourceIP " +
                    "— PRECEDED BY FAILURES IN THIS WINDOW"
                } else {
                    "After-hours $logonTypeName logon for '$targetAccount' from $sourceIP"
                }

                $eventObj = [PSCustomObject]@{
                    TimeCreated   = $event.TimeCreated
                    EventId       = 4624
                    Severity      = $severity
                    Account       = $targetAccount
                    SourceIP      = $sourceIP
                    SourceHost    = "N/A"
                    LogonType     = $logonTypeInt
                    LogonTypeName = $logonTypeName
                    FailureReason = "After-hours logon"
                    Description   = $description
                }

                $result.Events.Add($eventObj)
            }
        }
        catch {
            if ($_.Exception.Message -like "*No events were found*") {
                & $Logger "INFO" "Authentication" "No successful logon events found in window"
            }
            else {
                $errorMsg = "Failed to query Event ID 4624: $($_.Exception.Message)"
                & $Logger "ERROR" "Authentication" $errorMsg
                $result.ModuleErrors.Add($errorMsg)
            }
        }
    }

    # -------------------------------------------------------------------------
    # STEP 5: Calculate summary counts and sort events chronologically.
    #
    # Events are sorted oldest-first so the report reads as a timeline.
    # Counts are used by the orchestrator to generate the report summary
    # section and to determine overall report severity.
    # -------------------------------------------------------------------------
    $sortedEvents = $result.Events | Sort-Object TimeCreated
    $result.Events = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($e in $sortedEvents) { $result.Events.Add($e) }

    $result.TotalEvents = $result.Events.Count
    $result.CritCount   = ($result.Events | Where-Object { $_.Severity -eq "CRIT" }).Count
    $result.WarnCount   = ($result.Events | Where-Object { $_.Severity -eq "WARN" }).Count
    $result.InfoCount   = ($result.Events | Where-Object { $_.Severity -eq "INFO" }).Count

    & $Logger "INFO" "Authentication" (
        "Module complete. Total: $($result.TotalEvents) " +
        "CRIT: $($result.CritCount) " +
        "WARN: $($result.WarnCount) " +
        "INFO: $($result.InfoCount)"
    )

    return $result
}