# =============================================================================
# Get-ScheduledTaskEvents.ps1
# ops-log-monitor — Windows Scheduled Task Event Module
# =============================================================================
#
# PURPOSE:
#   Queries the Windows Security event log for scheduled task creation,
#   modification, and deletion events. Scheduled tasks are a common
#   persistence mechanism used by attackers after gaining initial access,
#   making creation/modification activity an important detection signal.
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
#     Category           : "ScheduledTasks"
#     CollectedAt        : [DateTime]
#     WindowStart        : [DateTime]
#     WindowEnd          : [DateTime]
#     TotalEvents        : [int]
#     CritCount          : [int]
#     WarnCount          : [int]
#     InfoCount          : [int]
#     ModuleErrors       : [string[]]
#     Events             : [PSCustomObject[]]
#     RapidCreateDelete  : [string[]]  (tasks created and deleted in same window)
#   }
#
#   Each event object contains:
#   {
#     TimeCreated    : [DateTime]
#     EventId        : [int]
#     Severity       : "CRIT" | "WARN" | "INFO"
#     TaskName       : [string]
#     SubjectAccount : [string]
#     Action         : [string]  ("Created" | "Deleted" | "Modified")
#     TaskCommand    : [string]  (extracted command/executable path, if found)
#     IsTrustedPath  : [bool]
#     Description    : [string]
#   }
#
# REQUIRED AUDIT POLICY:
#   Object Access > Audit Other Object Access Events: Success
#   Verify with: auditpol /get /subcategory:"Other Object Access Events"
#
# OPERATIONAL NOTES:
#   This module does not analyze task action content for maliciousness.
#   It reports creation/modification/deletion activity, flags non-trusted
#   execution paths and non-administrative creators, and detects rapid
#   create-then-delete patterns that suggest evidence cleanup. The
#   administrator is expected to review flagged tasks directly.
#
# =============================================================================

function Get-ScheduledTaskEvents {
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
        Category          = "ScheduledTasks"
        CollectedAt       = Get-Date
        WindowStart       = $StartTime
        WindowEnd         = $EndTime
        TotalEvents       = 0
        CritCount         = 0
        WarnCount         = 0
        InfoCount         = 0
        ModuleErrors      = [System.Collections.Generic.List[string]]::new()
        Events            = [System.Collections.Generic.List[PSCustomObject]]::new()
        RapidCreateDelete = [System.Collections.Generic.List[string]]::new()
    }

    & $Logger "INFO" "ScheduledTasks" "Module started. Window: $StartTime to $EndTime"

    function Get-XmlEventField {
        param([xml]$Xml, [string]$FieldName)
        $node = $Xml.Event.EventData.Data | Where-Object { $_.Name -eq $FieldName }
        if ($node) { return $node.'#text' } else { return "" }
    }

    # -------------------------------------------------------------------------
    # Build trusted path prefix list from config for path matching.
    # A task is considered trusted if its action executable path starts with
    # one of these prefixes. Comparison is case-insensitive, consistent with
    # Windows filesystem path semantics.
    # -------------------------------------------------------------------------
    $trustedPaths = $Config.TRUSTED_TASK_PATHS

    function Test-TrustedPath {
        param([string]$Path, [string[]]$TrustedPrefixes)
        if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
        foreach ($prefix in $TrustedPrefixes) {
            if ($Path.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
        return $false
    }

    # -------------------------------------------------------------------------
    # Build expected admin account set for creator/modifier comparison.
    # Tasks created by accounts outside this list are treated as higher risk.
    # -------------------------------------------------------------------------
    $expectedAdminSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($acct in $Config.EXPECTED_ADMIN_ACCOUNTS) {
        [void]$expectedAdminSet.Add($acct)
    }

    # -------------------------------------------------------------------------
    # Helper: extract the executable path or command from a Task Scheduler
    # task definition XML, which is embedded as a string within the event's
    # TaskContent field. The task content itself is XML, requiring a nested
    # parse. We extract the <Command> element from the <Exec> action.
    # -------------------------------------------------------------------------
    function Get-TaskCommandFromContent {
        param([string]$TaskContentXml)

        if ([string]::IsNullOrWhiteSpace($TaskContentXml)) {
            return ""
        }

        try {
            [xml]$taskXml = $TaskContentXml
            # Task Scheduler XML namespace requires explicit namespace handling
            $nsManager = New-Object System.Xml.XmlNamespaceManager($taskXml.NameTable)
            $nsManager.AddNamespace("t", "http://schemas.microsoft.com/windows/2004/02/mit/task")

            $commandNode = $taskXml.SelectSingleNode(
                "//t:Actions/t:Exec/t:Command", $nsManager
            )

            if ($commandNode) {
                $command = $commandNode.InnerText

                # Also attempt to capture arguments for fuller context
                $argsNode = $taskXml.SelectSingleNode(
                    "//t:Actions/t:Exec/t:Arguments", $nsManager
                )
                if ($argsNode -and $argsNode.InnerText) {
                    # Truncate long argument strings (common with encoded
                    # PowerShell payloads) for report readability
                    $argText = $argsNode.InnerText
                    if ($argText.Length -gt 150) {
                        $argText = $argText.Substring(0, 150) + "...(truncated)"
                    }
                    $command = "$command $argText"
                }

                return $command
            }
            return ""
        }
        catch {
            # TaskContent may not always parse cleanly (encoding issues,
            # partial XML in some event configurations). Return empty rather
            # than failing the entire module for one unparseable task.
            return ""
        }
    }

    # -------------------------------------------------------------------------
    # Track creation and deletion timestamps per task name to detect rapid
    # create-then-delete patterns, a known evidence-cleanup technique.
    # -------------------------------------------------------------------------
    $taskCreationTimes = @{}
    $taskDeletionTimes = @{}

    # -------------------------------------------------------------------------
    # STEP 1: Query Event ID 4698 — Scheduled task created.
    # -------------------------------------------------------------------------
    & $Logger "INFO" "ScheduledTasks" "Querying Event ID 4698 (scheduled task created)"

    try {
        $createFilter = @{
            LogName   = "Security"
            Id        = 4698
            StartTime = $StartTime
            EndTime   = $EndTime
        }

        $createEvents = Get-WinEvent -FilterHashtable $createFilter `
                                     -MaxEvents $Config.MONITORING_WINDOW_MAX_EVENTS `
                                     -ErrorAction Stop

        & $Logger "INFO" "ScheduledTasks" "Retrieved $($createEvents.Count) task creation events"

        foreach ($event in $createEvents) {
            [xml]$eventXml   = $event.ToXml()
            $taskName        = Get-XmlEventField $eventXml "TaskName"
            $subjectAccount  = Get-XmlEventField $eventXml "SubjectUserName"
            $subjectDomain   = Get-XmlEventField $eventXml "SubjectDomainName"
            $taskContent     = Get-XmlEventField $eventXml "TaskContentNew"

            $taskCommand = Get-TaskCommandFromContent $taskContent
            $isTrusted   = Test-TrustedPath -Path $taskCommand -TrustedPrefixes $trustedPaths

            $fullSubject = if ($subjectDomain -and $subjectDomain -ne "-") {
                "$subjectDomain\$subjectAccount"
            } else { $subjectAccount }

            $isExpectedAdmin = $expectedAdminSet.Contains($subjectAccount)

            # Record creation time for rapid-delete correlation in Step 2.
            $taskCreationTimes[$taskName] = $event.TimeCreated

            # Severity logic:
            # - Unexpected creator + untrusted path: CRIT (highest concern —
            #   non-admin account created a task running from an unusual location)
            # - Unexpected creator OR untrusted path: WARN
            # - Expected admin + trusted path: INFO (routine, expected activity)
            $severity = switch ($true) {
                { -not $isExpectedAdmin -and -not $isTrusted } { "CRIT"; break }
                { -not $isExpectedAdmin -or -not $isTrusted }  { "WARN"; break }
                default                                         { "INFO" }
            }

            $creatorNote = if (-not $isExpectedAdmin) {
                " — created by non-administrative account"
            } else { "" }

            $pathNote = if (-not $isTrusted -and $taskCommand) {
                " — executable path NOT in trusted locations: $taskCommand"
            } elseif (-not $taskCommand) {
                " — task action could not be parsed from event data"
            } else { "" }

            $eventObj = [PSCustomObject]@{
                TimeCreated    = $event.TimeCreated
                EventId        = 4698
                Severity       = $severity
                TaskName       = $taskName
                SubjectAccount = $fullSubject
                Action         = "Created"
                TaskCommand    = $taskCommand
                IsTrustedPath  = $isTrusted
                Description    = "Scheduled task '$taskName' created by " +
                                 "'$fullSubject'$creatorNote$pathNote"
            }

            $result.Events.Add($eventObj)
        }
    }
    catch {
        if ($_.Exception.Message -like "*No events were found*") {
            & $Logger "INFO" "ScheduledTasks" "No task creation events found in window"
        }
        else {
            $errorMsg = "Failed to query Event ID 4698: $($_.Exception.Message)"
            & $Logger "ERROR" "ScheduledTasks" $errorMsg
            $result.ModuleErrors.Add($errorMsg)
        }
    }

    # -------------------------------------------------------------------------
    # STEP 2: Query Event ID 4699 — Scheduled task deleted.
    #
    # We correlate deletions against the creation timestamps recorded in
    # Step 1 to detect rapid create-then-delete patterns within the same
    # monitoring window. This pattern is consistent with an attacker creating
    # a persistence mechanism, executing it, then deleting it to reduce
    # forensic evidence.
    # -------------------------------------------------------------------------
    & $Logger "INFO" "ScheduledTasks" "Querying Event ID 4699 (scheduled task deleted)"

    try {
        $deleteFilter = @{
            LogName   = "Security"
            Id        = 4699
            StartTime = $StartTime
            EndTime   = $EndTime
        }

        $deleteEvents = Get-WinEvent -FilterHashtable $deleteFilter `
                                     -MaxEvents $Config.MONITORING_WINDOW_MAX_EVENTS `
                                     -ErrorAction Stop

        & $Logger "INFO" "ScheduledTasks" "Retrieved $($deleteEvents.Count) task deletion events"

        # Rapid create-delete threshold: if a task is deleted within this many
        # minutes of its creation in the SAME monitoring window, flag it.
        $rapidDeleteThresholdMinutes = 60

        foreach ($event in $deleteEvents) {
            [xml]$eventXml  = $event.ToXml()
            $taskName       = Get-XmlEventField $eventXml "TaskName"
            $subjectAccount = Get-XmlEventField $eventXml "SubjectUserName"
            $subjectDomain  = Get-XmlEventField $eventXml "SubjectDomainName"

            $fullSubject = if ($subjectDomain -and $subjectDomain -ne "-") {
                "$subjectDomain\$subjectAccount"
            } else { $subjectAccount }

            $taskDeletionTimes[$taskName] = $event.TimeCreated

            $isExpectedAdmin = $expectedAdminSet.Contains($subjectAccount)
            $severity = if ($isExpectedAdmin) { "WARN" } else { "CRIT" }

            $rapidDeleteNote = ""
            if ($taskCreationTimes.ContainsKey($taskName)) {
                $timeSinceCreation = ($event.TimeCreated - $taskCreationTimes[$taskName]).TotalMinutes
                if ($timeSinceCreation -ge 0 -and $timeSinceCreation -le $rapidDeleteThresholdMinutes) {
                    $severity = "CRIT"
                    $rapidDeleteNote = " — RAPID CREATE-DELETE: created and deleted " +
                                      "within $([Math]::Round($timeSinceCreation, 1)) minutes " +
                                      "in this monitoring window. Possible evidence cleanup."
                    $result.RapidCreateDelete.Add($taskName)
                }
            }

            $creatorNote = if (-not $isExpectedAdmin) {
                " — deleted by non-administrative account"
            } else { "" }

            $eventObj = [PSCustomObject]@{
                TimeCreated    = $event.TimeCreated
                EventId        = 4699
                Severity       = $severity
                TaskName       = $taskName
                SubjectAccount = $fullSubject
                Action         = "Deleted"
                TaskCommand    = "N/A"
                IsTrustedPath  = $true
                Description    = "Scheduled task '$taskName' deleted by " +
                                 "'$fullSubject'$creatorNote$rapidDeleteNote"
            }

            $result.Events.Add($eventObj)
        }
    }
    catch {
        if ($_.Exception.Message -like "*No events were found*") {
            & $Logger "INFO" "ScheduledTasks" "No task deletion events found in window"
        }
        else {
            $errorMsg = "Failed to query Event ID 4699: $($_.Exception.Message)"
            & $Logger "ERROR" "ScheduledTasks" $errorMsg
            $result.ModuleErrors.Add($errorMsg)
        }
    }

    # -------------------------------------------------------------------------
    # STEP 3: Query Event ID 4702 — Scheduled task updated.
    #
    # Modification of an existing task is a known technique for hijacking a
    # trusted, long-standing task to execute attacker-controlled actions
    # without the visibility that creating a brand-new task would draw.
    # -------------------------------------------------------------------------
    & $Logger "INFO" "ScheduledTasks" "Querying Event ID 4702 (scheduled task updated)"

    try {
        $updateFilter = @{
            LogName   = "Security"
            Id        = 4702
            StartTime = $StartTime
            EndTime   = $EndTime
        }

        $updateEvents = Get-WinEvent -FilterHashtable $updateFilter `
                                     -MaxEvents $Config.MONITORING_WINDOW_MAX_EVENTS `
                                     -ErrorAction Stop

        & $Logger "INFO" "ScheduledTasks" "Retrieved $($updateEvents.Count) task modification events"

        foreach ($event in $updateEvents) {
            [xml]$eventXml   = $event.ToXml()
            $taskName        = Get-XmlEventField $eventXml "TaskName"
            $subjectAccount  = Get-XmlEventField $eventXml "SubjectUserName"
            $subjectDomain   = Get-XmlEventField $eventXml "SubjectDomainName"
            $taskContentNew  = Get-XmlEventField $eventXml "TaskContentNew"

            $taskCommand = Get-TaskCommandFromContent $taskContentNew
            $isTrusted   = Test-TrustedPath -Path $taskCommand -TrustedPrefixes $trustedPaths

            $fullSubject = if ($subjectDomain -and $subjectDomain -ne "-") {
                "$subjectDomain\$subjectAccount"
            } else { $subjectAccount }

            $isExpectedAdmin = $expectedAdminSet.Contains($subjectAccount)

            # Any modification to an existing task is at minimum WARN —
            # modification of trusted infrastructure deserves scrutiny even
            # when performed by an expected administrator, since it changes
            # behavior that was previously reviewed and approved.
            $severity = switch ($true) {
                { -not $isExpectedAdmin -and -not $isTrusted } { "CRIT"; break }
                { -not $isExpectedAdmin -or -not $isTrusted }  { "WARN"; break }
                default                                         { "WARN" }
            }

            $creatorNote = if (-not $isExpectedAdmin) {
                " — modified by non-administrative account"
            } else { "" }

            $pathNote = if (-not $isTrusted -and $taskCommand) {
                " — new action path NOT in trusted locations: $taskCommand"
            } else { "" }

            $eventObj = [PSCustomObject]@{
                TimeCreated    = $event.TimeCreated
                EventId        = 4702
                Severity       = $severity
                TaskName       = $taskName
                SubjectAccount = $fullSubject
                Action         = "Modified"
                TaskCommand    = $taskCommand
                IsTrustedPath  = $isTrusted
                Description    = "Scheduled task '$taskName' modified by " +
                                 "'$fullSubject'$creatorNote$pathNote. " +
                                 "Compare against prior known-good configuration."
            }

            $result.Events.Add($eventObj)
        }
    }
    catch {
        if ($_.Exception.Message -like "*No events were found*") {
            & $Logger "INFO" "ScheduledTasks" "No task modification events found in window"
        }
        else {
            $errorMsg = "Failed to query Event ID 4702: $($_.Exception.Message)"
            & $Logger "ERROR" "ScheduledTasks" $errorMsg
            $result.ModuleErrors.Add($errorMsg)
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

    & $Logger "INFO" "ScheduledTasks" (
        "Module complete. Total: $($result.TotalEvents) " +
        "CRIT: $($result.CritCount) " +
        "WARN: $($result.WarnCount) " +
        "INFO: $($result.InfoCount) " +
        "RapidCreateDelete: $($result.RapidCreateDelete.Count)"
    )

    return $result
}