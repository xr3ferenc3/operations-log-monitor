# =============================================================================
# Get-PrivilegeEvents.ps1
# ops-log-monitor — Windows Privilege Event Module
# =============================================================================
#
# PURPOSE:
#   Queries the Windows Security event log for privilege-related events within
#   a specified time window. Detects special privilege assignment at logon,
#   sensitive privilege use during sessions, and membership changes to
#   privileged local security groups.
#
# CALLED BY:
#   Invoke-LogMonitor.ps1 (orchestrator)
#
# INPUTS (parameters passed by orchestrator):
#   -StartTime   [DateTime]    Beginning of the monitoring window
#   -EndTime     [DateTime]    End of the monitoring window
#   -Config      [hashtable]   Configuration values from windows-monitor.conf.ps1
#   -Logger      [scriptblock] Logging function from orchestrator
#
# OUTPUT:
#   [PSCustomObject] with the following structure:
#   {
#     Category              : "Privilege"
#     CollectedAt           : [DateTime]
#     WindowStart           : [DateTime]
#     WindowEnd             : [DateTime]
#     TotalEvents           : [int]
#     CritCount             : [int]
#     WarnCount             : [int]
#     InfoCount             : [int]
#     ModuleErrors          : [string[]]
#     Events                : [PSCustomObject[]]
#     UnexpectedAdminLogons : [string[]]  (accounts not in expected admin list)
#     GroupChangeSummary    : [hashtable] (group name -> change count)
#   }
#
#   Each event object contains:
#   {
#     TimeCreated    : [DateTime]
#     EventId        : [int]
#     Severity       : "CRIT" | "WARN" | "INFO"
#     SubjectAccount : [string]  (account that performed the action)
#     TargetAccount  : [string]  (account affected, where applicable)
#     TargetGroup    : [string]  (group affected, where applicable)
#     Privileges     : [string]  (privilege names, where applicable)
#     Description    : [string]
#   }
#
# REQUIRED AUDIT POLICY:
#   Privilege Use > Audit Sensitive Privilege Use: Success and Failure
#   Privilege Use > Audit Special Logon: Success
#   Account Management > Audit Security Group Management: Success and Failure
#   Verify with: auditpol /get /subcategory:"Sensitive Privilege Use"
#                auditpol /get /subcategory:"Special Logon"
#                auditpol /get /subcategory:"Security Group Management"
#
# OPERATIONAL NOTES:
#   Event ID 4672 fires at every logon for any account holding sensitive
#   privileges. On a system with multiple administrators this generates
#   significant volume. The module filters expected admin accounts to INFO
#   severity and flags unexpected accounts at WARN. This design means the
#   report highlights deviations from the known administrative baseline
#   rather than burying them in expected activity.
#
# =============================================================================

function Get-PrivilegeEvents {
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
    # Initialize result object with all expected fields pre-populated.
    # -------------------------------------------------------------------------
    $result = [PSCustomObject]@{
        Category              = "Privilege"
        CollectedAt           = Get-Date
        WindowStart           = $StartTime
        WindowEnd             = $EndTime
        TotalEvents           = 0
        CritCount             = 0
        WarnCount             = 0
        InfoCount             = 0
        ModuleErrors          = [System.Collections.Generic.List[string]]::new()
        Events                = [System.Collections.Generic.List[PSCustomObject]]::new()
        UnexpectedAdminLogons = [System.Collections.Generic.List[string]]::new()
        GroupChangeSummary    = @{}
    }

    & $Logger "INFO" "Privilege" "Module started. Window: $StartTime to $EndTime"

    # -------------------------------------------------------------------------
    # Build lookup structures from config arrays for efficient comparisons.
    #
    # Expected admin accounts are stored in a HashSet for O(1) lookup.
    # High-risk privileges are stored in a HashSet for the same reason.
    # We will check every privilege in a 4673 event against this set.
    # -------------------------------------------------------------------------
    $expectedAdminSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($acct in $Config.EXPECTED_ADMIN_ACCOUNTS) {
        [void]$expectedAdminSet.Add($acct)
    }

    $highRiskPrivSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($priv in $Config.HIGH_RISK_PRIVILEGES) {
        [void]$highRiskPrivSet.Add($priv)
    }

    # -------------------------------------------------------------------------
    # Local helper function: extract a named field from event XML data.
    # Defined once here and reused across all event processing loops in this
    # module. The function is scoped to this function's execution context.
    # -------------------------------------------------------------------------
    function Get-XmlEventField {
        param(
            [xml]$Xml,
            [string]$FieldName
        )
        $node = $Xml.Event.EventData.Data |
                Where-Object { $_.Name -eq $FieldName }
        if ($node) { return $node.'#text' } else { return "" }
    }

    # -------------------------------------------------------------------------
    # STEP 1: Query Event ID 4672 — Special privileges assigned to new logon.
    #
    # This event fires at every logon where the authenticated account holds
    # one or more sensitive privileges. Any member of the local Administrators
    # group will generate this event at every logon.
    #
    # We separate expected admin logons (INFO) from unexpected privileged
    # logons (WARN) because the latter indicate an account holds administrative
    # privileges that may not be intentionally granted or documented.
    # -------------------------------------------------------------------------
    & $Logger "INFO" "Privilege" "Querying Event ID 4672 (special privilege assignment)"

    try {
        $privAssignFilter = @{
            LogName   = "Security"
            Id        = 4672
            StartTime = $StartTime
            EndTime   = $EndTime
        }

        $privAssignEvents = Get-WinEvent -FilterHashtable $privAssignFilter `
                                         -MaxEvents $Config.MONITORING_WINDOW_MAX_EVENTS `
                                         -ErrorAction Stop

        & $Logger "INFO" "Privilege" "Retrieved $($privAssignEvents.Count) privilege assignment events"

        foreach ($event in $privAssignEvents) {
            [xml]$eventXml   = $event.ToXml()
            $subjectAccount  = Get-XmlEventField $eventXml "SubjectUserName"
            $subjectDomain   = Get-XmlEventField $eventXml "SubjectDomainName"
            $privilegeList   = Get-XmlEventField $eventXml "PrivilegeList"

            # Skip well-known system accounts that legitimately hold
            # administrative privileges and generate 4672 continuously.
            # Reporting these would create enormous noise with no signal value.
            $systemAccounts = @(
                "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
                "DWM-1", "DWM-2", "DWM-3",
                "UMFD-0", "UMFD-1", "UMFD-2",
                "-"
            )
            if ($subjectAccount -in $systemAccounts) { continue }

            $isExpectedAdmin = $expectedAdminSet.Contains($subjectAccount)

            # Check whether any of the assigned privileges are in the
            # high-risk set. The privilege list is a newline-separated
            # string of privilege names in the event XML.
            $assignedPrivileges = $privilegeList -split "`n" |
                                  ForEach-Object { $_.Trim() } |
                                  Where-Object { $_ -ne "" }

            $hasHighRiskPriv = $assignedPrivileges |
                               Where-Object { $highRiskPrivSet.Contains($_) }

            # Severity logic:
            # - Expected admin with high-risk privilege: WARN (expected account,
            #   unexpected privilege — worth noting but not alarming)
            # - Expected admin without high-risk privilege: INFO (routine)
            # - Unexpected account with any privilege: WARN
            # - Unexpected account with high-risk privilege: CRIT
            $severity = switch ($true) {
                { -not $isExpectedAdmin -and $hasHighRiskPriv } { "CRIT"; break }
                { -not $isExpectedAdmin }                        { "WARN"; break }
                { $isExpectedAdmin -and $hasHighRiskPriv }       { "WARN"; break }
                default                                          { "INFO" }
            }

            if (-not $isExpectedAdmin) {
                $result.UnexpectedAdminLogons.Add($subjectAccount)
            }

            $fullAccount = if ($subjectDomain -and $subjectDomain -ne "-") {
                "$subjectDomain\$subjectAccount"
            } else {
                $subjectAccount
            }

            # Truncate the privilege list for readability in the description.
            # The full list can be very long. We show the first three and
            # indicate if more exist.
            $displayPrivs = if ($assignedPrivileges.Count -gt 3) {
                ($assignedPrivileges[0..2] -join ", ") +
                " (+ $($assignedPrivileges.Count - 3) more)"
            } else {
                $assignedPrivileges -join ", "
            }

            $unexpectedNote = if (-not $isExpectedAdmin) {
                " — ACCOUNT NOT IN EXPECTED ADMIN LIST"
            } else { "" }

            $highRiskNote = if ($hasHighRiskPriv) {
                " — HIGH-RISK PRIVILEGE ASSIGNED: $($hasHighRiskPriv -join ', ')"
            } else { "" }

            $eventObj = [PSCustomObject]@{
                TimeCreated    = $event.TimeCreated
                EventId        = 4672
                Severity       = $severity
                SubjectAccount = $fullAccount
                TargetAccount  = "N/A"
                TargetGroup    = "N/A"
                Privileges     = $displayPrivs
                Description    = "Privileged logon: '$fullAccount' assigned sensitive " +
                                 "privileges: $displayPrivs$unexpectedNote$highRiskNote"
            }

            $result.Events.Add($eventObj)
        }
    }
    catch {
        if ($_.Exception.Message -like "*No events were found*") {
            & $Logger "INFO" "Privilege" "No privilege assignment events found in window"
        }
        else {
            $errorMsg = "Failed to query Event ID 4672: $($_.Exception.Message)"
            & $Logger "ERROR" "Privilege" $errorMsg
            $result.ModuleErrors.Add($errorMsg)
        }
    }

    # -------------------------------------------------------------------------
    # STEP 2: Query Event ID 4673 — A privileged service was called.
    #
    # This event fires when a process calls a Windows API that requires a
    # specific privilege. We report only calls involving high-risk privileges
    # defined in config. Reporting all 4673 events would be impractical —
    # legitimate software makes thousands of privilege calls per hour.
    #
    # SeDebugPrivilege is the most significant: it allows a process to read
    # and write the memory of any other process, including lsass.exe where
    # Windows caches credential hashes. Malware and credential dumping tools
    # such as Mimikatz require SeDebugPrivilege.
    # -------------------------------------------------------------------------
    & $Logger "INFO" "Privilege" "Querying Event ID 4673 (privileged service calls)"

    try {
        $privUseFilter = @{
            LogName   = "Security"
            Id        = 4673
            StartTime = $StartTime
            EndTime   = $EndTime
        }

        $privUseEvents = Get-WinEvent -FilterHashtable $privUseFilter `
                                      -MaxEvents $Config.MONITORING_WINDOW_MAX_EVENTS `
                                      -ErrorAction Stop

        & $Logger "INFO" "Privilege" "Retrieved $($privUseEvents.Count) privileged service call events — filtering for high-risk privileges"

        foreach ($event in $privUseEvents) {
            [xml]$eventXml    = $event.ToXml()
            $subjectAccount   = Get-XmlEventField $eventXml "SubjectUserName"
            $subjectDomain    = Get-XmlEventField $eventXml "SubjectDomainName"
            $privilegeName    = Get-XmlEventField $eventXml "PrivilegeName"
            $processName      = Get-XmlEventField $eventXml "ProcessName"

            # Skip system accounts — they legitimately use high-risk privileges
            # continuously as part of normal OS operation.
            if ($subjectAccount -in @("SYSTEM", "LOCAL SERVICE",
                                       "NETWORK SERVICE", "-")) { continue }

            # Skip if the privilege is not in the high-risk set.
            # This is the primary filter that keeps 4673 reporting manageable.
            if (-not $highRiskPrivSet.Contains($privilegeName)) { continue }

            $fullAccount = if ($subjectDomain -and $subjectDomain -ne "-") {
                "$subjectDomain\$subjectAccount"
            } else {
                $subjectAccount
            }

            # High-risk privilege use by a non-system account is always CRIT.
            # There are very few legitimate reasons for user-context processes
            # to exercise SeDebugPrivilege or SeTcbPrivilege.
            $severity = "CRIT"

            # Extract just the process filename from the full path for
            # readability. Full path is preserved in the description.
            $processFileName = if ($processName) {
                Split-Path $processName -Leaf
            } else { "Unknown" }

            $eventObj = [PSCustomObject]@{
                TimeCreated    = $event.TimeCreated
                EventId        = 4673
                Severity       = $severity
                SubjectAccount = $fullAccount
                TargetAccount  = "N/A"
                TargetGroup    = "N/A"
                Privileges     = $privilegeName
                Description    = "HIGH-RISK PRIVILEGE USE: '$fullAccount' exercised " +
                                 "$privilegeName via process '$processFileName' " +
                                 "(full path: $processName)"
            }

            $result.Events.Add($eventObj)
        }
    }
    catch {
        if ($_.Exception.Message -like "*No events were found*") {
            & $Logger "INFO" "Privilege" "No privileged service call events found in window"
        }
        else {
            $errorMsg = "Failed to query Event ID 4673: $($_.Exception.Message)"
            & $Logger "ERROR" "Privilege" $errorMsg
            $result.ModuleErrors.Add($errorMsg)
        }
    }

    # -------------------------------------------------------------------------
    # STEP 3: Query Event IDs 4728, 4732, 4756 — Group membership changes.
    #
    # These three events cover additions to global (4728), local (4732), and
    # universal (4756) security groups respectively. On standalone and workgroup
    # servers, 4732 is the most significant because it covers additions to
    # local groups including the Administrators group.
    #
    # Group membership changes should always correlate with a documented change
    # request. Undocumented membership changes — especially to the Administrators
    # group — are a primary indicator of privilege escalation.
    # -------------------------------------------------------------------------
    & $Logger "INFO" "Privilege" "Querying Event IDs 4728/4732/4756 (group membership changes)"

    # Groups whose membership changes are reported at CRIT severity.
    # These are groups that grant significant access on Windows systems.
    $criticalGroups = @(
        "Administrators",
        "Remote Desktop Users",
        "Backup Operators",
        "Network Configuration Operators",
        "Power Users"
    )
    $criticalGroupSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($grp in $criticalGroups) { [void]$criticalGroupSet.Add($grp) }

    try {
        $groupChangeFilter = @{
            LogName   = "Security"
            Id        = @(4728, 4732, 4756)
            StartTime = $StartTime
            EndTime   = $EndTime
        }

        $groupChangeEvents = Get-WinEvent -FilterHashtable $groupChangeFilter `
                                          -MaxEvents $Config.MONITORING_WINDOW_MAX_EVENTS `
                                          -ErrorAction Stop

        & $Logger "INFO" "Privilege" "Retrieved $($groupChangeEvents.Count) group membership change events"

        foreach ($event in $groupChangeEvents) {
            [xml]$eventXml    = $event.ToXml()
            $subjectAccount   = Get-XmlEventField $eventXml "SubjectUserName"
            $subjectDomain    = Get-XmlEventField $eventXml "SubjectDomainName"
            $memberName       = Get-XmlEventField $eventXml "MemberName"
            $targetGroupName  = Get-XmlEventField $eventXml "TargetUserName"
            $targetGroupDomain = Get-XmlEventField $eventXml "TargetDomainName"

            # Clean up the member name — it often includes the domain in
            # CN=username,DC=domain,DC=com LDAP format on domain-joined systems.
            # Extract just the CN value for readability.
            if ($memberName -match "CN=([^,]+)") {
                $memberName = $Matches[1]
            }
            if ($memberName -in @("-", "")) { $memberName = "Unknown" }

            $fullSubject = if ($subjectDomain -and $subjectDomain -ne "-") {
                "$subjectDomain\$subjectAccount"
            } else { $subjectAccount }

            $fullGroup = if ($targetGroupDomain -and $targetGroupDomain -ne "-") {
                "$targetGroupDomain\$targetGroupName"
            } else { $targetGroupName }

            # Track group change counts for the summary hashtable.
            if (-not $result.GroupChangeSummary.ContainsKey($targetGroupName)) {
                $result.GroupChangeSummary[$targetGroupName] = 0
            }
            $result.GroupChangeSummary[$targetGroupName]++

            $isCriticalGroup = $criticalGroupSet.Contains($targetGroupName)

            # Self-escalation: the subject account added themselves to the group.
            # This is a significant finding — legitimate administrators do not
            # add themselves to privileged groups. This should always go through
            # a change management process with a different account performing
            # the action.
            $isSelfEscalation = ($subjectAccount -eq $memberName)

            $severity = switch ($true) {
                { $isSelfEscalation }   { "CRIT"; break }
                { $isCriticalGroup }    { "CRIT"; break }
                default                 { "WARN" }
            }

            $groupTypeNote = switch ($event.Id) {
                4728 { "global security group" }
                4732 { "local security group" }
                4756 { "universal security group" }
            }

            $selfEscalationNote = if ($isSelfEscalation) {
                " — SELF-ESCALATION: subject and member are the same account"
            } else { "" }

            $criticalNote = if ($isCriticalGroup) {
                " — CRITICAL GROUP"
            } else { "" }

            $eventObj = [PSCustomObject]@{
                TimeCreated    = $event.TimeCreated
                EventId        = $event.Id
                Severity       = $severity
                SubjectAccount = $fullSubject
                TargetAccount  = $memberName
                TargetGroup    = $fullGroup
                Privileges     = "N/A"
                Description    = "'$memberName' added to $groupTypeNote '$fullGroup' " +
                                 "by '$fullSubject'$criticalNote$selfEscalationNote"
            }

            $result.Events.Add($eventObj)
        }
    }
    catch {
        if ($_.Exception.Message -like "*No events were found*") {
            & $Logger "INFO" "Privilege" "No group membership change events found in window"
        }
        else {
            $errorMsg = "Failed to query Event IDs 4728/4732/4756: $($_.Exception.Message)"
            & $Logger "ERROR" "Privilege" $errorMsg
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

    & $Logger "INFO" "Privilege" (
        "Module complete. Total: $($result.TotalEvents) " +
        "CRIT: $($result.CritCount) " +
        "WARN: $($result.WarnCount) " +
        "INFO: $($result.InfoCount)"
    )

    return $result
}