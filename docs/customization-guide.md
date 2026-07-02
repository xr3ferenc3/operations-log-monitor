# Customization Guide

## Purpose of This Document

This document explains every configurable parameter in
`windows-monitor.conf.ps1` and `linux-monitor.conf`, and provides complete
worked examples for adding a new detection module to either platform.

The configuration files are the only files most administrators will ever
need to edit. This framework is designed so that adapting it to a specific
environment - adjusting thresholds, adding expected accounts, tuning noise
- never requires touching the module or orchestrator logic.

---

## Before You Customize: Use a Local Override

Both platforms support a local configuration override that is excluded
from version control, so site-specific settings never conflict with
repository updates and are never accidentally committed.

**Windows:**

```powershell
Copy-Item windows\config\windows-monitor.conf.ps1 `
          windows\config\windows-monitor.conf.local.ps1
```

**Linux:**

```bash
cp linux/config/linux-monitor.conf linux/config/linux-monitor.conf.local
```

Edit the `.local` copy. The orchestrator automatically prefers it over the
tracked configuration file if it exists. This is the recommended approach
for all environment-specific changes - only edit the tracked configuration
files directly if you are changing a default that should apply across all
deployments of this framework.

---

## Threshold Tuning

Thresholds control when an event is escalated from INFO to WARN, or from
WARN to CRIT. There is no universally correct threshold - the right value
depends on your environment's baseline activity level.

### How to find your baseline

Before tuning thresholds, run the framework for a week with default
settings and review the WARN-level findings. If a specific account or
source consistently appears at WARN without being part of a real problem,
either:

1. The threshold is too sensitive for your environment - raise it, or
2. The account or source should be added to an expected/exception list

Prefer option 2 when the cause is a *known, named* entity (a backup service
account, an admin's usual workstation). Prefer option 1 only when the noise
is generic (e.g., your SSH server faces the internet and absorbs constant
background scanning traffic that does not target any specific account).

### Windows threshold parameters

| Parameter | Default | What raising it does | What lowering it does |
|---|---|---|---|
| `AUTH_FAILURE_WARN_THRESHOLD` | 5 | Fewer accounts flagged for routine mistyped passwords | More sensitive to early-stage brute force, more noise from user error |
| `AUTH_FAILURE_CRIT_THRESHOLD` | 20 | Requires more sustained attack volume before CRIT | Escalates to CRIT sooner, useful on systems with low legitimate failure volume |
| `AUTH_SOURCE_WARN_THRESHOLD` | 10 | Less sensitive to distributed attempts from one source | Catches password spray patterns earlier |
| `AUTH_SOURCE_CRIT_THRESHOLD` | 50 | Requires higher volume from one source before CRIT | Escalates sooner - appropriate for internal-only RDP where any external-pattern volume is unusual |

### Linux threshold parameters

| Parameter | Default | What raising it does | What lowering it does |
|---|---|---|---|
| `AUTH_FAILURE_WARN_THRESHOLD` | 10 | Less noise from routine internet background scanning on exposed SSH | Earlier warning, more noise if SSH faces the internet |
| `AUTH_FAILURE_CRIT_THRESHOLD` | 50 | Appropriate for internet-facing SSH with constant scanner traffic | Appropriate for internal-only SSH where any volume is unusual |
| `AUTH_ACCOUNT_WARN_THRESHOLD` | 5 | Less sensitive to targeted account attacks | Catches targeted brute force against a specific username sooner |
| `SELINUX_DENIAL_WARN_THRESHOLD` | 5 | Tolerates more denial volume from a context before flagging | Surfaces new policy gaps faster after deployments |

**Operational guidance:** Internet-facing SSH servers almost always need
higher `AUTH_FAILURE_WARN_THRESHOLD` and `AUTH_FAILURE_CRIT_THRESHOLD`
values than internal-only servers, because automated scanning traffic is
constant background noise on the public internet. Consider whether SSH
needs to be internet-facing at all - restricting access via a VPN or
bastion host reduces this noise at the source rather than just tuning
around it.

---

## Managing Expected Account Lists

These lists are the single most important customization for keeping
severity classification meaningful. An account not on the expected list
generates WARN or CRIT findings every time it performs the monitored
activity - even if that activity is completely legitimate.

### Windows: `$EXPECTED_ADMIN_ACCOUNTS`

```powershell
$EXPECTED_ADMIN_ACCOUNTS = @(
    "Administrator",
    "admin",
    "sysadmin",
    "backup-svc"
)
```

Add every account name that legitimately holds local administrative
privileges on this system. This includes named individual administrator
accounts and service accounts that require elevated rights to function.

**Maintenance discipline:** Review this list during the monthly review
cycle described in `docs/interpreting-reports.md`. An account that left
this list (departed employee, decommissioned service) but still appears
in reports as "unexpected" is itself worth investigating - it means the
account still has privileges it should no longer have.

### Linux: `EXPECTED_SUDO_USERS` and `EXPECTED_SU_USERS`

```bash
EXPECTED_SUDO_USERS=(
    "root"
    "jsmith"
    "deploy-svc"
)
```

Same principle applies. This list should track the actual contents of
`/etc/sudoers` and `/etc/sudoers.d/` for accounts with broad sudo access.
It is acceptable - and often correct - for this list to be a subset of
everyone with *some* sudo access, if most users only have narrow, specific
command permissions that are not security-sensitive.

---

## Adding a New Windows Module

This worked example adds a hypothetical module monitoring USB storage
device insertion events (Event ID 6416), a common requirement in
environments with data loss prevention concerns.

### Step 1: Create the module file

Create `windows/modules/Get-RemovableMediaEvents.ps1` following the same
structural pattern as the existing modules:

```powershell
function Get-RemovableMediaEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [DateTime]$StartTime,
        [Parameter(Mandatory = $true)] [DateTime]$EndTime,
        [Parameter(Mandatory = $true)] [hashtable]$Config,
        [Parameter(Mandatory = $true)] [scriptblock]$Logger
    )

    $result = [PSCustomObject]@{
        Category     = "RemovableMedia"
        CollectedAt  = Get-Date
        WindowStart  = $StartTime
        WindowEnd    = $EndTime
        TotalEvents  = 0
        CritCount    = 0
        WarnCount    = 0
        InfoCount    = 0
        ModuleErrors = [System.Collections.Generic.List[string]]::new()
        Events       = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    & $Logger "INFO" "RemovableMedia" "Module started."

    try {
        $filter = @{ LogName = "Security"; Id = 6416; StartTime = $StartTime; EndTime = $EndTime }
        $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $Config.MONITORING_WINDOW_MAX_EVENTS -ErrorAction Stop

        foreach ($event in $events) {
            $result.Events.Add([PSCustomObject]@{
                TimeCreated = $event.TimeCreated
                EventId     = 6416
                Severity    = "WARN"
                Description = "Removable storage device connected"
            })
        }
    }
    catch {
        if ($_.Exception.Message -notlike "*No events*") {
            $result.ModuleErrors.Add($_.Exception.Message)
        }
    }

    $result.TotalEvents = $result.Events.Count
    $result.WarnCount    = ($result.Events | Where-Object Severity -eq "WARN").Count
    return $result
}
```

This minimal example omits some structure present in the production
modules (XML field extraction, threshold logic) for brevity - use one of
the existing five modules as your real starting template, not this
abbreviated example.

### Step 2: Add an enable flag to the configuration file

In `windows-monitor.conf.ps1`, Section 4:

```powershell
$MODULE_REMOVABLE_MEDIA_ENABLED = $true
```

### Step 3: Register the module in the orchestrator

In `Invoke-LogMonitor.ps1`, add an entry to `$ModuleExecutionPlan`:

```powershell
@{
    EnableFlag   = "MODULE_REMOVABLE_MEDIA_ENABLED"
    FileName     = "Get-RemovableMediaEvents.ps1"
    FunctionName = "Get-RemovableMediaEvents"
    ResultKey    = "RemovableMedia"
}
```

Also add `MODULE_REMOVABLE_MEDIA_ENABLED` to the `$Config` hashtable
construction earlier in the orchestrator, following the pattern of the
existing `MODULE_*_ENABLED` entries.

### Step 4: Test in isolation before integrating

```powershell
. .\windows\modules\Get-RemovableMediaEvents.ps1
$testLogger = { param($l,$s,$m) Write-Host "[$l] [$s] $m" }
$testConfig = @{ MONITORING_WINDOW_MAX_EVENTS = 1000 }
$result = Get-RemovableMediaEvents -StartTime (Get-Date).AddDays(-1) -EndTime (Get-Date) -Config $testConfig -Logger $testLogger
$result | Format-List
```

Confirm the function returns the expected object structure before wiring
it into the orchestrator.

---

## Adding a New Linux Module

This worked example adds a hypothetical module monitoring `firewalld` zone
or rule changes.

### Step 1: Create the module file

Create `linux/modules/firewall-events.sh` following the existing pattern:

```bash
#!/usr/bin/env bash

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "ERROR: firewall-events.sh is a module and must be sourced by log-monitor.sh." >&2
    exit 1
fi

run_firewall_module() {
    log_message "INFO" "Firewall" "Module started."

    local total_events=0 crit_count=0 warn_count=0 info_count=0
    local -a module_errors=()

    : > "${FIREWALL_MODULE_OUTPUT_FILE}"

    json_escape() {
        local input="$1"
        input="${input//\\/\\\\}"; input="${input//\"/\\\"}"
        input="${input//$'\n'/ }"; input="${input//$'\r'/}"
        printf '%s' "$input"
    }

    write_event() {
        local time_created="$1" event_type="$2" severity="$3" description="$4"
        description=$(json_escape "$description")
        printf '{"time_created":"%s","event_type":"%s","severity":"%s","description":"%s"}\n' \
            "$time_created" "$event_type" "$severity" "$description" >> "${FIREWALL_MODULE_OUTPUT_FILE}"
        total_events=$((total_events + 1))
        case "$severity" in
            CRIT) crit_count=$((crit_count + 1)) ;;
            WARN) warn_count=$((warn_count + 1)) ;;
            INFO) info_count=$((info_count + 1)) ;;
        esac
    }

    local fw_log
    fw_log=$(journalctl --no-pager --since="@${WINDOW_START_EPOCH}" \
                         --until="@${WINDOW_END_EPOCH}" \
                         --identifier=firewalld --output=short-iso 2>&1 || true)

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local ts; ts=$(printf '%s' "$line" | awk '{print $1}')
        if [[ "$line" =~ ZONE_CHANGED|RULE_ADDED ]]; then
            write_event "$ts" "firewall_change" "WARN" "$line"
        fi
    done <<< "$fw_log"

    cat > "${FIREWALL_MODULE_SUMMARY_FILE}" <<EOF
{"category":"Firewall","total_events":${total_events},"crit_count":${crit_count},"warn_count":${warn_count},"info_count":${info_count},"errors":[]}
EOF

    log_message "INFO" "Firewall" "Module complete. Total: ${total_events}"
}
```

### Step 2: Add an enable flag to the configuration file

In `linux-monitor.conf`, Section 4:

```bash
MODULE_FIREWALL_ENABLED="true"
```

### Step 3: Register the module in the orchestrator

In `log-monitor.sh`, add entries to the four associative arrays and the
execution order list:

```bash
MODULE_ENABLE_FLAGS["firewall-events.sh"]="MODULE_FIREWALL_ENABLED"
MODULE_FUNCTIONS["firewall-events.sh"]="run_firewall_module"
MODULE_RESULT_KEYS["firewall-events.sh"]="Firewall"
MODULE_EXECUTION_ORDER+=("firewall-events.sh")
```

Also export the workspace file paths alongside the other modules' paths:

```bash
export FIREWALL_MODULE_OUTPUT_FILE="${WORKSPACE_DIR}/firewall-events.jsonl"
export FIREWALL_MODULE_SUMMARY_FILE="${WORKSPACE_DIR}/firewall-summary.json"
```

And add a corresponding `case` entry in both `render_markdown_report` and
`render_json_report` for `firewall-events.sh`, following the pattern of
the existing five modules.

### Step 4: Test in isolation before integrating

```bash
export WINDOW_START_EPOCH=$(date -d '1 day ago' +%s)
export WINDOW_END_EPOCH=$(date +%s)
export FIREWALL_MODULE_OUTPUT_FILE=$(mktemp)
export FIREWALL_MODULE_SUMMARY_FILE=$(mktemp)

log_message() { echo "[$1] [$2] $3"; }

source linux/modules/firewall-events.sh
run_firewall_module

cat "$FIREWALL_MODULE_OUTPUT_FILE"
cat "$FIREWALL_MODULE_SUMMARY_FILE"
```

Confirm the output files are populated with correctly structured JSON
before wiring the module into `log-monitor.sh`.

---

## Suppressing Known-Benign Findings

Sometimes a finding is correctly detected but represents accepted,
documented behavior in your environment rather than a problem. The
framework provides two different mechanisms depending on the situation -
use the right one.

**Use an expected-account list** (`EXPECTED_ADMIN_ACCOUNTS`,
`EXPECTED_SUDO_USERS`, etc.) when the exception is about *who* is
performing the activity. This is the most common case.

**Use `SELINUX_KNOWN_NOISY_CONTEXTS`** (Linux only) when the exception is
about a specific SELinux policy gap that is documented and pending a
proper fix. This mechanism deliberately still records the finding at INFO
rather than silently dropping it - review this list periodically and
remove entries once the underlying policy gap is actually fixed, rather
than leaving exceptions in place indefinitely.

**Do not** suppress findings by disabling an entire module
(`MODULE_*_ENABLED = $false` / `"false"`) just to silence one noisy
finding within it. Disabling a module removes its entire detection
category, including findings you would want to see. Use the targeted
exception mechanisms above instead.

---

## Configuration Change Discipline

Treat configuration changes with the same care as code changes:

- Test changes in a non-production environment first when feasible
- Document *why* a threshold was changed or an account was added, not just
  that it was - a comment in the local override file is sufficient
- Increment `MONITOR_VERSION` when making a significant configuration
  change, so reports generated before and after the change are
  distinguishable when reviewed later (see `CHANGELOG.md` versioning
  policy for the same principle applied at the repository level)
- Review expected-account and exception lists monthly - stale entries are
  a slow-developing security gap, not a convenience