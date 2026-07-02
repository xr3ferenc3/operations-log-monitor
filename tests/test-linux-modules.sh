#!/usr/bin/env bash
# =============================================================================
# test-linux-modules.sh
# ops-log-monitor — Linux Module Structural Validation Tests
# =============================================================================
#
# PURPOSE:
#   Validates that each Linux detection module has valid syntax, refuses
#   direct execution, and produces correctly structured JSON Lines output
#   and summary files when executed in a synthetic test environment.
#
# PLATFORM BEHAVIOUR:
#   When run on a native Linux system (RHEL 9, Ubuntu, etc.) the full
#   test suite runs including functional module execution against a
#   synthetic far-past time window.
#
#   When run on Git Bash (Windows / MSYS2), journalctl, auditctl,
#   getenforce, ausearch and other Linux-specific commands are absent.
#   In this case the suite automatically detects the environment and
#   skips the functional execution groups (Groups 6-11), running only
#   Groups 1-5 (file existence, syntax, and direct-execution guards).
#   This is expected and correct — the Linux modules are designed to run
#   on Linux; Git Bash is a Windows development convenience tool.
#
# USAGE:
#   bash tests/test-linux-modules.sh
#
# EXIT CODES:
#   0 = All applicable tests passed
#   1 = One or more tests failed
#
# =============================================================================

set -uo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$TEST_DIR")"
MODULES_DIR="${REPO_ROOT}/linux/modules"
CONFIG_DIR="${REPO_ROOT}/linux/config"

TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0
declare -a FAILED_TEST_NAMES=()

# =============================================================================
# Platform detection
# =============================================================================

RUNNING_ON_WINDOWS_BASH=false
if [[ "${OSTYPE:-}" == "msys" ]] || \
   [[ "${OSTYPE:-}" == "cygwin" ]] || \
   [[ "$(uname -s 2>/dev/null)" =~ ^MINGW|^MSYS|^CYGWIN ]]; then
    RUNNING_ON_WINDOWS_BASH=true
fi

# Secondary check: if journalctl is simply not present (e.g. non-systemd
# Linux, or WSL without systemd), also skip functional tests.
if ! command -v journalctl >/dev/null 2>&1; then
    RUNNING_ON_WINDOWS_BASH=true
fi

# python3 check — used only for JSON validation in Groups 6-11
PYTHON3_AVAILABLE=false
if command -v python3 >/dev/null 2>&1; then
    PYTHON3_AVAILABLE=true
fi

# =============================================================================
# Assertion framework
# =============================================================================

assert_true() {
    local test_name="$1"
    local condition="$2"
    local fail_message="${3:-Condition was false}"

    if [[ "$condition" == "true" ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        printf '  \033[32mPASS\033[0m  %s\n' "$test_name"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        FAILED_TEST_NAMES+=("$test_name")
        printf '  \033[31mFAIL\033[0m  %s\n' "$test_name"
        printf '        %s\n' "$fail_message"
    fi
}

assert_skip() {
    local test_name="$1"
    local reason="${2:-Not applicable on this platform}"
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
    printf '  \033[33mSKIP\033[0m  %s\n' "$test_name"
    printf '        %s\n' "$reason"
}

assert_file_exists() {
    local test_name="$1"
    local file_path="$2"
    if [[ -f "$file_path" ]]; then
        assert_true "$test_name" "true"
    else
        assert_true "$test_name" "false" "Expected file not found at: $file_path"
    fi
}

assert_json_valid() {
    local test_name="$1"
    local json_content="$2"

    if [[ "$PYTHON3_AVAILABLE" == "false" ]]; then
        assert_skip "$test_name" "python3 not available for JSON validation"
        return
    fi

    if printf '%s' "$json_content" | \
       python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
        assert_true "$test_name" "true"
    else
        local preview
        preview=$(printf '%s' "$json_content" | head -c 200)
        assert_true "$test_name" "false" \
            "Not valid JSON. Content preview: ${preview}"
    fi
}

print_section_header() {
    local title="$1"
    printf '\n\033[36m─────────────────────────────────────────────────────\033[0m\n'
    printf '\033[36m  %s\033[0m\n' "$title"
    printf '\033[36m─────────────────────────────────────────────────────\033[0m\n'
}

# =============================================================================
# Header
# =============================================================================

echo ""
echo "============================================================="
echo " ops-log-monitor — Linux Module Tests"
echo " $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================="

if [[ "$RUNNING_ON_WINDOWS_BASH" == "true" ]]; then
    echo ""
    printf '\033[33m NOTE: Running in Git Bash / non-systemd environment.\033[0m\n'
    printf '\033[33m       Groups 1-5 (syntax and structure) will run fully.\033[0m\n'
    printf '\033[33m       Groups 6-11 (functional execution) will be skipped\033[0m\n'
    printf '\033[33m       because Linux tools (journalctl, auditctl, etc.)\033[0m\n'
    printf '\033[33m       are not available in this shell environment.\033[0m\n'
    printf '\033[33m       Run on a native Linux system for full coverage.\033[0m\n'
fi

# =============================================================================
# MODULE FILE LIST
# =============================================================================

MODULE_FILES=(
    "auth-events.sh"
    "service-events.sh"
    "privilege-events.sh"
    "system-health-events.sh"
    "kernel-events.sh"
)

# =============================================================================
# GROUP 1: File existence
# =============================================================================
print_section_header "Group 1: Module File Existence"

for file in "${MODULE_FILES[@]}"; do
    assert_file_exists "Module file exists: ${file}" "${MODULES_DIR}/${file}"
done

# =============================================================================
# GROUP 2: Configuration file existence
# =============================================================================
print_section_header "Group 2: Configuration File Existence"

assert_file_exists "Configuration file exists" "${CONFIG_DIR}/linux-monitor.conf"

# =============================================================================
# GROUP 3: Bash syntax validation
# =============================================================================
print_section_header "Group 3: Bash Syntax Validation"

for file in "${MODULE_FILES[@]}"; do
    file_path="${MODULES_DIR}/${file}"
    if [[ -f "$file_path" ]]; then
        err_output=$(bash -n "$file_path" 2>&1)
        if [[ $? -eq 0 ]]; then
            assert_true "Syntax valid: ${file}" "true"
        else
            assert_true "Syntax valid: ${file}" "false" \
                "bash -n reported: ${err_output}"
        fi
    fi
done

if [[ -f "${CONFIG_DIR}/linux-monitor.conf" ]]; then
    err_output=$(bash -n "${CONFIG_DIR}/linux-monitor.conf" 2>&1)
    if [[ $? -eq 0 ]]; then
        assert_true "Syntax valid: linux-monitor.conf" "true"
    else
        assert_true "Syntax valid: linux-monitor.conf" "false" \
            "bash -n reported: ${err_output}"
    fi
fi

# =============================================================================
# GROUP 4: Executable bit check
# =============================================================================
print_section_header "Group 4: Executable Permission Check"

for file in "${MODULE_FILES[@]}"; do
    file_path="${MODULES_DIR}/${file}"
    if [[ -f "$file_path" ]]; then
        if [[ -x "$file_path" ]]; then
            assert_true "Executable bit set: ${file}" "true"
        else
            assert_true "Executable bit set: ${file}" "false" \
                "File is not executable — run: chmod +x ${file_path}"
        fi
    fi
done

# =============================================================================
# GROUP 5: Direct-execution guard
# =============================================================================
print_section_header "Group 5: Direct-Execution Guard"

for file in "${MODULE_FILES[@]}"; do
    file_path="${MODULES_DIR}/${file}"
    if [[ -f "$file_path" ]]; then
        set +e
        output=$(bash "$file_path" 2>&1)
        exit_code=$?
        set -e

        guard_worked="false"
        if [[ "$exit_code" -ne 0 ]] && \
           [[ "$output" == *"must be sourced"* ]]; then
            guard_worked="true"
        fi

        assert_true "Direct-execution guard works: ${file}" "$guard_worked" \
            "Expected non-zero exit + 'must be sourced' message. Got exit=${exit_code}"
    fi
done

# =============================================================================
# GROUPS 6-11: Functional tests — Linux only
# =============================================================================

if [[ "$RUNNING_ON_WINDOWS_BASH" == "true" ]]; then

    print_section_header "Groups 6-11: Functional Execution (SKIPPED — not on Linux)"

    functional_tests=(
        "auth-events.sh — run_auth_module executed without error"
        "auth-events.sh — summary file is valid JSON"
        "auth-events.sh — every line in events file is valid JSON"
        "service-events.sh — run_service_module executed without error"
        "service-events.sh — summary file is valid JSON"
        "service-events.sh — every line in events file is valid JSON"
        "privilege-events.sh — run_privilege_module executed without error"
        "privilege-events.sh — summary file is valid JSON"
        "privilege-events.sh — every line in events file is valid JSON"
        "privilege-events.sh — decode_audit_cmd hex decode correct"
        "privilege-events.sh — decode_audit_cmd passthrough correct"
        "system-health-events.sh — run_system_health_module executed without error"
        "system-health-events.sh — summary file is valid JSON"
        "system-health-events.sh — every line in events file is valid JSON"
        "system-health-events.sh — summary includes unexpected_shutdowns field"
        "kernel-events.sh — run_kernel_module executed without error"
        "kernel-events.sh — summary file is valid JSON"
        "kernel-events.sh — every line in events file is valid JSON"
        "json_escape — plain text passthrough"
        "json_escape — double quote escaping"
        "json_escape — backslash escaping"
        "json_escape — newline collapsing"
    )

    for test_name in "${functional_tests[@]}"; do
        assert_skip "$test_name" "Requires Linux (journalctl/auditd not available in Git Bash)"
    done

else
    # =========================================================================
    # Full functional test suite — native Linux only
    # =========================================================================

    # --- Synthetic environment setup ---

    TEST_WORKSPACE=$(mktemp -d -t ops-log-monitor-test.XXXXXX)
    cleanup_test_workspace() { rm -rf "$TEST_WORKSPACE" 2>/dev/null; }
    trap cleanup_test_workspace EXIT

    LOG_CAPTURE_FILE="${TEST_WORKSPACE}/test-log-capture.log"
    log_message() {
        local level="$1" source="$2" message="$3"
        printf '[%s] [%s] %s\n' "$level" "$source" "$message" \
            >> "$LOG_CAPTURE_FILE"
    }

    export WINDOW_START_EPOCH
    export WINDOW_END_EPOCH
    export WINDOW_START_ISO="2015-01-01T00:00:00Z"
    export WINDOW_END_ISO="2015-01-01T00:00:01Z"

    WINDOW_START_EPOCH=$(date -d "2015-01-01 00:00:00" +%s 2>/dev/null || echo "1420070400")
    WINDOW_END_EPOCH=$(date -d "2015-01-01 00:00:01" +%s 2>/dev/null || echo "1420070401")

    export AUTH_FAILURE_WARN_THRESHOLD=10
    export AUTH_FAILURE_CRIT_THRESHOLD=50
    export AUTH_ACCOUNT_WARN_THRESHOLD=5
    export AUTH_ACCOUNT_CRIT_THRESHOLD=20
    export AUTH_INVALID_USER_CRIT_THRESHOLD=20
    export AUTH_MONITOR_ROOT_SSH="true"
    export SECURE_LOG="/var/log/secure"
    export AUDIT_LOG="/var/log/audit/audit.log"
    export AUDIT_LOG_DIR="/var/log/audit"
    export SELINUX_MONITOR_ENABLED="true"
    export SELINUX_DENIAL_WARN_THRESHOLD=5
    export SELINUX_DENIAL_CRIT_THRESHOLD=25
    export OOM_KILL_ALWAYS_CRIT="true"

    SECURITY_RELEVANT_SERVICES=("sshd.service" "auditd.service" "firewalld.service")
    CRITICAL_SYSTEM_SERVICES=("dbus.service" "NetworkManager.service")
    EXPECTED_SUDO_USERS=("root")
    EXPECTED_SU_USERS=("root")
    SELINUX_KNOWN_NOISY_CONTEXTS=()
    KERNEL_ERROR_PATTERNS=("Out of memory" "oom.kill" "Killed process"
                           "I/O error" "kernel panic" "Oops:" "BUG:"
                           "soft lockup" "hard lockup" "RCU stall")
    KERNEL_SUPPRESS_PATTERNS=()

    export AUTH_MODULE_OUTPUT_FILE="${TEST_WORKSPACE}/auth-events.jsonl"
    export AUTH_MODULE_SUMMARY_FILE="${TEST_WORKSPACE}/auth-summary.json"
    export SERVICE_MODULE_OUTPUT_FILE="${TEST_WORKSPACE}/service-events.jsonl"
    export SERVICE_MODULE_SUMMARY_FILE="${TEST_WORKSPACE}/service-summary.json"
    export PRIVILEGE_MODULE_OUTPUT_FILE="${TEST_WORKSPACE}/privilege-events.jsonl"
    export PRIVILEGE_MODULE_SUMMARY_FILE="${TEST_WORKSPACE}/privilege-summary.json"
    export SYSHEALTH_MODULE_OUTPUT_FILE="${TEST_WORKSPACE}/syshealth-events.jsonl"
    export SYSHEALTH_MODULE_SUMMARY_FILE="${TEST_WORKSPACE}/syshealth-summary.json"
    export KERNEL_MODULE_OUTPUT_FILE="${TEST_WORKSPACE}/kernel-events.jsonl"
    export KERNEL_MODULE_SUMMARY_FILE="${TEST_WORKSPACE}/kernel-summary.json"

    # --- Helper: validate summary file ---
    validate_summary_file() {
        local module_name="$1"
        local summary_file="$2"
        local expected_category="$3"

        assert_file_exists "${module_name} — summary file was created" "$summary_file"

        if [[ -f "$summary_file" && "$PYTHON3_AVAILABLE" == "true" ]]; then
            local summary_content
            summary_content=$(cat "$summary_file")

            assert_json_valid "${module_name} — summary file is valid JSON" "$summary_content"

            local category total crit warn info
            category=$(printf '%s' "$summary_content" | \
                python3 -c "import json,sys; print(json.load(sys.stdin).get('category',''))" 2>/dev/null || echo "")
            total=$(printf '%s' "$summary_content" | \
                python3 -c "import json,sys; print(json.load(sys.stdin).get('total_events',-1))" 2>/dev/null || echo "-1")
            crit=$(printf '%s' "$summary_content" | \
                python3 -c "import json,sys; print(json.load(sys.stdin).get('crit_count',-1))" 2>/dev/null || echo "-1")
            warn=$(printf '%s' "$summary_content" | \
                python3 -c "import json,sys; print(json.load(sys.stdin).get('warn_count',-1))" 2>/dev/null || echo "-1")
            info=$(printf '%s' "$summary_content" | \
                python3 -c "import json,sys; print(json.load(sys.stdin).get('info_count',-1))" 2>/dev/null || echo "-1")

            assert_true "${module_name} — category field is '${expected_category}'" \
                "$([[ "$category" == "$expected_category" ]] && echo true || echo false)" \
                "Expected '${expected_category}', got '${category}'"

            if [[ "$total" -ge 0 && "$crit" -ge 0 && "$warn" -ge 0 && "$info" -ge 0 ]]; then
                local sum=$((crit + warn + info))
                assert_true "${module_name} — total_events == crit+warn+info" \
                    "$([[ "$total" -eq "$sum" ]] && echo true || echo false)" \
                    "total(${total}) != crit(${crit})+warn(${warn})+info(${info})=${sum}"
            else
                assert_true "${module_name} — count fields are non-negative integers" "false" \
                    "Missing/invalid counts: total=${total} crit=${crit} warn=${warn} info=${info}"
            fi
        fi
    }

    validate_events_file_is_jsonl() {
        local module_name="$1"
        local events_file="$2"

        if [[ ! -f "$events_file" ]]; then
            assert_true "${module_name} — events file exists" "false" \
                "Expected file not found: ${events_file}"
            return
        fi

        if [[ ! -s "$events_file" ]]; then
            assert_true "${module_name} — events file exists (empty, expected for synthetic window)" "true"
            return
        fi

        if [[ "$PYTHON3_AVAILABLE" == "false" ]]; then
            assert_skip "${module_name} — every line in events file is valid JSON" \
                "python3 not available"
            return
        fi

        local all_valid="true"
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            if ! printf '%s' "$line" | \
               python3 -c "import json,sys; json.loads(sys.stdin.read())" 2>/dev/null; then
                all_valid="false"
                break
            fi
        done < "$events_file"

        assert_true "${module_name} — every line in events file is valid JSON" "$all_valid" \
            "One or more lines in ${events_file} are not valid JSON"
    }

    # -----------------------------------------------------------------------
    print_section_header "Group 6: auth-events.sh — Structural Validation"

    # shellcheck source=/dev/null
    source "${MODULES_DIR}/auth-events.sh"

    set +e
    run_auth_module 2>"${TEST_WORKSPACE}/auth-stderr.log"
    auth_exit=$?
    set -e

    assert_true "auth-events.sh — run_auth_module executed without error" \
        "$([[ $auth_exit -eq 0 ]] && echo true || echo false)" \
        "Exit status: ${auth_exit}. stderr: $(cat "${TEST_WORKSPACE}/auth-stderr.log" 2>/dev/null | head -3)"

    validate_summary_file "auth-events.sh" "$AUTH_MODULE_SUMMARY_FILE" "Authentication"
    validate_events_file_is_jsonl "auth-events.sh" "$AUTH_MODULE_OUTPUT_FILE"

    # -----------------------------------------------------------------------
    print_section_header "Group 7: service-events.sh — Structural Validation"

    # shellcheck source=/dev/null
    source "${MODULES_DIR}/service-events.sh"

    set +e
    run_service_module 2>"${TEST_WORKSPACE}/service-stderr.log"
    service_exit=$?
    set -e

    assert_true "service-events.sh — run_service_module executed without error" \
        "$([[ $service_exit -eq 0 ]] && echo true || echo false)" \
        "Exit status: ${service_exit}. stderr: $(cat "${TEST_WORKSPACE}/service-stderr.log" 2>/dev/null | head -3)"

    validate_summary_file "service-events.sh" "$SERVICE_MODULE_SUMMARY_FILE" "Services"
    validate_events_file_is_jsonl "service-events.sh" "$SERVICE_MODULE_OUTPUT_FILE"

    # -----------------------------------------------------------------------
    print_section_header "Group 8: privilege-events.sh — Structural Validation"

    # shellcheck source=/dev/null
    source "${MODULES_DIR}/privilege-events.sh"

    set +e
    run_privilege_module 2>"${TEST_WORKSPACE}/privilege-stderr.log"
    priv_exit=$?
    set -e

    assert_true "privilege-events.sh — run_privilege_module executed without error" \
        "$([[ $priv_exit -eq 0 ]] && echo true || echo false)" \
        "Exit status: ${priv_exit}. stderr: $(cat "${TEST_WORKSPACE}/privilege-stderr.log" 2>/dev/null | head -3)"

    validate_summary_file "privilege-events.sh" "$PRIVILEGE_MODULE_SUMMARY_FILE" "Privilege"
    validate_events_file_is_jsonl "privilege-events.sh" "$PRIVILEGE_MODULE_OUTPUT_FILE"

    if declare -f decode_audit_cmd > /dev/null; then
        decoded=$(decode_audit_cmd "6c73202d6c61")
        assert_true "privilege-events.sh — decode_audit_cmd hex decode correct" \
            "$([[ "$decoded" == "ls -la" ]] && echo true || echo false)" \
            "Expected 'ls -la', got '${decoded}'"

        decoded_pt=$(decode_audit_cmd "not-hex-input!")
        assert_true "privilege-events.sh — decode_audit_cmd passthrough correct" \
            "$([[ "$decoded_pt" == "not-hex-input!" ]] && echo true || echo false)" \
            "Expected passthrough, got '${decoded_pt}'"
    else
        assert_true "privilege-events.sh — decode_audit_cmd function defined" "false" \
            "Function not found after sourcing module"
    fi

    # -----------------------------------------------------------------------
    print_section_header "Group 9: system-health-events.sh — Structural Validation"

    # shellcheck source=/dev/null
    source "${MODULES_DIR}/system-health-events.sh"

    set +e
    run_system_health_module 2>"${TEST_WORKSPACE}/syshealth-stderr.log"
    health_exit=$?
    set -e

    assert_true "system-health-events.sh — run_system_health_module executed without error" \
        "$([[ $health_exit -eq 0 ]] && echo true || echo false)" \
        "Exit status: ${health_exit}. stderr: $(cat "${TEST_WORKSPACE}/syshealth-stderr.log" 2>/dev/null | head -3)"

    validate_summary_file "system-health-events.sh" "$SYSHEALTH_MODULE_SUMMARY_FILE" "SystemHealth"
    validate_events_file_is_jsonl "system-health-events.sh" "$SYSHEALTH_MODULE_OUTPUT_FILE"

    if [[ -f "$SYSHEALTH_MODULE_SUMMARY_FILE" && "$PYTHON3_AVAILABLE" == "true" ]]; then
        summary_content=$(cat "$SYSHEALTH_MODULE_SUMMARY_FILE")
        has_field=$(printf '%s' "$summary_content" | \
            python3 -c "import json,sys; d=json.load(sys.stdin); print('unexpected_shutdowns' in d)" \
            2>/dev/null || echo "False")
        assert_true "system-health-events.sh — summary has unexpected_shutdowns field" \
            "$([[ "$has_field" == "True" ]] && echo true || echo false)" \
            "Field 'unexpected_shutdowns' missing from summary JSON"
    fi

    # -----------------------------------------------------------------------
    print_section_header "Group 10: kernel-events.sh — Structural Validation"

    # shellcheck source=/dev/null
    source "${MODULES_DIR}/kernel-events.sh"

    set +e
    run_kernel_module 2>"${TEST_WORKSPACE}/kernel-stderr.log"
    kernel_exit=$?
    set -e

    assert_true "kernel-events.sh — run_kernel_module executed without error" \
        "$([[ $kernel_exit -eq 0 ]] && echo true || echo false)" \
        "Exit status: ${kernel_exit}. stderr: $(cat "${TEST_WORKSPACE}/kernel-stderr.log" 2>/dev/null | head -3)"

    validate_summary_file "kernel-events.sh" "$KERNEL_MODULE_SUMMARY_FILE" "Kernel"
    validate_events_file_is_jsonl "kernel-events.sh" "$KERNEL_MODULE_OUTPUT_FILE"

    # -----------------------------------------------------------------------
    print_section_header "Group 11: json_escape Helper Correctness"

    if declare -f json_escape > /dev/null; then
        result=$(json_escape 'simple text')
        assert_true "json_escape — plain text passthrough" \
            "$([[ "$result" == "simple text" ]] && echo true || echo false)" \
            "Expected 'simple text', got '${result}'"

        result=$(json_escape 'text with "quotes"')
        assert_true "json_escape — double quote escaping" \
            "$([[ "$result" == 'text with \"quotes\"' ]] && echo true || echo false)" \
            "Expected escaped quotes, got '${result}'"

        result=$(json_escape 'back\slash')
        assert_true "json_escape — backslash escaping" \
            "$([[ "$result" == 'back\\slash' ]] && echo true || echo false)" \
            "Expected escaped backslash, got '${result}'"

        result=$(json_escape $'line one\nline two')
        assert_true "json_escape — newline collapsing" \
            "$([[ "$result" == "line one line two" ]] && echo true || echo false)" \
            "Expected newline collapsed to space, got '${result}'"
    else
        assert_true "json_escape — function available for testing" "false" \
            "json_escape not found after sourcing modules"
    fi

fi  # end Linux-only block

# =============================================================================
# RESULTS SUMMARY
# =============================================================================

TOTAL_TESTS=$((TESTS_PASSED + TESTS_FAILED))

echo ""
echo "============================================================="
echo " Test Results Summary"
echo "============================================================="
printf ' Total tests:  %s\n' "$TOTAL_TESTS"
printf ' Passed:       \033[32m%s\033[0m\n' "$TESTS_PASSED"
if [[ "$TESTS_FAILED" -gt 0 ]]; then
    printf ' Failed:       \033[31m%s\033[0m\n' "$TESTS_FAILED"
else
    printf ' Failed:       %s\n' "$TESTS_FAILED"
fi
if [[ "$TESTS_SKIPPED" -gt 0 ]]; then
    printf ' Skipped:      \033[33m%s\033[0m  (run on Linux for full coverage)\n' "$TESTS_SKIPPED"
fi
echo "============================================================="

if [[ "$TESTS_FAILED" -gt 0 ]]; then
    echo ""
    printf '\033[31m FAILED TESTS:\033[0m\n'
    for name in "${FAILED_TEST_NAMES[@]}"; do
        printf '   - %s\n' "$name"
    done
fi

echo ""
[[ "$TESTS_FAILED" -gt 0 ]] && exit 1 || exit 0