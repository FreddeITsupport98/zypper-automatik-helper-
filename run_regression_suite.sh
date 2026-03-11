#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGRESSION_DIR="${SCRIPT_DIR}/regressions"
DEFAULT_TARGET_FILE="${SCRIPT_DIR}/zypper-auto.sh"
TARGET_FILE=""
INCLUDE_STATEFUL=0
PLAYWRIGHT_TEST_PYTHON_BIN=""
ONLY_PATTERNS=()
EXCLUDE_PATTERNS=()

usage() {
    cat <<'EOF'
Usage: ./run_regression_suite.sh [options] [path/to/zypper-auto.sh]

Runs auto-discovered regressions from:
  - ./regressions/test_*.sh
  - ./regressions/test_*.py

Safety behavior:
  - Stateful tests are skipped by default.
  - Use --include-stateful to explicitly include stateful tests.
  - Optional tests are warn-only on failure.
  - Preflight checks run automatically before tests:
    - Shared syntax baseline via `scripts/syntax-check.sh` (bash syntax + shellcheck)
    - Runtime-aware Python compile checks (`python -m py_compile`)

Test metadata markers (add as single comment lines in test files):
  - # RUNNER_STATEFUL=1      include only with --include-stateful
  - # RUNNER_OPTIONAL=1      do not fail full suite on test failure
  - # RUNNER_RUNTIME=...     python runtime selector: default|playwright
  - # RUNNER_REQUIRES_ROOT=1 require root for this test
  - # RUNNER_NEEDS_TARGET=0  shell test does not accept target-file arg

Options:
  --include-stateful         Include tests marked RUNNER_STATEFUL=1
  --only PATTERN             Include only tests whose basename matches shell glob PATTERN (repeatable)
  --exclude PATTERN          Exclude tests whose basename matches shell glob PATTERN (repeatable)
  -h, --help                 Show this help

Runtime environment variables:
  RUNTIME_TEST_PYTHON     Python runtime for required Python runtime regressions
                          (default: python3)
  PLAYWRIGHT_TEST_PYTHON  Python runtime for optional Playwright regression
                          (default: ./.venv-playwright-regression/bin/python
                          when present, otherwise RUNTIME_TEST_PYTHON)
  RUNNER_SKIP_SHELLCHECK  Set to 1/true/yes to skip shellcheck preflight checks
EOF
}

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

resolve_python_runtime() {
    local candidate="$1"
    if [ -x "${candidate}" ]; then
        printf '%s\n' "${candidate}"
        return 0
    fi
    if command -v "${candidate}" >/dev/null 2>&1; then
        command -v "${candidate}"
        return 0
    fi
    return 1
}

runner_meta_value() {
    local file="$1"
    local key="$2"
    local default_value="$3"
    local line=""
    local prefix="# ${key}="
    line="$(grep -m1 -E "^# ${key}=" "${file}" || true)"
    if [ -n "${line}" ]; then
        printf '%s\n' "${line#"${prefix}"}"
    else
        printf '%s\n' "${default_value}"
    fi
}

is_truthy() {
    case "$1" in
        1|true|TRUE|yes|YES|on|ON)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

matches_any_pattern() {
    local value="$1"
    shift
    local pattern=""
    for pattern in "$@"; do
        # shellcheck disable=SC2254
        case "${value}" in
            ${pattern})
                return 0
                ;;
        esac
    done
    return 1
}

test_matches_filters() {
    local test_name="$1"
    if [ "${#ONLY_PATTERNS[@]}" -gt 0 ]; then
        if ! matches_any_pattern "${test_name}" "${ONLY_PATTERNS[@]}"; then
            return 1
        fi
    fi
    if [ "${#EXCLUDE_PATTERNS[@]}" -gt 0 ]; then
        if matches_any_pattern "${test_name}" "${EXCLUDE_PATTERNS[@]}"; then
            return 1
        fi
    fi
    return 0
}

ensure_test_executable_if_needed() {
    local test_path="$1"
    local test_name=""
    test_name="$(basename "${test_path}")"
    if [ -x "${test_path}" ]; then
        return 0
    fi
    chmod +x "${test_path}" || fail "Could not mark regression test executable: ${test_name}"
    printf 'INFO: Marked test executable: %s\n' "${test_name}"
}

run_preflight_syntax_baseline() {
    local syntax_script="${SCRIPT_DIR}/scripts/syntax-check.sh"
    local syntax_skip_shellcheck="${RUNNER_SKIP_SHELLCHECK:-0}"
    local syntax_python="${RUNTIME_TEST_PYTHON_BIN:-python3}"
    local syntax_args=()
    local runtime_tag=""
    local test_path=""
    [ -f "${syntax_script}" ] || fail "Missing syntax baseline script: ${syntax_script}"

    syntax_args=( "--skip-node" "--no-runner" "--target" "${SCRIPT_DIR}/run_regression_suite.sh" "--target" "${TARGET_FILE}" )
    for test_path in "${required_shell_tests[@]}"; do
        syntax_args+=( "--target" "${test_path}" )
    done
    for test_path in "${optional_shell_tests[@]}"; do
        syntax_args+=( "--target" "${test_path}" )
    done
    for test_path in "${required_python_tests[@]}"; do
        runtime_tag="$(runner_meta_value "${test_path}" "RUNNER_RUNTIME" "default")"
        if [ "${runtime_tag}" = "default" ]; then
            syntax_args+=( "--python-target" "${test_path}" )
        fi
    done
    for test_path in "${optional_python_tests[@]}"; do
        runtime_tag="$(runner_meta_value "${test_path}" "RUNNER_RUNTIME" "default")"
        if [ "${runtime_tag}" = "default" ]; then
            syntax_args+=( "--python-target" "${test_path}" )
        fi
    done

    printf '\n==> preflight: shared syntax baseline (scripts/syntax-check.sh)\n'
    SYNTAX_SKIP_SHELLCHECK="${syntax_skip_shellcheck}" SYNTAX_PYTHON="${syntax_python}" "${syntax_script}" "${syntax_args[@]}"
}

run_preflight_python_compile_checks() {
    local runtime_tag=""
    local python_bin=""
    local compiled_count=0
    if [ "${total_python_tests}" -le 0 ]; then
        return 0
    fi
    printf '\n==> preflight: runtime-specific python compile checks\n'
    for test_path in "${required_python_tests[@]}"; do
        runtime_tag="$(runner_meta_value "${test_path}" "RUNNER_RUNTIME" "default")"
        if [ "${runtime_tag}" = "default" ]; then
            continue
        fi
        python_bin="$(python_bin_for_runtime_tag "${runtime_tag}")"
        printf 'Compiling with %s: %s\n' "${python_bin}" "$(basename "${test_path}")"
        "${python_bin}" -m py_compile "${test_path}"
        compiled_count=$((compiled_count + 1))
    done
    for test_path in "${optional_python_tests[@]}"; do
        runtime_tag="$(runner_meta_value "${test_path}" "RUNNER_RUNTIME" "default")"
        if [ "${runtime_tag}" = "default" ]; then
            continue
        fi
        python_bin="$(python_bin_for_runtime_tag "${runtime_tag}")"
        printf 'Compiling with %s: %s\n' "${python_bin}" "$(basename "${test_path}")"
        "${python_bin}" -m py_compile "${test_path}"
        compiled_count=$((compiled_count + 1))
    done
    if [ "${compiled_count}" -eq 0 ]; then
        printf 'No runtime-specific python targets selected\n'
    fi
}

run_preflight_checks() {
    printf '\nRunning preflight checks before regression execution...\n'
    run_preflight_syntax_baseline
    run_preflight_python_compile_checks
}

resolve_playwright_test_python_bin() {
    if [ -n "${PLAYWRIGHT_TEST_PYTHON_BIN}" ]; then
        printf '%s\n' "${PLAYWRIGHT_TEST_PYTHON_BIN}"
        return 0
    fi

    PLAYWRIGHT_TEST_PYTHON="${PLAYWRIGHT_TEST_PYTHON:-}"
    if [ -n "${PLAYWRIGHT_TEST_PYTHON}" ]; then
        PLAYWRIGHT_TEST_PYTHON_BIN="$(resolve_python_runtime "${PLAYWRIGHT_TEST_PYTHON}" || true)"
        [ -n "${PLAYWRIGHT_TEST_PYTHON_BIN}" ] || fail "PLAYWRIGHT_TEST_PYTHON not found/executable: ${PLAYWRIGHT_TEST_PYTHON}"
        printf '%s\n' "${PLAYWRIGHT_TEST_PYTHON_BIN}"
        return 0
    fi

    PLAYWRIGHT_VENV_PY="${SCRIPT_DIR}/.venv-playwright-regression/bin/python"
    if [ -x "${PLAYWRIGHT_VENV_PY}" ]; then
        PLAYWRIGHT_TEST_PYTHON_BIN="${PLAYWRIGHT_VENV_PY}"
    else
        PLAYWRIGHT_TEST_PYTHON_BIN="${RUNTIME_TEST_PYTHON_BIN}"
    fi
    printf '%s\n' "${PLAYWRIGHT_TEST_PYTHON_BIN}"
}

python_bin_for_runtime_tag() {
    local runtime_tag="$1"
    case "${runtime_tag}" in
        ""|default)
            printf '%s\n' "${RUNTIME_TEST_PYTHON_BIN}"
            ;;
        playwright)
            resolve_playwright_test_python_bin
            ;;
        *)
            fail "Unknown RUNNER_RUNTIME value: ${runtime_tag}"
            ;;
    esac
}

run_shell_test() {
    local test_path="$1"
    local optional="$2"
    local test_name=""
    local needs_target="1"
    local requires_root="0"
    local label=""
    test_name="$(basename "${test_path}")"
    needs_target="$(runner_meta_value "${test_path}" "RUNNER_NEEDS_TARGET" "1")"
    requires_root="$(runner_meta_value "${test_path}" "RUNNER_REQUIRES_ROOT" "0")"
    if is_truthy "${optional}"; then
        label=" (optional)"
    fi

    if is_truthy "${requires_root}" && [ "${EUID:-$(id -u)}" -ne 0 ] 2>/dev/null; then
        fail "Test ${test_name} requires root; rerun with sudo when using this selection"
    fi

    printf '\n==> %s%s\n' "${test_name}" "${label}"
    if is_truthy "${optional}"; then
        if is_truthy "${needs_target}"; then
            bash "${test_path}" "${TARGET_FILE}" || printf 'WARN: Optional shell test failed: %s\n' "${test_name}"
        else
            bash "${test_path}" || printf 'WARN: Optional shell test failed: %s\n' "${test_name}"
        fi
        return 0
    fi

    if is_truthy "${needs_target}"; then
        bash "${test_path}" "${TARGET_FILE}"
    else
        bash "${test_path}"
    fi
}

run_python_test() {
    local test_path="$1"
    local optional="$2"
    local test_name=""
    local runtime_tag=""
    local requires_root="0"
    local label=""
    local python_bin=""
    test_name="$(basename "${test_path}")"
    runtime_tag="$(runner_meta_value "${test_path}" "RUNNER_RUNTIME" "default")"
    requires_root="$(runner_meta_value "${test_path}" "RUNNER_REQUIRES_ROOT" "0")"
    python_bin="$(python_bin_for_runtime_tag "${runtime_tag}")"
    if is_truthy "${optional}"; then
        label=" (optional)"
    fi

    if is_truthy "${requires_root}" && [ "${EUID:-$(id -u)}" -ne 0 ] 2>/dev/null; then
        fail "Test ${test_name} requires root; rerun with sudo when using this selection"
    fi

    printf '\n==> %s%s\n' "${test_name}" "${label}"
    printf 'Using python runtime: %s\n' "${python_bin}"
    if is_truthy "${optional}"; then
        "${python_bin}" -m unittest -v "${test_path}" || printf 'WARN: Optional python test failed: %s\n' "${test_name}"
        return 0
    fi
    "${python_bin}" -m unittest -v "${test_path}"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --include-stateful)
            INCLUDE_STATEFUL=1
            shift
            ;;
        --only)
            [ "${2:-}" ] || fail "--only requires a pattern"
            ONLY_PATTERNS+=( "$2" )
            shift 2
            ;;
        --exclude)
            [ "${2:-}" ] || fail "--exclude requires a pattern"
            EXCLUDE_PATTERNS+=( "$2" )
            shift 2
            ;;
        --)
            shift
            break
            ;;
        -*)
            fail "Unknown option: $1"
            ;;
        *)
            if [ -n "${TARGET_FILE}" ]; then
                fail "Unexpected extra argument: $1"
            fi
            TARGET_FILE="$1"
            shift
            ;;
    esac
done

if [ "$#" -gt 0 ]; then
    fail "Unexpected extra arguments: $*"
fi

TARGET_FILE="${TARGET_FILE:-${DEFAULT_TARGET_FILE}}"
[ -f "${TARGET_FILE}" ] || fail "Target file not found: ${TARGET_FILE}"
[ -d "${REGRESSION_DIR}" ] || fail "Regression directory not found: ${REGRESSION_DIR}"

shopt -s nullglob
all_shell_tests=( "${REGRESSION_DIR}"/test_*.sh )
all_python_tests=( "${REGRESSION_DIR}"/test_*.py )
shopt -u nullglob

required_shell_tests=()
optional_shell_tests=()
required_python_tests=()
optional_python_tests=()
skipped_stateful_tests=()
filtered_out_tests=()

for test_path in "${all_shell_tests[@]}"; do
    test_name="$(basename "${test_path}")"
    ensure_test_executable_if_needed "${test_path}"
    if ! test_matches_filters "${test_name}"; then
        filtered_out_tests+=( "${test_name}" )
        continue
    fi
    test_stateful="$(runner_meta_value "${test_path}" "RUNNER_STATEFUL" "0")"
    test_optional="$(runner_meta_value "${test_path}" "RUNNER_OPTIONAL" "0")"
    if is_truthy "${test_stateful}" && [ "${INCLUDE_STATEFUL}" -ne 1 ]; then
        skipped_stateful_tests+=( "${test_name}" )
        continue
    fi
    if is_truthy "${test_optional}"; then
        optional_shell_tests+=( "${test_path}" )
    else
        required_shell_tests+=( "${test_path}" )
    fi
done

for test_path in "${all_python_tests[@]}"; do
    test_name="$(basename "${test_path}")"
    ensure_test_executable_if_needed "${test_path}"
    if ! test_matches_filters "${test_name}"; then
        filtered_out_tests+=( "${test_name}" )
        continue
    fi
    test_stateful="$(runner_meta_value "${test_path}" "RUNNER_STATEFUL" "0")"
    test_optional="$(runner_meta_value "${test_path}" "RUNNER_OPTIONAL" "0")"
    if is_truthy "${test_stateful}" && [ "${INCLUDE_STATEFUL}" -ne 1 ]; then
        skipped_stateful_tests+=( "$(basename "${test_path}")" )
        continue
    fi
    if is_truthy "${test_optional}"; then
        optional_python_tests+=( "${test_path}" )
    else
        required_python_tests+=( "${test_path}" )
    fi
done

total_shell_tests=$(( ${#required_shell_tests[@]} + ${#optional_shell_tests[@]} ))
total_python_tests=$(( ${#required_python_tests[@]} + ${#optional_python_tests[@]} ))
total_runnable_tests=$(( total_shell_tests + total_python_tests ))
[ "${total_runnable_tests}" -gt 0 ] || fail "No runnable regression tests found under ${REGRESSION_DIR} after applying filters/stateful rules"

printf 'Auto-discovered runnable tests: shell=%d python=%d (stateful skipped=%d)\n' \
    "${total_shell_tests}" "${total_python_tests}" "${#skipped_stateful_tests[@]}"
if [ "${#ONLY_PATTERNS[@]}" -gt 0 ]; then
    printf 'INFO: Active --only patterns:\n'
    for p in "${ONLY_PATTERNS[@]}"; do
        printf '  - %s\n' "${p}"
    done
fi
if [ "${#EXCLUDE_PATTERNS[@]}" -gt 0 ]; then
    printf 'INFO: Active --exclude patterns:\n'
    for p in "${EXCLUDE_PATTERNS[@]}"; do
        printf '  - %s\n' "${p}"
    done
fi
if [ "${#filtered_out_tests[@]}" -gt 0 ]; then
    printf 'INFO: Filtered out tests (%d):\n' "${#filtered_out_tests[@]}"
    for t in "${filtered_out_tests[@]}"; do
        printf '  - %s\n' "${t}"
    done
fi
if [ "${#skipped_stateful_tests[@]}" -gt 0 ]; then
    printf 'INFO: Skipped stateful tests by default; rerun with --include-stateful to include:\n'
    for t in "${skipped_stateful_tests[@]}"; do
        printf '  - %s\n' "${t}"
    done
fi
if [ "${total_python_tests}" -gt 0 ]; then
    RUNTIME_TEST_PYTHON="${RUNTIME_TEST_PYTHON:-python3}"
    RUNTIME_TEST_PYTHON_BIN="$(resolve_python_runtime "${RUNTIME_TEST_PYTHON}" || true)"
    [ -n "${RUNTIME_TEST_PYTHON_BIN}" ] || fail "RUNTIME_TEST_PYTHON not found/executable: ${RUNTIME_TEST_PYTHON}"
fi

run_preflight_checks

printf '\nRunning shell regressions against: %s\n' "${TARGET_FILE}"
for test_path in "${required_shell_tests[@]}"; do
    run_shell_test "${test_path}" "0"
done
for test_path in "${optional_shell_tests[@]}"; do
    run_shell_test "${test_path}" "1"
done

for test_path in "${required_python_tests[@]}"; do
    run_python_test "${test_path}" "0"
done
for test_path in "${optional_python_tests[@]}"; do
    run_python_test "${test_path}" "1"
done

printf '\nPASS: Regression suite completed\n'
