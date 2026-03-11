#!/usr/bin/env bash
# RUNNER_NEEDS_TARGET=0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RUNNER_FILE="${1:-${REPO_ROOT}/run_regression_suite.sh}"
SYNTAX_FILE="${2:-${REPO_ROOT}/scripts/syntax-check.sh}"

usage() {
    cat <<'EOF'
Usage: ./test_runner_python_target_preflight_regression.sh [path/to/run_regression_suite.sh] [path/to/scripts/syntax-check.sh]

Focused static regression smoke test for shared preflight python-target wiring:
  - scripts/syntax-check.sh supports --python-target and keeps explicit PYTHON_TARGET_FILES array
  - run_regression_suite preflight forwards default-runtime python tests via --python-target
  - run_regression_suite keeps runtime-tagged python compile checks in runner-side preflight
EOF
}

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

pass() {
    printf 'PASS: %s\n' "$1"
}

require_contains() {
    local haystack="$1"
    local needle="$2"
    local label="$3"
    if ! grep -Fq -- "${needle}" <<< "${haystack}"; then
        fail "${label} (missing: ${needle})"
    fi
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

[ -f "${RUNNER_FILE}" ] || fail "Runner file not found: ${RUNNER_FILE}"
[ -f "${SYNTAX_FILE}" ] || fail "Syntax script file not found: ${SYNTAX_FILE}"

syntax_text="$(cat -- "${SYNTAX_FILE}")"

preflight_syntax_block="$(
    awk '
        /run_preflight_syntax_baseline\(\) \{/ {inblk=1}
        inblk {print}
        /run_preflight_python_compile_checks\(\) \{/ && inblk {exit}
    ' "${RUNNER_FILE}"
)"
[ -n "${preflight_syntax_block}" ] || fail "Could not locate run_preflight_syntax_baseline block"

preflight_python_block="$(
    awk '
        /run_preflight_python_compile_checks\(\) \{/ {inblk=1}
        inblk {print}
        /run_preflight_checks\(\) \{/ && inblk {exit}
    ' "${RUNNER_FILE}"
)"
[ -n "${preflight_python_block}" ] || fail "Could not locate run_preflight_python_compile_checks block"

require_contains "${syntax_text}" "PYTHON_TARGET_FILES=()" "syntax checker missing PYTHON_TARGET_FILES array"
require_contains "${syntax_text}" "--python-target FILE     Add an explicit python script target (repeatable)" "syntax checker help missing --python-target option"
require_contains "${syntax_text}" "--python-target)" "syntax checker parser missing --python-target case"
require_contains "${syntax_text}" "PYTHON_TARGET_FILES+=( \"\$2\" )" "syntax checker parser missing python-target append"
require_contains "${syntax_text}" "for path in \"\${PYTHON_TARGET_FILES[@]}\"; do" "syntax checker missing explicit python target existence checks"
require_contains "${syntax_text}" "\"\${PYTHON_BIN}\" -m py_compile \"\${path}\"" "syntax checker missing python compile execution for explicit targets"

require_contains "${preflight_syntax_block}" "if [ \"\${runtime_tag}\" = \"default\" ]; then" "runner syntax baseline missing default-runtime guard"
require_contains "${preflight_syntax_block}" "syntax_args+=( \"--python-target\" \"\${test_path}\" )" "runner syntax baseline missing python-target forwarding"
require_contains "${preflight_syntax_block}" "SYNTAX_PYTHON=\"\${syntax_python}\"" "runner syntax baseline missing shared python runtime export"
require_contains "${preflight_syntax_block}" "\"\${syntax_script}\" \"\${syntax_args[@]}\"" "runner syntax baseline missing shared script invocation"

require_contains "${preflight_python_block}" "if [ \"\${runtime_tag}\" = \"default\" ]; then" "runner runtime-specific python preflight missing default skip guard"
require_contains "${preflight_python_block}" "continue" "runner runtime-specific python preflight missing continue for default runtime"
require_contains "${preflight_python_block}" "python_bin=\"\$(python_bin_for_runtime_tag \"\${runtime_tag}\")\"" "runner runtime-specific python preflight missing tagged runtime resolution"
require_contains "${preflight_python_block}" "No runtime-specific python targets selected" "runner runtime-specific python preflight missing empty-state message"

pass "Runner python-target preflight wiring regression checks passed"
