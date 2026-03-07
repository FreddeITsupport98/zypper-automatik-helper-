#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_FILE="${1:-${SCRIPT_DIR}/zypper-auto.sh}"

usage() {
    cat <<'EOF'
Usage: ./test_wrapper_lock_race_regression.sh [path/to/zypper-auto.sh]

Regression smoke test for zypper-with-ps wrapper lock handling:
  - wrapper defines lock detail + lock output helpers
  - wrapper uses lock wait before manual dup/update/dist-upgrade run
  - wrapper retries once when lock contention appears during zypper execution
  - wrapper prints detailed lock owner info on final lock failure
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

[ -f "${TARGET_FILE}" ] || fail "Target file not found: ${TARGET_FILE}"

source_text="$(cat -- "${TARGET_FILE}")"

# Helper definitions used by the generated zypper-with-ps wrapper
require_contains "${source_text}" "zypp_lock_details() {" "wrapper lock-details helper missing"
require_contains "${source_text}" "is_zypp_lock_output() {" "wrapper lock-output detector helper missing"
require_contains "${source_text}" "wait_for_zypp_lock_clear() {" "wrapper lock wait helper missing"
require_contains "${source_text}" "LOCK_RETRY_INITIAL_DELAY_SECONDS=0 disables waiting (fail fast)." "wrapper lock wait helper must document zero-delay behavior"

# Manual zypper wrapper flow (dup/dist-upgrade/update)
require_contains "${source_text}" "if [[ \"\$*\" == *\"dup\"* ]] || [[ \"\$*\" == *\"dist-upgrade\"* ]] || [[ \"\$*\" == *\"update\"* ]] ; then" "wrapper manual update gate missing"
require_contains "${source_text}" "if ! wait_for_zypp_lock_clear \"\$max_attempts\" \"\$base_delay\"; then" "wrapper must wait for lock before running zypper"
require_contains "${source_text}" "run_attempt_max=2" "wrapper must allow one execution retry on lock race"
require_contains "${source_text}" "if is_zypp_lock_output \"\$ZYPPER_OUT_FILE\"; then" "wrapper must parse lock text from zypper output"
require_contains "${source_text}" "if [ \"\$run_attempt\" -lt \"\$run_attempt_max\" ] && { [ \"\$EXIT_CODE\" -eq 7 ] || [ \"\$FINAL_OUTPUT_LOCK\" -eq 1 ]; }; then" "wrapper lock-race retry condition missing"
require_contains "${source_text}" "Lock contention detected during zypper run (attempt \$run_attempt/\$run_attempt_max)." "wrapper missing lock-race retry log message"
require_contains "${source_text}" "if wait_for_zypp_lock_clear \"\$max_attempts\" \"\$base_delay\"; then" "wrapper must wait again before retrying zypper after lock race"

# Final lock failure messaging
require_contains "${source_text}" "if [ \"\$EXIT_CODE\" -eq 7 ] || [ \"\$LOCK_FAILURE\" -eq 1 ] || [ \"\$FINAL_OUTPUT_LOCK\" -eq 1 ]; then" "wrapper final lock failure condition missing"
require_contains "${source_text}" "lock_info=\"\$(zypp_lock_details)\"" "wrapper must capture lock details for final lock failure"
require_contains "${source_text}" "echo \"Lock details: lock_file=\${lock_file} pid=\${lock_pid} owner=\${lock_owner}\"" "wrapper final lock failure details message missing"

pass "Wrapper lock-race regression checks passed"
