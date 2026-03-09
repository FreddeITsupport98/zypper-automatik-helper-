#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_FILE="${1:-${SCRIPT_DIR}/zypper-auto.sh}"

usage() {
    cat <<'EOF'
Usage: ./test_verify_snapshot_policy_regression.sh [path/to/zypper-auto.sh]

Regression smoke test for verification Safety Net snapshot policy:
  - run_smart_verification_with_safety_net supports explicit snapshot mode control
  - verify-only path forces snapshot mode "never"
  - install verification path forces snapshot mode "always"
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

fn_block="$(
    awk '
        /run_smart_verification_with_safety_net\(\) \{/ {inblk=1}
        inblk {print}
        /^}/ && inblk {exit}
    ' "${TARGET_FILE}"
)"
[ -n "${fn_block}" ] || fail "Could not locate run_smart_verification_with_safety_net function block"

require_contains "${fn_block}" "snapshot_mode=\"\${2:-auto}\"" "snapshot mode default missing"
require_contains "${fn_block}" "always|install|install-update-only)" "snapshot enable mode branch missing"
require_contains "${fn_block}" "never|off|disabled)" "snapshot disable mode branch missing"
require_contains "${fn_block}" "if [ \"\${snapshot_enabled}\" -eq 1 ] 2>/dev/null; then" "snapshot enabled gate missing"
require_contains "${fn_block}" "skipping pre/post Snapper snapshots for this verification run" "snapshot skip log missing"
require_contains "${fn_block}" "__znh_finalize_repair_safety_snapshot \"\$rc\" || true" "snapshot finalize call missing"

require_contains "${source_text}" "run_smart_verification_with_safety_net 2 never" "verify-only path must disable safety snapshots"
require_contains "${source_text}" "run_smart_verification_with_safety_net 1 always" "install verification path must keep safety snapshots"

pass "Verification snapshot policy regression checks passed"
