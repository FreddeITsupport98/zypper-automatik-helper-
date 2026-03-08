#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_FILE="${1:-${SCRIPT_DIR}/zypper-auto.sh}"

usage() {
    cat <<'EOF'
Usage: ./test_stale_module_dirs_runtime_regression.sh [path/to/zypper-auto.sh]

Runtime regression test for run_stale_module_dirs_only using temporary roots:
  - audit mode is non-destructive and reports stale versions
  - non-interactive quarantine is rejected without --yes
  - quarantine --yes moves stale dirs into quarantine and keeps bootable dirs
  - post-quarantine audit reports zero stale versions
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

stale_helper_block="$(
    awk '
        /run_stale_module_dirs_only\(\) \{/ {inblk=1}
        inblk {print}
        /# --- Helper: Reset download\/notifier state \(CLI\) ---/ && inblk {exit}
    ' "${TARGET_FILE}"
)"
[ -n "${stale_helper_block}" ] || fail "Could not locate run_stale_module_dirs_only block"

# Minimal stubs required by run_stale_module_dirs_only when executed in isolation.
log_error() { printf '%s\n' "$*" >&2; }
update_status() { :; }
execute_guarded() {
    local _desc="$1"
    shift
    "$@"
}

eval "${stale_helper_block}"

TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "${TMP_ROOT}" 2>/dev/null || true' EXIT

LIB_ROOT="${TMP_ROOT}/lib/modules"
USR_ROOT="${TMP_ROOT}/usr/lib/modules"
QUARANTINE_ROOT="${TMP_ROOT}/quarantine"

mkdir -p "${LIB_ROOT}" "${USR_ROOT}" "${QUARANTINE_ROOT}" || fail "Failed to create temp roots"

# Bootable directory (has modules.dep) - must never be quarantined.
mkdir -p "${LIB_ROOT}/6.14.0-1-default"
touch "${LIB_ROOT}/6.14.0-1-default/modules.dep"

# Stale directories (no modules.dep) - expected quarantine candidates.
mkdir -p "${LIB_ROOT}/6.13.9-1-default"
mkdir -p "${USR_ROOT}/6.13.8-2-default"

AUDIT_OUT="${TMP_ROOT}/audit.out"
if ! ZNH_STALE_MODULE_LIB_ROOT="${LIB_ROOT}" ZNH_STALE_MODULE_USR_LIB_ROOT="${USR_ROOT}" \
    run_stale_module_dirs_only audit 0 "${QUARANTINE_ROOT}" >"${AUDIT_OUT}" 2>&1; then
    fail "audit mode failed unexpectedly"
fi

audit_txt="$(cat -- "${AUDIT_OUT}")"
require_contains "${audit_txt}" "Mode: audit" "audit output missing mode"
require_contains "${audit_txt}" "Scan roots: ${LIB_ROOT} , ${USR_ROOT}" "audit output missing overridden scan roots"
require_contains "${audit_txt}" "Stale non-bootable versions: 2" "audit output missing stale count"
require_contains "${audit_txt}" "Audit-only mode (safe default): no changes made." "audit output missing safe-default message"

[ -d "${LIB_ROOT}/6.13.9-1-default" ] || fail "audit mode should not move stale lib module dir"
[ -d "${USR_ROOT}/6.13.8-2-default" ] || fail "audit mode should not move stale usr-lib module dir"

NO_YES_OUT="${TMP_ROOT}/no-yes.out"
if ZNH_STALE_MODULE_LIB_ROOT="${LIB_ROOT}" ZNH_STALE_MODULE_USR_LIB_ROOT="${USR_ROOT}" \
    run_stale_module_dirs_only quarantine 0 "${QUARANTINE_ROOT}" >"${NO_YES_OUT}" 2>&1 </dev/null; then
    fail "non-interactive quarantine without --yes should fail"
fi

no_yes_txt="$(cat -- "${NO_YES_OUT}")"
require_contains "${no_yes_txt}" "Non-interactive quarantine requires --yes / -y" "missing non-interactive guard error"

YES_OUT="${TMP_ROOT}/yes.out"
if ! ZNH_STALE_MODULE_LIB_ROOT="${LIB_ROOT}" ZNH_STALE_MODULE_USR_LIB_ROOT="${USR_ROOT}" \
    run_stale_module_dirs_only quarantine 1 "${QUARANTINE_ROOT}" >"${YES_OUT}" 2>&1; then
    fail "quarantine --yes failed unexpectedly"
fi

yes_txt="$(cat -- "${YES_OUT}")"
require_contains "${yes_txt}" "Mode: quarantine" "quarantine output missing mode"
require_contains "${yes_txt}" "Module dirs moved: 2" "quarantine output missing moved count"
require_contains "${yes_txt}" "Move failures: 0" "quarantine output missing failure count"
require_contains "${yes_txt}" "Restore examples (if needed):" "quarantine output missing restore hint"

[ ! -d "${LIB_ROOT}/6.13.9-1-default" ] || fail "stale lib module dir should be moved during quarantine"
[ ! -d "${USR_ROOT}/6.13.8-2-default" ] || fail "stale usr-lib module dir should be moved during quarantine"
[ -f "${LIB_ROOT}/6.14.0-1-default/modules.dep" ] || fail "bootable module dir should remain intact after quarantine"

quarantine_dir="$(find "${QUARANTINE_ROOT}" -mindepth 1 -maxdepth 1 -type d -name 'stale-module-dirs-*' | head -n 1 || true)"
[ -n "${quarantine_dir}" ] || fail "quarantine run did not create timestamped quarantine dir"
[ -d "${quarantine_dir}/lib-modules/6.13.9-1-default" ] || fail "quarantined lib module dir missing"
[ -d "${quarantine_dir}/usr-lib-modules/6.13.8-2-default" ] || fail "quarantined usr-lib module dir missing"

POST_AUDIT_OUT="${TMP_ROOT}/post-audit.out"
if ! ZNH_STALE_MODULE_LIB_ROOT="${LIB_ROOT}" ZNH_STALE_MODULE_USR_LIB_ROOT="${USR_ROOT}" \
    run_stale_module_dirs_only audit 0 "${QUARANTINE_ROOT}" >"${POST_AUDIT_OUT}" 2>&1; then
    fail "post-quarantine audit failed unexpectedly"
fi

post_audit_txt="$(cat -- "${POST_AUDIT_OUT}")"
require_contains "${post_audit_txt}" "Stale non-bootable versions: 0" "post-quarantine audit should report no stale versions"
require_contains "${post_audit_txt}" "No stale non-bootable module directories detected." "post-quarantine audit missing no-stale message"

pass "Runtime stale module-dir helper regression checks passed"
