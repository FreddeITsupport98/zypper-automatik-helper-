#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_FILE="${1:-${SCRIPT_DIR}/zypper-auto.sh}"

usage() {
    cat <<'EOF'
Usage: ./test_kernel_purge_lock_regression.sh [path/to/zypper-auto.sh]

Regression smoke test for kernel purge lock handling:
  - __znh_kernel_purge_old_kernels defines lock helpers
  - direct purge path waits for lock and retries once on lock-race
  - persistent lock contention is downgraded to graceful skip + audit record
  - zypper/auto/systemd-fallback paths route through the lock-aware direct helper
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

kernel_purge_block="$(
    awk '
        /__znh_kernel_purge_old_kernels\(\) \{/ {inblk=1}
        inblk {print}
        /__znh_audit_record "kernel-purge:maybe"/ && inblk {exit}
    ' "${TARGET_FILE}"
)"
[ -n "${kernel_purge_block}" ] || fail "Could not locate __znh_kernel_purge_old_kernels block"

require_contains "${kernel_purge_block}" "__znh_kernel_purge_lock_file() {" "kernel purge lock-file helper missing"
require_contains "${kernel_purge_block}" "__znh_kernel_purge_lock_details() {" "kernel purge lock-details helper missing"
require_contains "${kernel_purge_block}" "__znh_kernel_purge_lock_active() {" "kernel purge lock-active helper missing"
require_contains "${kernel_purge_block}" "__znh_kernel_purge_wait_for_lock() {" "kernel purge wait helper missing"
require_contains "${kernel_purge_block}" "__znh_kernel_purge_run_direct_zypper() {" "kernel purge direct runner helper missing"

require_contains "${kernel_purge_block}" "__znh_kernel_purge_wait_for_lock \"\${timeout_s}\"" "direct runner must wait for lock"
require_contains "${kernel_purge_block}" "waiting and retrying once" "direct runner must log retry-on-lock path"
require_contains "${kernel_purge_block}" "__znh_audit_record \"kernel-purge:skipped:zypp-lock-timeout\"" "missing lock-timeout skip audit record"
require_contains "${kernel_purge_block}" "__znh_audit_record \"kernel-purge:skipped:zypp-lock-race\"" "missing lock-race skip audit record"
require_contains "${kernel_purge_block}" "Skipping purge-kernels after retry because lock is still active" "missing graceful skip log after retry"

require_contains "${kernel_purge_block}" "__znh_kernel_purge_run_direct_zypper \"Kernel purge (zypper purge-kernels)\" || true" "zypper/auto branches must use lock-aware direct runner"
require_contains "${kernel_purge_block}" "falling back to direct zypper purge-kernels" "systemd fallback log missing"
require_contains "${kernel_purge_block}" "__znh_audit_record \"kernel-purge:skipped:zypp-lock-timeout:systemd\"" "systemd lock-timeout skip audit record missing"

pass "Kernel purge lock-handling regression checks passed"
