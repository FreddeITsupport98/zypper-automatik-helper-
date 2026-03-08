#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_FILE="${1:-${SCRIPT_DIR}/zypper-auto.sh}"

usage() {
    cat <<'EOF'
Usage: ./test_boot_kernel_inventory_regression.sh [path/to/zypper-auto.sh]

Regression smoke test for boot-kernel inventory counting:
  - /api/boot/stats kernel inventory counts only module trees with modules.dep
  - API exposes raw module directory count separately (raw_dirs_count)
  - Snapper Manager Boot/EFI kernel detail text clarifies bootable count and extra module dirs
  - kernel-family-purge and kernel-purge safety counting use modules.dep-filtered versions
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

require_not_contains() {
    local haystack="$1"
    local needle="$2"
    local label="$3"
    if grep -Fq -- "${needle}" <<< "${haystack}"; then
        fail "${label} (unexpected: ${needle})"
    fi
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

[ -f "${TARGET_FILE}" ] || fail "Target file not found: ${TARGET_FILE}"

source_text="$(cat -- "${TARGET_FILE}")"

kernel_stats_block="$(
    awk '
        /def _installed_kernels_stats\(\) -> dict:/ {inblk=1}
        inblk {print}
        /if path == "\/api\/boot\/stats":/ && inblk {exit}
    ' "${TARGET_FILE}"
)"
[ -n "${kernel_stats_block}" ] || fail "Could not locate _installed_kernels_stats block"

kernel_family_block="$(
    awk '
        /__znh_installed_kernel_versions_list\(\) \{/ {inblk=1}
        inblk {print}
        /local installed_kvers installed_count/ && inblk {exit}
    ' "${TARGET_FILE}"
)"
[ -n "${kernel_family_block}" ] || fail "Could not locate __znh_installed_kernel_versions_list block"

kernel_purge_block="$(
    awk '
        /__znh_kernel_purge_old_kernels\(\) \{/ {inblk=1}
        inblk {print}
        /__znh_audit_record "kernel-purge:maybe"/ && inblk {exit}
    ' "${TARGET_FILE}"
)"
[ -n "${kernel_purge_block}" ] || fail "Could not locate __znh_kernel_purge_old_kernels block"

# Python API inventory logic assertions
require_contains "${kernel_stats_block}" "\"raw_dirs_count\": 0," "installed_kernels stats missing raw_dirs_count field"
require_contains "${kernel_stats_block}" "raw_versions = set()" "installed_kernels stats should track raw module directory versions"
require_contains "${kernel_stats_block}" "raw_vers = sorted(list(raw_versions))" "installed_kernels stats missing raw_vers list"
require_contains "${kernel_stats_block}" "for kv in raw_vers:" "installed_kernels stats should iterate raw_vers"
require_contains "${kernel_stats_block}" "dep_path = \"\"" "installed_kernels stats missing dep_path guard"
require_contains "${kernel_stats_block}" "if not dep_path:" "installed_kernels stats must skip dirs without modules.dep"
require_contains "${kernel_stats_block}" "owner = _rpm_owner_name(dep_path)" "installed_kernels stats should resolve owner from validated modules.dep"
require_contains "${kernel_stats_block}" "vers.append(str(kv))" "installed_kernels stats should append only validated kernel versions"
require_contains "${kernel_stats_block}" "\"raw_dirs_count\": int(len(raw_vers))," "installed_kernels stats should expose raw_dirs_count in API payload"

# WebUI text clarity assertions
require_contains "${source_text}" "bootable installed versions=" "Boot/EFI kernel detail text must show bootable installed versions"
require_contains "${source_text}" "extra module dirs=" "Boot/EFI kernel detail text should expose extra module-dir count when present"

# Shell safety counting assertions
require_contains "${kernel_family_block}" "for _kvd in /lib/modules/* /usr/lib/modules/*; do" "kernel-family installed-kvers helper must iterate module directories"
require_contains "${kernel_family_block}" "if [ -f \"/lib/modules/\${_kv}/modules.dep\" ] || [ -f \"/usr/lib/modules/\${_kv}/modules.dep\" ]; then" "kernel-family installed-kvers helper must require modules.dep"

require_contains "${kernel_purge_block}" "for __kp_dir in /lib/modules/* /usr/lib/modules/*; do" "kernel-purge installed-kernel counting must iterate module directories"
require_contains "${kernel_purge_block}" "if [ -f \"/lib/modules/\${__kp_kv}/modules.dep\" ] || [ -f \"/usr/lib/modules/\${__kp_kv}/modules.dep\" ]; then" "kernel-purge installed-kernel counting must require modules.dep"
require_not_contains "${kernel_purge_block}" "find /lib/modules /usr/lib/modules -maxdepth 1 -mindepth 1 -type d -printf '%f\\n'" "kernel-purge must not count raw module directories without modules.dep filtering"

pass "Boot-kernel inventory counting regression checks passed"
