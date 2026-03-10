#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET_FILE="${1:-${REPO_ROOT}/zypper-auto.sh}"

usage() {
    cat <<'EOF'
Usage: ./test_stale_module_dirs_helper_regression.sh [path/to/zypper-auto.sh]

Regression smoke test for stale module-dir helper wiring:
  - run_stale_module_dirs_only exists with safe audit/quarantine behavior
  - quarantine path includes root-path guard, explicit confirmation, and non-destructive move
  - CLI parser exposes --stale-module-dirs and related options
  - help text and shell completions include --stale-module-dirs
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

stale_helper_block="$(
    awk '
        /run_stale_module_dirs_only\(\) \{/ {inblk=1}
        inblk {print}
        /# --- Helper: Reset download\/notifier state \(CLI\) ---/ && inblk {exit}
    ' "${TARGET_FILE}"
)"
[ -n "${stale_helper_block}" ] || fail "Could not locate run_stale_module_dirs_only block"

require_contains "${stale_helper_block}" "case \"\${mode}\" in" "stale module helper missing mode dispatch"
require_contains "${stale_helper_block}" "audit|quarantine) ;;" "stale module helper mode dispatch missing audit/quarantine options"
require_contains "${stale_helper_block}" "if [ \"\${quarantine_root}\" = \"/\" ]; then" "stale module helper missing unsafe quarantine-root guard"
require_contains "${stale_helper_block}" "if [ \"\${mode}\" = \"audit\" ]; then" "stale module helper missing audit mode branch"
require_contains "${stale_helper_block}" "Audit-only mode (safe default): no changes made." "stale module helper missing safe-default audit output"
require_contains "${stale_helper_block}" "Non-interactive quarantine requires --yes / -y" "stale module helper missing explicit non-interactive confirmation guard"
require_contains "${stale_helper_block}" "execute_guarded \"Quarantine stale module dir (\${src})\" mv -f -- \"\${src}\" \"\${dst_parent}/\"" "stale module helper missing non-destructive move operation"
require_contains "${stale_helper_block}" "echo \"Restore examples (if needed):\"" "stale module helper missing restore guidance"
require_not_contains "${stale_helper_block}" "rm -rf" "stale module helper should not perform destructive recursive deletes"

require_contains "${source_text}" "elif [[ \"\${1:-}\" == \"--stale-module-dirs\" || \"\${1:-}\" == \"--stale-modules\" ]]; then" "CLI parser missing --stale-module-dirs branch"
require_contains "${source_text}" "STALE_MODE=\"audit\"" "CLI parser missing safe default mode for stale module helper"
require_contains "${source_text}" "--quarantine-root" "CLI parser missing --quarantine-root option support"
require_contains "${source_text}" "Unknown option for --stale-module-dirs:" "CLI parser missing unknown-option guard for stale module helper"
require_contains "${source_text}" "--reset-config|--reset-downloads|--reset-state|--stale-module-dirs|--stale-modules|--rm-conflict|" "early option allowlist missing stale-module options"

require_contains "${source_text}" "  --stale-module-dirs     Audit/quarantine stale non-bootable /lib/modules dirs (safe helper)" "help output missing --stale-module-dirs command description"
require_contains "${source_text}" "ZNH_CLI_WORDS=\"install debug snapper scrub-ghost" "completion command word list missing"
require_contains "${source_text}" "--stale-module-dirs --reset-downloads" "completion command word list missing stale-module option"
require_contains "${source_text}" "complete -c zypper-auto-helper -f -a \"--stale-module-dirs\"" "fish completion missing stale-module option"

pass "Stale module-dir helper regression checks passed"
