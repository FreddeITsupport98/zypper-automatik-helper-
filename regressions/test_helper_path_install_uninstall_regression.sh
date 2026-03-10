#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET_FILE="${1:-${REPO_ROOT}/zypper-auto.sh}"

usage() {
    cat <<'EOF'
Usage: ./test_helper_path_install_uninstall_regression.sh [path/to/zypper-auto.sh]

Regression smoke test for helper PATH accessibility + uninstall cleanup:
  - install flow defines a compatibility link path (/usr/bin/zypper-auto-helper)
  - install flow creates/refreshes compatibility symlink to /usr/local/bin helper
  - uninstall dry-run mentions compatibility symlink cleanup
  - uninstall only removes /usr/bin helper when symlink target matches managed helper
  - uninstall shell cleanup removes full zypper-auto-helper wrapper blocks from bash/zsh rc files
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

require_contains "${source_text}" "COMMAND_COMPAT_LINK=\"/usr/bin/zypper-auto-helper\"" "install flow missing compatibility link variable"
require_contains "${source_text}" "Install compatibility PATH symlink \${COMMAND_COMPAT_LINK} -> \${COMMAND_PATH}" "install flow missing compatibility symlink action"
require_contains "${source_text}" "ln -sfn \"\${COMMAND_PATH}\" \"\${COMMAND_COMPAT_LINK}\"" "install flow missing symlink command"

require_contains "${source_text}" "/usr/bin/zypper-auto-helper (compatibility symlink when pointing to /usr/local/bin/zypper-auto-helper)" "uninstall dry-run missing compatibility symlink note"
require_contains "${source_text}" "if [ -L /usr/bin/zypper-auto-helper ]; then" "uninstall missing symlink-target guard"
require_contains "${source_text}" "readlink -f /usr/bin/zypper-auto-helper" "uninstall missing symlink target resolution"
require_contains "${source_text}" "Remove compatibility symlink /usr/bin/zypper-auto-helper" "uninstall missing guarded symlink removal action"
require_contains "${source_text}" "Leaving /usr/bin/zypper-auto-helper in place (non-symlink file may be package-managed)" "uninstall missing non-symlink safety guard"

require_contains "${source_text}" "-e '/# zypper-auto-helper command wrapper (added by zypper-auto-helper)/,/^}\$/d'" "uninstall missing bash/zsh wrapper block cleanup"

pass "Helper PATH install/uninstall regression checks passed"
