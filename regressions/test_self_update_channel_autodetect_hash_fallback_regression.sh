#!/usr/bin/env bash
# RUNNER_NEEDS_TARGET=0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET_FILE="${1:-${REPO_ROOT}/zypper-auto.sh}"

usage() {
    cat <<'EOF'
Usage: ./test_self_update_channel_autodetect_hash_fallback_regression.sh [path/to/zypper-auto.sh]

Focused static regression for self-update CLI behavior:
  - auto-detect channel from state metadata when channel arg is omitted
  - content-hash fallback exists for both stable/rolling to avoid no-op ref drift loops
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

self_update_block="$(
    awk '
        /run_self_update_only\(\) \{/ {inblk=1}
        inblk {
            if ($0 ~ /^run_self_update_rollback_only\(\) \{/) {exit}
            print
        }
    ' "${TARGET_FILE}"
)"

[ -n "${self_update_block}" ] || fail "Could not locate run_self_update_only block"

# Auto channel-detection scaffolding
require_contains "${self_update_block}" "state_last_channel=\"\$(__znh_self_update_state_get last_update_channel" "missing state last_update_channel read"
require_contains "${self_update_block}" "state_install_source=\"\$(__znh_self_update_state_get install_source" "missing state install_source read"
require_contains "${self_update_block}" "if [ -z \"\${requested_channel:-}\" ]; then" "missing requested_channel omission guard"
require_contains "${self_update_block}" "detected_reason=\"state:last_update_channel\"" "missing last_update_channel detection reason"
require_contains "${self_update_block}" "detected_reason=\"state:install_source\"" "missing install_source detection reason"
require_contains "${self_update_block}" "channel=\"\${requested_channel:-\${detected_channel:-\${SELF_UPDATE_CHANNEL:-stable}}}\"" "missing channel fallback chain"
require_contains "${self_update_block}" "log_info \"[self-update] Auto-detected channel=\${channel} (\${detected_reason})\"" "missing auto-detected channel log"

# Content-hash truth fallback scaffolding (stable + rolling)
require_contains "${self_update_block}" "# Content-hash truth fallback (stable + rolling):" "missing content-hash fallback section marker"
require_contains "${self_update_block}" "if [ \"\${channel}\" = \"stable\" ] && [ -n \"\${raw_url_tag:-}\" ]; then" "missing stable raw_url_tag compare branch"
require_contains "${self_update_block}" "if [ -n \"\${local_hash:-}\" ] && [ \"\${local_hash}\" = \"\${remote_hash}\" ]; then" "missing local/remote hash equality guard"
require_contains "${self_update_block}" "log_info \"[self-update] Local file perfectly matches remote \${channel} payload. Seeding state.\"" "missing content-match state seeding log"
require_contains "${self_update_block}" "__znh_self_update_state_write \"\${remote_ref}\" \"\${installed_rolling_sha}\" \"stable\" \"\${remote_ref}\" \"stable-release\"" "missing stable state seed write"
require_contains "${self_update_block}" "__znh_self_update_state_write \"\${installed_stable_tag}\" \"\${remote_ref}\" \"rolling\" \"\${remote_ref}\" \"rolling-commit\"" "missing rolling state seed write"

pass "Self-update channel auto-detection and content-hash fallback regression checks passed"
