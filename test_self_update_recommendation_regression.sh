#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_FILE="${1:-${SCRIPT_DIR}/zypper-auto.sh}"

usage() {
    cat <<'EOF'
Usage: ./test_self_update_recommendation_regression.sh [path/to/zypper-auto.sh]

Focused regression smoke test for self-update recommendation and stable semantics:
  - backend exposes latest-release-candidate + layered MD5 recommendation helpers
  - /api/self-update/status uses content-based compare + recommendation payload
  - WebUI stable changelog/release-notes use latest release candidate list endpoint
  - WebUI install overlay preselects post-action from API recommendation metadata
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

self_update_status_block="$(
    awk '
        /if path == "\/api\/self-update\/status":/ {inblk=1}
        inblk {
            if ($0 ~ /# --- Self-update job status \(dashboard\) ---/) {exit}
            print
        }
    ' "${TARGET_FILE}"
)"
[ -n "${self_update_status_block}" ] || fail "Could not locate /api/self-update/status block"

su_render_install_block="$(
    awk '
        /function _suRenderInstall\(confirmInfo\) \{/ {inblk=1}
        inblk {
            if ($0 ~ /function _suUpdateProgress\(stage, percent\) \{/) {exit}
            print
        }
    ' "${TARGET_FILE}"
)"
[ -n "${su_render_install_block}" ] || fail "Could not locate _suRenderInstall block"

self_update_changelog_block="$(
    awk '
        /function selfUpdateFetchChangelog\(btnEl\) \{/ {inblk=1}
        inblk {
            if ($0 ~ /function selfUpdateToggleChannel\(btnEl\) \{/) {exit}
            print
        }
    ' "${TARGET_FILE}"
)"
[ -n "${self_update_changelog_block}" ] || fail "Could not locate selfUpdateFetchChangelog block"

require_contains "${source_text}" "def _github_latest_release_candidate(timeout_s: int = 10) -> dict:" "backend missing latest release candidate helper"
require_contains "${source_text}" "def _read_remote_script_bytes(ref: str, timeout_s: int = 15) -> tuple[bytes, str]:" "backend missing remote script bytes helper"
require_contains "${source_text}" "def _script_layer_md5s(text: str) -> dict:" "backend missing layered MD5 helper"
require_contains "${source_text}" "def _recommend_post_action(local_layers: dict, remote_layers: dict, *, has_remote: bool) -> tuple[str, str, list[str]]:" "backend missing recommendation helper"

require_contains "${self_update_status_block}" "j = _github_latest_release_candidate(timeout_s=10)" "status endpoint missing stable release-candidate selection"
require_contains "${self_update_status_block}" "data, pth = _read_remote_script_bytes(remote_ref, timeout_s=15)" "status endpoint missing remote script content fetch"
require_contains "${self_update_status_block}" "local_layer_md5 = _script_layer_md5s(local_script_text)" "status endpoint missing local layered MD5 calculation"
require_contains "${self_update_status_block}" "remote_layer_md5 = _script_layer_md5s(remote_script_text)" "status endpoint missing remote layered MD5 calculation"
require_contains "${self_update_status_block}" "rec_action, rec_reason, rec_changed_layers = _recommend_post_action(" "status endpoint missing recommendation decision call"
require_contains "${source_text}" "\"stable_candidate\": {" "status payload missing stable candidate metadata"
require_contains "${source_text}" "\"post_action_recommendation\": {" "status payload missing post-action recommendation object"
require_contains "${source_text}" "\"recommended\": str(rec_action or \"none\")," "status payload missing recommendation value"
require_contains "${source_text}" "\"changed_layers\": rec_changed_layers if isinstance(rec_changed_layers, list) else []," "status payload missing changed-layer list"

require_contains "${source_text}" "function _suFetchLatestStableReleaseCandidate() {" "frontend missing stable release-candidate helper"
require_contains "${source_text}" "_githubApiJson(base + '/releases?per_page=25')" "frontend missing stable releases list fetch"
require_contains "${source_text}" "return _suFetchLatestStableReleaseCandidate().then(function(j) {" "frontend stable notes/changelog not wired to candidate helper"
require_contains "${self_update_changelog_block}" "return _suFetchLatestStableReleaseCandidate().then(function(j) {" "self-update changelog missing stable candidate fetch path"
require_contains "${source_text}" "toast('Changelog loaded', 'Stable release-candidate notes fetched', 'ok');" "frontend missing stable candidate changelog toast text"

require_contains "${su_render_install_block}" "var rec = (st && st.post_action_recommendation) ? st.post_action_recommendation : null;" "install overlay missing recommendation extraction from status payload"
require_contains "${su_render_install_block}" "_su.post_action = _suNormalizeRecommendedAction(recAction);" "install overlay missing recommendation preselection assignment"
require_contains "${su_render_install_block}" "recHtml," "install overlay missing recommendation hint rendering"

pass "Self-update recommendation regression checks passed"
