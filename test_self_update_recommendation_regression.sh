#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_FILE="${1:-${SCRIPT_DIR}/zypper-auto.sh}"

usage() {
    cat <<'EOF'
Usage: ./test_self_update_recommendation_regression.sh [path/to/zypper-auto.sh]

Focused regression smoke test for self-update recommendation and stable semantics:
  - backend exposes policy-aware latest-release-candidate + layered SHA256 recommendation helpers
  - /api/self-update/status uses content-based compare + recommendation payload
  - WebUI stable changelog/release-notes use stable-policy-aware candidate selection
  - WebUI install overlay preselects post-action and explains recommendation/override state
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

require_contains "${source_text}" "def _github_latest_release_candidate(*, policy: str = \"release\", timeout_s: int = 10) -> tuple[dict, dict]:" "backend missing policy-aware latest release candidate helper"
require_contains "${source_text}" "def _read_remote_script_bytes(ref: str, timeout_s: int = 15) -> tuple[bytes, str]:" "backend missing remote script bytes helper"
require_contains "${source_text}" "def _script_layer_sha256s(text: str) -> dict:" "backend missing layered SHA256 helper"
require_contains "${source_text}" "def _recommend_post_action(local_layers: dict, remote_layers: dict, *, has_remote: bool) -> tuple[str, str, list[str], str, str]:" "backend missing recommendation helper"
require_contains "${source_text}" "def _detect_install_origin(*, install_source: str, active_channel: str, active_ref: str, stable_tag: str, rolling_sha: str) -> dict:" "backend missing install-origin detection helper"
require_contains "${source_text}" "def _recommend_channel_switch(*, configured_channel: str, active_channel: str, install_origin: dict, channel_switch: bool, is_externally_managed: bool) -> tuple[str, str, str, str]:" "backend missing channel-switch recommendation helper"

require_contains "${self_update_status_block}" "_github_latest_release_candidate(policy=stable_policy, timeout_s=10)" "status endpoint missing policy-aware stable release-candidate selection"
require_contains "${self_update_status_block}" "data, pth = _read_remote_script_bytes(remote_ref, timeout_s=15)" "status endpoint missing remote script content fetch"
require_contains "${self_update_status_block}" "local_layer_sha256 = _script_layer_sha256s(local_script_text)" "status endpoint missing local layered SHA256 calculation"
require_contains "${self_update_status_block}" "remote_layer_sha256 = _script_layer_sha256s(remote_script_text)" "status endpoint missing remote layered SHA256 calculation"
require_contains "${self_update_status_block}" "rec_action, rec_reason, rec_changed_layers, rec_confidence, rec_risk_level = _recommend_post_action(" "status endpoint missing expanded recommendation decision call"
require_contains "${source_text}" "\"stable_candidate\": {" "status payload missing stable candidate metadata"
require_contains "${source_text}" "\"post_action_recommendation\": {" "status payload missing post-action recommendation object"
require_contains "${source_text}" "\"install_origin\": dict(install_origin) if isinstance(install_origin, dict) else {}," "status payload missing install-origin object"
require_contains "${source_text}" "\"channel_recommendation\": {" "status payload missing channel recommendation object"
require_contains "${source_text}" "\"recommended\": str(rec_action or \"none\")," "status payload missing recommendation value"
require_contains "${source_text}" "\"changed_layers\": rec_changed_layers if isinstance(rec_changed_layers, list) else []," "status payload missing changed-layer list"
require_contains "${source_text}" "\"confidence\": str(rec_confidence or \"\")," "status payload missing recommendation confidence"
require_contains "${source_text}" "\"risk_level\": str(rec_risk_level or \"\")," "status payload missing recommendation risk level"
require_contains "${source_text}" "\"stable_policy\": stable_policy," "status payload missing stable policy field"
require_contains "${source_text}" "\"configured_stable_policy\": stable_policy," "status payload missing configured stable policy field"
require_contains "${source_text}" "\"selection\": str(stable_provenance.get(\"selection\", stable_policy)" "status payload missing stable selection provenance field"
require_contains "${source_text}" "\"source_urls\": [str(x) for x in (stable_provenance.get(\"source_urls\") or [])]" "status payload missing stable source_urls provenance field"

require_contains "${source_text}" "function _suFetchLatestStableReleaseCandidate(statusHint) {" "frontend missing policy-aware stable release-candidate helper"
require_contains "${source_text}" "function _suSelectStableReleaseCandidate(arr, policy) {" "frontend missing stable candidate policy selector helper"
require_contains "${source_text}" "_githubApiJson(base + '/releases?per_page=25')" "frontend missing stable releases list fetch"
require_contains "${source_text}" "return _suFetchLatestStableReleaseCandidate(statusHint || null).then(function(sel) {" "frontend stable notes fetch not wired to policy-aware candidate helper"
require_contains "${self_update_changelog_block}" "return _suFetchLatestStableReleaseCandidate(statusHint).then(function(sel) {" "self-update changelog missing policy-aware stable candidate fetch path"
require_contains "${source_text}" "toast('Changelog loaded', 'Stable notes fetched (' + String((prov && prov.selection) ? prov.selection : 'release') + ')', 'ok');" "frontend missing stable policy changelog toast text"

require_contains "${su_render_install_block}" "var rec = (st && st.post_action_recommendation) ? st.post_action_recommendation : null;" "install overlay missing recommendation extraction from status payload"
require_contains "${su_render_install_block}" "_su.post_action = _suNormalizeRecommendedAction(recAction);" "install overlay missing recommendation preselection assignment"
require_contains "${su_render_install_block}" "Why recommended?" "install overlay missing explainability disclosure"
require_contains "${su_render_install_block}" "function _suChangedLayerLabel(name) {" "install overlay missing plain-language changed-layer labels"
require_contains "${su_render_install_block}" "id=\\\"su-post-action-warning\\\"" "install overlay missing manual override warning container"
require_contains "${su_render_install_block}" "function syncPostActionWarning() {" "install overlay missing override warning sync helper"
require_contains "${su_render_install_block}" "switch_to_rolling" "install overlay missing switch-to-rolling recommendation handling"
require_contains "${su_render_install_block}" "Recommendation: switch channel to rolling before installing." "install overlay missing explicit rolling switch recommendation text"

pass "Self-update recommendation regression checks passed"
