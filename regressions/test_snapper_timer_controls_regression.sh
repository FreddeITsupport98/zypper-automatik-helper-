#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET_FILE="${1:-${REPO_ROOT}/zypper-auto.sh}"

usage() {
    cat <<'EOF'
Usage: ./test_snapper_timer_controls_regression.sh [path/to/zypper-auto.sh]

Regression smoke test for Snapper per-timer controls:
  - Option 5/6 UI contains individual timer buttons (timeline/cleanup/boot)
  - _wireSnapperUI binds per-timer button clicks to timer-enable/timer-disable actions
  - confirm-token expiry is auto-recovered in both run and background-start flows
  - frontend has a timer-badge refresh helper and uses it after timer toggles
  - frontend does an initial timer-badge refresh on Snapper UI wire-up
  - frontend syncs Snapper timer enable/disable button state from timer status
  - Snapper status output shows timer service enabled/active/preset fields clearly
  - frontend stores a short-lived authoritative timer override from /api/snapper/timers
    and reconciles it in applyLiveData so stale status-data polls do not revert badges
  - backend exposes /api/snapper/timers for immediate badge state fetches
  - helper has __znh_snapper_single_timer and timer-enable/timer-disable subcommands
  - /api/snapper/confirm allows per-timer actions with ENABLE/DISABLE phrases
  - /api/snapper/start and /api/snapper/run map per-timer actions to helper commands
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

wire_snapper_block="$(
    awk '
        /function _wireSnapperUI\(\) \{/ {inblk=1}
        inblk {print}
        /\/\/ --- scrub-ghost Manager/ && inblk {exit}
    ' "${TARGET_FILE}"
)"
[ -n "${wire_snapper_block}" ] || fail "Could not locate _wireSnapperUI block"

helper_snapper_block="$(
    awk '
        /__znh_snapper_single_timer\(\) \{/ {inblk=1}
        inblk {print}
        /__znh_timer_state\(\) \{/ && inblk {exit}
    ' "${TARGET_FILE}"
)"
[ -n "${helper_snapper_block}" ] || fail "Could not locate snapper helper timer block"

snapper_status_block="$(
    awk '
        /__znh_snapper_status\(\) \{/ {inblk=1}
        inblk {print}
        /__znh_snapper_create_snapshot\(\) \{/ && inblk {exit}
    ' "${TARGET_FILE}"
)"
[ -n "${snapper_status_block}" ] || fail "Could not locate __znh_snapper_status block"

confirm_api_block="$(
    awk '
        /if path == "\/api\/snapper\/confirm":/ {inblk=1}
        inblk {
            if ($0 ~ /if path == "\/api\/snapper\/start":/) {exit}
            print
        }
    ' "${TARGET_FILE}"
)"
[ -n "${confirm_api_block}" ] || fail "Could not locate /api/snapper/confirm block"

start_api_block="$(
    awk '
        /if path == "\/api\/snapper\/start":/ {inblk=1}
        inblk {
            if ($0 ~ /if path == "\/api\/snapper\/run":/) {exit}
            print
        }
    ' "${TARGET_FILE}"
)"
[ -n "${start_api_block}" ] || fail "Could not locate /api/snapper/start block"

run_api_block="$(
    awk '
        /if path == "\/api\/snapper\/run":/ {inblk=1}
        inblk {print}
        /# --- scrub-ghost/ && inblk {exit}
    ' "${TARGET_FILE}"
)"
[ -n "${run_api_block}" ] || fail "Could not locate /api/snapper/run block"

timers_api_block="$(
    awk '
        /if path == "\/api\/snapper\/timers":/ {inblk=1}
        inblk {
            if ($0 ~ /if path == "\/api\/snapper\/status":/) {exit}
            print
        }
    ' "${TARGET_FILE}"
)"
[ -n "${timers_api_block}" ] || fail "Could not locate /api/snapper/timers block"

snapper_run_block="$(
    awk '
        /function snapperRun\(action, params, confirmAction\) \{/ {inblk=1}
        inblk {print}
        /function _snCleanupPreflightSummaryText\(pf, mode\) \{/ && inblk {exit}
    ' "${TARGET_FILE}"
)"
[ -n "${snapper_run_block}" ] || fail "Could not locate snapperRun block"

snapper_confirm_modal_block="$(
    awk '
        /function _snOpenConfirmAndRun\(opts\) \{/ {inblk=1}
        inblk {print}
        /function znhSnapperRefreshTimerBadges\(\) \{/ && inblk {exit}
    ' "${TARGET_FILE}"
)"
[ -n "${snapper_confirm_modal_block}" ] || fail "Could not locate _snOpenConfirmAndRun block"

apply_live_data_block="$(
    awk '
        /function applyLiveData\(d\) \{/ {inblk=1}
        inblk {print}
        /var liveEnabled = false;/ && inblk {exit}
    ' "${TARGET_FILE}"
)"
[ -n "${apply_live_data_block}" ] || fail "Could not locate applyLiveData block"

# UI/markup assertions
require_contains "${source_text}" "id=\"snapper-auto-enable-btn\">Enable all" "Option 5 all-enable button label missing"
require_contains "${source_text}" "id=\"snapper-enable-timeline-btn\"" "Option 5 per-timer timeline button missing"
require_contains "${source_text}" "id=\"snapper-enable-cleanup-btn\"" "Option 5 per-timer cleanup button missing"
require_contains "${source_text}" "id=\"snapper-enable-boot-btn\"" "Option 5 per-timer boot button missing"
require_contains "${source_text}" "id=\"snapper-auto-disable-btn\" style=\"border-color: rgba(239,68,68,0.30);\">Disable all" "Option 6 all-disable button label missing"
require_contains "${source_text}" "id=\"snapper-disable-timeline-btn\"" "Option 6 per-timer timeline button missing"
require_contains "${source_text}" "id=\"snapper-disable-cleanup-btn\"" "Option 6 per-timer cleanup button missing"
require_contains "${source_text}" "id=\"snapper-disable-boot-btn\"" "Option 6 per-timer boot button missing"

# Frontend wiring assertions
require_contains "${wire_snapper_block}" "var b5a = document.getElementById('snapper-enable-timeline-btn');" "snapper-enable-timeline DOM lookup missing"
require_contains "${wire_snapper_block}" "var b5b = document.getElementById('snapper-enable-cleanup-btn');" "snapper-enable-cleanup DOM lookup missing"
require_contains "${wire_snapper_block}" "var b5c = document.getElementById('snapper-enable-boot-btn');" "snapper-enable-boot DOM lookup missing"
require_contains "${wire_snapper_block}" "var b6a = document.getElementById('snapper-disable-timeline-btn');" "snapper-disable-timeline DOM lookup missing"
require_contains "${wire_snapper_block}" "var b6b = document.getElementById('snapper-disable-cleanup-btn');" "snapper-disable-cleanup DOM lookup missing"
require_contains "${wire_snapper_block}" "var b6c = document.getElementById('snapper-disable-boot-btn');" "snapper-disable-boot DOM lookup missing"
require_contains "${wire_snapper_block}" "snapperRun('timer-enable-timeline', {}, 'timer-enable-timeline');" "timer-enable-timeline click binding missing"
require_contains "${wire_snapper_block}" "snapperRun('timer-enable-cleanup', {}, 'timer-enable-cleanup');" "timer-enable-cleanup click binding missing"
require_contains "${wire_snapper_block}" "snapperRun('timer-enable-boot', {}, 'timer-enable-boot');" "timer-enable-boot click binding missing"
require_contains "${wire_snapper_block}" "snapperRun('timer-disable-timeline', {}, 'timer-disable-timeline');" "timer-disable-timeline click binding missing"
require_contains "${wire_snapper_block}" "snapperRun('timer-disable-cleanup', {}, 'timer-disable-cleanup');" "timer-disable-cleanup click binding missing"
require_contains "${wire_snapper_block}" "snapperRun('timer-disable-boot', {}, 'timer-disable-boot');" "timer-disable-boot click binding missing"
require_contains "${source_text}" "function znhSnapperRefreshTimerBadges() {" "znhSnapperRefreshTimerBadges helper function missing"
require_contains "${source_text}" "_api('/api/snapper/timers', { method: 'GET' })" "timer badge refresh helper must call /api/snapper/timers"
require_contains "${source_text}" "function _snIsConfirmTokenError(errObj) {" "confirm-token error classifier helper missing"
require_contains "${source_text}" "function _snRequestFreshConfirmToken(action, params) {" "confirm-token refresh helper missing"
require_contains "${source_text}" "var _znhSnapperTimerOverride = null;" "snapper timer override state variable missing"
require_contains "${source_text}" "function _znhSnapperTimerStateNorm(v) {" "snapper timer state normalizer helper missing"
require_contains "${source_text}" "if (s === 'on' || s === 'true' || s === 'yes') return 'enabled';" "snapper timer state normalizer missing boolean-ish enabled aliases"
require_contains "${source_text}" "if (s === 'off' || s === 'false' || s === 'no') return 'disabled';" "snapper timer state normalizer missing boolean-ish disabled aliases"
require_contains "${source_text}" "var enMatch = s.match(/\\benabled\\s*=\\s*([a-z-]+)/);" "snapper timer state normalizer missing verbose enabled-field parsing"
require_contains "${source_text}" "if (s.indexOf('enabled') >= 0 && s.indexOf('active') >= 0) return 'enabled';" "snapper timer state normalizer missing fallback enabled+active heuristic"
require_contains "${source_text}" "function _znhSnapperTimerUiSetBtn(id, mode, disabled, title) {" "snapper timer UI button helper missing"
require_contains "${source_text}" "function znhSnapperSyncTimerButtons(payload) {" "snapper timer button sync helper missing"
require_contains "${source_text}" "window.znhSnapperSyncTimerButtons = znhSnapperSyncTimerButtons;" "snapper timer button sync helper export missing"
require_contains "${source_text}" "function _znhSnapperTimerMaybeApiSync() {" "snapper timer throttled api resync helper missing"
require_contains "${source_text}" "function _znhSnapperTimerOverrideSetFromApi(payload) {" "snapper timer override set helper missing"
require_contains "${source_text}" "function _znhSnapperTimerOverrideGet() {" "snapper timer override getter helper missing"
require_contains "${source_text}" "function _znhSnapperTimerOverrideMaybeClear(serverData) {" "snapper timer override clear helper missing"
require_contains "${source_text}" "var _znhSnapperTimerPassiveSyncTimer = null;" "snapper timer passive sync timer state var missing"
require_contains "${source_text}" "var _znhSnapperTimerPassiveSyncStarted = false;" "snapper timer passive sync started-state var missing"
require_contains "${source_text}" "function _znhSnapperTimerReadDomPayload() {" "snapper timer DOM payload helper missing"
require_contains "${source_text}" "function _znhSnapperTimerPayloadFromAction(action, basePayload) {" "snapper timer action->payload helper missing"
require_contains "${source_text}" "function _znhSnapperTimerApplyActionOverride(action) {" "snapper timer optimistic override helper missing"
require_contains "${source_text}" "function _znhSnapperTimerPassiveSyncIntervalMs() {" "snapper timer passive sync interval helper missing"
require_contains "${source_text}" "function _znhSnapperTimerPassiveSyncSchedule() {" "snapper timer passive sync scheduler helper missing"
require_contains "${source_text}" "function _znhSnapperTimerEnsurePassiveSync() {" "snapper timer passive sync init helper missing"
require_contains "${source_text}" "document.addEventListener('visibilitychange', function() {" "snapper timer passive sync visibility listener missing"
require_contains "${source_text}" "_znhSnapperTimerPassiveSyncSchedule();" "snapper timer passive sync schedule call missing"
require_contains "${source_text}" "_znhSnapperTimerOverrideSetFromApi(r);" "timer refresh helper missing authoritative override write"
require_contains "${source_text}" "if (typeof znhSnapperSyncTimerButtons === 'function') znhSnapperSyncTimerButtons(r);" "timer refresh helper missing button sync call"
require_contains "${wire_snapper_block}" "if (typeof znhSnapperRefreshTimerBadges === 'function') {" "initial timer refresh guard missing in _wireSnapperUI"
require_contains "${wire_snapper_block}" "znhSnapperRefreshTimerBadges();" "initial timer refresh call missing in _wireSnapperUI"
require_contains "${wire_snapper_block}" "if (typeof _znhSnapperTimerEnsurePassiveSync === 'function') {" "passive timer sync guard missing in _wireSnapperUI"
require_contains "${wire_snapper_block}" "_znhSnapperTimerEnsurePassiveSync();" "passive timer sync initialization missing in _wireSnapperUI"
require_contains "${snapper_run_block}" "var didTimerToggle = false;" "snapperRun must track timer-toggle actions for refresh"
require_contains "${snapper_run_block}" "if (didTimerToggle) {" "snapperRun missing post-toggle refresh gate"
require_contains "${snapper_run_block}" "_znhSnapperTimerApplyActionOverride(actionStr);" "snapperRun missing optimistic timer action override apply"
require_contains "${snapper_run_block}" "if (typeof znhSnapperRefreshTimerBadges === 'function') znhSnapperRefreshTimerBadges();" "snapperRun missing timer badge refresh call"
require_contains "${snapper_run_block}" "needsRefresh = !!confirmAction && _snIsConfirmTokenError(e0);" "snapperRun missing confirm-token error detection"
require_contains "${snapper_run_block}" "_snRequestFreshConfirmToken(confirmAction, params)" "snapperRun missing refresh confirm-token request"
require_contains "${snapper_run_block}" "Confirmation refreshed" "snapperRun missing user feedback for confirm-token refresh"
require_contains "${apply_live_data_block}" "var snapTimeline = d.snapper_timeline_timer;" "applyLiveData missing snapper timeline local state"
require_contains "${apply_live_data_block}" "_znhSnapperTimerOverrideMaybeClear(d);" "applyLiveData missing override catch-up clear logic"
require_contains "${apply_live_data_block}" "var _ov = _znhSnapperTimerOverrideGet();" "applyLiveData missing timer override lookup"
require_contains "${apply_live_data_block}" "if (_ov.timeline) snapTimeline = _ov.timeline;" "applyLiveData missing timeline override application"
require_contains "${apply_live_data_block}" "if (_ov.cleanup) snapCleanup = _ov.cleanup;" "applyLiveData missing cleanup override application"
require_contains "${apply_live_data_block}" "if (_ov.boot) snapBoot = _ov.boot;" "applyLiveData missing boot override application"
require_contains "${apply_live_data_block}" "znhSnapperSyncTimerButtons({" "applyLiveData missing timer button sync call"
require_contains "${apply_live_data_block}" "_znhSnapperTimerMaybeApiSync();" "applyLiveData missing throttled timer API resync call"
require_contains "${snapper_confirm_modal_block}" "function _startSnapperJobWithToken(tok, phr, didRetry) {" "_snOpenConfirmAndRun missing background start helper"
require_contains "${snapper_confirm_modal_block}" "shouldRetry = (!didRetry) && _snIsConfirmTokenError(err0);" "_snOpenConfirmAndRun missing token-expiry retry detection"
require_contains "${snapper_confirm_modal_block}" "_snRequestFreshConfirmToken(confirmAct, _sn.params || {})" "_snOpenConfirmAndRun missing confirm-token refresh request"
require_contains "${snapper_confirm_modal_block}" "Confirm token expired while dialog was open. Refreshing token and retrying..." "_snOpenConfirmAndRun missing token-refresh progress log"

# Helper/subcommand assertions
require_contains "${helper_snapper_block}" "__znh_snapper_single_timer() {" "__znh_snapper_single_timer helper missing"
require_contains "${helper_snapper_block}" "timeline|snapper-timeline.timer" "single-timer helper missing timeline case mapping"
require_contains "${helper_snapper_block}" "cleanup|snapper-cleanup.timer" "single-timer helper missing cleanup case mapping"
require_contains "${helper_snapper_block}" "boot|snapper-boot.timer" "single-timer helper missing boot case mapping"
require_contains "${helper_snapper_block}" "source=snapper-timer-disable:%s" "single-timer helper missing cleanup disable intent marker source"
require_contains "${helper_snapper_block}" "timer-enable)" "snapper subcommand case timer-enable missing"
require_contains "${helper_snapper_block}" "timer-disable)" "snapper subcommand case timer-disable missing"
require_contains "${helper_snapper_block}" "__znh_snapper_single_timer enable" "timer-enable subcommand not routed to helper"
require_contains "${helper_snapper_block}" "__znh_snapper_single_timer disable" "timer-disable subcommand not routed to helper"
require_contains "${snapper_status_block}" "echo \"-- snapper systemd timers (enabled vs active) --\"" "snapper status missing timer status section header"
require_contains "${snapper_status_block}" "enabled=\$(systemctl is-enabled \"\${u}\" 2>/dev/null || echo \"unknown\")" "snapper status missing enabled-state lookup"
require_contains "${snapper_status_block}" "active=\$(systemctl is-active \"\${u}\" 2>/dev/null || echo \"unknown\")" "snapper status missing active-state lookup"
require_contains "${snapper_status_block}" "preset=\$(systemctl list-unit-files --no-legend \"\${u}\" 2>/dev/null | awk 'NR==1 {print \$3}' || true)" "snapper status missing preset lookup"
require_contains "${snapper_status_block}" "printf '  %-22s enabled=%-8s active=%-8s preset=%s\\n'" "snapper status missing enabled/active/preset formatted output"
require_contains "${snapper_status_block}" "NOTE: timer is enabled but not active. Try: sudo systemctl start \${u}" "snapper status missing enabled-but-inactive note"
require_contains "${snapper_status_block}" "TIP: enable it with: sudo systemctl enable --now \${u}" "snapper status missing disabled timer enable hint"

# Confirm API assertions
require_contains "${confirm_api_block}" "\"timer-enable-timeline\": \"Type ENABLE to confirm enabling snapper-timeline.timer.\"" "confirm allowlist missing timer-enable-timeline"
require_contains "${confirm_api_block}" "\"timer-enable-cleanup\": \"Type ENABLE to confirm enabling snapper-cleanup.timer.\"" "confirm allowlist missing timer-enable-cleanup"
require_contains "${confirm_api_block}" "\"timer-enable-boot\": \"Type ENABLE to confirm enabling snapper-boot.timer.\"" "confirm allowlist missing timer-enable-boot"
require_contains "${confirm_api_block}" "\"timer-disable-timeline\": \"Type DISABLE to confirm disabling snapper-timeline.timer.\"" "confirm allowlist missing timer-disable-timeline"
require_contains "${confirm_api_block}" "\"timer-disable-cleanup\": \"Type DISABLE to confirm disabling snapper-cleanup.timer.\"" "confirm allowlist missing timer-disable-cleanup"
require_contains "${confirm_api_block}" "\"timer-disable-boot\": \"Type DISABLE to confirm disabling snapper-boot.timer.\"" "confirm allowlist missing timer-disable-boot"
require_contains "${confirm_api_block}" "elif action in (\"timer-enable-timeline\", \"timer-enable-cleanup\", \"timer-enable-boot\"):" "confirm phrase mapping missing timer-enable action tuple"
require_contains "${confirm_api_block}" "elif action in (\"timer-disable-timeline\", \"timer-disable-cleanup\", \"timer-disable-boot\"):" "confirm phrase mapping missing timer-disable action tuple"

# /api/snapper/start assertions
require_contains "${start_api_block}" "\"timer-enable-timeline\"," "start needs_confirm missing timer-enable-timeline"
require_contains "${start_api_block}" "\"timer-enable-cleanup\"," "start needs_confirm missing timer-enable-cleanup"
require_contains "${start_api_block}" "\"timer-enable-boot\"," "start needs_confirm missing timer-enable-boot"
require_contains "${start_api_block}" "\"timer-disable-timeline\"," "start needs_confirm missing timer-disable-timeline"
require_contains "${start_api_block}" "\"timer-disable-cleanup\"," "start needs_confirm missing timer-disable-cleanup"
require_contains "${start_api_block}" "\"timer-disable-boot\"," "start needs_confirm missing timer-disable-boot"
require_contains "${start_api_block}" "cmd = [HELPER_BIN, \"snapper\", \"timer-enable\", \"timeline\"]" "start action mapping missing helper command for timer-enable-timeline"
require_contains "${start_api_block}" "cmd = [HELPER_BIN, \"snapper\", \"timer-enable\", \"cleanup\"]" "start action mapping missing helper command for timer-enable-cleanup"
require_contains "${start_api_block}" "cmd = [HELPER_BIN, \"snapper\", \"timer-enable\", \"boot\"]" "start action mapping missing helper command for timer-enable-boot"
require_contains "${start_api_block}" "cmd = [HELPER_BIN, \"snapper\", \"timer-disable\", \"timeline\"]" "start action mapping missing helper command for timer-disable-timeline"
require_contains "${start_api_block}" "cmd = [HELPER_BIN, \"snapper\", \"timer-disable\", \"cleanup\"]" "start action mapping missing helper command for timer-disable-cleanup"
require_contains "${start_api_block}" "cmd = [HELPER_BIN, \"snapper\", \"timer-disable\", \"boot\"]" "start action mapping missing helper command for timer-disable-boot"

# /api/snapper/run assertions
require_contains "${run_api_block}" "\"timer-enable-timeline\"," "run needs_confirm missing timer-enable-timeline"
require_contains "${run_api_block}" "\"timer-enable-cleanup\"," "run needs_confirm missing timer-enable-cleanup"
require_contains "${run_api_block}" "\"timer-enable-boot\"," "run needs_confirm missing timer-enable-boot"
require_contains "${run_api_block}" "\"timer-disable-timeline\"," "run needs_confirm missing timer-disable-timeline"
require_contains "${run_api_block}" "\"timer-disable-cleanup\"," "run needs_confirm missing timer-disable-cleanup"
require_contains "${run_api_block}" "\"timer-disable-boot\"," "run needs_confirm missing timer-disable-boot"
require_contains "${run_api_block}" "cmd = [\"/usr/local/bin/zypper-auto-helper\", \"snapper\", \"timer-enable\", \"timeline\"]" "run action mapping missing helper command for timer-enable-timeline"
require_contains "${run_api_block}" "cmd = [\"/usr/local/bin/zypper-auto-helper\", \"snapper\", \"timer-enable\", \"cleanup\"]" "run action mapping missing helper command for timer-enable-cleanup"
require_contains "${run_api_block}" "cmd = [\"/usr/local/bin/zypper-auto-helper\", \"snapper\", \"timer-enable\", \"boot\"]" "run action mapping missing helper command for timer-enable-boot"
require_contains "${run_api_block}" "cmd = [\"/usr/local/bin/zypper-auto-helper\", \"snapper\", \"timer-disable\", \"timeline\"]" "run action mapping missing helper command for timer-disable-timeline"
require_contains "${run_api_block}" "cmd = [\"/usr/local/bin/zypper-auto-helper\", \"snapper\", \"timer-disable\", \"cleanup\"]" "run action mapping missing helper command for timer-disable-cleanup"
require_contains "${run_api_block}" "cmd = [\"/usr/local/bin/zypper-auto-helper\", \"snapper\", \"timer-disable\", \"boot\"]" "run action mapping missing helper command for timer-disable-boot"
# /api/snapper/timers assertions
require_contains "${timers_api_block}" "def _snapper_timer_probe(unit: str) -> dict:" "timers endpoint missing _snapper_timer_probe helper"
require_contains "${timers_api_block}" "\"systemctl\", \"show\", u," "timers endpoint missing systemctl show probe"
require_contains "${timers_api_block}" "\"NextElapseUSecRealtime\"" "timers endpoint missing next-trigger property probe"
require_contains "${timers_api_block}" "\"LastTriggerUSec\"" "timers endpoint missing last-trigger property probe"
require_contains "${timers_api_block}" "\"Result\"" "timers endpoint missing last-result property probe"
require_contains "${timers_api_block}" "def _systemd_time_to_utc(raw: str) -> str:" "timers endpoint missing systemd time conversion helper"
require_contains "${timers_api_block}" "[\"systemctl\", \"is-enabled\", u]" "timers endpoint missing systemctl is-enabled probe"
require_contains "${timers_api_block}" "[\"systemctl\", \"is-active\", u]" "timers endpoint missing systemctl is-active probe"
require_contains "${timers_api_block}" "\"state\": \"missing\"" "timers endpoint missing default missing-state initialization"
require_contains "${timers_api_block}" "\"next_trigger_utc\": \"\"" "timers endpoint missing next_trigger_utc field initialization"
require_contains "${timers_api_block}" "\"last_trigger_utc\": \"\"" "timers endpoint missing last_trigger_utc field initialization"
require_contains "${timers_api_block}" "\"last_result\": \"unknown\"" "timers endpoint missing last_result field initialization"
require_contains "${timers_api_block}" "\"partial_reason\": \"\"" "timers endpoint missing partial_reason field initialization"
require_contains "${timers_api_block}" "state = \"enabled\"" "timers endpoint missing enabled-state handling"
require_contains "${timers_api_block}" "state = \"partial\"" "timers endpoint missing partial-state handling"
require_contains "${timers_api_block}" "state = \"disabled\"" "timers endpoint missing disabled-state handling"
require_contains "${timers_api_block}" "out[\"partial_reason\"] = \"unit not found in systemd unit files\"" "timers endpoint missing unit-not-found partial reason"
require_contains "${timers_api_block}" "out[\"partial_reason\"] = f\"state mismatch (enabled={str(en_state or 'unknown')}, active={str(act_state or 'unknown')})\"" "timers endpoint missing mismatch partial reason"
require_contains "${timers_api_block}" "t_timeline = _snapper_timer_probe(\"snapper-timeline.timer\")" "timers endpoint missing timeline timer probe assignment"
require_contains "${timers_api_block}" "t_cleanup = _snapper_timer_probe(\"snapper-cleanup.timer\")" "timers endpoint missing cleanup timer probe assignment"
require_contains "${timers_api_block}" "t_boot = _snapper_timer_probe(\"snapper-boot.timer\")" "timers endpoint missing boot timer probe assignment"
require_contains "${timers_api_block}" "\"snapper_timeline_timer\": str(t_timeline.get(\"state\", \"missing\"))," "timers endpoint missing timeline timer compatibility field"
require_contains "${timers_api_block}" "\"snapper_cleanup_timer\": str(t_cleanup.get(\"state\", \"missing\"))," "timers endpoint missing cleanup timer compatibility field"
require_contains "${timers_api_block}" "\"snapper_boot_timer\": str(t_boot.get(\"state\", \"missing\"))," "timers endpoint missing boot timer compatibility field"
require_contains "${timers_api_block}" "\"snapper_timeline_timer_live\": t_timeline," "timers endpoint missing timeline live detail field"
require_contains "${timers_api_block}" "\"snapper_cleanup_timer_live\": t_cleanup," "timers endpoint missing cleanup live detail field"
require_contains "${timers_api_block}" "\"snapper_boot_timer_live\": t_boot," "timers endpoint missing boot live detail field"

pass "Snapper per-timer controls regression checks passed"
