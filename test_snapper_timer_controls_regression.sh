#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_FILE="${1:-${SCRIPT_DIR}/zypper-auto.sh}"

usage() {
    cat <<'EOF'
Usage: ./test_snapper_timer_controls_regression.sh [path/to/zypper-auto.sh]

Regression smoke test for Snapper per-timer controls:
  - Option 5/6 UI contains individual timer buttons (timeline/cleanup/boot)
  - _wireSnapperUI binds per-timer button clicks to timer-enable/timer-disable actions
  - frontend has a timer-badge refresh helper and uses it after timer toggles
  - frontend does an initial timer-badge refresh on Snapper UI wire-up
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
require_contains "${wire_snapper_block}" "if (typeof znhSnapperRefreshTimerBadges === 'function') {" "initial timer refresh guard missing in _wireSnapperUI"
require_contains "${wire_snapper_block}" "znhSnapperRefreshTimerBadges();" "initial timer refresh call missing in _wireSnapperUI"
require_contains "${snapper_run_block}" "var didTimerToggle = false;" "snapperRun must track timer-toggle actions for refresh"
require_contains "${snapper_run_block}" "if (didTimerToggle) {" "snapperRun missing post-toggle refresh gate"
require_contains "${snapper_run_block}" "if (typeof znhSnapperRefreshTimerBadges === 'function') znhSnapperRefreshTimerBadges();" "snapperRun missing timer badge refresh call"

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
require_contains "${timers_api_block}" "def _snapper_timer_exists(unit: str) -> bool:" "timers endpoint missing _snapper_timer_exists helper"
require_contains "${timers_api_block}" "def _snapper_timer_state(unit: str) -> str:" "timers endpoint missing _snapper_timer_state helper"
require_contains "${timers_api_block}" "return \"missing\"" "timers endpoint missing missing-state handling"
require_contains "${timers_api_block}" "return \"enabled\"" "timers endpoint missing enabled-state handling"
require_contains "${timers_api_block}" "return \"partial\"" "timers endpoint missing partial-state handling"
require_contains "${timers_api_block}" "return \"disabled\"" "timers endpoint missing disabled-state handling"
require_contains "${timers_api_block}" "\"snapper_timeline_timer\": _snapper_timer_state(\"snapper-timeline.timer\")," "timers endpoint missing timeline timer field"
require_contains "${timers_api_block}" "\"snapper_cleanup_timer\": _snapper_timer_state(\"snapper-cleanup.timer\")," "timers endpoint missing cleanup timer field"
require_contains "${timers_api_block}" "\"snapper_boot_timer\": _snapper_timer_state(\"snapper-boot.timer\")," "timers endpoint missing boot timer field"

pass "Snapper per-timer controls regression checks passed"
