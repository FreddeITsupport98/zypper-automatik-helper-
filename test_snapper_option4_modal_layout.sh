#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_FILE="${1:-${SCRIPT_DIR}/zypper-auto.sh}"

usage() {
    cat <<'EOF'
Usage: ./test_snapper_option4_modal_layout.sh [path/to/zypper-auto.sh]

Regression smoke test for Snapper Option 4 WebUI layout:
  - Option 4 card stays compact (mode selector + run button + status badges)
  - Option 4 card does NOT contain snopt-* customization controls
  - Cleanup confirmation modal contains snopt-* customization controls
  - Cleanup modal wiring uses existing settings helper functions
  - _wireSnapperUI no longer binds static snopt-* controls
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

option4_card_block="$(
    awk '
        /<span class="stat-label">Full Cleanup \(Option 4\)<\/span>/ {inblk=1}
        inblk {print}
        /<span class="stat-label">AUTO enable timers \(Option 5\)<\/span>/ && inblk {exit}
    ' "${TARGET_FILE}"
)"

[ -n "${option4_card_block}" ] || fail "Could not locate Option 4 card block"

require_contains "${option4_card_block}" "Details + customization moved into the cleanup confirmation dialog to keep this panel compact." "Option 4 compact note missing"
require_contains "${option4_card_block}" "id=\"snapper-cleanup-mode\"" "Option 4 mode selector missing"
require_contains "${option4_card_block}" "id=\"snapper-cleanup-btn\"" "Option 4 cleanup button missing"
require_contains "${option4_card_block}" "id=\"kernel-purge-badge\"" "Option 4 kernel purge badge missing"
require_contains "${option4_card_block}" "id=\"scrub-ghost-badge\"" "Option 4 scrub-ghost badge missing"
require_contains "${option4_card_block}" "id=\"kernel-family-purge-badge\"" "Option 4 kernel family badge missing"
require_not_contains "${option4_card_block}" "snopt-" "Option 4 card must not contain customization controls"
require_not_contains "${option4_card_block}" "Customize cleanup behavior" "Legacy in-card customization heading should be removed"

require_contains "${source_text}" "cleanupDetailsHtml = [" "cleanupDetailsHtml block missing"
require_contains "${source_text}" "id=\"snopt-kp-enabled\"" "Modal missing snopt-kp-enabled"
require_contains "${source_text}" "id=\"snopt-kp-implicit\"" "Modal missing snopt-kp-implicit"
require_contains "${source_text}" "id=\"snopt-sg-enabled\"" "Modal missing snopt-sg-enabled"
require_contains "${source_text}" "id=\"snopt-sg-grub\"" "Modal missing snopt-sg-grub"
require_contains "${source_text}" "id=\"snopt-family-enabled\"" "Modal missing snopt-family-enabled"
require_contains "${source_text}" "id=\"snopt-family-force-only\"" "Modal missing snopt-family-force-only"
require_contains "${source_text}" "id=\"snopt-family-dry-run\"" "Modal missing snopt-family-dry-run"
require_contains "${source_text}" "id=\"snopt-family-targets\"" "Modal missing snopt-family-targets"
require_contains "${source_text}" "id=\"snopt-apply\"" "Modal missing snopt-apply"
require_contains "${source_text}" "id=\"snopt-refresh\"" "Modal missing snopt-refresh"

require_contains "${source_text}" "function _wireCleanupCustomizePanel() {" "Modal cleanup wiring function missing"
require_contains "${source_text}" "znhSnapperCleanupSettingsPanelApply();" "Modal apply binding missing"
require_contains "${source_text}" "znhSnapperCleanupSettingsPanelSyncFromConfig();" "Modal refresh/sync binding missing"
require_contains "${source_text}" "_wireCleanupCustomizePanel();" "Modal wiring call missing"

wire_snapper_block="$(
    awk '
        /function _wireSnapperUI\(\) \{/ {inblk=1}
        inblk {print}
        /\/\/ --- scrub-ghost Manager/ && inblk {exit}
    ' "${TARGET_FILE}"
)"

[ -n "${wire_snapper_block}" ] || fail "Could not locate _wireSnapperUI block"

require_not_contains "${wire_snapper_block}" "Option 4 customization panel (persistent settings)" "Legacy static Option 4 customization wiring comment should be removed"
require_not_contains "${wire_snapper_block}" "document.getElementById('snopt-apply')" "Static snopt-apply binding should not remain in _wireSnapperUI"
require_not_contains "${wire_snapper_block}" "document.getElementById('snopt-refresh')" "Static snopt-refresh binding should not remain in _wireSnapperUI"
require_contains "${wire_snapper_block}" "var modeSel = document.getElementById('snapper-cleanup-mode');" "_wireSnapperUI should still track cleanup mode selector for badge refresh"

pass "Option 4 compact-card + modal-only customization layout regression checks passed"
