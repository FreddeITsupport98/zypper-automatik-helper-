#!/usr/bin/env bash
# RUNNER_NEEDS_TARGET=0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET_FILE="${1:-${REPO_ROOT}/zypper-auto.sh}"

usage() {
    cat <<'EOF'
Usage: ./test_webui_blank_guard_regression.sh [path/to/zypper-auto.sh]

Focused static regression for WebUI blank-screen prevention in multi-tab guard logic:
  - _znhMiHardBlockShow only hides main-content when blocker page was shown
  - _znhMiPreventBlankScreen helper exists and restores main-content when both blocker and main are hidden
  - _znhMiTick and znhMultiInstanceInit call the prevention helper
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

require_contains "${source_text}" "function _znhMiHardBlockShow(msg) {" "missing hard-block show function"
require_contains "${source_text}" "var pageShown = false;" "hard-block show missing pageShown guard state"
require_contains "${source_text}" "if (pageShown) {" "hard-block show missing guarded hide branch"
require_contains "${source_text}" "main.style.display = 'none';" "hard-block show missing hide-main action"
require_contains "${source_text}" "main.style.display = 'block';" "hard-block show missing fallback show-main action"
require_contains "${source_text}" "multi-tab blocker missing; main-content left visible" "hard-block show missing fallback warning"

require_contains "${source_text}" "function _znhMiPreventBlankScreen() {" "missing blank-screen prevention helper"
require_contains "${source_text}" "if (!mainVisible && !pageVisible) {" "blank-screen helper missing both-hidden detection"
require_contains "${source_text}" "Recovered blank WebUI (main-content hidden without blocker)" "blank-screen helper missing recovery warning"
require_contains "${source_text}" "toast('Recovered blank WebUI', 'Main content was restored automatically', 'err');" "blank-screen helper missing recovery toast"

require_contains "${source_text}" "try { _znhMiPreventBlankScreen(); } catch (e0b) {}" "tick loop missing blank-screen prevention call"
require_contains "${source_text}" "try { _znhMiPreventBlankScreen(); } catch (e10) {}" "init path missing blank-screen prevention call before loop start"

pass "WebUI blank-screen prevention regression checks passed"
