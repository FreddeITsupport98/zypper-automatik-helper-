#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
TARGET="${REPO_ROOT}/zypper-auto.sh"

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

[ -f "${TARGET}" ] || fail "missing target file: ${TARGET}"

grep -q 'id="znh-welcome-overlay"' "${TARGET}" || fail "welcome overlay container missing"
grep -q 'znhWelcomeMaybeShow' "${TARGET}" || fail "welcome init function missing"
grep -q 'znh_webui_welcome_seen_helper_version_v1' "${TARGET}" || fail "welcome version-tracking localStorage key missing"
grep -q 'id="advanced-panels-toggle"' "${TARGET}" || fail "advanced-panels master toggle missing"
grep -q 'id="snapper-ghost-card"' "${TARGET}" || fail "snapper/ghost advanced card id missing"
grep -q 'id="recent-activity-card"' "${TARGET}" || fail "recent-activity advanced card id missing"
grep -q 'znh_webui_advanced_panels_v1' "${TARGET}" || fail "advanced panel state key missing"
grep -q 'znhAdvancedPanelsInit' "${TARGET}" || fail "advanced panel init function missing"

echo "PASS: welcome overlay + advanced panel default-hide wiring is present"
