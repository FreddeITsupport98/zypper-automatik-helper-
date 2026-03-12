#!/usr/bin/env bash
# RUNNER_NEEDS_TARGET=0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET_FILE="${1:-${REPO_ROOT}/zypper-auto.sh}"

usage() {
    cat <<'EOF'
Usage: ./test_managers_ai_incident_summary_regression.sh [path/to/zypper-auto.sh]

Focused static regression for Managers -> Server -> AI Smart Report incident summary wiring:
  - incident summary container exists (mgr-ai-incidents)
  - aiIncEl is wired from DOM
  - _aiRenderIncidentSummary renderer exists and updates the container
  - renderer is called on success and failure/generating states are handled
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

require_contains "${source_text}" "id=\\\"mgr-ai-incidents\\\"" "missing incident summary DOM container"
require_contains "${source_text}" "var aiIncEl = document.getElementById('mgr-ai-incidents');" "missing aiIncEl DOM binding"
require_contains "${source_text}" "function _aiRenderIncidentSummary(r) {" "missing incident summary renderer function"
require_contains "${source_text}" "if (!aiIncEl) return;" "renderer missing aiIncEl guard"
require_contains "${source_text}" "aiIncEl.innerHTML = html.join('');" "renderer missing container update"
require_contains "${source_text}" "try { _aiRenderIncidentSummary(r || {}); } catch (eIR) {}" "missing success-path renderer call"
require_contains "${source_text}" "if (aiIncEl) aiIncEl.textContent = 'Generating incident summary…';" "missing generating-state incident summary message"
require_contains "${source_text}" "if (aiIncEl) aiIncEl.textContent = 'Incident summary unavailable: ' + String(msg);" "missing failure-state incident summary message"

pass "Managers AI incident summary wiring regression checks passed"
