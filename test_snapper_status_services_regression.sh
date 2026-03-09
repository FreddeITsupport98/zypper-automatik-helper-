#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_FILE="${1:-${SCRIPT_DIR}/zypper-auto.sh}"

usage() {
    cat <<'EOF'
Usage: ./test_snapper_status_services_regression.sh [path/to/zypper-auto.sh]

Focused regression smoke test for Snapper Manager status/service reporting:
  - Snapper menu exposes Option 1 status entry and routes it to __znh_snapper_status
  - __znh_snapper_status prints timer enabled/active/preset service-state output
  - status block prints guidance hints for inactive/disabled timers
  - Dashboard API /api/snapper/status invokes helper snapper status and returns HTTP 200 with rc/output
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

snapper_menu_block="$(
    awk '
        /run_snapper_menu_only\(\) \{/ {inblk=1}
        inblk {print}
        /# --- Helper: Interactive debug \/ diagnostics menu \(CLI\) ---/ && inblk {exit}
    ' "${TARGET_FILE}"
)"
[ -n "${snapper_menu_block}" ] || fail "Could not locate run_snapper_menu_only block"

snapper_status_block="$(
    awk '
        /__znh_snapper_status\(\) \{/ {inblk=1}
        inblk {print}
        /__znh_snapper_create_snapshot\(\) \{/ && inblk {exit}
    ' "${TARGET_FILE}"
)"
[ -n "${snapper_status_block}" ] || fail "Could not locate __znh_snapper_status block"

api_status_block="$(
    awk '
        /if path == "\/api\/snapper\/status":/ {inblk=1}
        inblk {
            if ($0 ~ /if path == "\/api\/snapper\/list":/) {exit}
            print
        }
    ' "${TARGET_FILE}"
)"
[ -n "${api_status_block}" ] || fail "Could not locate /api/snapper/status block"

require_contains "${source_text}" "echo \"  1) Status (configs + snapshot detection + timers)\"" "Snapper menu missing option 1 status label"
require_contains "${snapper_menu_block}" "1)" "Snapper menu case for option 1 missing"
require_contains "${snapper_menu_block}" "__znh_snapper_status" "Snapper menu option 1 not routed to __znh_snapper_status"

require_contains "${snapper_status_block}" "echo \"-- snapper systemd timers (enabled vs active) --\"" "Snapper status missing timer service-state section"
require_contains "${snapper_status_block}" "for u in snapper-timeline.timer snapper-cleanup.timer snapper-boot.timer; do" "Snapper status missing timer unit loop"
require_contains "${snapper_status_block}" "enabled=\$(systemctl is-enabled \"\${u}\" 2>/dev/null || echo \"unknown\")" "Snapper status missing enabled-state lookup"
require_contains "${snapper_status_block}" "active=\$(systemctl is-active \"\${u}\" 2>/dev/null || echo \"unknown\")" "Snapper status missing active-state lookup"
require_contains "${snapper_status_block}" "preset=\$(systemctl list-unit-files --no-legend \"\${u}\" 2>/dev/null | awk 'NR==1 {print \$3}' || true)" "Snapper status missing preset-state lookup"
require_contains "${snapper_status_block}" "printf '  %-22s enabled=%-8s active=%-8s preset=%s\\n'" "Snapper status missing enabled/active/preset formatted output"
require_contains "${snapper_status_block}" "NOTE: timer is enabled but not active. Try: sudo systemctl start \${u}" "Snapper status missing enabled-but-inactive guidance"
require_contains "${snapper_status_block}" "TIP: enable it with: sudo systemctl enable --now \${u}" "Snapper status missing disabled-timer guidance"
require_contains "${snapper_status_block}" "echo \"-- snapper timer schedule (systemctl list-timers) --\"" "Snapper status missing timer schedule section"
require_contains "${snapper_status_block}" "systemctl --no-pager list-timers 'snapper-*.timer' 2>/dev/null || true" "Snapper status missing list-timers call"

require_contains "${api_status_block}" "cmd = [\"/usr/local/bin/zypper-auto-helper\", \"snapper\", \"status\"]" "API status endpoint missing helper command mapping"
require_contains "${api_status_block}" "rc, out = _run_cmd(cmd, timeout_s=30, log=getattr(self.server, \"_znh_log\", None))" "API status endpoint missing _run_cmd invocation"
require_contains "${api_status_block}" "return _json_response(self, 200, {\"ok\": (rc == 0), \"rc\": rc, \"output\": out}, origin)" "API status endpoint missing HTTP 200 rc/output response"

pass "Snapper Manager service-status regression checks passed"
