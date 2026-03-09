#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_FILE="${1:-${SCRIPT_DIR}/zypper-auto.sh}"

usage() {
    cat <<'EOF'
Usage: ./test_diag_follower_low_noise_regression.sh [path/to/zypper-auto.sh]

Regression smoke test for low-noise diagnostics/live-log behavior:
  - zypper-auto-diag-follow uses one multiplexed tail process for all files
  - diagnostics runner caps followed service logs (newest N)
  - debug-menu/live-logs fallback paths cap service log source fanout
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

diag_follow_helper_block="$(
    awk '
        /write_atomic "\$\{diag_follower\}" << '\''EOF'\''/ {inblk=1}
        inblk {print}
        /^[[:space:]]*EOF$/ && inblk {exit}
    ' "${TARGET_FILE}"
)"
[ -n "${diag_follow_helper_block}" ] || fail "Could not locate embedded zypper-auto-diag-follow helper block"

diag_runner_block="$(
    awk '
        /run_diag_logs_runner_only\(\) \{/ {inblk=1}
        inblk {print}
        /run_snapshot_state_only\(\) \{/ && inblk {exit}
    ' "${TARGET_FILE}"
)"
[ -n "${diag_runner_block}" ] || fail "Could not locate run_diag_logs_runner_only block"

debug_menu_block="$(
    awk '
        /run_debug_menu_only\(\) \{/ {inblk=1}
        inblk {print}
        /run_dash_open_only\(\) \{/ && inblk {exit}
    ' "${TARGET_FILE}"
)"
[ -n "${debug_menu_block}" ] || fail "Could not locate run_debug_menu_only block"

live_logs_block="$(
    awk '
        /elif \[\[ "\$\{1:-\}" == "--live-logs" \]\]; then/ {inblk=1}
        inblk {print}
        /elif \[\[ "\$\{1:-\}" == "scrub-ghost" \]\]; then/ && inblk {exit}
    ' "${TARGET_FILE}"
)"
[ -n "${live_logs_block}" ] || fail "Could not locate --live-logs dispatch block"

require_contains "${diag_follow_helper_block}" "follow_paths=()" "diag-follow helper missing follow_paths array setup"
require_contains "${diag_follow_helper_block}" "tail -n 0 -F \"\${follow_paths[@]}\" 2>/dev/null | awk" "diag-follow helper missing single-process tail multiplexer"
require_contains "${diag_follow_helper_block}" "tag_for_path[parts[1]] = parts[2]" "diag-follow helper missing path->tag map for multiplexer"
require_not_contains "${diag_follow_helper_block}" "tail -n 0 -F \"\$path\" | sed -u \"s/^/[SRC=\${src}] /\" &" "diag-follow helper should not spawn one tail process per file anymore"

require_contains "${diag_runner_block}" "max_service_logs=\"\${ZNH_DIAG_MAX_SERVICE_LOGS:-6}\"" "diag runner missing configurable service-log cap"
require_contains "${diag_runner_block}" "head -n \"\${max_service_logs}\"" "diag runner missing newest-service-log cap"
require_contains "${diag_runner_block}" "Diagnostics follower low-noise mode: tracking" "diag runner missing low-noise cap summary log"

require_contains "${debug_menu_block}" "service_log_limit=\"\${ZNH_LIVE_LOGS_MAX_SERVICE_LOGS:-8}\"" "debug menu fallback missing service-log cap"
require_contains "${debug_menu_block}" "head -n \"\${service_log_limit}\"" "debug menu fallback missing capped service log selection"

require_contains "${live_logs_block}" "LIVE_SERVICE_LOG_LIMIT=\"\${ZNH_LIVE_LOGS_MAX_SERVICE_LOGS:-8}\"" "--live-logs fallback missing service-log cap"
require_contains "${live_logs_block}" "head -n \"\${LIVE_SERVICE_LOG_LIMIT}\"" "--live-logs fallback missing capped service log selection"
# Config/schema/WebUI settings wiring assertions for the new caps.
require_contains "${source_text}" "ZNH_DIAG_MAX_SERVICE_LOGS=6" "config template/global defaults missing ZNH_DIAG_MAX_SERVICE_LOGS"
require_contains "${source_text}" "ZNH_LIVE_LOGS_MAX_SERVICE_LOGS=8" "config template/global defaults missing ZNH_LIVE_LOGS_MAX_SERVICE_LOGS"
require_contains "${source_text}" "\"ZNH_DIAG_MAX_SERVICE_LOGS\": {\"type\": \"int\", \"min\": 1, \"max\": 30, \"step\": 1, \"default\": \"6\"}" "dashboard schema missing ZNH_DIAG_MAX_SERVICE_LOGS entry"
require_contains "${source_text}" "\"ZNH_LIVE_LOGS_MAX_SERVICE_LOGS\": {\"type\": \"int\", \"min\": 1, \"max\": 30, \"step\": 1, \"default\": \"8\"}" "dashboard schema missing ZNH_LIVE_LOGS_MAX_SERVICE_LOGS entry"
require_contains "${source_text}" "validate_nonneg_int_bounded_optional ZNH_DIAG_MAX_SERVICE_LOGS 6 1 30" "config validation missing ZNH_DIAG_MAX_SERVICE_LOGS bounds"
require_contains "${source_text}" "validate_nonneg_int_bounded_optional ZNH_LIVE_LOGS_MAX_SERVICE_LOGS 8 1 30" "config validation missing ZNH_LIVE_LOGS_MAX_SERVICE_LOGS bounds"
require_contains "${source_text}" "key: 'ZNH_DIAG_MAX_SERVICE_LOGS'" "Settings UI fields missing ZNH_DIAG_MAX_SERVICE_LOGS"
require_contains "${source_text}" "key: 'ZNH_LIVE_LOGS_MAX_SERVICE_LOGS'" "Settings UI fields missing ZNH_LIVE_LOGS_MAX_SERVICE_LOGS"

pass "Low-noise diagnostics follower regression checks passed"
