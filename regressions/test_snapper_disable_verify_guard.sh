#!/usr/bin/env bash
# RUNNER_STATEFUL=1
# RUNNER_REQUIRES_ROOT=1
# RUNNER_NEEDS_TARGET=0
set -euo pipefail

MARKER_FILE="/var/lib/zypper-auto/snapper-auto-disabled.intent"
DEFAULT_HELPER_BIN="/usr/local/bin/zypper-auto-helper"

KEEP_STATE=0
SKIP_VERIFY=0
VERIFY_TIMEOUT_SECONDS="${VERIFY_TIMEOUT_SECONDS:-1200}"
HELPER_BIN="${ZYPPER_AUTO_HELPER_BIN:-${DEFAULT_HELPER_BIN}}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

TRACK_UNITS=(
    "snapper-timeline.timer"
    "snapper-cleanup.timer"
    "snapper-boot.timer"
    "btrfs-scrub.timer"
    "btrfs-balance.timer"
    "btrfs-trim.timer"
    "btrfs-defrag.timer"
    "fstrim.timer"
)

STATE_CAPTURED=0
TMP_DIR=""
MARKER_BACKUP_FILE=""
MARKER_HAD=0

declare -A BASE_UNIT_EXISTS=()
declare -A BASE_UNIT_ENABLED=()
declare -A BASE_UNIT_ACTIVE=()

usage() {
    cat <<'EOF'
Usage: sudo ./regressions/test_snapper_disable_verify_guard.sh [options]

Regression smoke test for Snapper disable-intent behavior:
  1) Runs: zypper-auto-helper snapper auto-off
  2) Verifies marker file exists and snapper-cleanup.timer is disabled/inactive
  3) Runs: zypper-auto-helper --verify
  4) Verifies marker still exists and verify did not re-enable cleanup timer

By default, baseline timer + marker state is restored automatically on exit.

Options:
  --helper PATH         Override helper binary (default: /usr/local/bin/zypper-auto-helper)
  --verify-timeout SEC  Timeout for --verify (default: 1200)
  --skip-verify         Skip step 3 (verify run), keep only pre/post auto-off checks
  --keep-state          Keep modified state (disable marker + timer changes) after test
  -h, --help            Show this help
EOF
}

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

info() {
    printf 'INFO: %s\n' "$1"
}

pass() {
    printf 'PASS: %s\n' "$1"
}

unit_exists() {
    local unit="$1"
    local first=""
    first="$(systemctl list-unit-files --no-legend "${unit}" 2>/dev/null | awk 'NR==1 {print $1}' || true)"
    [ "${first}" = "${unit}" ]
}

unit_enabled() {
    local unit="$1"
    systemctl is-enabled --quiet "${unit}" 2>/dev/null
}

unit_active() {
    local unit="$1"
    systemctl is-active --quiet "${unit}" 2>/dev/null
}

capture_baseline_state() {
    local unit=""
    for unit in "${TRACK_UNITS[@]}"; do
        BASE_UNIT_EXISTS["${unit}"]=0
        BASE_UNIT_ENABLED["${unit}"]=0
        BASE_UNIT_ACTIVE["${unit}"]=0

        if unit_exists "${unit}"; then
            BASE_UNIT_EXISTS["${unit}"]=1
            if unit_enabled "${unit}"; then
                BASE_UNIT_ENABLED["${unit}"]=1
            fi
            if unit_active "${unit}"; then
                BASE_UNIT_ACTIVE["${unit}"]=1
            fi
        fi
    done

    if [ -f "${MARKER_FILE}" ]; then
        MARKER_HAD=1
        cp -f -- "${MARKER_FILE}" "${MARKER_BACKUP_FILE}" 2>/dev/null || true
    else
        MARKER_HAD=0
    fi

    STATE_CAPTURED=1
}

restore_baseline_state() {
    local unit=""

    if [ "${KEEP_STATE}" -eq 1 ] 2>/dev/null; then
        info "--keep-state active: skipping baseline restore"
        return 0
    fi

    if [ "${STATE_CAPTURED}" -ne 1 ] 2>/dev/null; then
        return 0
    fi

    info "Restoring baseline timer + marker state..."

    for unit in "${TRACK_UNITS[@]}"; do
        if [ "${BASE_UNIT_EXISTS[${unit}]:-0}" -eq 0 ] 2>/dev/null; then
            continue
        fi
        if ! unit_exists "${unit}"; then
            continue
        fi

        if [ "${BASE_UNIT_ENABLED[${unit}]:-0}" -eq 1 ] 2>/dev/null; then
            systemctl enable "${unit}" >/dev/null 2>&1 || true
        else
            systemctl disable "${unit}" >/dev/null 2>&1 || true
        fi

        if [ "${BASE_UNIT_ACTIVE[${unit}]:-0}" -eq 1 ] 2>/dev/null; then
            systemctl start "${unit}" >/dev/null 2>&1 || true
        else
            systemctl stop "${unit}" >/dev/null 2>&1 || true
        fi
    done

    if [ "${MARKER_HAD}" -eq 1 ] 2>/dev/null; then
        if [ -f "${MARKER_BACKUP_FILE}" ]; then
            cp -f -- "${MARKER_BACKUP_FILE}" "${MARKER_FILE}" 2>/dev/null || true
            chmod 644 "${MARKER_FILE}" 2>/dev/null || true
        fi
    else
        rm -f -- "${MARKER_FILE}" 2>/dev/null || true
    fi
}

cleanup() {
    restore_baseline_state || true
    if [ -n "${TMP_DIR}" ] && [ -d "${TMP_DIR}" ]; then
        rm -rf -- "${TMP_DIR}" 2>/dev/null || true
    fi
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --helper)
            [ "${2:-}" ] || fail "--helper requires a path"
            HELPER_BIN="$2"
            shift 2
            ;;
        --verify-timeout)
            [ "${2:-}" ] || fail "--verify-timeout requires seconds"
            VERIFY_TIMEOUT_SECONDS="$2"
            shift 2
            ;;
        --skip-verify)
            SKIP_VERIFY=1
            shift
            ;;
        --keep-state)
            KEEP_STATE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "Unknown option: $1"
            ;;
    esac
done

if [ "${EUID:-$(id -u)}" -ne 0 ] 2>/dev/null; then
    fail "Run as root (sudo) so the script can manage systemd timers and marker files"
fi

if ! command -v systemctl >/dev/null 2>&1; then
    fail "systemctl not found"
fi

if ! [[ "${VERIFY_TIMEOUT_SECONDS}" =~ ^[0-9]+$ ]] || [ "${VERIFY_TIMEOUT_SECONDS}" -lt 60 ] 2>/dev/null; then
    fail "--verify-timeout must be an integer >= 60"
fi

if [ ! -x "${HELPER_BIN}" ] 2>/dev/null; then
    if [ -x "${REPO_ROOT}/zypper-auto.sh" ] 2>/dev/null; then
        HELPER_BIN="${REPO_ROOT}/zypper-auto.sh"
    else
        fail "Helper binary not executable: ${HELPER_BIN}"
    fi
fi

if ! unit_exists "snapper-cleanup.timer"; then
    fail "snapper-cleanup.timer is not installed on this system; cannot run this regression"
fi

TMP_DIR="$(mktemp -d)"
MARKER_BACKUP_FILE="${TMP_DIR}/marker.backup"
trap cleanup EXIT

capture_baseline_state

info "Using helper: ${HELPER_BIN}"
info "Step 1/4: disable Snapper automation (auto-off)"
"${HELPER_BIN}" snapper auto-off

info "Step 2/4: assert marker + cleanup timer disabled"
if [ ! -f "${MARKER_FILE}" ]; then
    fail "Expected marker file missing after auto-off: ${MARKER_FILE}"
fi
if unit_enabled "snapper-cleanup.timer"; then
    fail "snapper-cleanup.timer is still enabled after auto-off"
fi
if unit_active "snapper-cleanup.timer"; then
    fail "snapper-cleanup.timer is still active after auto-off"
fi

if [ "${SKIP_VERIFY}" -eq 0 ] 2>/dev/null; then
    info "Step 3/4: run verification (timeout: ${VERIFY_TIMEOUT_SECONDS}s)"
    verify_rc=0
    if command -v timeout >/dev/null 2>&1; then
        if ! timeout "${VERIFY_TIMEOUT_SECONDS}" "${HELPER_BIN}" --verify; then
            verify_rc=$?
        fi
    else
        if ! "${HELPER_BIN}" --verify; then
            verify_rc=$?
        fi
    fi
    info "Verify exit code: ${verify_rc}"
else
    info "Step 3/4: skipped (--skip-verify)"
fi

info "Step 4/4: assert verify did not re-enable Snapper cleanup timer"
if [ ! -f "${MARKER_FILE}" ]; then
    fail "Marker file missing after verify: ${MARKER_FILE}"
fi
if unit_enabled "snapper-cleanup.timer"; then
    fail "Regression detected: verify re-enabled snapper-cleanup.timer"
fi
if unit_active "snapper-cleanup.timer"; then
    fail "Regression detected: verify started snapper-cleanup.timer"
fi

pass "Snapper disable-intent guard works: marker persists and verify does not re-enable cleanup timer"
