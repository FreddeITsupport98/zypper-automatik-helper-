#!/usr/bin/env bash
# RUNNER_NEEDS_TARGET=0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET_FILE="${1:-${REPO_ROOT}/zypper-auto.sh}"

usage() {
    cat <<'EOF'
Usage: ./test_self_update_bg_notify_wiring_regression.sh [path/to/zypper-auto.sh]

Focused static regression for Self-Update WebUI wiring:
  - _wireSelfUpdateUI declares bgNotifyBtn
  - guard includes bgNotifyBtn (no stale pre-declaration guard)
  - bgNotifyBtn declaration appears before guard and listener usage
EOF
}

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

pass() {
    printf 'PASS: %s\n' "$1"
}

line_in_block() {
    local block="$1"
    local needle="$2"
    grep -nF -- "${needle}" <<< "${block}" | head -n1 | cut -d: -f1
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

[ -f "${TARGET_FILE}" ] || fail "Target file not found: ${TARGET_FILE}"

wire_block="$(
    awk '
        BEGIN { inblk=0; depth=0 }
        /function _wireSelfUpdateUI\(\) \{/ && inblk==0 {
            inblk=1
        }
        inblk {
            print
            line=$0
            opens=gsub(/\{/, "{", line)
            closes=gsub(/\}/, "}", line)
            depth += opens - closes
            if (depth == 0) exit
        }
    ' "${TARGET_FILE}"
)"

[ -n "${wire_block}" ] || fail "Could not locate _wireSelfUpdateUI block"

decl_needle="var bgNotifyBtn = document.getElementById('self-update-bg-notify-btn');"
guard_needle="if (!chEl && !statusEl && !toggleBtn && !bgNotifyBtn && !runBtn && !clBtn && !simBtn) return;"
listener_needle="if (bgNotifyBtn) bgNotifyBtn.addEventListener('click', function(ev) {"
stale_guard_needle="if (!chEl && !statusEl && !toggleBtn && !runBtn && !clBtn && !simBtn) return;"

grep -Fq -- "${decl_needle}" <<< "${wire_block}" || fail "_wireSelfUpdateUI missing bgNotifyBtn declaration"
grep -Fq -- "${guard_needle}" <<< "${wire_block}" || fail "_wireSelfUpdateUI missing bgNotifyBtn-aware early-return guard"
grep -Fq -- "${listener_needle}" <<< "${wire_block}" || fail "_wireSelfUpdateUI missing bgNotifyBtn listener"

if grep -Fq -- "${stale_guard_needle}" <<< "${wire_block}"; then
    fail "_wireSelfUpdateUI still contains stale guard without bgNotifyBtn"
fi

decl_line="$(line_in_block "${wire_block}" "${decl_needle}")"
guard_line="$(line_in_block "${wire_block}" "${guard_needle}")"
listener_line="$(line_in_block "${wire_block}" "${listener_needle}")"

[ -n "${decl_line}" ] || fail "Could not compute bgNotifyBtn declaration line"
[ -n "${guard_line}" ] || fail "Could not compute bgNotifyBtn guard line"
[ -n "${listener_line}" ] || fail "Could not compute bgNotifyBtn listener line"

if [ "${decl_line}" -gt "${guard_line}" ]; then
    fail "bgNotifyBtn declaration appears after early-return guard (order regression)"
fi
if [ "${decl_line}" -gt "${listener_line}" ]; then
    fail "bgNotifyBtn declaration appears after listener usage (order regression)"
fi

pass "Self-update bgNotifyBtn wiring regression checks passed"
