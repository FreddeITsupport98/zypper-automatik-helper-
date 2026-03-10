#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_FILE="${1:-${SCRIPT_DIR}/zypper-auto.sh}"

usage() {
    cat <<'EOF'
Usage: ./run_regression_suite.sh [path/to/zypper-auto.sh]

Runs the non-destructive regression suite against zypper-auto.sh:
  - wrapper lock race regression
  - self-update recommendation regression
  - verify snapshot policy regression
  - snapper timer controls regression
  - snapper service-status regression
  - stale module helper/static + runtime regressions (runtime uses temp sandbox roots)
  - self-update/snapper runtime API failure-path regressions (mocked GitHub/systemctl)
  - boot kernel inventory regression
  - kernel purge lock handling regression
  - helper PATH install/uninstall regression
  - snapper option-4 modal layout regression
  - optional playwright snapper timer browser regression (skip-safe; prefers .venv-playwright-regression when present)
EOF
}

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

[ -f "${TARGET_FILE}" ] || fail "Target file not found: ${TARGET_FILE}"

tests=(
    "test_wrapper_lock_race_regression.sh"
    "test_self_update_recommendation_regression.sh"
    "test_verify_snapshot_policy_regression.sh"
    "test_diag_follower_low_noise_regression.sh"
    "test_snapper_timer_controls_regression.sh"
    "test_snapper_status_services_regression.sh"
    "test_stale_module_dirs_helper_regression.sh"
    "test_stale_module_dirs_runtime_regression.sh"
    "test_boot_kernel_inventory_regression.sh"
    "test_kernel_purge_lock_regression.sh"
    "test_helper_path_install_uninstall_regression.sh"
    "test_snapper_option4_modal_layout.sh"
)

printf 'Running shell regressions against: %s\n' "${TARGET_FILE}"
for t in "${tests[@]}"; do
    printf '\n==> %s\n' "${t}"
    bash "${SCRIPT_DIR}/${t}" "${TARGET_FILE}"
done

if command -v python3 >/dev/null 2>&1; then
    printf '\n==> test_self_update_api_runtime_regression.py\n'
    python3 -m unittest -v "${SCRIPT_DIR}/test_self_update_api_runtime_regression.py"
    printf '\n==> test_snapper_timer_playwright_regression.py (optional)\n'
    PLAYWRIGHT_TEST_PYTHON="${PLAYWRIGHT_TEST_PYTHON:-}"
    if [ -n "${PLAYWRIGHT_TEST_PYTHON}" ] && [ ! -x "${PLAYWRIGHT_TEST_PYTHON}" ]; then
        fail "PLAYWRIGHT_TEST_PYTHON is set but not executable: ${PLAYWRIGHT_TEST_PYTHON}"
    fi
    if [ -z "${PLAYWRIGHT_TEST_PYTHON}" ]; then
        PLAYWRIGHT_VENV_PY="${SCRIPT_DIR}/.venv-playwright-regression/bin/python"
        if [ -x "${PLAYWRIGHT_VENV_PY}" ]; then
            PLAYWRIGHT_TEST_PYTHON="${PLAYWRIGHT_VENV_PY}"
        else
            PLAYWRIGHT_TEST_PYTHON="python3"
        fi
    fi
    printf 'Using Playwright test python: %s\n' "${PLAYWRIGHT_TEST_PYTHON}"
    "${PLAYWRIGHT_TEST_PYTHON}" -m unittest -v "${SCRIPT_DIR}/test_snapper_timer_playwright_regression.py" || true
else
    printf '\nSkipping optional Playwright regression: python3 not found\n'
fi

printf '\nPASS: Regression suite completed\n'
