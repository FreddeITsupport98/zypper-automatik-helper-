#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PLAYWRIGHT_BOOTSTRAP_PYTHON="${PLAYWRIGHT_BOOTSTRAP_PYTHON:-python3}"
PLAYWRIGHT_VENV_DIR_DEFAULT="${REPO_ROOT}/.venv-playwright-regression"
PLAYWRIGHT_VENV_DIR="${PLAYWRIGHT_VENV_DIR:-${PLAYWRIGHT_VENV_DIR_DEFAULT}}"
INSTALL_BROWSER=1
RECREATE_VENV=0

usage() {
    cat <<'EOF'
Usage: scripts/bootstrap_playwright_regression.sh [options]

Creates/updates the local Playwright regression virtualenv and Chromium runtime
used by test_snapper_timer_playwright_regression.py and run_regression_suite.sh.

Options:
  --python <bin>       Python executable to use for venv creation (default: python3,
                       overridable via PLAYWRIGHT_BOOTSTRAP_PYTHON).
  --venv-dir <path>    Virtualenv path (default: ./.venv-playwright-regression,
                       overridable via PLAYWRIGHT_VENV_DIR).
  --skip-browser       Skip 'playwright install chromium'.
  --recreate           Remove and recreate the target virtualenv first.
  -h, --help           Show this help text.
EOF
}

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

require_opt_value() {
    local opt="$1"
    local val="${2:-}"
    [ -n "${val}" ] || fail "Missing value for ${opt}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --python)
            require_opt_value "$1" "${2:-}"
            PLAYWRIGHT_BOOTSTRAP_PYTHON="$2"
            shift 2
            ;;
        --venv-dir)
            require_opt_value "$1" "${2:-}"
            PLAYWRIGHT_VENV_DIR="$2"
            shift 2
            ;;
        --skip-browser)
            INSTALL_BROWSER=0
            shift
            ;;
        --recreate)
            RECREATE_VENV=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            fail "Unknown option: $1"
            ;;
    esac
done

if ! command -v "${PLAYWRIGHT_BOOTSTRAP_PYTHON}" >/dev/null 2>&1; then
    fail "Python executable not found: ${PLAYWRIGHT_BOOTSTRAP_PYTHON}"
fi

if [ "${RECREATE_VENV}" -eq 1 ] && [ -d "${PLAYWRIGHT_VENV_DIR}" ]; then
    printf 'Recreating virtualenv: %s\n' "${PLAYWRIGHT_VENV_DIR}"
    rm -rf "${PLAYWRIGHT_VENV_DIR}"
fi

if [ ! -x "${PLAYWRIGHT_VENV_DIR}/bin/python" ]; then
    printf 'Creating virtualenv: %s\n' "${PLAYWRIGHT_VENV_DIR}"
    "${PLAYWRIGHT_BOOTSTRAP_PYTHON}" -m venv "${PLAYWRIGHT_VENV_DIR}"
else
    printf 'Using existing virtualenv: %s\n' "${PLAYWRIGHT_VENV_DIR}"
fi

VENV_PYTHON="${PLAYWRIGHT_VENV_DIR}/bin/python"

printf 'Installing/updating Playwright Python package...\n'
"${VENV_PYTHON}" -m pip install --upgrade playwright

if [ "${INSTALL_BROWSER}" -eq 1 ]; then
    printf 'Installing/updating Playwright Chromium runtime...\n'
    "${VENV_PYTHON}" -m playwright install chromium
else
    printf 'Skipping browser runtime install (--skip-browser).\n'
fi

printf '\nBootstrap complete.\n'
printf 'Optional Playwright regression can now run with:\n'
printf '  PLAYWRIGHT_TEST_PYTHON="%s" bash run_regression_suite.sh zypper-auto.sh\n' "${VENV_PYTHON}"
printf 'Or rely on auto-detect when using default venv path.\n'
