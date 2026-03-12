#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MAIN_TARGET_DEFAULT="${REPO_ROOT}/zypper-auto.sh"
RUNNER_TARGET="${REPO_ROOT}/run_regression_suite.sh"
REGRESSION_DIR="${REPO_ROOT}/regressions"

INCLUDE_REGRESSIONS=0
INCLUDE_RUNNER=1
SKIP_NODE_CHECK=0
INSTALL_MISSING=0
TARGET_FILES=()
PYTHON_TARGET_FILES=()
NODE_TARGET_FILES=()
AUTO_CHMOD=1

usage() {
    cat <<'EOF'
Usage: ./scripts/syntax-check.sh [options]

Runs unified syntax/lint checks used by this repository:
  - Bash syntax checks (bash -n)
  - Shell lint checks (shellcheck, unless skipped)
  - Python compile checks (python -m py_compile)
  - Optional Node.js syntax checks (node --check) for JS files

Options:
  --target FILE            Add an explicit shell script target (repeatable)
  --python-target FILE     Add an explicit python script target (repeatable)
  --include-regressions    Include regressions/test_*.sh + regressions/test_*.py
  --no-runner              Skip run_regression_suite.sh check target
  --no-auto-chmod          Disable automatic chmod u+x on discovered script targets
  --skip-node              Skip Node.js JS syntax checks
  --install-missing        Auto-install missing check tools via distro package manager
  -h, --help               Show this help

Environment:
  SYNTAX_INSTALL_MISSING   1/true/yes enables auto-install behavior (same as --install-missing)
  SYNTAX_PYTHON            Python runtime for py_compile (default: python3)
  SYNTAX_SKIP_SHELLCHECK   1/true/yes to skip shellcheck checks
  SYNTAX_NODE_TARGETS      Space-separated explicit JS files to check with node --check
  SYNTAX_AUTO_CHMOD        1/true/yes (default) auto-set user executable bit on discovered script targets
EOF
}

auto_chmod_script_targets() {
    # Rule 5.2 support: when scanning, ensure script targets are executable.
    # This keeps regression/test scripts runnable without manual chmod steps.
    local p=""
    local changed=0
    local skipped=0
    local total=0
    local -a all=()
    all=( "${TARGET_FILES[@]}" "${PYTHON_TARGET_FILES[@]}" )

    for p in "${all[@]}"; do
        [ -f "${p}" ] || continue
        total=$((total + 1))
        if [ ! -x "${p}" ]; then
            if [ ! -w "${p}" ]; then
                skipped=$((skipped + 1))
                printf 'WARN: auto-chmod skipped (not writable): %s\n' "${p#"${REPO_ROOT}"/}"
                continue
            fi
            chmod u+x "${p}" 2>/dev/null || true
            if [ -x "${p}" ]; then
                changed=$((changed + 1))
                printf 'INFO: auto-chmod u+x %s\n' "${p#"${REPO_ROOT}"/}"
            else
                skipped=$((skipped + 1))
                printf 'WARN: auto-chmod skipped (chmod failed): %s\n' "${p#"${REPO_ROOT}"/}"
            fi
        fi
    done

    if [ "${total}" -gt 0 ] 2>/dev/null; then
        printf 'INFO: auto-chmod scan complete (targets=%s changed=%s skipped=%s)\n' "${total}" "${changed}" "${skipped}"
    fi
}

package_manager() {
    if command -v zypper >/dev/null 2>&1; then
        printf 'zypper\n'
        return 0
    fi
    if command -v dnf >/dev/null 2>&1; then
        printf 'dnf\n'
        return 0
    fi
    if command -v apt-get >/dev/null 2>&1; then
        printf 'apt-get\n'
        return 0
    fi
    if command -v pacman >/dev/null 2>&1; then
        printf 'pacman\n'
        return 0
    fi
    return 1
}

install_package() {
    local command_name="$1"
    local package_name="$2"
    local pm=""
    local prefix=()
    pm="$(package_manager || true)"
    [ -n "${pm}" ] || fail "No supported package manager found to install ${command_name}"

    if [ "${EUID:-$(id -u)}" -ne 0 ] 2>/dev/null; then
        command -v sudo >/dev/null 2>&1 || fail "sudo is required to install ${command_name}"
        prefix=( sudo )
    fi

    printf 'INFO: Installing missing dependency for %s: %s (via %s)\n' "${command_name}" "${package_name}" "${pm}"
    case "${pm}" in
        zypper)
            "${prefix[@]}" zypper --non-interactive install --no-recommends "${package_name}"
            ;;
        dnf)
            "${prefix[@]}" dnf -y install "${package_name}"
            ;;
        apt-get)
            "${prefix[@]}" apt-get update
            "${prefix[@]}" apt-get -y install "${package_name}"
            ;;
        pacman)
            "${prefix[@]}" pacman -Sy --noconfirm "${package_name}"
            ;;
        *)
            fail "Unsupported package manager: ${pm}"
            ;;
    esac
}

ensure_command() {
    local command_name="$1"
    local package_name="$2"
    if command -v "${command_name}" >/dev/null 2>&1; then
        return 0
    fi
    if [ "${INSTALL_MISSING}" -ne 1 ]; then
        fail "${command_name} not found. Re-run with --install-missing or install package: ${package_name}"
    fi
    install_package "${command_name}" "${package_name}"
    command -v "${command_name}" >/dev/null 2>&1 || fail "Failed to install command: ${command_name}"
}

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

is_truthy() {
    case "$1" in
        1|true|TRUE|yes|YES|on|ON)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

append_unique() {
    local value="$1"
    shift
    local -n arr_ref="$1"
    local existing=""
    for existing in "${arr_ref[@]}"; do
        if [ "${existing}" = "${value}" ]; then
            return 0
        fi
    done
    arr_ref+=( "${value}" )
}

resolve_python_runtime() {
    local candidate="$1"
    if [ -x "${candidate}" ]; then
        printf '%s\n' "${candidate}"
        return 0
    fi
    if command -v "${candidate}" >/dev/null 2>&1; then
        command -v "${candidate}"
        return 0
    fi
    return 1
}

discover_regression_targets() {
    local test_path=""
    shopt -s nullglob
    for test_path in "${REGRESSION_DIR}"/test_*.sh; do
        append_unique "${test_path}" TARGET_FILES
    done
    for test_path in "${REGRESSION_DIR}"/test_*.py; do
        append_unique "${test_path}" PYTHON_TARGET_FILES
    done
    shopt -u nullglob
}

discover_node_targets() {
    local explicit_targets="${SYNTAX_NODE_TARGETS:-}"
    local path=""

    if [ -n "${explicit_targets}" ]; then
        # shellcheck disable=SC2206
        local explicit_array=( ${explicit_targets} )
        for path in "${explicit_array[@]}"; do
            append_unique "${path}" NODE_TARGET_FILES
        done
    fi

    while IFS= read -r path; do
        [ -n "${path}" ] || continue
        append_unique "${path}" NODE_TARGET_FILES
    done < <(
        find "${REPO_ROOT}" \
            \( -type d -name .git -o -type d -name node_modules -o -type d -name .venv -o -type d -name .venv-playwright-regression \) -prune -o \
            \( -type f -name '*.js' -o -type f -name '*.mjs' -o -type f -name '*.cjs' \) -print
    )
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --target)
            [ "${2:-}" ] || fail "--target requires a file path"
            TARGET_FILES+=( "$2" )
            shift 2
            ;;
        --python-target)
            [ "${2:-}" ] || fail "--python-target requires a file path"
            PYTHON_TARGET_FILES+=( "$2" )
            shift 2
            ;;
        --include-regressions)
            INCLUDE_REGRESSIONS=1
            shift
            ;;
        --no-runner)
            INCLUDE_RUNNER=0
            shift
            ;;
        --skip-node)
            SKIP_NODE_CHECK=1
            shift
            ;;
        --no-auto-chmod)
            AUTO_CHMOD=0
            shift
            ;;
        --install-missing)
            INSTALL_MISSING=1
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

if is_truthy "${SYNTAX_INSTALL_MISSING:-0}"; then
    INSTALL_MISSING=1
fi
if ! is_truthy "${SYNTAX_AUTO_CHMOD:-1}"; then
    AUTO_CHMOD=0
fi

if [ "${#TARGET_FILES[@]}" -eq 0 ]; then
    TARGET_FILES=( "${MAIN_TARGET_DEFAULT}" )
fi

if [ "${INCLUDE_RUNNER}" -eq 1 ] && [ -f "${RUNNER_TARGET}" ]; then
    append_unique "${RUNNER_TARGET}" TARGET_FILES
fi

if [ "${INCLUDE_REGRESSIONS}" -eq 1 ] && [ -d "${REGRESSION_DIR}" ]; then
    discover_regression_targets
fi

for path in "${TARGET_FILES[@]}"; do
    [ -f "${path}" ] || fail "Shell target file not found: ${path}"
done
for path in "${PYTHON_TARGET_FILES[@]}"; do
    [ -f "${path}" ] || fail "Python target file not found: ${path}"
done

if [ "${AUTO_CHMOD}" -eq 1 ]; then
    printf '\n==> Auto chmod script targets\n'
    auto_chmod_script_targets
else
    printf '\n==> Auto chmod script targets (disabled)\n'
fi

printf '==> Bash syntax checks\n'
for path in "${TARGET_FILES[@]}"; do
    printf 'bash -n %s\n' "${path#"${REPO_ROOT}"/}"
    bash -n "${path}"
done

SKIP_SHELLCHECK_VALUE="${SYNTAX_SKIP_SHELLCHECK:-0}"
if is_truthy "${SKIP_SHELLCHECK_VALUE}"; then
    printf '\n==> ShellCheck checks (skipped by SYNTAX_SKIP_SHELLCHECK)\n'
else
    ensure_command shellcheck shellcheck
    printf '\n==> ShellCheck checks\n'
    shellcheck "${TARGET_FILES[@]}"
fi

if [ "${#PYTHON_TARGET_FILES[@]}" -gt 0 ]; then
    SYNTAX_PYTHON="${SYNTAX_PYTHON:-python3}"
    if [ "${SYNTAX_PYTHON}" = "python3" ]; then
        ensure_command python3 python3
    fi
    PYTHON_BIN="$(resolve_python_runtime "${SYNTAX_PYTHON}" || true)"
    [ -n "${PYTHON_BIN}" ] || fail "SYNTAX_PYTHON not found/executable: ${SYNTAX_PYTHON} (for default runtime use --install-missing)"

    printf '\n==> Python compile checks (%s)\n' "${PYTHON_BIN}"
    for path in "${PYTHON_TARGET_FILES[@]}"; do
        printf '%s -m py_compile %s\n' "${PYTHON_BIN}" "${path#"${REPO_ROOT}"/}"
        "${PYTHON_BIN}" -m py_compile "${path}"
    done
else
    printf '\n==> Python compile checks\n'
    printf 'No python targets selected\n'
fi

if [ "${SKIP_NODE_CHECK}" -eq 1 ]; then
    printf '\n==> Node.js syntax checks (skipped by --skip-node)\n'
else
    discover_node_targets
    if [ "${#NODE_TARGET_FILES[@]}" -le 0 ]; then
        printf '\n==> Node.js syntax checks\n'
        printf 'No JS targets discovered\n'
    else
        ensure_command node nodejs
        printf '\n==> Node.js syntax checks\n'
        for path in "${NODE_TARGET_FILES[@]}"; do
            [ -f "${path}" ] || fail "Node target file not found: ${path}"
            printf 'node --check %s\n' "${path#"${REPO_ROOT}"/}"
            node --check "${path}"
        done
    fi
fi

printf '\nPASS: syntax-check completed\n'
