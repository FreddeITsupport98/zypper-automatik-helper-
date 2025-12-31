#!/bin/bash
#
#       VERSION 53 - Snooze controls, safety preflight, and CLI helper
# This script installs the final architecture and fixes the policy lock.
# It replaces 'sudo' with 'pkexec' in the Python script to ensure
# zypper refresh/dry-run is not instantly blocked by pam_kwallet5.
#
# MUST be run with sudo or as root.

# --- 1. Strict Mode & Config ---
set -euo pipefail

# --- Logging Configuration ---
LOG_DIR="/var/log/zypper-auto"
LOG_FILE="${LOG_DIR}/install-$(date +%Y%m%d-%H%M%S).log"
STATUS_FILE="${LOG_DIR}/last-status.txt"
MAX_LOG_FILES=10  # Keep only the last 10 log files
MAX_LOG_SIZE_MB=50  # Maximum size for a single log file in MB

# Create log directory
mkdir -p "${LOG_DIR}"
chmod 755 "${LOG_DIR}"

# Cleanup old log files (keep only the last MAX_LOG_FILES)
cleanup_old_logs() {
    log_debug "Cleaning up old log files in ${LOG_DIR}..."
    
    # Count install log files
    local log_count=$(find "${LOG_DIR}" -name "install-*.log" 2>/dev/null | wc -l)
    
    if [ "$log_count" -gt "$MAX_LOG_FILES" ]; then
        log_info "Found $log_count log files, removing oldest to keep only $MAX_LOG_FILES"
        find "${LOG_DIR}" -name "install-*.log" -type f -printf '%T+ %p\n' | \
            sort | head -n -"$MAX_LOG_FILES" | cut -d' ' -f2- | \
            while read -r old_log; do
                log_debug "Removing old log: $old_log"
                rm -f "$old_log"
            done
        log_success "Old logs cleaned up"
    else
        log_debug "Log count ($log_count) is within limit ($MAX_LOG_FILES)"
    fi
    
    # Also cleanup service logs that are too large
    if [ -d "${LOG_DIR}/service-logs" ]; then
        find "${LOG_DIR}/service-logs" -name "*.log" -type f -size +"${MAX_LOG_SIZE_MB}M" | \
            while read -r large_log; do
                log_info "Rotating large log file: $large_log"
                mv "$large_log" "${large_log}.old"
                touch "$large_log"
            done
    fi
}

# Initialize log file
echo "==============================================" | tee "${LOG_FILE}"
echo "Zypper Auto-Helper Installation Log" | tee -a "${LOG_FILE}"
echo "Started: $(date)" | tee -a "${LOG_FILE}"
echo "Log file: ${LOG_FILE}" | tee -a "${LOG_FILE}"
echo "==============================================" | tee -a "${LOG_FILE}"
echo "" | tee -a "${LOG_FILE}"

# Logging functions
log_info() {
    echo "[INFO] $(date '+%H:%M:%S') $*" | tee -a "${LOG_FILE}"
}

log_success() {
    echo "[SUCCESS] $(date '+%H:%M:%S') $*" | tee -a "${LOG_FILE}"
}

log_error() {
    echo "[ERROR] $(date '+%H:%M:%S') $*" | tee -a "${LOG_FILE}" >&2
}

log_debug() {
    echo "[DEBUG] $(date '+%H:%M:%S') $*" | tee -a "${LOG_FILE}"
}

log_command() {
    local cmd="$*"
    log_debug "Executing: $cmd"
    if eval "$cmd" >> "${LOG_FILE}" 2>&1; then
        log_success "Command succeeded: $cmd"
        return 0
    else
        local exit_code=$?
        log_error "Command failed (exit code $exit_code): $cmd"
        return $exit_code
    fi
}

# Status update function
update_status() {
    local status="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $status" | tee "${STATUS_FILE}" | tee -a "${LOG_FILE}"
}

# Trap errors and log them
trap 'log_error "Script failed at line $LINENO with exit code $?"; update_status "FAILED: Installation encountered an error at line $LINENO"; exit 1' ERR

# --- Root/System Service Config ---
DL_SERVICE_NAME="zypper-autodownload"
DL_SERVICE_FILE="/etc/systemd/system/${DL_SERVICE_NAME}.service"
DL_TIMER_FILE="/etc/systemd/system/${DL_SERVICE_NAME}.timer"

CLEANUP_SERVICE_NAME="zypper-cache-cleanup"
CLEANUP_SERVICE_FILE="/etc/systemd/system/${CLEANUP_SERVICE_NAME}.service"
CLEANUP_TIMER_FILE="/etc/systemd/system/${CLEANUP_SERVICE_NAME}.timer"

# --- User Service Config ---
NT_SERVICE_NAME="zypper-notify-user"
NT_SCRIPT_NAME="zypper-notify-updater.py"
INSTALL_SCRIPT_NAME="zypper-run-install"
VIEW_CHANGES_SCRIPT_NAME="zypper-view-changes"

# --- 2. Sanity Checks & User Detection ---
update_status "Running sanity checks..."
log_info ">>> Running Sanity Checks..."
log_debug "EUID: $EUID"

if [ "$EUID" -ne 0 ]; then
  log_error "This script must be run with sudo or as root."
  update_status "FAILED: Script not run as root"
  exit 1
fi
log_success "Root privileges confirmed"

if [ -z "${SUDO_USER:-}" ]; then
    log_error "Could not detect the user. Please run with 'sudo', not as pure root."
    update_status "FAILED: SUDO_USER not detected"
    exit 1
fi
log_success "Detected user: $SUDO_USER"

SUDO_USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
log_debug "User home directory: $SUDO_USER_HOME"

if [ ! -d "$SUDO_USER_HOME" ]; then
    log_error "Could not find home directory for user $SUDO_USER."
    update_status "FAILED: User home directory not found"
    exit 1
fi
log_success "User home directory found: $SUDO_USER_HOME"

# Define user-level paths
USER_CONFIG_DIR="$SUDO_USER_HOME/.config/systemd/user"
USER_BIN_DIR="$SUDO_USER_HOME/.local/bin"
NT_SERVICE_FILE="$USER_CONFIG_DIR/${NT_SERVICE_NAME}.service"
NT_TIMER_FILE="$USER_CONFIG_DIR/${NT_SERVICE_NAME}.timer"
NOTIFY_SCRIPT_PATH="$USER_BIN_DIR/${NT_SCRIPT_NAME}"
INSTALL_SCRIPT_PATH="$USER_BIN_DIR/${INSTALL_SCRIPT_NAME}"
VIEW_CHANGES_SCRIPT_PATH="$USER_BIN_DIR/${VIEW_CHANGES_SCRIPT_NAME}"

# --- Helper: Self-check syntax for this script and the notifier ---
run_self_check() {
    log_info ">>> Running self-check (syntax)..."
    update_status "Running syntax checks..."

    # Check bash syntax of this installer
    log_debug "Checking bash syntax of $0"
    if ! bash -n "$0" >> "${LOG_FILE}" 2>&1; then
        log_error "Self-check FAILED: bash syntax error in $0"
        update_status "FAILED: Bash syntax error in installer script"
        exit 1
    fi
    log_success "Bash syntax check passed for installer"

    # Check Python notifier syntax if it already exists
    if [ -f "$NOTIFY_SCRIPT_PATH" ]; then
        log_debug "Checking Python syntax of $NOTIFY_SCRIPT_PATH"
        if ! python3 -m py_compile "$NOTIFY_SCRIPT_PATH" >> "${LOG_FILE}" 2>&1; then
            log_error "Self-check FAILED: Python syntax error in $NOTIFY_SCRIPT_PATH"
            update_status "FAILED: Python syntax error in notifier script"
            exit 1
        fi
        log_success "Python syntax check passed for notifier"
    else
        log_info "Python notifier $NOTIFY_SCRIPT_PATH not found yet (first install?)"
    fi

    log_success "Self-check passed"
    update_status "Syntax checks completed successfully"
}

# --- Function: Run Verification (used by both install and --verify modes) ---
run_verification_only() {
    # This function contains all the verification logic
    # It can be called standalone or as part of installation
    
    VERIFICATION_FAILED=0
    REPAIR_ATTEMPTS=0
    MAX_REPAIR_ATTEMPTS=3
    
    log_info ">>> Running advanced installation verification and auto-repair..."
    update_status "Verifying installation..."

# Helper function for advanced repair with retry logic
attempt_repair() {
    local check_name="$1"
    local repair_command="$2"
    local verify_command="$3"
    local max_attempts="${4:-2}"
    
    REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))  # Track that we're attempting a repair
    
    for i in $(seq 1 $max_attempts); do
        log_info "  → Repair attempt $i/$max_attempts: $check_name"
        if eval "$repair_command" >> "${LOG_FILE}" 2>&1; then
            sleep 0.5  # Brief pause for system to stabilize
            if eval "$verify_command" &>/dev/null; then
                log_success "  ✓ Repaired successfully on attempt $i"
                return 0
            fi
        fi
    done
    log_error "  ✗ Failed to repair after $max_attempts attempts"
    return 1
}

# Check 1: System service is active and healthy
log_debug "[1/12] Checking system downloader service..."
if systemctl is-active "${DL_SERVICE_NAME}.timer" &>/dev/null; then
    # Additional health check: verify it's enabled
    if systemctl is-enabled "${DL_SERVICE_NAME}.timer" &>/dev/null; then
        log_success "✓ System downloader timer is active and enabled"
    else
        log_error "✗ System downloader timer is active but NOT enabled (won't survive reboot)"
        if attempt_repair "enable timer for persistence" \
            "systemctl enable ${DL_SERVICE_NAME}.timer" \
            "systemctl is-enabled ${DL_SERVICE_NAME}.timer"; then
            log_success "  ✓ Timer is now enabled for persistence"
        else
            VERIFICATION_FAILED=1
        fi
    fi
else
    log_error "✗ System downloader timer is NOT active"
    # Try comprehensive repair
    if attempt_repair "restart system downloader" \
        "systemctl daemon-reload && systemctl enable --now ${DL_SERVICE_NAME}.timer" \
        "systemctl is-active ${DL_SERVICE_NAME}.timer" 3; then
        log_success "  ✓ System downloader timer repaired"
    else
        log_error "  → Attempting nuclear option: recreating service files..."
        # Service file should exist from earlier in install, but verify
        if [ ! -f "${DL_SERVICE_FILE}" ] || [ ! -f "${DL_TIMER_FILE}" ]; then
            log_error "  ✗ CRITICAL: Service files missing - installation may have failed"
            VERIFICATION_FAILED=1
        else
            systemctl daemon-reload >> "${LOG_FILE}" 2>&1
            systemctl enable --now "${DL_SERVICE_NAME}.timer" >> "${LOG_FILE}" 2>&1
            sleep 1
            if systemctl is-active "${DL_SERVICE_NAME}.timer" &>/dev/null; then
                log_success "  ✓ Nuclear repair successful"
            else
                log_error "  ✗ CRITICAL: Cannot start system timer - check permissions"
                VERIFICATION_FAILED=1
            fi
        fi
    fi
fi

# Check 2: User service is active and healthy
log_debug "[2/12] Checking user notifier service..."
if sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user is-active "${NT_SERVICE_NAME}.timer" &>/dev/null; then
    # Check if enabled
    if sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user is-enabled "${NT_SERVICE_NAME}.timer" &>/dev/null; then
        log_success "✓ User notifier timer is active and enabled"
        # Deep health check: verify it's actually triggering
        NEXT_TRIGGER=$(sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user list-timers "${NT_SERVICE_NAME}.timer" 2>/dev/null | grep -o "left" || echo "")
        if [ -n "$NEXT_TRIGGER" ]; then
            log_success "  ✓ Timer has upcoming triggers scheduled"
        else
            log_error "  ⚠ Warning: Timer is active but no triggers scheduled"
            log_info "  → Restarting to reset trigger schedule..."
            sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user restart "${NT_SERVICE_NAME}.timer" >> "${LOG_FILE}" 2>&1
        fi
    else
        log_error "✗ User timer is active but NOT enabled"
        if attempt_repair "enable user timer" \
            "sudo -u $SUDO_USER DBUS_SESSION_BUS_ADDRESS=$USER_BUS_PATH systemctl --user enable ${NT_SERVICE_NAME}.timer" \
            "sudo -u $SUDO_USER DBUS_SESSION_BUS_ADDRESS=$USER_BUS_PATH systemctl --user is-enabled ${NT_SERVICE_NAME}.timer"; then
            log_success "  ✓ User timer enabled"
        else
            VERIFICATION_FAILED=1
        fi
    fi
else
    log_error "✗ User notifier timer is NOT active"
    # Multi-stage repair process
    log_info "  → Stage 1: Daemon reload and restart..."
    if attempt_repair "restart user service" \
        "sudo -u $SUDO_USER DBUS_SESSION_BUS_ADDRESS=$USER_BUS_PATH systemctl --user daemon-reload && sudo -u $SUDO_USER DBUS_SESSION_BUS_ADDRESS=$USER_BUS_PATH systemctl --user enable --now ${NT_SERVICE_NAME}.timer" \
        "sudo -u $SUDO_USER DBUS_SESSION_BUS_ADDRESS=$USER_BUS_PATH systemctl --user is-active ${NT_SERVICE_NAME}.timer" 3; then
        log_success "  ✓ User notifier timer repaired"
    else
        log_error "  → Stage 2: Checking for service file corruption..."
        if [ ! -f "${NT_SERVICE_FILE}" ] || [ ! -f "${NT_TIMER_FILE}" ]; then
            log_error "  ✗ CRITICAL: User service files missing"
            VERIFICATION_FAILED=1
        else
            # Check file permissions
            if [ ! -r "${NT_SERVICE_FILE}" ] || [ ! -r "${NT_TIMER_FILE}" ]; then
                log_error "  ⚠ Service files have wrong permissions"
                chown "$SUDO_USER:$SUDO_USER" "${NT_SERVICE_FILE}" "${NT_TIMER_FILE}" >> "${LOG_FILE}" 2>&1
                chmod 644 "${NT_SERVICE_FILE}" "${NT_TIMER_FILE}" >> "${LOG_FILE}" 2>&1
            fi
            
            # Final attempt
            log_info "  → Stage 3: Nuclear option - full service reset..."
            sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user stop "${NT_SERVICE_NAME}.timer" >> "${LOG_FILE}" 2>&1 || true
            sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user disable "${NT_SERVICE_NAME}.timer" >> "${LOG_FILE}" 2>&1 || true
            sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user daemon-reload >> "${LOG_FILE}" 2>&1
            sleep 1
            sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user enable --now "${NT_SERVICE_NAME}.timer" >> "${LOG_FILE}" 2>&1
            sleep 1
            
            if sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user is-active "${NT_SERVICE_NAME}.timer" &>/dev/null; then
                log_success "  ✓ Nuclear repair successful - user timer now active"
            else
                log_error "  ✗ CRITICAL: All repair attempts failed"
                log_error "  → This may indicate a DBUS or systemd user session issue"
                log_info "  → Try: loginctl enable-linger $SUDO_USER"
                VERIFICATION_FAILED=1
            fi
        fi
    fi
fi

# Check 3: Python script exists and is executable
log_debug "Checking Python notifier script..."
if [ -x "${NOTIFY_SCRIPT_PATH}" ]; then
    log_success "✓ Python notifier script is executable"
    # Check Python syntax
    if python3 -m py_compile "${NOTIFY_SCRIPT_PATH}" &>/dev/null; then
        log_success "✓ Python script syntax is valid"
    else
        log_error "✗ Python script has syntax errors"
        log_error "  → Cannot auto-fix: syntax errors require manual intervention"
        VERIFICATION_FAILED=1
    fi
else
    log_error "✗ Python notifier script is missing or not executable"
    if [ -f "${NOTIFY_SCRIPT_PATH}" ]; then
        log_info "  → Attempting to fix: making script executable..."
        chmod +x "${NOTIFY_SCRIPT_PATH}" >> "${LOG_FILE}" 2>&1
        chown "$SUDO_USER:$SUDO_USER" "${NOTIFY_SCRIPT_PATH}" >> "${LOG_FILE}" 2>&1
        if [ -x "${NOTIFY_SCRIPT_PATH}" ]; then
            log_success "  ✓ Fixed: Python script is now executable"
        else
            log_error "  ✗ Failed to make Python script executable"
            VERIFICATION_FAILED=1
        fi
    else
        log_error "  → Cannot auto-fix: file is completely missing"
        VERIFICATION_FAILED=1
    fi
fi

# Check 4: Downloader script exists and is executable
log_debug "Checking downloader script..."
if [ -x "$DOWNLOADER_SCRIPT" ]; then
    log_success "✓ Downloader script is executable"
    # Check bash syntax
    if bash -n "$DOWNLOADER_SCRIPT" &>/dev/null; then
        log_success "✓ Downloader script syntax is valid"
    else
        log_error "✗ Downloader script has syntax errors"
        VERIFICATION_FAILED=1
    fi
else
    log_error "✗ Downloader script is missing or not executable"
    VERIFICATION_FAILED=1
fi

# Check 5: Shell wrapper exists
log_debug "Checking zypper wrapper script..."
if [ -x "$ZYPPER_WRAPPER_PATH" ]; then
    log_success "✓ Zypper wrapper script is executable"
else
    log_error "✗ Zypper wrapper script is missing or not executable"
    VERIFICATION_FAILED=1
fi

# Check 6: Fish shell integration (if Fish is installed)
if [ -d "$SUDO_USER_HOME/.config/fish" ]; then
    log_debug "Checking Fish shell integration..."
    if [ -f "$SUDO_USER_HOME/.config/fish/conf.d/zypper-wrapper.fish" ]; then
        log_success "✓ Fish shell wrapper is installed"
    else
        log_error "✗ Fish shell wrapper is missing"
        VERIFICATION_FAILED=1
    fi
fi

# Check 7: No old Python processes running
log_debug "Checking for stale Python processes..."
if pgrep -f "zypper-notify-updater.py" &>/dev/null; then
    PROCESS_COUNT=$(pgrep -f "zypper-notify-updater.py" | wc -l)
    if [ $PROCESS_COUNT -gt 1 ]; then
        log_error "⚠ Warning: $PROCESS_COUNT Python notifier processes running (expected 0-1)"
        log_info "  → Attempting to fix: killing stale processes..."
        pkill -9 -f "zypper-notify-updater.py" >> "${LOG_FILE}" 2>&1
        sleep 1
        if pgrep -f "zypper-notify-updater.py" &>/dev/null; then
            NEW_COUNT=$(pgrep -f "zypper-notify-updater.py" | wc -l)
            log_info "  ✓ Fixed: Reduced to $NEW_COUNT process(es)"
        else
            log_success "  ✓ Fixed: All stale processes killed"
        fi
    else
        log_success "✓ Python notifier process count is normal"
    fi
else
    log_success "✓ No stale Python processes detected"
fi

# Check 8: Python bytecode cache is clear
log_debug "Checking Python bytecode cache..."
if find "$SUDO_USER_HOME/.local/bin" -name "*.pyc" -o -name "__pycache__" 2>/dev/null | grep -q .; then
    log_error "⚠ Warning: Python bytecode cache exists (may cause issues)"
    log_info "  → Attempting to fix: clearing bytecode cache..."
    find "$SUDO_USER_HOME/.local/bin" -name "*.pyc" -delete >> "${LOG_FILE}" 2>&1
    find "$SUDO_USER_HOME/.local/bin" -type d -name "__pycache__" -exec rm -rf {} + >> "${LOG_FILE}" 2>&1 || true
    if find "$SUDO_USER_HOME/.local/bin" -name "*.pyc" -o -name "__pycache__" 2>/dev/null | grep -q .; then
        log_error "  ✗ Failed to clear bytecode cache completely"
    else
        log_success "  ✓ Fixed: Python bytecode cache cleared"
    fi
else
    log_success "✓ Python bytecode cache is clean"
fi

# Check 9: Log directories exist
log_debug "Checking log directories..."
if [ -d "${LOG_DIR}" ] && [ -d "${USER_LOG_DIR}" ]; then
    log_success "✓ Log directories exist"
else
    log_error "✗ Log directories are missing"
    VERIFICATION_FAILED=1
fi

# Check 10: Status file exists
log_debug "Checking status file..."
if [ -f "/var/log/zypper-auto/download-status.txt" ]; then
    CURRENT_STATUS=$(cat /var/log/zypper-auto/download-status.txt)
    log_success "✓ Status file exists (current: $CURRENT_STATUS)"
else
    log_info "ℹ Status file will be created on first run"
fi

# Calculate repair statistics
PROBLEMS_FOUND=$REPAIR_ATTEMPTS
PROBLEMS_FIXED=$((REPAIR_ATTEMPTS - VERIFICATION_FAILED))

echo "" | tee -a "${LOG_FILE}"
echo "==============================================" | tee -a "${LOG_FILE}"
echo "Verification Summary:" | tee -a "${LOG_FILE}"
echo "  - Checks performed: 12" | tee -a "${LOG_FILE}"
echo "  - Problems detected: $PROBLEMS_FOUND" | tee -a "${LOG_FILE}"
echo "  - Problems auto-fixed: $PROBLEMS_FIXED" | tee -a "${LOG_FILE}"
echo "  - Remaining issues: $VERIFICATION_FAILED" | tee -a "${LOG_FILE}"
echo "==============================================" | tee -a "${LOG_FILE}"
echo "" | tee -a "${LOG_FILE}"

if [ $VERIFICATION_FAILED -eq 0 ]; then
    log_success ">>> All verification checks passed! ✓"
    if [ $PROBLEMS_FOUND -gt 0 ]; then
        log_success "  ✓ Auto-repair fixed $PROBLEMS_FIXED issue(s)"
    fi
else
    log_error ">>> $VERIFICATION_FAILED verification check(s) failed!"
    log_error "  → Auto-repair attempted but could not fix all issues"
    log_info "  → Review logs: ${LOG_FILE}"
    log_info "  → Common fixes:"
    log_info "     - Check systemd permissions: sudo loginctl enable-linger $SUDO_USER"
    log_info "     - Verify DBUS session: echo \$DBUS_SESSION_BUS_ADDRESS"
    log_info "     - Re-run installation: sudo $0 install"
fi
echo "" | tee -a "${LOG_FILE}"
    
    # Return exit code based on verification results
    return $VERIFICATION_FAILED
}

# --- Helper: Soar-only installation mode (CLI) ---
run_soar_install_only() {
    log_info ">>> Soar installation helper mode..."
    update_status "Running Soar installation helper..."

    SOAR_PRESENT=0

    # Detect Soar for the target user in common locations
    if sudo -u "$SUDO_USER" command -v soar >/dev/null 2>&1; then
        SOAR_PRESENT=1
    elif [ -x "$SUDO_USER_HOME/.local/bin/soar" ]; then
        SOAR_PRESENT=1
    elif [ -d "$SUDO_USER_HOME/pkgforge" ] && \
         find "$SUDO_USER_HOME/pkgforge" -maxdepth 1 -type f -name 'soar*' -perm -u+x 2>/dev/null | grep -q .; then
        SOAR_PRESENT=1
    fi

    if [ "$SOAR_PRESENT" -eq 1 ]; then
        log_success "Soar already appears to be installed for user $SUDO_USER"
        echo "Soar appears to be installed for user $SUDO_USER." | tee -a "${LOG_FILE}"
        echo "Try: sudo -u $SUDO_USER soar --help" | tee -a "${LOG_FILE}"
        return 0
    fi

    if ! command -v curl >/dev/null 2>&1; then
        log_error "curl is required to install Soar but is not installed."
        echo "Install curl with: sudo zypper install curl" | tee -a "${LOG_FILE}"
        return 1
    fi

    SOAR_INSTALL_CMD='curl -fsSL "https://raw.githubusercontent.com/pkgforge/soar/main/install.sh" | sh'

    echo "" | tee -a "${LOG_FILE}"
    echo "This will run the official Soar installer as user $SUDO_USER:" | tee -a "${LOG_FILE}"
    echo "  $SOAR_INSTALL_CMD" | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"

    if sudo -u "$SUDO_USER" bash -lc "$SOAR_INSTALL_CMD"; then
        log_success "Soar installation finished for user $SUDO_USER"
        echo "" | tee -a "${LOG_FILE}"
        echo "You can now run: sudo -u $SUDO_USER soar sync" | tee -a "${LOG_FILE}"
        return 0
    else
        local rc=$?
        log_error "Soar installer exited with code $rc"
        return $rc
    fi
}

# --- Helper: Uninstall core zypper-auto-helper components ---
run_uninstall_helper_only() {
    log_info ">>> Uninstalling zypper-auto-helper core components..."

    echo "" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"
    echo "  zypper-auto-helper Uninstall" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"
    echo "This will remove timers, services, helper binaries, logs, and user" | tee -a "${LOG_FILE}"
    echo "scripts/aliases installed by zypper-auto-helper for user $SUDO_USER." | tee -a "${LOG_FILE}"
    echo "The installer script (zypper-auto.sh) and your Soar/Homebrew installs" | tee -a "${LOG_FILE}"
    echo "will be left untouched." | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"

    read -p "Are you sure you want to uninstall zypper-auto-helper components? [y/N]: " -r CONFIRM
    echo
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        log_info "Uninstall aborted by user. No changes made."
        update_status "ABORTED: zypper-auto-helper uninstall cancelled by user"
        return 0
    fi

    update_status "Uninstalling zypper-auto-helper components..."

    # 1. Stop and disable root timers/services
    log_debug "Disabling root timers and services..."
    systemctl disable --now zypper-autodownload.timer >> "${LOG_FILE}" 2>&1 || true
    systemctl disable --now zypper-cache-cleanup.timer >> "${LOG_FILE}" 2>&1 || true
    systemctl stop zypper-autodownload.service >> "${LOG_FILE}" 2>&1 || true
    systemctl stop zypper-cache-cleanup.service >> "${LOG_FILE}" 2>&1 || true

    # 2. Stop and disable user timer/service
    if [ -n "${SUDO_USER:-}" ]; then
        log_debug "Disabling user timer and service for $SUDO_USER..."
        sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u "$SUDO_USER")/bus" \
            systemctl --user disable --now zypper-notify-user.timer >> "${LOG_FILE}" 2>&1 || true
        sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u "$SUDO_USER")/bus" \
            systemctl --user stop zypper-notify-user.service >> "${LOG_FILE}" 2>&1 || true
    fi

    # 3. Remove systemd unit files and root binaries
    log_debug "Removing root systemd units and binaries..."
    rm -f /etc/systemd/system/zypper-autodownload.service >> "${LOG_FILE}" 2>&1 || true
    rm -f /etc/systemd/system/zypper-autodownload.timer >> "${LOG_FILE}" 2>&1 || true
    rm -f /etc/systemd/system/zypper-cache-cleanup.service >> "${LOG_FILE}" 2>&1 || true
    rm -f /etc/systemd/system/zypper-cache-cleanup.timer >> "${LOG_FILE}" 2>&1 || true
    rm -f /usr/local/bin/zypper-download-with-progress >> "${LOG_FILE}" 2>&1 || true
    rm -f /usr/local/bin/zypper-auto-helper >> "${LOG_FILE}" 2>&1 || true

    # 4. Remove user-level scripts and systemd units
    if [ -n "${SUDO_USER_HOME:-}" ]; then
        log_debug "Removing user scripts and units under $SUDO_USER_HOME..."
        rm -f "$SUDO_USER_HOME/.config/systemd/user/zypper-notify-user.service" >> "${LOG_FILE}" 2>&1 || true
        rm -f "$SUDO_USER_HOME/.config/systemd/user/zypper-notify-user.timer" >> "${LOG_FILE}" 2>&1 || true
        rm -f "$SUDO_USER_HOME/.local/bin/zypper-notify-updater.py" >> "${LOG_FILE}" 2>&1 || true
        rm -f "$SUDO_USER_HOME/.local/bin/zypper-run-install" >> "${LOG_FILE}" 2>&1 || true
        rm -f "$SUDO_USER_HOME/.local/bin/zypper-with-ps" >> "${LOG_FILE}" 2>&1 || true
        rm -f "$SUDO_USER_HOME/.local/bin/zypper-view-changes" >> "${LOG_FILE}" 2>&1 || true
        rm -f "$SUDO_USER_HOME/.local/bin/zypper-soar-install-helper" >> "${LOG_FILE}" 2>&1 || true
        rm -f "$SUDO_USER_HOME/.config/fish/conf.d/zypper-wrapper.fish" >> "${LOG_FILE}" 2>&1 || true
        rm -f "$SUDO_USER_HOME/.config/fish/conf.d/zypper-auto-helper-alias.fish" >> "${LOG_FILE}" 2>&1 || true

        # Remove bash/zsh aliases we added (non-fatal if missing)
        sed -i '/# Zypper wrapper for auto service check/d' "$SUDO_USER_HOME/.bashrc" 2>>"${LOG_FILE}" || true
        sed -i '/alias zypper=/d' "$SUDO_USER_HOME/.bashrc" 2>>"${LOG_FILE}" || true
        sed -i '/# Zypper wrapper for auto service check/d' "$SUDO_USER_HOME/.zshrc" 2>>"${LOG_FILE}" || true
        sed -i '/alias zypper=/d' "$SUDO_USER_HOME/.zshrc" 2>>"${LOG_FILE}" || true
        sed -i '/# zypper-auto-helper command alias/d' "$SUDO_USER_HOME/.bashrc" 2>>"${LOG_FILE}" || true
        sed -i '/alias zypper-auto-helper=/d' "$SUDO_USER_HOME/.bashrc" 2>>"${LOG_FILE}" || true
        sed -i '/# zypper-auto-helper command alias/d' "$SUDO_USER_HOME/.zshrc" 2>>"${LOG_FILE}" || true
        sed -i '/alias zypper-auto-helper=/d' "$SUDO_USER_HOME/.zshrc" 2>>"${LOG_FILE}" || true
    fi

    # 5. Remove logs and caches
    # Keep the current uninstall log file so we don't break logging while
    # this function is still running, but remove other helper logs and
    # caches.
    log_debug "Removing logs and caches (preserving this uninstall log)..."
    if [ -d "$LOG_DIR" ]; then
        # Delete all files in $LOG_DIR except the current LOG_FILE
        find "$LOG_DIR" -maxdepth 1 -type f ! -name "$(basename "$LOG_FILE")" -delete >> "${LOG_FILE}" 2>&1 || true
        # Remove any service sub-logs directory completely
        rm -rf "$LOG_DIR/service-logs" >> "${LOG_FILE}" 2>&1 || true
    fi
    if [ -n "${SUDO_USER_HOME:-}" ]; then
        rm -rf "$SUDO_USER_HOME/.local/share/zypper-notify" >> "${LOG_FILE}" 2>&1 || true
        rm -rf "$SUDO_USER_HOME/.cache/zypper-notify" >> "${LOG_FILE}" 2>&1 || true
    fi

    # 6. Reload systemd daemons
    log_debug "Reloading systemd daemons after uninstall..."
    systemctl daemon-reload >> "${LOG_FILE}" 2>&1 || true
    if [ -n "${SUDO_USER:-}" ]; then
        sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u "$SUDO_USER")/bus" \
            systemctl --user daemon-reload >> "${LOG_FILE}" 2>&1 || true
    fi

    log_success "Core zypper-auto-helper components uninstalled (installer script left in place)."
    update_status "SUCCESS: zypper-auto-helper core components uninstalled"
}

# --- Helper: Homebrew-only installation mode (CLI) ---
run_brew_install_only() {
    log_info ">>> Homebrew (brew) installation helper mode..."
    update_status "Running Homebrew installation helper..."

    # Detect an existing brew installation for the target user and, if found,
    # prefer to run a self-update (brew update && brew upgrade) instead of
    # re-running the installer.
    BREW_PATH=""

    # 1) In the user's PATH
    if sudo -u "$SUDO_USER" command -v brew >/dev/null 2>&1; then
        BREW_PATH="brew"
    # 2) In a per-user ~/.linuxbrew or ~/.homebrew prefix
    elif [ -x "$SUDO_USER_HOME/.linuxbrew/bin/brew" ]; then
        BREW_PATH="$SUDO_USER_HOME/.linuxbrew/bin/brew"
    elif [ -x "$SUDO_USER_HOME/.homebrew/bin/brew" ]; then
        BREW_PATH="$SUDO_USER_HOME/.homebrew/bin/brew"
    # 3) In the default Linuxbrew prefix /home/linuxbrew/.linuxbrew
    elif [ -x "/home/linuxbrew/.linuxbrew/bin/brew" ]; then
        BREW_PATH="/home/linuxbrew/.linuxbrew/bin/brew"
    fi

    if [ -n "$BREW_PATH" ]; then
        log_success "Homebrew already appears to be installed for user $SUDO_USER"
        echo "brew appears to be installed for user $SUDO_USER." | tee -a "${LOG_FILE}"

        # Build the brew command to run as the target user
        if [ "$BREW_PATH" = "brew" ]; then
            BREW_CMD=(sudo -u "$SUDO_USER" brew)
        else
            BREW_CMD=(sudo -u "$SUDO_USER" "$BREW_PATH")
        fi

        echo "Checking for Homebrew updates from GitHub (brew update) for user $SUDO_USER" | tee -a "${LOG_FILE}"
        if ! "${BREW_CMD[@]}" update >> "${LOG_FILE}" 2>&1; then
            local rc=$?
            log_error "Homebrew 'brew update' failed for user $SUDO_USER (exit code $rc)"
            return $rc
        fi

        # After syncing with GitHub, see if anything needs upgrading
        OUTDATED=$("${BREW_CMD[@]}" outdated --quiet 2>/dev/null || true)
        OUTDATED_COUNT=$(printf '%s\n' "$OUTDATED" | sed '/^$/d' | wc -l | tr -d ' ')

        if [ "${OUTDATED_COUNT:-0}" -eq 0 ]; then
            echo "Homebrew is already up to date for user $SUDO_USER (no formulae to upgrade)." | tee -a "${LOG_FILE}"
            return 0
        fi

        echo "Homebrew has ${OUTDATED_COUNT} outdated formulae for user $SUDO_USER; running 'brew upgrade'..." | tee -a "${LOG_FILE}"
        if "${BREW_CMD[@]}" upgrade >> "${LOG_FILE}" 2>&1; then
            log_success "Homebrew upgrade completed for user $SUDO_USER (upgraded ${OUTDATED_COUNT} formulae)"
            return 0
        else
            local rc=$?
            log_error "Homebrew 'brew upgrade' failed for user $SUDO_USER (exit code $rc)"
            return $rc
        fi
    fi

    # Ensure basic prerequisites for the installer (inline to avoid ordering issues)
    if ! command -v curl >/dev/null 2>&1; then
        log_info "curl is required for the Homebrew installer. Installing via zypper..."
        if ! zypper -n install curl >> "${LOG_FILE}" 2>&1; then
            log_error "Failed to install curl. Please install it manually and re-run with --brew."
            return 1
        fi
    fi

    if ! command -v git >/dev/null 2>&1; then
        log_info "git is required for Homebrew operations. Installing via zypper..."
        if ! zypper -n install git >> "${LOG_FILE}" 2>&1; then
            log_error "Failed to install git. Please install it manually and re-run with --brew."
            return 1
        fi
    fi

    BREW_INSTALL_CMD='/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'

    echo "" | tee -a "${LOG_FILE}"
    echo "This will run the official Homebrew installer as user $SUDO_USER:" | tee -a "${LOG_FILE}"
    echo "  $BREW_INSTALL_CMD" | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"

    if sudo -u "$SUDO_USER" bash -lc "$BREW_INSTALL_CMD"; then
        log_success "Homebrew installation finished for user $SUDO_USER"
        echo "" | tee -a "${LOG_FILE}"
        echo "You may need to add brew to your PATH. For example:" | tee -a "${LOG_FILE}"
        echo '  eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"' | tee -a "${LOG_FILE}"
        echo 'or see:  https://docs.brew.sh/Homebrew-on-Linux' | tee -a "${LOG_FILE}"
        return 0
    else
        local rc=$?
        log_error "Homebrew installer exited with code $rc"
        return $rc
    fi
}

# Show help if requested
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" || "${1:-}" == "help" ]]; then
    echo "Zypper Auto-Helper - Installation and Maintenance Tool"
    echo ""
    echo "Usage: sudo zypper-auto-helper [COMMAND]"
    echo "   or: sudo $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  install           Install or update the zypper auto-updater system (default)"
    echo "  --verify          Run verification and auto-repair checks"
    echo "  --repair          Same as --verify (alias)"
    echo "  --diagnose        Same as --verify (alias)"
    echo "  --check           Run syntax checks only"
    echo "  --self-check      Same as --check (alias)"
    echo "  --soar            Install/upgrade optional Soar CLI helper for the user"
    echo "  --brew            Install/upgrade Homebrew (brew) for the user"
    echo "  --uninstall-zypper-helper  Remove zypper-auto-helper services, timers, logs, and user scripts"
    echo "  --help            Show this help message"
    echo ""
    echo "Examples:"
    echo "  sudo zypper-auto-helper install         # Full installation"
    echo "  sudo zypper-auto-helper --verify        # Check system health and auto-fix issues"
    echo "  sudo zypper-auto-helper --check         # Verify script syntax"
    echo "  sudo zypper-auto-helper --soar          # Install or upgrade Soar CLI helper"
    echo ""
    echo "Verification checks (--verify):"
    echo "  - System/user services active and enabled"
    echo "  - Python scripts executable and valid syntax"
    echo "  - Shell wrappers installed correctly"
    echo "  - No stale processes or bytecode cache"
    echo "  - Auto-repairs most common issues"
    echo ""
    echo "Note: After installation, you can use 'zypper-auto-helper' from anywhere."
    echo ""
    exit 0
fi

# Optional mode: only run self-check and exit
if [[ "${1:-}" == "--self-check" || "${1:-}" == "--check" ]]; then
    log_info "Self-check mode requested"
    run_self_check
    log_success "Self-check mode completed"
    exit 0
fi

# Optional modes: Soar, Homebrew, and uninstall helper-only
if [[ "${1:-}" == "--soar" ]]; then
    log_info "Soar helper-only mode requested"
    run_soar_install_only
    exit $?
elif [[ "${1:-}" == "--brew" ]]; then
    log_info "Homebrew helper-only mode requested"
    run_brew_install_only
    exit $?
elif [[ "${1:-}" == "--uninstall-zypper-helper" ]]; then
    log_info "Uninstall zypper-auto-helper mode requested"
    run_uninstall_helper_only
    exit $?
fi

# Optional mode: run verification and auto-repair
if [[ "${1:-}" == "--verify" || "${1:-}" == "--repair" || "${1:-}" == "--diagnose" ]]; then
    log_info "Verification and auto-repair mode requested"
    echo "" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"
    echo "  Zypper Auto-Helper - Verification Mode" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"
    
    # Set a flag to skip to verification section
    VERIFICATION_ONLY_MODE=1
    # We'll jump to the verification section after defining all variables
fi

# --- Helper function to check and install ---
check_and_install() {
    local cmd=$1
    local package=$2
    local purpose=$3

    log_debug "Checking for command: $cmd (package: $package)"
    
    if ! command -v $cmd &> /dev/null; then
        log_info "---"
        log_info "⚠️  Dependency missing: '$cmd' ($purpose)."
        log_info "   This is provided by the package '$package'."
        read -p "   May I install it for you? (y/n) " -n 1 -r
        echo
        log_debug "User response: $REPLY"
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Installing $package..."
            update_status "Installing dependency: $package"
            
            if ! sudo zypper install -y "$package" >> "${LOG_FILE}" 2>&1; then
                log_error "Failed to install $package. Please install it manually and re-run this script."
                update_status "FAILED: Could not install $package"
                exit 1
            fi
            log_success "Successfully installed $package"
        else
            log_error "Dependency '$package' is required. Please install it manually and re-run this script."
            update_status "FAILED: Required dependency $package not installed"
            exit 1
        fi
    else
        log_success "Command '$cmd' found"
    fi
}

# Skip installation if we're only verifying
if [ "${VERIFICATION_ONLY_MODE:-0}" -eq 1 ]; then
    log_info "Skipping installation steps - verification mode"
    # Need to set DOWNLOADER_SCRIPT path for verification
    DOWNLOADER_SCRIPT="/usr/local/bin/zypper-download-with-progress"
    ZYPPER_WRAPPER_PATH="$USER_BIN_DIR/zypper-with-ps"
    USER_LOG_DIR="$SUDO_USER_HOME/.local/share/zypper-notify"
    USER_BUS_PATH="unix:path=/run/user/$(id -u "$SUDO_USER")/bus"
    # Jump to verification section (we'll use a function)
    run_verification_only
    exit $?
fi

# --- 2b. Dependency Checks ---
update_status "Checking dependencies..."
log_info ">>> Checking dependencies..."
check_and_install "nmcli" "NetworkManager" "checking metered connection"
check_and_install "upower" "upower" "checking AC power"
check_and_install "inxi" "inxi" "hardware and network detection"
check_and_install "python3" "python3" "running the notifier script"
check_and_install "pkexec" "polkit" "graphical authentication"

# Check Python version (must be 3.7+)
log_debug "Checking Python version..."
PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
log_debug "Python version: $PY_VERSION"

if [ "$(echo -e "$PY_VERSION\n3.7" | sort -V | head -n1)" != "3.7" ]; then
    log_error "Python 3.7 or newer is required. Found $PY_VERSION."
    update_status "FAILED: Python version too old ($PY_VERSION)"
    exit 1
fi
log_success "Python version check passed: $PY_VERSION"

# Check for PyGobject (the notification library)
log_debug "Checking for PyGObject..."
if ! python3 -c "import gi" &> /dev/null; then
    log_info "---"
    log_info "⚠️  Dependency missing: 'python3-gobject' (for notifications)."
    read -p "   May I install it for you? (y/n) " -n 1 -r
    echo
    log_debug "User response: $REPLY"
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Installing python3-gobject..."
        update_status "Installing python3-gobject..."
        
        if ! sudo zypper install -y "python3-gobject" >> "${LOG_FILE}" 2>&1; then
            log_error "Failed to install python3-gobject. Please install it manually and re-run this script."
            update_status "FAILED: Could not install python3-gobject"
            exit 1
        fi
        log_success "Successfully installed python3-gobject"
    else
        log_error "Dependency 'python3-gobject' is required. Please install it manually and re-run this script."
        update_status "FAILED: python3-gobject not installed"
        exit 1
    fi
else
    log_success "PyGObject found"
fi
log_success "All dependencies passed"
update_status "All dependencies verified"

# --- 3. Clean Up Old Logs First ---
log_info ">>> Cleaning up old log files..."
update_status "Cleaning up old installation logs..."
cleanup_old_logs

# --- 4. Clean Up ALL Previous Versions (System & User) ---
log_info ">>> Cleaning up all old system-wide services..."
update_status "Removing old system services..."
log_debug "Disabling old timers and services..."
systemctl disable --now zypper-autodownload.timer >> "${LOG_FILE}" 2>&1 || true
systemctl stop zypper-autodownload.service >> "${LOG_FILE}" 2>&1 || true
systemctl disable --now zypper-notify.timer >> "${LOG_FILE}" 2>&1 || true
systemctl stop zypper-notify.service >> "${LOG_FILE}" 2>&1 || true
systemctl disable --now zypper-smart-updater.timer >> "${LOG_FILE}" 2>&1 || true
systemctl stop zypper-smart-updater.service >> "${LOG_FILE}" 2>&1 || true

log_debug "Removing old system binaries..."
rm -f /usr/local/bin/zypper-run-install* >> "${LOG_FILE}" 2>&1
rm -f /usr/local/bin/notify-updater >> "${LOG_FILE}" 2>&1
rm -f /usr/local/bin/zypper-smart-updater-script >> "${LOG_FILE}" 2>&1
log_success "Old system services disabled and files removed"

log_info ">>> Cleaning up old user-space services..."
update_status "Removing old user services..."
SUDO_USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
log_debug "Disabling user timer..."
sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$SUDO_USER/bus" systemctl --user disable --now zypper-notify-user.timer >> "${LOG_FILE}" 2>&1 || true

# Force kill any running Python notifier processes
log_debug "Force-killing any running Python notifier processes..."
pkill -9 -f "zypper-notify-updater.py" >> "${LOG_FILE}" 2>&1 || true
sleep 1

# Clear Python bytecode cache
log_debug "Clearing Python bytecode cache..."
find "$SUDO_USER_HOME/.local/bin" -name "*.pyc" -delete >> "${LOG_FILE}" 2>&1 || true
find "$SUDO_USER_HOME/.local/bin" -type d -name "__pycache__" -exec rm -rf {} + >> "${LOG_FILE}" 2>&1 || true

log_debug "Removing old user binaries and configs..."
rm -f "$SUDO_USER_HOME/.local/bin/zypper-run-install*" >> "${LOG_FILE}" 2>&1
rm -f "$SUDO_USER_HOME/.local/bin/zypper-open-terminal*" >> "${LOG_FILE}" 2>&1
rm -f "$SUDO_USER_HOME/.local/bin/zypper-notify-updater" >> "${LOG_FILE}" 2>&1
rm -f "$SUDO_USER_HOME/.local/bin/zypper-notify-updater.py" >> "${LOG_FILE}" 2>&1
rm -f "$SUDO_USER_HOME/.config/systemd/user/zypper-notify-user."* >> "${LOG_FILE}" 2>&1
log_success "Old user services disabled and files removed"

# --- 5. Create/Update DOWNLOADER (Root Service) ---
log_info ">>> Creating (root) downloader service: ${DL_SERVICE_FILE}"
update_status "Creating system downloader service..."
log_debug "Writing service file: ${DL_SERVICE_FILE}"

# Create service log directory
mkdir -p "${LOG_DIR}/service-logs"
chmod 755 "${LOG_DIR}/service-logs"

# First, create the downloader script with progress tracking
DOWNLOADER_SCRIPT="/usr/local/bin/zypper-download-with-progress"
log_debug "Creating downloader script with progress tracking: $DOWNLOADER_SCRIPT"
cat << 'DLSCRIPT' > "$DOWNLOADER_SCRIPT"
#!/bin/bash
# Zypper downloader with real-time progress tracking
set -euo pipefail

LOG_DIR="/var/log/zypper-auto"
STATUS_FILE="$LOG_DIR/download-status.txt"
START_TIME_FILE="$LOG_DIR/download-start-time.txt"
CACHE_DIR="/var/cache/zypp/packages"

# Helper: handle "System management is locked" gracefully so the
# downloader doesn't spam errors when the user is running zypper/Yast.
handle_lock_or_fail() {
    local err_file="$1"
    if grep -q "System management is locked" "$err_file" 2>/dev/null; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Zypper is locked by another process; skipping this downloader run (will retry on next timer)" >&2
        echo "idle" > "$STATUS_FILE"
        rm -f "$err_file"
        exit 0
    fi
}

# Write status: refreshing
echo "refreshing" > "$STATUS_FILE"
date +%s > "$START_TIME_FILE"

# Refresh repos
REFRESH_ERR=$(mktemp)
if ! /usr/bin/nice -n -20 /usr/bin/ionice -c1 -n0 /usr/bin/zypper --non-interactive --no-gpg-checks refresh >/dev/null 2>"$REFRESH_ERR"; then
    handle_lock_or_fail "$REFRESH_ERR"
    cat "$REFRESH_ERR" >&2 || true
    rm -f "$REFRESH_ERR"
    exit 1
fi
rm -f "$REFRESH_ERR"

# Get update info
DRY_OUTPUT=$(mktemp)
DRY_ERR=$(mktemp)
if ! /usr/bin/nice -n -20 /usr/bin/ionice -c1 -n0 /usr/bin/zypper --non-interactive dup --dry-run > "$DRY_OUTPUT" 2>"$DRY_ERR"; then
    handle_lock_or_fail "$DRY_ERR"
    cat "$DRY_ERR" >&2 || true
    rm -f "$DRY_ERR" "$DRY_OUTPUT"
    exit 1
fi
rm -f "$DRY_ERR"

if ! grep -q "packages to upgrade" "$DRY_OUTPUT"; then
    echo "idle" > "$STATUS_FILE"
    rm -f "$DRY_OUTPUT"
    exit 0
fi

# Extract package count and size
PKG_COUNT=$(grep -oP "\d+(?= packages to upgrade)" "$DRY_OUTPUT" | head -1)
DOWNLOAD_SIZE=$(grep -oP "Overall download size: ([\d.]+ [KMG]iB)" "$DRY_OUTPUT" | grep -oP "[\d.]+ [KMG]iB" || echo "unknown")

# Detect case where everything is already cached so we don't show a fake
# download progress bar. In that situation zypper's summary contains a
# line similar to:
#   0 B  |  -   88.3 MiB  already in cache
if grep -q "already in cache" "$DRY_OUTPUT" && \
   grep -qE "^[[:space:]]*0 B[[:space:]]*\|" "$DRY_OUTPUT"; then
    # All data is already in the local cache; mark as a completed
    # download with 0 newly-downloaded packages and skip the
    # --download-only pass entirely.
    echo "complete:0:0" > "$STATUS_FILE"
    rm -f "$DRY_OUTPUT"
    exit 0
fi

rm -f "$DRY_OUTPUT"

# Count packages before download
BEFORE_COUNT=$(find "$CACHE_DIR" -name "*.rpm" 2>/dev/null | wc -l)

# Write initial downloading status so the tracker loop sees it immediately
echo "downloading:$PKG_COUNT:$DOWNLOAD_SIZE:0:0" > "$STATUS_FILE"
# Start background progress tracker
(
    while [ -f "$STATUS_FILE" ] && grep -q "^downloading:" "$STATUS_FILE" 2>/dev/null; do
        sleep 2  # Update every 2 seconds
        CURRENT_COUNT=$(find "$CACHE_DIR" -name "*.rpm" 2>/dev/null | wc -l)
        DOWNLOADED=$((CURRENT_COUNT - BEFORE_COUNT))
        if [ $DOWNLOADED -lt 0 ]; then DOWNLOADED=0; fi
        if [ $DOWNLOADED -gt $PKG_COUNT ]; then DOWNLOADED=$PKG_COUNT; fi
        
        # Calculate percentage
        if [ $PKG_COUNT -gt 0 ]; then
            PERCENT=$((DOWNLOADED * 100 / PKG_COUNT))
        else
            PERCENT=0
        fi
        
        echo "downloading:$PKG_COUNT:$DOWNLOAD_SIZE:$DOWNLOADED:$PERCENT" > "$STATUS_FILE"
    done
) &
TRACKER_PID=$!

# Do the actual download. We intentionally ignore most non-zero exit codes so
# that partial downloads remain in the cache even if zypper encounters solver
# problems that require manual intervention later. We still special-case the
# lock error to avoid noisy logs when another zypper instance is running.
set +e
DL_ERR=$(mktemp)
/usr/bin/nice -n -20 /usr/bin/ionice -c1 -n0 /usr/bin/zypper --non-interactive --no-gpg-checks dup --download-only >/dev/null 2>"$DL_ERR"
ZYP_RET=$?
if [ $ZYP_RET -ne 0 ]; then
    handle_lock_or_fail "$DL_ERR"
fi
rm -f "$DL_ERR"
set -e

# Kill the progress tracker
kill $TRACKER_PID 2>/dev/null || true
wait $TRACKER_PID 2>/dev/null || true

# Count packages after download
AFTER_COUNT=$(find "$CACHE_DIR" -name "*.rpm" 2>/dev/null | wc -l)
ACTUAL_DOWNLOADED=$((AFTER_COUNT - BEFORE_COUNT))

# Calculate duration
START_TIME=$(cat "$START_TIME_FILE" 2>/dev/null || date +%s)
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Decide final status:
#  - If we actually downloaded new packages, mark as complete
#  - If nothing was downloaded but zypper returned an error, mark an error
#    so the notifier can tell the user that manual intervention is required
#  - Otherwise, leave the previous status (e.g. idle or complete:0:0)
if [ $ACTUAL_DOWNLOADED -gt 0 ]; then
    echo "complete:$DURATION:$ACTUAL_DOWNLOADED" > "$STATUS_FILE"
elif [ $ZYP_RET -ne 0 ]; then
    echo "error:solver:$ZYP_RET" > "$STATUS_FILE"
fi

DLSCRIPT
chmod +x "$DOWNLOADER_SCRIPT"
log_success "Downloader script created with progress tracking"

# Now create the service file
cat << EOF > ${DL_SERVICE_FILE}
[Unit]
Description=Download Tumbleweed updates in background
ConditionACPower=true
ConditionNotOnMeteredConnection=true
Wants=network-online.target
After=network-online.target nss-lookup.target

[Service]
Type=oneshot
IOSchedulingClass=realtime
IOSchedulingPriority=0
Nice=-20
StandardOutput=append:${LOG_DIR}/service-logs/downloader.log
StandardError=append:${LOG_DIR}/service-logs/downloader-error.log
ExecStart=${DOWNLOADER_SCRIPT}
EOF
log_success "Downloader service file created"

# --- 6. Create/Update DOWNLOADER (Root Timer) ---
log_info ">>> Creating (root) downloader timer: ${DL_TIMER_FILE}"
log_debug "Writing timer file: ${DL_TIMER_FILE}"
cat << EOF > ${DL_TIMER_FILE}
[Unit]
Description=Run ${DL_SERVICE_NAME} every minute to download updates

[Timer]
OnBootSec=2min
OnCalendar=minutely
Persistent=true

[Install]
WantedBy=timers.target
EOF
log_success "Downloader timer file created"

log_info ">>> Enabling (root) downloader timer: ${DL_SERVICE_NAME}.timer"
update_status "Enabling system downloader timer..."
log_debug "Reloading systemd daemon..."
systemctl daemon-reload >> "${LOG_FILE}" 2>&1

log_debug "Enabling and starting timer..."
if systemctl enable --now "${DL_SERVICE_NAME}.timer" >> "${LOG_FILE}" 2>&1; then
    log_success "Downloader timer enabled and started"
else
    log_error "Failed to enable downloader timer"
    update_status "FAILED: Could not enable downloader timer"
    exit 1
fi

# --- 6b. Create Cache Cleanup Service ---
log_info ">>> Creating (root) cache cleanup service: ${CLEANUP_SERVICE_FILE}"
update_status "Creating cache cleanup service..."
log_debug "Writing service file: ${CLEANUP_SERVICE_FILE}"
cat << EOF > ${CLEANUP_SERVICE_FILE}
[Unit]
Description=Clean up old zypper cache packages

[Service]
Type=oneshot
ExecStart=/usr/bin/find /var/cache/zypp/packages -type f -name '*.rpm' -mtime +30 -delete
ExecStart=/usr/bin/find /var/cache/zypp/packages -type d -empty -delete
StandardOutput=append:${LOG_DIR}/service-logs/cleanup.log
StandardError=append:${LOG_DIR}/service-logs/cleanup-error.log
EOF
log_success "Cache cleanup service file created"

log_info ">>> Creating (root) cache cleanup timer: ${CLEANUP_TIMER_FILE}"
log_debug "Writing timer file: ${CLEANUP_TIMER_FILE}"
cat << EOF > ${CLEANUP_TIMER_FILE}
[Unit]
Description=Run cache cleanup weekly

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
EOF
log_success "Cache cleanup timer file created"

log_info ">>> Enabling (root) cache cleanup timer: ${CLEANUP_SERVICE_NAME}.timer"
update_status "Enabling cache cleanup timer..."
systemctl daemon-reload >> "${LOG_FILE}" 2>&1
if systemctl enable --now "${CLEANUP_SERVICE_NAME}.timer" >> "${LOG_FILE}" 2>&1; then
    log_success "Cache cleanup timer enabled and started"
else
    log_error "Failed to enable cache cleanup timer (non-fatal)"
fi

# --- 7. Create User Directories ---
log_info ">>> Creating user directories (if needed)..."
update_status "Creating user directories..."
log_debug "Creating $USER_CONFIG_DIR"
mkdir -p "$USER_CONFIG_DIR"
chown -R "$SUDO_USER:$SUDO_USER" "$SUDO_USER_HOME/.config"

log_debug "Creating $USER_BIN_DIR"
mkdir -p "$USER_BIN_DIR"
chown -R "$SUDO_USER:$SUDO_USER" "$SUDO_USER_HOME/.local"
log_success "User directories created"

# Create user log directory
USER_LOG_DIR="$SUDO_USER_HOME/.local/share/zypper-notify"
log_debug "Creating user log directory: $USER_LOG_DIR"
mkdir -p "$USER_LOG_DIR"
chown -R "$SUDO_USER:$SUDO_USER" "$USER_LOG_DIR"

# --- 7b. Create Zypper Wrapper for Manual Updates ---
log_info ">>> Creating zypper wrapper script for manual updates..."
update_status "Creating zypper wrapper..."
ZYPPER_WRAPPER_PATH="$USER_BIN_DIR/zypper-with-ps"
log_debug "Writing zypper wrapper to: $ZYPPER_WRAPPER_PATH"
cat << 'EOF' > "$ZYPPER_WRAPPER_PATH"
#!/usr/bin/env bash
# Zypper wrapper that automatically runs 'zypper ps -s' after 'zypper dup'
# This shows which services need restarting after updates

# Check if we're running 'dup', 'dist-upgrade' or 'update'
if [[ "$*" == *"dup"* ]] || [[ "$*" == *"dist-upgrade"* ]] || [[ "$*" == *"update"* ]]; then
    # Run the actual zypper command
    sudo /usr/bin/zypper "$@"
    EXIT_CODE=$?

    # Always run Flatpak and Snap updates after dup, even if dup had no updates or failed
    echo ""
    echo "=========================================="
    echo "  Flatpak Updates"
    echo "=========================================="
    echo ""

    if command -v flatpak >/dev/null 2>&1; then
        if sudo flatpak update -y; then
            echo "✅ Flatpak updates completed."
        else
            echo "⚠️  Flatpak update failed (continuing)."
        fi
    else
        echo "⚠️  Flatpak is not installed - skipping Flatpak updates."
        echo "   To install: sudo zypper install flatpak"
    fi

    echo ""
    echo "=========================================="
    echo "  Snap Updates"
    echo "=========================================="
    echo ""

    if command -v snap >/dev/null 2>&1; then
        if pkexec snap refresh; then
            echo "✅ Snap updates completed."
        else
            echo "⚠️  Snap refresh failed (continuing)."
        fi
    else
        echo "⚠️  Snapd is not installed - skipping Snap updates."
        echo "   To install: sudo zypper install snapd"
        echo "   Then enable: sudo systemctl enable --now snapd"
    fi

    echo ""
    echo "=========================================="
    echo "  Soar (stable) Update & Sync (optional)"
    echo "=========================================="
    echo ""

    if command -v soar >/dev/null 2>&1; then
        # First, check if a newer *stable* Soar release exists on GitHub.
        # We compare the local "soar --version" against
        # https://api.github.com/repos/pkgforge/soar/releases/latest (stable only).
        if command -v curl >/dev/null 2>&1; then
            echo "Checking for newer stable Soar release from GitHub..."

            LOCAL_VER_RAW=$(soar --version 2>/dev/null | head -n1)
            LOCAL_VER=$(echo "$LOCAL_VER_RAW" | grep -oE 'v?[0-9]+(\.[0-9]+)*' | head -n1 || true)
            LOCAL_BASE=${LOCAL_VER#v}

            REMOTE_JSON=$(curl -fsSL "https://api.github.com/repos/pkgforge/soar/releases/latest" 2>/dev/null || true)
            REMOTE_VER=$(printf '%s\n' "$REMOTE_JSON" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name" *: *"([^"]+)".*/\1/' || true)
            REMOTE_BASE=${REMOTE_VER#v}

            if [ -n "$LOCAL_BASE" ] && [ -n "$REMOTE_BASE" ]; then
                LATEST=$(printf '%s\n%s\n' "$LOCAL_BASE" "$REMOTE_BASE" | sort -V | tail -n1)
                if [ "$LATEST" = "$REMOTE_BASE" ] && [ "$LOCAL_BASE" != "$REMOTE_BASE" ]; then
                    echo "New stable Soar available ($LOCAL_VER -> $REMOTE_VER), updating..."
                    if curl -fsSL "https://raw.githubusercontent.com/pkgforge/soar/main/install.sh" | sh; then
                        echo "✅ Soar updated to latest stable release."
                    else
                        echo "⚠️  Failed to update Soar from GitHub (continuing with existing version)."
                    fi
                else
                    echo "Soar is already up to date (local: ${LOCAL_VER:-unknown}, latest stable: ${REMOTE_VER:-unknown})."
                fi
            else
                echo "Could not determine Soar versions; running installer to ensure latest stable."
                if curl -fsSL "https://raw.githubusercontent.com/pkgforge/soar/main/install.sh" | sh; then
                    echo "✅ Soar updated to latest stable release."
                else
                    echo "⚠️  Failed to update Soar from GitHub (continuing with existing version)."
                fi
            fi
        else
            echo "⚠️  curl is not installed; skipping automatic Soar update from GitHub."
            echo "    You can update Soar manually from: https://github.com/pkgforge/soar/releases"
        fi

        # Then run the usual metadata sync.
        if soar sync; then
            echo "✅ Soar sync completed."
            # Optionally refresh Soar-managed apps that support "soar update".
            if soar update; then
                echo "✅ Soar update completed."
            else
                echo "⚠️  Soar update failed (continuing)."
            fi
        else
            echo "⚠️  Soar sync failed (continuing)."
        fi
    else
        echo "ℹ️  Soar is not installed - skipping Soar update/sync."
        echo "    Install from: https://github.com/pkgforge/soar/releases"
    fi

    echo ""
    echo "=========================================="
    echo "  Homebrew (brew) Updates (optional)"
    echo "=========================================="
    echo ""

    # Try to detect Homebrew in PATH or the default Linuxbrew prefix
    if command -v brew >/dev/null 2>&1 || [ -x "/home/linuxbrew/.linuxbrew/bin/brew" ]; then
        # Normalise brew command path
        if command -v brew >/dev/null 2>&1; then
            BREW_BIN="brew"
        else
            BREW_BIN="/home/linuxbrew/.linuxbrew/bin/brew"
        fi

        echo "Checking for Homebrew updates from GitHub (brew update)..."
        if ! $BREW_BIN update; then
            echo "⚠️  Homebrew 'brew update' failed (continuing without brew upgrade)."
        else
            # After syncing with GitHub, see if anything needs upgrading
            OUTDATED=$($BREW_BIN outdated --quiet 2>/dev/null || true)
            OUTDATED_COUNT=$(printf '%s\n' "$OUTDATED" | sed '/^$/d' | wc -l | tr -d ' ')

            if [ "${OUTDATED_COUNT:-0}" -eq 0 ]; then
                echo "Homebrew is already up to date (no formulae to upgrade)."
            else
                echo "Homebrew has ${OUTDATED_COUNT} outdated formulae; running 'brew upgrade'..."
                if $BREW_BIN upgrade; then
                    echo "✅ Homebrew upgrade completed (upgraded ${OUTDATED_COUNT} formulae)."
                else
                    echo "⚠️  Homebrew 'brew upgrade' failed (continuing)."
                fi
            fi
        fi
    else
        echo "ℹ️  Homebrew (brew) is not installed - skipping brew update/upgrade."
        echo "    To install via helper: sudo zypper-auto-helper --brew"
    fi

    # Always show service restart info, even if zypper reported errors
    echo ""
    echo "=========================================="
    echo "  Post-Update Service Check"
    echo "=========================================="
    echo ""
    echo "Checking which services need to be restarted..."
    echo ""
    
    # Run zypper ps -s to show services using old libraries
    ZYPPER_PS_OUTPUT=$(sudo /usr/bin/zypper ps -s 2>/dev/null || true)
    echo "$ZYPPER_PS_OUTPUT"
    
    # Check if there are any running processes
    if echo "$ZYPPER_PS_OUTPUT" | grep -q "running processes"; then
        echo ""
        echo "ℹ️  Services listed above are using old library versions."
        echo ""
        echo "What this means:"
        echo "  • These services/processes are still running old code in memory"
        echo "  • They should be restarted to use the updated libraries"
        echo ""
        echo "Options:"
        echo "  1. Restart individual services: systemctl restart <service>"
        echo "  2. Reboot your system (recommended for kernel/system updates)"
        echo ""
    else
        echo "✅ No services require restart. You're all set!"
        echo ""
    fi
    
    exit $EXIT_CODE
else
    # Not a dup command, just run zypper normally
    sudo /usr/bin/zypper "$@"
fi
EOF
chown "$SUDO_USER:$SUDO_USER" "$ZYPPER_WRAPPER_PATH"
chmod +x "$ZYPPER_WRAPPER_PATH"
log_success "Zypper wrapper script created and made executable"

# Add shell alias/function to user's shell config
log_info ">>> Adding zypper alias to shell configurations..."
update_status "Configuring shell aliases..."

# Bash configuration
if [ -f "$SUDO_USER_HOME/.bashrc" ]; then
    log_debug "Adding zypper alias to .bashrc"
    # Remove old alias if it exists
    sed -i '/# Zypper wrapper for auto service check/d' "$SUDO_USER_HOME/.bashrc"
    sed -i '/alias zypper=/d' "$SUDO_USER_HOME/.bashrc"
    # Add new alias
    echo "" >> "$SUDO_USER_HOME/.bashrc"
    echo "# Zypper wrapper for auto service check (added by zypper-auto-helper)" >> "$SUDO_USER_HOME/.bashrc"
    echo "alias zypper='$ZYPPER_WRAPPER_PATH'" >> "$SUDO_USER_HOME/.bashrc"
    chown "$SUDO_USER:$SUDO_USER" "$SUDO_USER_HOME/.bashrc"
    log_success "Added zypper alias to .bashrc"
fi

# Fish configuration
if [ -d "$SUDO_USER_HOME/.config/fish" ]; then
    log_debug "Adding zypper wrapper to fish config"
    FISH_CONFIG_DIR="$SUDO_USER_HOME/.config/fish/conf.d"
    mkdir -p "$FISH_CONFIG_DIR"
    FISH_ALIAS_FILE="$FISH_CONFIG_DIR/zypper-wrapper.fish"
    cat > "$FISH_ALIAS_FILE" << 'FISHEOF'
# Zypper wrapper for auto service check (added by zypper-auto-helper)

# Wrap zypper command
function zypper --wraps zypper --description "Wrapper for zypper with post-update checks"
    # Check if we already have sudo in the command (avoid double sudo)
    set -l has_sudo 0
    for arg in $argv
        if test "$arg" = "sudo"
            set has_sudo 1
            break
        end
    end
    
    # Call the wrapper script (which handles sudo internally)
    ~/.local/bin/zypper-with-ps $argv
end

# Wrap sudo command when used with zypper
function sudo --wraps sudo --description "Wrapper for sudo to intercept zypper commands"
    # Check if first argument is zypper
    if test (count $argv) -gt 0; and test "$argv[1]" = "zypper"
        # Remove 'zypper' from argv and call our zypper wrapper
        set -l zypper_args $argv[2..-1]
        ~/.local/bin/zypper-with-ps $zypper_args
    else
        # Not a zypper command, use real sudo
        command sudo $argv
    end
end
FISHEOF
    chown -R "$SUDO_USER:$SUDO_USER" "$SUDO_USER_HOME/.config/fish"
    log_success "Added zypper wrapper functions to fish config"
fi

# Zsh configuration
if [ -f "$SUDO_USER_HOME/.zshrc" ]; then
    log_debug "Adding zypper alias to .zshrc"
    # Remove old alias if it exists
    sed -i '/# Zypper wrapper for auto service check/d' "$SUDO_USER_HOME/.zshrc"
    sed -i '/alias zypper=/d' "$SUDO_USER_HOME/.zshrc"
    # Add new alias
    echo "" >> "$SUDO_USER_HOME/.zshrc"
    echo "# Zypper wrapper for auto service check (added by zypper-auto-helper)" >> "$SUDO_USER_HOME/.zshrc"
    echo "alias zypper='$ZYPPER_WRAPPER_PATH'" >> "$SUDO_USER_HOME/.zshrc"
    chown "$SUDO_USER:$SUDO_USER" "$SUDO_USER_HOME/.zshrc"
    log_success "Added zypper alias to .zshrc"
fi

log_success "Shell aliases configured. Restart your shell or run 'source ~/.bashrc' (or equivalent) to activate."

# --- 7c. Add zypper-auto-helper command alias to shells ---
log_info ">>> Adding zypper-auto-helper command alias to shell configurations..."
update_status "Configuring zypper-auto-helper aliases..."

# Bash configuration for zypper-auto-helper
if [ -f "$SUDO_USER_HOME/.bashrc" ]; then
    log_debug "Adding zypper-auto-helper alias to .bashrc"
    # Remove old alias if it exists
    sed -i '/# zypper-auto-helper command alias/d' "$SUDO_USER_HOME/.bashrc"
    sed -i '/alias zypper-auto-helper=/d' "$SUDO_USER_HOME/.bashrc"
    # Add new alias
    echo "" >> "$SUDO_USER_HOME/.bashrc"
    echo "# zypper-auto-helper command alias (added by zypper-auto-helper)" >> "$SUDO_USER_HOME/.bashrc"
    echo "alias zypper-auto-helper='sudo /usr/local/bin/zypper-auto-helper'" >> "$SUDO_USER_HOME/.bashrc"
    chown "$SUDO_USER:$SUDO_USER" "$SUDO_USER_HOME/.bashrc"
    log_success "Added zypper-auto-helper alias to .bashrc"
fi

# Fish configuration for zypper-auto-helper
if [ -d "$SUDO_USER_HOME/.config/fish" ]; then
    log_debug "Adding zypper-auto-helper alias to fish config"
    FISH_HELPER_FILE="$SUDO_USER_HOME/.config/fish/conf.d/zypper-auto-helper-alias.fish"
    cat > "$FISH_HELPER_FILE" << 'FISHHELPER'
# zypper-auto-helper command alias (added by zypper-auto-helper)
alias zypper-auto-helper='sudo /usr/local/bin/zypper-auto-helper'
FISHHELPER
    chown "$SUDO_USER:$SUDO_USER" "$FISH_HELPER_FILE"
    log_success "Added zypper-auto-helper alias to fish config"
fi

# Zsh configuration for zypper-auto-helper
if [ -f "$SUDO_USER_HOME/.zshrc" ]; then
    log_debug "Adding zypper-auto-helper alias to .zshrc"
    # Remove old alias if it exists
    sed -i '/# zypper-auto-helper command alias/d' "$SUDO_USER_HOME/.zshrc"
    sed -i '/alias zypper-auto-helper=/d' "$SUDO_USER_HOME/.zshrc"
    # Add new alias
    echo "" >> "$SUDO_USER_HOME/.zshrc"
    echo "# zypper-auto-helper command alias (added by zypper-auto-helper)" >> "$SUDO_USER_HOME/.zshrc"
    echo "alias zypper-auto-helper='sudo /usr/local/bin/zypper-auto-helper'" >> "$SUDO_USER_HOME/.zshrc"
    chown "$SUDO_USER:$SUDO_USER" "$SUDO_USER_HOME/.zshrc"
    log_success "Added zypper-auto-helper alias to .zshrc"
fi

log_success "zypper-auto-helper command aliases configured for all shells."

# --- 8. Create/Update NOTIFIER (User Service) ---
log_info ">>> Creating (user) notifier service: ${NT_SERVICE_FILE}"
update_status "Creating user notifier service..."
log_debug "Writing user service file: ${NT_SERVICE_FILE}"
cat << EOF > ${NT_SERVICE_FILE}
[Unit]
Description=Notify user of pending Tumbleweed updates
Wants=network-online.target
After=network-online.target nss-lookup.target

[Service]
Type=oneshot
StandardOutput=append:${USER_LOG_DIR}/notifier.log
StandardError=append:${USER_LOG_DIR}/notifier-error.log
ExecStart=/usr/bin/python3 ${NOTIFY_SCRIPT_PATH}
EOF
chown "$SUDO_USER:$SUDO_USER" "${NT_SERVICE_FILE}"
log_success "User notifier service file created"

# --- 9. Create/Update NOTIFIER (User Timer) ---
log_info ">>> Creating (user) notifier timer: ${NT_TIMER_FILE}"
log_debug "Writing user timer file: ${NT_TIMER_FILE}"
cat << EOF > ${NT_TIMER_FILE}
[Unit]
Description=Run ${NT_SERVICE_NAME} every minute to check for updates

[Timer]
# First run a few seconds after the user manager starts,
# then re-run every minute.
OnBootSec=5sec
OnCalendar=minutely
Persistent=true

[Install]
WantedBy=timers.target
EOF
chown "$SUDO_USER:$SUDO_USER" "${NT_TIMER_FILE}"
log_success "User notifier timer file created"

# --- 10. Create/Update Notification Script (v47 Python with logging) ---
log_info ">>> Creating (user) Python notification script: ${NOTIFY_SCRIPT_PATH}"
update_status "Creating Python notifier script..."
log_debug "Writing Python script to: ${NOTIFY_SCRIPT_PATH}"
cat << 'EOF' > ${NOTIFY_SCRIPT_PATH}
#!/usr/bin/env python3
#
# zypper-notify-updater.py (v53 with snooze controls and safety preflight)
#
# This script is run as the USER. It uses PyGObject (gi)
# to create a robust, clickable notification.

import sys
import subprocess
import os
import re
import time
from datetime import datetime, timedelta
from pathlib import Path

DEBUG = os.getenv("ZNH_DEBUG", "").lower() in ("1", "true", "yes", "debug")

# Logging setup
LOG_DIR = Path.home() / ".local" / "share" / "zypper-notify"
LOG_FILE = LOG_DIR / "notifier-detailed.log"
STATUS_FILE = LOG_DIR / "last-run-status.txt"
HISTORY_FILE = LOG_DIR / "update-history.log"
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5MB
MAX_HISTORY_SIZE = 1 * 1024 * 1024  # 1MB

# Cache directory
CACHE_DIR = Path.home() / ".cache" / "zypper-notify"
CACHE_FILE = CACHE_DIR / "last_check.txt"
SNOOZE_FILE = CACHE_DIR / "snooze_until.txt"
CACHE_EXPIRY_MINUTES = 10

# Ensure directories exist
LOG_DIR.mkdir(parents=True, exist_ok=True)
CACHE_DIR.mkdir(parents=True, exist_ok=True)

def rotate_log_if_needed():
    """Rotate log file if it exceeds MAX_LOG_SIZE."""
    try:
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > MAX_LOG_SIZE:
            backup = LOG_FILE.with_suffix(".log.old")
            if backup.exists():
                backup.unlink()
            LOG_FILE.rename(backup)
    except Exception as e:
        print(f"Failed to rotate log: {e}", file=sys.stderr)

def log_to_file(level: str, msg: str) -> None:
    """Write log message to file with timestamp."""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] [{level}] {msg}\n")
    except Exception as e:
        print(f"Failed to write log: {e}", file=sys.stderr)

def log_info(msg: str) -> None:
    """Log info message."""
    log_to_file("INFO", msg)
    print(f"[INFO] {msg}")

def log_error(msg: str) -> None:
    """Log error message."""
    log_to_file("ERROR", msg)
    print(f"[ERROR] {msg}", file=sys.stderr)

def log_debug(msg: str) -> None:
    """Log debug message."""
    if DEBUG:
        log_to_file("DEBUG", msg)
        print(f"[DEBUG] {msg}", file=sys.stderr)

def update_status(status: str) -> None:
    """Update the status file with current state."""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(STATUS_FILE, "w", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {status}\n")
    except Exception as e:
        log_error(f"Failed to update status file: {e}")

# --- Caching Functions ---
def read_cache():
    """Read cached update check results.
    Returns: (timestamp, package_count, snapshot) or None if cache invalid/missing.
    """
    try:
        if not CACHE_FILE.exists():
            return None
        
        with open(CACHE_FILE, 'r') as f:
            line = f.read().strip()
            parts = line.split('|')
            if len(parts) != 3:
                return None
            
            timestamp_str, pkg_count, snapshot = parts
            cache_time = datetime.fromisoformat(timestamp_str)
            
            # Check if cache is still valid
            age_minutes = (datetime.now() - cache_time).total_seconds() / 60
            if age_minutes > CACHE_EXPIRY_MINUTES:
                log_debug(f"Cache expired (age: {age_minutes:.1f} minutes)")
                return None
            
            log_debug(f"Cache hit (age: {age_minutes:.1f} minutes)")
            return cache_time, int(pkg_count), snapshot
    except Exception as e:
        log_debug(f"Failed to read cache: {e}")
        return None

def write_cache(package_count: int, snapshot: str) -> None:
    """Write update check results to cache."""
    try:
        timestamp = datetime.now().isoformat()
        with open(CACHE_FILE, 'w') as f:
            f.write(f"{timestamp}|{package_count}|{snapshot}")
        log_debug(f"Cache written: {package_count} packages, snapshot {snapshot}")
    except Exception as e:
        log_debug(f"Failed to write cache: {e}")

# --- Snooze Functions ---
def check_snoozed() -> bool:
    """Check if updates are currently snoozed.
    Returns True if snoozed, False otherwise.
    """
    try:
        if not SNOOZE_FILE.exists():
            return False
        
        with open(SNOOZE_FILE, 'r') as f:
            snooze_until_str = f.read().strip()
            snooze_until = datetime.fromisoformat(snooze_until_str)
            
            if datetime.now() < snooze_until:
                remaining = snooze_until - datetime.now()
                hours = remaining.total_seconds() / 3600
                log_info(f"Updates snoozed for {hours:.1f} more hours")
                return True
            else:
                # Snooze expired, remove file
                SNOOZE_FILE.unlink()
                log_info("Snooze expired, removing snooze file")
                return False
    except Exception as e:
        log_debug(f"Failed to check snooze: {e}")
        return False

def set_snooze(hours: int) -> None:
    """Set snooze for specified number of hours."""
    try:
        snooze_until = datetime.now() + timedelta(hours=hours)
        with open(SNOOZE_FILE, 'w') as f:
            f.write(snooze_until.isoformat())
        log_info(f"Updates snoozed for {hours} hours until {snooze_until.strftime('%Y-%m-%d %H:%M')}")
    except Exception as e:
        log_error(f"Failed to set snooze: {e}")

# --- History Logging ---
def log_update_history(snapshot: str, package_count: int) -> None:
    """Log update installation to history file."""
    try:
        # Rotate history if needed
        if HISTORY_FILE.exists() and HISTORY_FILE.stat().st_size > MAX_HISTORY_SIZE:
            backup = HISTORY_FILE.with_suffix(".log.old")
            if backup.exists():
                backup.unlink()
            HISTORY_FILE.rename(backup)
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(HISTORY_FILE, 'a') as f:
            f.write(f"[{timestamp}] Installed snapshot {snapshot} with {package_count} packages\n")
        log_info(f"Update history logged: {snapshot}")
    except Exception as e:
        log_error(f"Failed to log update history: {e}")

# --- Safety Checks ---
def check_disk_space() -> tuple[bool, str]:
    """Check if there's enough disk space for updates.
    Returns: (has_space, message)
    """
    try:
        result = subprocess.run(
            ['df', '-BG', '/'],
            capture_output=True,
            text=True,
            check=True
        )
        lines = result.stdout.strip().split('\n')
        if len(lines) < 2:
            return True, "Could not determine disk space"
        
        # Parse df output: Filesystem 1G-blocks Used Available Use% Mounted
        fields = lines[1].split()
        if len(fields) < 4:
            return True, "Could not parse disk space"
        
        available_str = fields[3].rstrip('G')
        available_gb = int(available_str)
        
        if available_gb < 5:
            msg = f"Only {available_gb}GB free. 5GB required for updates."
            log_info(msg)
            return False, msg
        
        log_debug(f"Disk space check passed: {available_gb}GB available")
        return True, f"{available_gb}GB available"
    except Exception as e:
        log_debug(f"Disk space check failed: {e}")
        return True, "Could not check disk space"

def check_snapshots() -> tuple[bool, str]:
    """Check if snapper is installed and whether configs/snapshots exist.

    Returns: (has_snapshots, message)
    - has_snapshots=True  => at least one snapshot exists
    - has_snapshots=False => snapper not installed, not configured, or zero snapshots
    """
    # First, see if snapper is installed and if there is a root config
    try:
        cfg_result = subprocess.run(
            ['snapper', 'list-configs'],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except FileNotFoundError:
        msg = "Snapper not installed"
        log_info(msg)
        return False, msg
    except Exception as e:
        log_debug(f"Snapshot config check failed: {e}")
        return False, "Could not check snapshots"

    has_config = False
    root_config = False
    if cfg_result.returncode == 0 and cfg_result.stdout.strip():
        for line in cfg_result.stdout.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('Config'):
                continue
            parts = [p.strip() for p in line.split('|')]
            if len(parts) < 2:
                continue
            name = parts[1]
            if not name:
                continue
            has_config = True
            if name == 'root':
                root_config = True

    # Now check the actual snapshots
    try:
        result = subprocess.run(
            ['snapper', 'list'],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception as e:
        log_debug(f"Snapshot list check failed: {e}")
        if root_config or has_config:
            msg = "Snapper configured (root) but snapshot list not available"
            log_info(msg)
            return False, msg
        return False, "Could not check snapshots"

    # Combine stdout/stderr for permission checks
    out_all = (result.stdout or "") + "\n" + (result.stderr or "")
    if "No permissions" in out_all:
        # On openSUSE Tumbleweed with Btrfs, this usually means snapshots
        # exist but are only visible to root. Treat this as "snapshots
        # present" but explain the limitation.
        if root_config or has_config:
            msg = "Snapper snapshots exist (root-only; run as root to view)"
        else:
            msg = "Snapper present but requires root to view snapshots"
        log_info(msg)
        return True, msg

    if result.returncode == 0:
        lines = [ln for ln in result.stdout.split('\n') if ln.strip()]

        # snapper list normally has 2 header lines; anything beyond that is a snapshot
        if len(lines) > 2:
            snapshot_count = len(lines) - 2
            log_debug(f"Snapper is working, {snapshot_count} snapshots available")
            return True, f"{snapshot_count} snapshots available"
        if root_config or has_config:
            msg = "Snapper configured (root) but no snapshots yet"
            log_info(msg)
            return False, msg
        msg = "Snapper not configured or no snapshots"
        log_info(msg)
        return False, msg

    # Non-zero return code from snapper list (and no explicit "No permissions")
    if root_config or has_config:
        msg = "Snapper configured (root) but snapshot list failed"
        log_info(msg)
        return False, msg

    msg = "Snapper not configured or no snapshots"
    log_info(msg)
    return False, msg
def check_network_quality() -> tuple[bool, str]:
    """Check network latency to ensure stable connection.
    Returns: (is_good, message)
    """
    try:
        result = subprocess.run(
            ['ping', '-c', '3', '-W', '2', '1.1.1.1'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            msg = "Network unreachable"
            log_info(msg)
            return False, msg
        
        # Parse ping output for average latency
        # Example: rtt min/avg/max/mdev = 10.1/15.2/20.3/5.1 ms
        match = re.search(r'rtt min/avg/max/mdev = [\\d.]+/([\\d.]+)/', result.stdout)
        if match:
            avg_latency = float(match.group(1))
            if avg_latency > 200:
                msg = f"High latency: {avg_latency:.0f}ms"
                log_info(msg)
                return False, msg
            log_debug(f"Network quality good: {avg_latency:.0f}ms latency")
            return True, f"{avg_latency:.0f}ms latency"
        
        log_debug("Network quality check passed (couldn't parse latency)")
        return True, "Network OK"
    except Exception as e:
        log_debug(f"Network quality check failed: {e}")
        return True, "Could not check network"


def is_zypper_locked(stderr_text: str | None = None) -> bool:
    """Best-effort detection of a zypper/libzypp lock.

    Checks both stderr text for the canonical message and the zypp
    lockfile (/run/zypp.pid or /var/run/zypp.pid) to avoid false
    positives.
    """
    try:
        if stderr_text and "System management is locked" in stderr_text:
            return True

        for pid_file in ("/run/zypp.pid", "/var/run/zypp.pid"):
            try:
                with open(pid_file, "r", encoding="utf-8") as f:
                    pid_str = f.read().strip()
                if not pid_str:
                    continue
                pid = int(pid_str)
            except (OSError, ValueError):
                continue

            try:
                out = subprocess.check_output(
                    ["ps", "-p", str(pid), "-o", "comm="],
                    text=True,
                    stderr=subprocess.DEVNULL,
                ).strip().lower()
            except subprocess.CalledProcessError:
                continue

            if out and any(tok in out for tok in ("zypper", "yast")):
                return True
    except Exception as e:
        log_debug(f"Lock detection failed: {e}")

    return False


# Rotate log at startup if needed
rotate_log_if_needed()
log_info("=" * 60)
log_info("Zypper Notify Updater started")
update_status("Starting update check...")

try:
    import gi
    gi.require_version("Notify", "0.7")
    from gi.repository import Notify, GLib
    log_debug("PyGObject imported successfully")
except ImportError as e:
    log_error(f"PyGObject (gi) not found: {e}")
    update_status("FAILED: PyGObject not available")
    sys.exit(1)

def has_battery_via_inxi() -> bool:
    """Use inxi to detect if the system reports a real battery.

    We look for a Battery section in `inxi -Bazy` output.
    """
    try:
        out = subprocess.check_output(
            ["inxi", "-Bazy"], text=True, stderr=subprocess.DEVNULL
        )
        log_debug("inxi battery check executed")
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        log_debug(f"inxi battery check failed: {e}")
        return False

    # Check if output contains both Battery: and ID- (can be on different lines)
    if "Battery:" in out and "ID-" in out:
        log_debug("Battery detected via inxi")
        return True
    log_debug("No battery detected via inxi")
    return False


def detect_form_factor():
    """Detect whether this machine is a laptop or a desktop.

    Prefer inxi's Machine Type if available; fall back to upower/battery heuristics.
    Returns "laptop", "desktop", or "unknown".
    """
    log_debug("Detecting form factor...")
    # 0. If inxi reports a real battery, treat as laptop immediately.
    try:
        if has_battery_via_inxi():
            log_info("Form factor detected: laptop (via inxi battery)")
            return "laptop"
    except Exception as e:
        log_debug(f"has_battery_via_inxi failed in detect_form_factor: {e}")

    # 1. Prefer inxi's Machine Type (very reliable on most systems)
    try:
        out = subprocess.check_output(
            ["inxi", "-Mazy"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        for line in out.splitlines():
            if "Type:" in line:
                # Example: "  Type: Laptop System: HP ..."
                val = line.split("Type:", 1)[1].strip().lower()
                if val.startswith("laptop") or "notebook" in val:
                    log_info(f"Form factor detected: laptop (via inxi Type: {val})")
                    return "laptop"
                if val.startswith("desktop") or "tower" in val or "server" in val:
                    log_info(f"Form factor detected: desktop (via inxi Type: {val})")
                    return "desktop"
    except Exception as e:
        log_debug(f"inxi -Mazy failed in detect_form_factor: {e}")

    # 2. Fall back to the previous upower + battery-based heuristic
    try:
        devices = subprocess.check_output(["upower", "-e"], text=True).strip().splitlines()
    except Exception as e:
        log_debug(f"upower -e failed in detect_form_factor: {e}")
        devices = []

    has_battery = False
    has_line_power = False

    if devices:
        try:
            for dev in devices:
                if not dev:
                    continue
                info = subprocess.check_output(["upower", "-i", dev], text=True, errors="ignore").lower()

                if "line_power" in dev:
                    has_line_power = True

                if "battery" in info:
                    # Heuristic: real laptop batteries usually have power supply yes
                    if "power supply: yes" in info or "power-supply: yes" in info:
                        has_battery = True
        except Exception as e:
            log_debug(f"upower inspection failed in detect_form_factor: {e}")

    # If upower clearly indicates laptop
    if has_battery and has_line_power:
        log_info("Form factor detected: laptop (via upower battery+line_power)")
        return "laptop"

    # If upower sees a battery but no line_power, treat as laptop as well.
    # Some laptops expose only a battery device without a separate line_power
    # entry; in that case, we must *not* classify as desktop or we will
    # incorrectly assume always-on AC power.
    if has_battery and not has_line_power:
        log_info("Form factor detected: laptop (via upower battery only)")
        return "laptop"

    # No battery seen by upower; fall back to inxi battery information
    if not has_battery:
        if has_battery_via_inxi():
            log_info("Form factor detected: laptop (fallback inxi check)")
            return "laptop"
        log_info("Form factor detected: desktop (no battery found)")
        return "desktop"

    # Last resort
    log_info("Form factor detected: unknown")
    return "unknown"


def on_ac_power(form_factor: str) -> bool:
    """Check if the system is on AC power.

    On desktops (no battery), we assume AC is effectively always on.
    """
    log_debug(f"Checking AC power status (form_factor: {form_factor})")
    if form_factor == "desktop":
        log_debug("Desktop detected, assuming AC power always available")
        return True

    try:
        devices = subprocess.check_output(["upower", "-e"], text=True).strip().splitlines()
        line_power_devices = [d for d in devices if "line_power" in d]

        if not line_power_devices:
            # Laptop but no explicit line_power device; be conservative
            log_error("No line_power device found; treating as battery (unsafe)")
            return False

        for dev in line_power_devices:
            info = subprocess.check_output(["upower", "-i", dev], text=True, errors="ignore")
            for line in info.splitlines():
                line = line.strip().lower()
                if line.startswith("online:"):
                    value = line.split(":", 1)[1].strip()
                    if value in ("yes", "true"):
                        log_info("AC power detected: plugged in")
                        return True
                    elif value in ("no", "false"):
                        log_info("AC power detected: on battery")
                        return False

        # Could not parse any 'online' line; be conservative for laptops
        log_error("Could not parse AC status; treating as battery (unsafe)")
        return False

    except Exception as e:
        # On a laptop and we truly cannot determine AC: be safe and treat as battery
        log_error(f"AC power check failed: {e}")
        return False


def is_metered() -> bool:
    """Check if any active connection is metered using nmcli.

    Uses GENERAL.METERED per active connection.
    Treats values like 'yes', 'guess-yes', 'payg' as metered.
    """
    log_debug("Checking if connection is metered...")
    try:
        # List all connections with ACTIVE flag
        output = subprocess.check_output(
            ["nmcli", "-t", "-f", "NAME,UUID,DEVICE,ACTIVE", "connection", "show"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        log_debug(f"nmcli connection list failed for metered check: {e}")
        return False

    active_ids = []
    for line in output.strip().splitlines():
        if not line:
            continue
        parts = line.split(":")
        if len(parts) < 4:
            continue
        name, uuid, device, active = parts[:4]
        if active.strip().lower() == "yes":
            # Prefer UUID (stable), but fall back to name if missing
            ident = uuid.strip() or name.strip()
            if ident:
                active_ids.append(ident)

    if not active_ids:
        return False

    for ident in active_ids:
        m = ""
        try:
            m = subprocess.check_output(
                ["nmcli", "-g", "GENERAL.METERED", "connection", "show", ident],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip().lower()
        except subprocess.CalledProcessError as e:
            # Some nmcli versions don't support -g GENERAL.METERED; fall back
            # to parsing the full "connection show" output.
            log_debug(f"nmcli GENERAL.METERED failed for {ident}: {e}; trying full show")
            try:
                full = subprocess.check_output(
                    ["nmcli", "connection", "show", ident],
                    text=True,
                    stderr=subprocess.DEVNULL,
                )
            except subprocess.CalledProcessError as e2:
                log_debug(f"nmcli full show failed for {ident}: {e2}")
                continue

            for line in full.splitlines():
                line = line.strip()
                if line.lower().startswith("general.metered:"):
                    m = line.split(":", 1)[1].strip().lower()
                    break

        if m in ("yes", "guess-yes", "payg", "guess-payg"):
            log_info(f"Metered connection detected: {ident} is {m}")
            return True

    # All active connections are explicitly unmetered/unknown
    log_debug("No metered connections detected")
    return False


# --- Environment change tracking ---
ENV_STATE_DIR = os.path.expanduser("~/.cache/zypper-notify")
ENV_STATE_FILE = os.path.join(ENV_STATE_DIR, "env_state.txt")
LAST_NOTIFICATION_FILE = os.path.join(ENV_STATE_DIR, "last_notification.txt")


def _read_last_env_state() -> str:
    try:
        with open(ENV_STATE_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def _write_env_state(state: str) -> None:
    try:
        os.makedirs(ENV_STATE_DIR, exist_ok=True)
        with open(ENV_STATE_FILE, "w", encoding="utf-8") as f:
            f.write(state)
    except OSError as e:
        log_debug(f"Failed to write env state: {e}")


def _read_last_notification() -> str:
    """Read the last notification state (title+message)."""
    try:
        with open(LAST_NOTIFICATION_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def _write_last_notification(title: str, message: str) -> None:
    """Write the last notification state."""
    try:
        os.makedirs(ENV_STATE_DIR, exist_ok=True)
        notification_key = f"{title}|{message}"
        with open(LAST_NOTIFICATION_FILE, "w", encoding="utf-8") as f:
            f.write(notification_key)
    except OSError as e:
        log_debug(f"Failed to write last notification: {e}")


def _notify_env_change(prev_state: str, form_factor: str, on_ac: bool, metered: bool, safe: bool) -> None:
    """Track environment changes and notify once per change.

    - When conditions become *unsafe* (battery or metered), show a
      "paused" notification explaining why.
    - When they become *safe* again (AC + unmetered), show a
      "now safe" notification.
    """
    current_state = f"form_factor={form_factor}, on_ac={on_ac}, metered={metered}, safe={safe}"

    if prev_state == current_state:
        log_debug("Environment state unchanged, no notification needed")
        return  # no change

    log_info(f"Environment state changed from [{prev_state}] to [{current_state}]")
    # Always record the new state
    _write_env_state(current_state)

    # Decide a short human‑readable message
    if safe:
        title = "Update conditions now safe"
        if metered:
            # logically shouldn't happen (safe implies not metered), but guard anyway
            body = "Updates may proceed, but connection is marked metered."
        elif form_factor == "laptop" and on_ac:
            body = "Laptop is on AC power and network is unmetered. Updates can be downloaded."
        else:
            body = "Conditions are okay to download updates."
    else:
        title = "Updates paused due to conditions"
        if metered:
            body = "Active connection is metered. Background update downloads are skipped."
        elif form_factor == "laptop" and not on_ac:
            body = "Laptop is running on battery. Background update downloads are skipped."
        else:
            body = "Current conditions are not safe for background update downloads."

    log_info(f"Showing environment change notification: {title}")
    try:
        n = Notify.Notification.new(title, body, "dialog-information")
        n.set_timeout(8000)
        n.show()
    except Exception as e:
        log_error(f"Failed to show environment change notification: {e}")


def is_safe() -> bool:
    """Combined safety check.

    - desktops: don't block on AC; only check metered.
    - laptops: require AC and not metered.

    Returns True if it's safe to run a full refresh, False otherwise.
    """
    log_info("Performing safety check...")
    update_status("Checking environment conditions...")
    
    form_factor = detect_form_factor()

    # Pre-compute AC and metered status for clearer logging
    metered = is_metered()
    if form_factor == "laptop":
        on_ac = on_ac_power(form_factor)
    else:
        on_ac = True  # desktops/unknown are treated as effectively always on AC

    # Decide safety based on current conditions
    safe = (not metered) and (form_factor != "laptop" or on_ac)

    # Log environment and safety
    log_info(f"Environment: form_factor={form_factor}, on_ac={on_ac}, metered={metered}, safe={safe}")

    # Notify user if conditions changed since last run
    prev_state = _read_last_env_state()
    _notify_env_change(prev_state, form_factor, on_ac, metered, safe)

    # Apply safety policy
    if metered:
        log_info("Metered connection detected. Skipping refresh.")
        update_status("SKIPPED: Metered connection detected")
        return False

    if form_factor == "laptop":
        if not on_ac:
            log_info("Running on battery (or AC unknown). Skipping refresh.")
            update_status("SKIPPED: Running on battery")
            return False
        else:
            log_info("Laptop on AC power.")

    # Desktop or unknown: no AC restriction (already checked metered above)
    log_info("Environment is safe for updates")
    return True


def get_updates():
    """Run zypper and return the output.

    Returns:
        - stdout string from "zypper dup --dry-run" when environment is safe
        - "" (empty string) if environment is not safe and we skip zypper
        - None if zypper/PolicyKit fails
    """
    log_info("Starting update check...")
    try:
        safe = is_safe()

        if not safe:
            # Environment not safe (battery or metered). We already showed
            # an environment change notification, so just skip zypper.
            log_info("Environment not safe for background updates; skipping zypper.")
            return ""

        log_info("Safe to refresh. Running full check...")
        update_status("Running zypper refresh...")
        log_debug("Executing: pkexec zypper refresh")
        
        subprocess.run(
            ["pkexec", "zypper", "--non-interactive", "--no-gpg-checks", "refresh"],
            check=True,
            capture_output=True,
        )
        log_info("Zypper refresh completed successfully")

        update_status("Running zypper dup --dry-run...")
        log_debug("Executing: pkexec zypper dup --dry-run")
        
        result = subprocess.run(
            ["pkexec", "zypper", "--non-interactive", "dup", "--dry-run"],
            check=True,
            capture_output=True,
            text=True,
        )
        log_info("Zypper dry-run completed successfully")
        return result.stdout

    except subprocess.CalledProcessError as e:
        """Handle zypper failures more intelligently.

        - Distinguish between a normal zypper lock, PolicyKit errors,
          and solver/interaction errors (e.g. vendor conflicts).
        """
        # Normalise stderr/stdout to strings
        stderr_text = ""
        stdout_text = ""
        if e.stderr:
            stderr_text = e.stderr.decode() if isinstance(e.stderr, bytes) else str(e.stderr)
        if e.stdout:
            stdout_text = e.stdout.decode() if isinstance(e.stdout, bytes) else str(e.stdout)

        # 1) Zypper is locked by another process – this is expected sometimes.
        if is_zypper_locked(stderr_text):
            log_info("Zypper is currently locked by another process (likely the downloader or a manual zypper run). Skipping this check.")
            update_status("SKIPPED: Zypper locked by another process")

            # Show a gentle desktop notification so the user knows why
            # the background check was skipped.
            try:
                lock_note = Notify.Notification.new(
                    "Updates paused while zypper is running",
                    "Background checks will retry automatically in about a minute.",
                    "system-software-update",
                )
                lock_note.set_timeout(5000)
                lock_note.set_hint(
                    "x-canonical-private-synchronous",
                    GLib.Variant("s", "zypper-locked"),
                )
                lock_note.show()
            except Exception as ne:
                log_debug(f"Could not show lock notification: {ne}")

            return ""  # Return empty string to skip notification

        # 2) Check for PolicyKit / authentication style errors.
        lower_stderr = stderr_text.lower()
        polkit_markers = (
            "polkit",
            "authentication is required",
            "authentication failed",
            "not authorized",
            "not authorised",
        )
        if any(marker in lower_stderr for marker in polkit_markers):
            log_error("Policy Block Failure: PolicyKit/PAM refused command")
            update_status("FAILED: PolicyKit/PAM authentication error")
            if stderr_text:
                log_error(f"Policy Error: {stderr_text.strip()}")
            if stdout_text:
                log_debug(f"Command stdout: {stdout_text}")
            return None

        # 3) Otherwise, treat as a normal zypper/solver error that needs manual action.
        log_error("Zypper dry-run failed: manual intervention required")
        if stderr_text:
            log_debug(f"Zypper stderr: {stderr_text.strip()}")

        # Try to extract the first 'Problem:' line to show a useful hint.
        problem_line = ""
        for line in stdout_text.splitlines():
            if line.strip().startswith("Problem:"):
                problem_line = line.strip()
                break

        if problem_line:
            summary = problem_line
        else:
            summary = "Zypper dup --dry-run failed. See logs for detailed information."

        update_status("FAILED: Zypper dry-run requires manual decision")
        err_title = "Updates require manual decision"
        err_message = (
            summary
            + "\n\n"
            + "Open a terminal and run:\n"
            + "  sudo zypper dup\n"
            + "to resolve this interactively. After that, the notifier will resume normally."
        )

        n = Notify.Notification.new(err_title, err_message, "dialog-warning")
        n.set_timeout(30000)  # 30 seconds
        n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "zypper-error"))

        # Add an action button to launch the interactive helper in a terminal
        action_script = os.path.expanduser("~/.local/bin/zypper-run-install")
        n.add_action("install", "Open Helper", on_action, action_script)

        log_info("Manual-intervention notification displayed (with Open Helper action)")

        # Run a short GLib main loop so the user can click the action
        loop = GLib.MainLoop()
        n.connect("closed", lambda *args: loop.quit())
        n.show()
        try:
            loop.run()
        except KeyboardInterrupt:
            log_info("Manual-intervention main loop interrupted")

        return None

def extract_package_preview(output: str, max_packages: int = 5) -> list:
    """Extract a preview of packages being updated.
    Returns list of package names.
    """
    packages = []
    try:
        # Look for lines that show package upgrades
        # Format: package-name | version | arch | repository
        in_upgrade_section = False
        for line in output.splitlines():
            line = line.strip()
            
            if "packages to upgrade" in line.lower():
                in_upgrade_section = True
                continue
            
            # Skip non-package summary lines that can appear in the table,
            # such as the "Package download size" section or "0 B | ... already in cache".
            lower = line.lower()
            if any(tok in lower for tok in ["package download size", "overall package size", "already in cache"]):
                continue
            
            if in_upgrade_section and "|" in line:
                # Parse package line
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 1 and parts[0] and not parts[0].startswith("-"):
                    pkg_name = parts[0]
                    # Skip header lines and size-like pseudo "names" such as "0 B" or "12.3 MiB"
                    if pkg_name not in ["Name", "Status", "#"] and not re.match(r"^[0-9].*", pkg_name):
                        packages.append(pkg_name)
                        if len(packages) >= max_packages:
                            break
            
            # Stop if we hit another section
            if in_upgrade_section and line and not line.startswith("|") and "|" not in line:
                if packages:  # Only break if we found some packages
                    break
    except Exception as e:
        log_debug(f"Failed to extract package preview: {e}")
    
    return packages


def parse_output(output: str, include_preview: bool = True):
    """Parse zypper's output for info.

    Returns: (title, message, snapshot, package_count)
             or (None, None, None, 0).
    """
    log_debug("Parsing zypper output...")
    
    if "Nothing to do." in output:
        log_info("No updates found in zypper output")
        return None, None, None, 0

    # Count Packages
    count_match = re.search(r"(\d+) packages to upgrade", output)
    package_count = int(count_match.group(1)) if count_match else 0
    
    # If no packages found or count is 0, return None
    if package_count == 0:
        log_info("No packages to upgrade (count is 0)")
        return None, None, None, 0

    # Find Snapshot
    snapshot_match = None
    # Preferred: product line such as
    #   openSUSE Tumbleweed  20251227-0 -> 20251228-0
    product_match = re.search(r"openSUSE Tumbleweed\s+\S+\s*->\s*([0-9T\-]+)", output)
    if product_match:
        snapshot_match = product_match
    else:
        # Fallback: older tumbleweed-release pattern
        snapshot_match = re.search(r"tumbleweed-release.*->\s*([\dTb\-]+)", output)
    snapshot = snapshot_match.group(1) if snapshot_match else ""

    log_info(
        f"Found {package_count} packages to upgrade"
        + (f" (snapshot: {snapshot})" if snapshot else "")
    )

    # Build strings
    title = f"Snapshot {snapshot} Ready" if snapshot else "Updates Ready to Install"

    if package_count == 1:
        message = "1 update is pending."
    else:
        message = f"{package_count} updates are pending."
    
    # Add package preview if requested
    if include_preview and package_count > 0:
        preview_packages = extract_package_preview(output, max_packages=3)
        if preview_packages:
            preview_str = ", ".join(preview_packages)
            if len(preview_packages) < package_count:
                preview_str += f", and {package_count - len(preview_packages)} more"
            message += f"\n\nIncluding: {preview_str}"

    return title, message, snapshot, package_count

def on_action(notification, action_id, user_data):
    """Callback to run when an action button is clicked."""
    log_info(f"User clicked action: {action_id}")
    
    if action_id == "install":
        update_status("User initiated update installation")
        action_script = user_data
        try:
            # Prefer to launch via systemd-run so the process is clearly
            # associated with the user session and not tied to this script.
            try:
                log_debug(f"Launching install script via systemd-run: {action_script}")
                subprocess.Popen([
                    "systemd-run",
                    "--user",
                    "--scope",
                    action_script,
                ])
            except FileNotFoundError:
                # Fallback: run the script directly if systemd-run is not available.
                log_debug(f"Launching install script directly: {action_script}")
                subprocess.Popen([action_script])
            log_info("Install script launched successfully")
        except Exception as e:
            log_error(f"Failed to launch action script: {e}")
    
    elif action_id == "snooze-1h":
        set_snooze(1)
        update_status("Updates snoozed for 1 hour")
    
    elif action_id == "snooze-4h":
        set_snooze(4)
        update_status("Updates snoozed for 4 hours")
    
    elif action_id == "snooze-1d":
        set_snooze(24)
        update_status("Updates snoozed for 1 day")
    
    elif action_id == "view-changes":
        log_info("User clicked View Changes button")
        update_status("User viewing update details")
        view_script = os.path.expanduser("~/.local/bin/zypper-view-changes")
        try:
            # Make sure the script is executable
            import stat
            if os.path.exists(view_script):
                os.chmod(view_script, os.stat(view_script).st_mode | stat.S_IEXEC)
                log_debug(f"Launching view changes script via systemd-run: {view_script}")
                try:
                    subprocess.Popen([
                        "systemd-run",
                        "--user",
                        "--scope",
                        view_script,
                    ])
                except FileNotFoundError:
                    log_debug("systemd-run not found, launching directly")
                    subprocess.Popen([view_script], start_new_session=True)
                log_info("View changes script launched successfully")
            else:
                log_error(f"View changes script not found: {view_script}")
        except Exception as e:
            log_error(f"Failed to launch view changes script: {e}")
            import traceback
            log_debug(f"Traceback: {traceback.format_exc()}")
        # Don't close notification or quit loop for view changes
        return
    
    notification.close()
    GLib.MainLoop().quit()

def main():
    try:
        log_debug("Initializing notification system...")
        Notify.init("zypper-updater")
        
        # Check if updates are snoozed FIRST - skip all notifications if snoozed
        if check_snoozed():
            log_info("Updates are currently snoozed, skipping all notifications")
            return
        
        # Check if downloader is actively downloading updates
        download_status_file = "/var/log/zypper-auto/download-status.txt"
        if os.path.exists(download_status_file):
            try:
                # Treat very old statuses as stale so we don't get stuck forever
                try:
                    mtime = os.path.getmtime(download_status_file)
                    age_seconds = time.time() - mtime
                except Exception as e:
                    log_debug(f"Could not stat download status file: {e}")
                    age_seconds = 0

                with open(download_status_file, 'r') as f:
                    status = f.read().strip()

                # If status looks like an in‑progress state but is stale, ignore it
                if status in ("refreshing",) or status.startswith("downloading:"):
                    if age_seconds > 300:  # older than 5 minutes
                        log_info(f"Stale download status '{status}' (age {age_seconds:.0f}s) - ignoring and continuing to full check")
                    else:
                        # Handle stage-based status for fresh operations
                        if status == "refreshing":
                            log_info("Stage: Refreshing repositories")
                            n = Notify.Notification.new(
                                "Checking for updates...",
                                "Refreshing repositories...",
                                "emblem-synchronizing"
                            )
                            n.set_timeout(5000)  # 5 seconds
                            # Set hint to replace previous download status notifications
                            n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "zypper-download-status"))
                            n.show()
                            time.sleep(0.1)
                            return  # Exit, will check again in 5 seconds

                        elif status.startswith("downloading:"):
                            # Extract from "downloading:TOTAL:SIZE:DOWNLOADED:PERCENT" format
                            try:
                                parts = status.split(":")
                                pkg_total = parts[1] if len(parts) > 1 else "?"
                                download_size = parts[2] if len(parts) > 2 else "unknown size"
                                pkg_downloaded = parts[3] if len(parts) > 3 else "0"
                                percent = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0

                                log_info(f"Stage: Downloading {pkg_downloaded} of {pkg_total} packages ({download_size})")

                                # Build progress bar visual
                                if 0 <= percent <= 100:
                                    bar_length = 20
                                    filled = int(bar_length * percent / 100)
                                    bar = "█" * filled + "░" * (bar_length - filled)
                                    progress_text = f"[{bar}] {percent}%"
                                else:
                                    progress_text = "Processing..."

                                # Build message with progress
                                if download_size and download_size != "unknown":
                                    msg = f"Downloading {pkg_downloaded} of {pkg_total} packages\n{progress_text}\n{download_size} total • HIGH priority"
                                else:
                                    msg = f"Downloading {pkg_downloaded} of {pkg_total} packages\n{progress_text}\nHIGH priority"

                                n = Notify.Notification.new(
                                    "Downloading updates...",
                                    msg,
                                    "emblem-downloads"
                                )

                                # Add progress bar hint (0-100) for notification daemons that support it
                                if 0 <= percent <= 100:
                                    n.set_hint("value", GLib.Variant("i", percent))
                                    n.set_category("transfer.progress")  # Category hint for progress notifications
                                else:
                                    # Indeterminate progress (pulsing animation)
                                    n.set_hint("value", GLib.Variant("i", 0))
                                    n.set_category("transfer")
                            except Exception as e:
                                log_debug(f"Error parsing download status: {e}")
                                log_info("Stage: Downloading packages")
                                n = Notify.Notification.new(
                                    "Downloading updates...",
                                    "Background download is in progress at HIGH priority.",
                                    "emblem-downloads"
                                )
                                n.set_hint("value", GLib.Variant("i", 50))

                            # Common settings for the progress notification
                            n.set_timeout(5000)  # 5 seconds
                            # Set hint to replace previous download status notifications
                            n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "zypper-download-status"))
                            n.show()

                            # Keep updating the same notification until the downloader
                            # finishes (status changes away from "downloading:").
                            while True:
                                time.sleep(2)
                                try:
                                    with open(download_status_file, 'r') as f2:
                                        new_status = f2.read().strip()
                                except Exception as e:
                                    log_debug(f"Error reading download status during progress loop: {e}")
                                    break

                                if not new_status.startswith("downloading:"):
                                    # Status changed (likely to complete: or idle) –
                                    # update our local variable so the logic below
                                    # can handle completion.
                                    status = new_status
                                    log_debug(f"Download status changed to '{status}', leaving progress loop")
                                    break

                                try:
                                    parts = new_status.split(":")
                                    pkg_total = parts[1] if len(parts) > 1 else "?"
                                    download_size = parts[2] if len(parts) > 2 else "unknown size"
                                    pkg_downloaded = parts[3] if len(parts) > 3 else "0"
                                    percent = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0

                                    log_info(f"Stage: Downloading {pkg_downloaded} of {pkg_total} packages ({download_size})")

                                    # Rebuild progress bar
                                    if 0 <= percent <= 100:
                                        bar_length = 20
                                        filled = int(bar_length * percent / 100)
                                        bar = "█" * filled + "░" * (bar_length - filled)
                                        progress_text = f"[{bar}] {percent}%"
                                    else:
                                        progress_text = "Processing..."

                                    if download_size and download_size != "unknown":
                                        msg = f"Downloading {pkg_downloaded} of {pkg_total} packages\n{progress_text}\n{download_size} total • HIGH priority"
                                    else:
                                        msg = f"Downloading {pkg_downloaded} of {pkg_total} packages\n{progress_text}\nHIGH priority"

                                    # Update the existing notification in place
                                    n.update("Downloading updates...", msg, "emblem-downloads")

                                    if 0 <= percent <= 100:
                                        n.set_hint("value", GLib.Variant("i", percent))
                                        n.set_category("transfer.progress")
                                    else:
                                        n.set_hint("value", GLib.Variant("i", 0))
                                        n.set_category("transfer")

                                    n.show()
                                except Exception as e:
                                    log_debug(f"Error updating download progress notification: {e}")
                                    # If something goes wrong, just break out and
                                    # let the rest of main() continue.
                                    break

                            # Do not return here – fall through so that a
                            # subsequent 'complete:' status is handled by the
                            # code below.

                # Fresh 'complete:' or 'idle' status fall through to the normal logic below
                if status.startswith("complete:"):
                    # Extract from "complete:DURATION:ACTUAL_DOWNLOADED" format (seconds)
                    try:
                        parts = status.split(":")
                        duration = int(parts[1]) if len(parts) > 1 else 0
                        actual_downloaded = int(parts[2]) if len(parts) > 2 else 0
                        
                        minutes = duration // 60
                        seconds = duration % 60
                        
                        if minutes > 0:
                            time_str = f"{minutes}m {seconds}s"
                        else:
                            time_str = f"{seconds}s"
                        
                        # Build a completion message for both cases:
                        #  - actual_downloaded == 0  => everything was already in cache
                        #  - actual_downloaded > 0   => we just downloaded new packages
                        if actual_downloaded == 0:
                            log_info("All packages were already cached; treating as completed download")
                            changelog_msg = (
                                "All update packages are already present in the local cache.\n\n"
                                "Packages are ready to install."
                            )
                        else:
                            # Packages were actually downloaded, show notification
                            log_info(f"Downloaded {actual_downloaded} packages in {time_str}")
                            
                            # Get changelog preview by running zypper dup --dry-run
                            changelog_msg = f"Downloaded {actual_downloaded} packages in {time_str}.\n\nPackages are ready to install."
                            try:
                                log_debug("Fetching update details for changelog preview...")
                                result = subprocess.run(
                                    ["pkexec", "zypper", "--non-interactive", "dup", "--dry-run"],
                                    capture_output=True,
                                    text=True,
                                    timeout=30
                                )
                                if result.returncode == 0:
                                    # Extract package preview
                                    preview_packages = extract_package_preview(result.stdout, max_packages=5)
                                    if preview_packages:
                                        preview_str = ", ".join(preview_packages)
                                        changelog_msg = (
                                            f"Downloaded {actual_downloaded} packages in {time_str}.\n\n"
                                            f"Including: {preview_str}\n\nReady to install."
                                        )
                                        log_info(f"Added changelog preview: {preview_str}")
                            except Exception as e:
                                log_debug(f"Could not fetch changelog preview: {e}")
                        
                        n = Notify.Notification.new(
                            "✅ Downloads Complete!",
                            changelog_msg,
                            "emblem-default"
                        )
                        n.set_timeout(0)  # 0 = persist until user interaction
                        n.set_urgency(Notify.Urgency.NORMAL)  # Normal urgency
                        n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "zypper-download-complete"))
                        n.show()
                        time.sleep(0.1)  # Wait a bit before continuing
                        # Clear the complete status so it doesn't show again
                        try:
                            with open("/var/log/zypper-auto/download-status.txt", "w") as f:
                                f.write("idle")
                        except Exception:
                            pass
                        # Continue to show install notification below
                    except Exception:
                        log_debug("Could not parse completion time")
                        # Continue to show install notification below
                
                elif status == "idle":
                    log_debug("Status is idle (no updates to download)")
                    # Continue to normal check below

                elif status.startswith("error:solver:"):
                    # Background downloader hit a solver/non-interactive error.
                    # Inform the user that manual intervention is required.
                    try:
                        parts = status.split(":")
                        exit_code = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None
                    except Exception:
                        exit_code = None

                    if exit_code is not None:
                        log_info(f"Background downloader encountered a zypper solver/error exit code {exit_code}")
                        body = (
                            f"Background download of updates hit a zypper solver error (exit code {exit_code}).\n\n"
                            "Some packages may already be cached, but zypper needs your decision to continue.\n\n"
                            "Open a terminal and run:\n"
                            "  sudo zypper dup\n"
                            "to resolve the conflicts. After that, the automatic downloader will resume as normal."
                        )
                    else:
                        log_info("Background downloader reported a solver error (unknown exit code)")
                        body = (
                            "Background download of updates hit a zypper solver error.\n\n"
                            "Some packages may already be cached, but zypper needs your decision to continue.\n\n"
                            "Open a terminal and run:\n"
                            "  sudo zypper dup\n"
                            "to resolve the conflicts. After that, the automatic downloader will resume as normal."
                        )

                    n = Notify.Notification.new(
                        "Background downloader needs your attention",
                        body,
                        "dialog-warning",
                    )
                    n.set_timeout(30000)
                    n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "zypper-download-error"))
                    n.show()

                    # Reset the status to idle so we don't spam the same notification forever.
                    try:
                        with open(download_status_file, "w") as f:
                            f.write("idle")
                    except Exception as e2:
                        log_debug(f"Failed to reset download status after solver error: {e2}")

                    # Do not run another zypper dry-run in this cycle; wait for user action.
                    return
                    
            except Exception as e:
                log_debug(f"Could not read download status: {e}")

        # Run safety checks before proceeding
        has_space, space_msg = check_disk_space()
        has_snapshots, snapshot_msg = check_snapshots()
        net_ok, net_msg = check_network_quality()
        
        # Log safety check results
        log_info(f"Safety checks: disk={space_msg}, snapshots={snapshot_msg}, network={net_msg}")
        
        output = get_updates()

        # If get_updates() failed with a real error (not just zypper lock), show error notification
        if output is None:
            log_error("Update check failed due to PolicyKit/authentication error")
            update_status("FAILED: Update check failed")
            err_title = "Update check failed"
            err_message = (
                "The updater could not authenticate with PolicyKit.\n"
                "This may be a configuration issue.\n\n"
                "Try running 'pkexec zypper dup --dry-run' manually to test."
            )
            n = Notify.Notification.new(err_title, err_message, "dialog-error")
            n.set_timeout(30000)  # 30 seconds
            n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "zypper-error"))
            n.show()
            log_info("Error notification displayed")
            return

        # Empty string means environment was unsafe and zypper was skipped.
        if not output or not output.strip():
            log_info("No zypper run performed (environment not safe). Exiting.")
            return

        title, message, snapshot, package_count = parse_output(output)
        if not title:
            # No updates available: check if we already showed this
            log_info("System is up-to-date.")
            update_status("SUCCESS: System up-to-date")
            
            # Check if we already showed "no updates" notification
            last_notification = _read_last_notification()
            no_updates_key = "No updates found|Your system is already up to date."
            
            if last_notification == no_updates_key:
                log_info("'No updates' notification already shown, skipping duplicate")
                return
            
            # First time or changed - show notification
            log_info("Showing 'no updates found' notification for the first time")
            _write_last_notification("No updates found", "Your system is already up to date.")
            
            n = Notify.Notification.new(
                "No updates found",
                "Your system is already up to date.",
                "dialog-information",
            )
            n.set_timeout(10000)  # 10 seconds
            n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "zypper-no-updates"))
            n.show()
            return
        
        # Write cache for future checks
        write_cache(package_count, snapshot)

        log_info("Updates are pending. Sending 'updates ready' reminder.")
        update_status(f"Updates available: {title}")
        
        # Add safety warnings / info lines to message
        warnings = []
        if not has_space:
            warnings.append(f"⚠️ {space_msg}")
        # Always show Snapper state; use ℹ️ when snapshots exist, ⚠️ when they don't
        if snapshot_msg:
            icon = "ℹ️" if has_snapshots else "⚠️"
            warnings.append(f"{icon} {snapshot_msg}")
        if not net_ok:
            warnings.append(f"⚠️ {net_msg}")
        
        if warnings:
            message += "\n\n" + "\n".join(warnings)

        # Check if this notification is different from the last one
        last_notification = _read_last_notification()
        current_notification = f"{title}|{message}"
        
        if last_notification == current_notification:
            log_debug("Notification unchanged, re-showing to keep it visible")
            # Don't return - we need to keep showing it to keep it persistent
        else:
            log_info(f"Notification changed from [{last_notification}] to [{current_notification}]")
        
        _write_last_notification(title, message)

        # Get the path to the action script
        action_script = os.path.expanduser("~/.local/bin/zypper-run-install")

        # Create the notification with a stable ID so it replaces the previous one
        log_debug(f"Creating notification: {title}")
        n = Notify.Notification.new(title, message, "system-software-update")
        n.set_timeout(0) # 0 = persistent notification (no timeout)
        n.set_urgency(Notify.Urgency.CRITICAL) # Make it more noticeable
        
        # Set a consistent ID so notifications replace each other
        n.set_hint("desktop-entry", GLib.Variant("s", "zypper-updater"))
        n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "zypper-updates"))

        # Add action buttons with shorter labels
        n.add_action("install", "Install Now", on_action, action_script)
        n.add_action("view-changes", "View Changes", on_action, None)
        n.add_action("snooze-1h", "1h", on_action, None)
        n.add_action("snooze-4h", "4h", on_action, None)
        n.add_action("snooze-1d", "1d", on_action, None)

        log_info("Displaying persistent update notification with Install and Snooze buttons")
        n.show()
        
        # Run main loop indefinitely - only exit when user interacts with notification
        # This keeps the notification visible until user takes action
        log_info("Running GLib main loop indefinitely - waiting for user action...")
        loop = GLib.MainLoop()
        n.connect("closed", lambda *args: loop.quit())
        
        try:
            loop.run()
        except KeyboardInterrupt:
            log_info("Main loop interrupted")
        
        log_info("Main loop finished - user interacted with notification or it was dismissed")

    except Exception as e:
        log_error(f"An error occurred in main: {e}")
        update_status(f"FAILED: {str(e)}")
        import traceback
        log_error(f"Traceback: {traceback.format_exc()}")
    finally:
        log_info("Shutting down notification system")
        Notify.uninit()
        log_info("Zypper Notify Updater finished")
        log_info("=" * 60)

if __name__ == "__main__":
    main()
EOF

chown "$SUDO_USER:$SUDO_USER" "${NOTIFY_SCRIPT_PATH}"
chmod +x "${NOTIFY_SCRIPT_PATH}"
log_success "Python notifier script created and made executable"

# --- 11. Create/Update Install Script (user) ---
log_info ">>> Creating (user) install script: ${INSTALL_SCRIPT_PATH}"
update_status "Creating install helper script..."
log_debug "Writing install script to: ${INSTALL_SCRIPT_PATH}"
cat << 'EOF' > "${INSTALL_SCRIPT_PATH}"
#!/usr/bin/env bash
set -euo pipefail

# Enhanced install script with post-update service check
TERMINALS=("konsole" "gnome-terminal" "kitty" "alacritty" "xterm")

# Create a wrapper script that will run in the terminal
RUN_UPDATE() {
    echo ""
    echo "=========================================="
    echo "  Running System Update"
    echo "=========================================="
    echo ""
    
    # Run the update
    if pkexec zypper dup; then
        UPDATE_SUCCESS=true
    else
        UPDATE_SUCCESS=false
    fi
    
    echo ""
    echo "=========================================="
    echo "  Update Complete - Post-Update Check"
    echo "=========================================="
    echo ""

    # Always run Flatpak and Snap updates, even if dup had no updates or failed
    echo "=========================================="
    echo "  Flatpak Updates"
    echo "=========================================="
    echo ""

    if command -v flatpak >/dev/null 2>&1; then
        if pkexec flatpak update -y; then
            echo "✅ Flatpak updates completed."
        else
            echo "⚠️  Flatpak update failed (continuing)."
        fi
    else
        echo "⚠️  Flatpak is not installed - skipping Flatpak updates."
        echo "   To install: sudo zypper install flatpak"
    fi

    echo ""
    echo "=========================================="
    echo "  Snap Updates"
    echo "=========================================="
    echo ""

    if command -v snap >/dev/null 2>&1; then
        if pkexec snap refresh; then
            echo "✅ Snap updates completed."
        else
            echo "⚠️  Snap refresh failed (continuing)."
        fi
    else
        echo "⚠️  Snapd is not installed - skipping Snap updates."
        echo "   To install: sudo zypper install snapd"
        echo "   Then enable: sudo systemctl enable --now snapd"
    fi

    echo ""
    echo "=========================================="
    echo "  Soar (stable) Update & Sync"
    echo "=========================================="
    echo ""

    if command -v soar >/dev/null 2>&1; then
        # First, check if a newer *stable* Soar release exists on GitHub.
        # We compare the local "soar --version" against
        # https://api.github.com/repos/pkgforge/soar/releases/latest (stable only).
        if command -v curl >/dev/null 2>&1; then
            echo "Checking for newer stable Soar release from GitHub..."

            LOCAL_VER_RAW=$(soar --version 2>/dev/null | head -n1)
            LOCAL_VER=$(echo "$LOCAL_VER_RAW" | grep -oE 'v?[0-9]+(\.[0-9]+)*' | head -n1 || true)
            LOCAL_BASE=${LOCAL_VER#v}

            REMOTE_JSON=$(curl -fsSL "https://api.github.com/repos/pkgforge/soar/releases/latest" 2>/dev/null || true)
            REMOTE_VER=$(printf '%s\n' "$REMOTE_JSON" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name" *: *"([^"]+)".*/\1/' || true)
            REMOTE_BASE=${REMOTE_VER#v}

            if [ -n "$LOCAL_BASE" ] && [ -n "$REMOTE_BASE" ]; then
                LATEST=$(printf '%s\n%s\n' "$LOCAL_BASE" "$REMOTE_BASE" | sort -V | tail -n1)
                if [ "$LATEST" = "$REMOTE_BASE" ] && [ "$LOCAL_BASE" != "$REMOTE_BASE" ]; then
                    echo "New stable Soar available ($LOCAL_VER -> $REMOTE_VER), updating..."
                    if curl -fsSL "https://raw.githubusercontent.com/pkgforge/soar/main/install.sh" | sh; then
                        echo "✅ Soar updated to latest stable release."
                    else
                        echo "⚠️  Failed to update Soar from GitHub (continuing with existing version)."
                    fi
                else
                    echo "Soar is already up to date (local: ${LOCAL_VER:-unknown}, latest stable: ${REMOTE_VER:-unknown})."
                fi
            else
                echo "Could not determine Soar versions; running installer to ensure latest stable."
                if curl -fsSL "https://raw.githubusercontent.com/pkgforge/soar/main/install.sh" | sh; then
                    echo "✅ Soar updated to latest stable release."
                else
                    echo "⚠️  Failed to update Soar from GitHub (continuing with existing version)."
                fi
            fi
        else
            echo "⚠️  curl is not installed; skipping automatic Soar update from GitHub."
            echo "    You can update Soar manually from: https://github.com/pkgforge/soar/releases"
        fi

        # Then run the usual metadata sync.
        if soar sync; then
            echo "✅ Soar sync completed."
            # Optionally refresh Soar-managed apps that support "soar update".
            if soar update; then
                echo "✅ Soar update completed."
            else
                echo "⚠️  Soar update failed (continuing)."
            fi
        else
            echo "⚠️  Soar sync failed (continuing)."
        fi
    else
        echo "ℹ️  Soar is not installed."
        if command -v curl >/dev/null 2>&1; then
            echo "    Soar can be installed from the official GitHub installer."
            read -rp "    Do you want to install Soar (stable) from GitHub now? [y/N]: " SOAR_INSTALL_REPLY
            if [[ "$SOAR_INSTALL_REPLY" =~ ^[Yy]$ ]]; then
                echo "Installing Soar from GitHub..."
                if curl -fsSL "https://raw.githubusercontent.com/pkgforge/soar/main/install.sh" | sh; then
                    echo "✅ Soar installed successfully."
                    # Optionally run initial sync if the binary is now available
                    if command -v soar >/dev/null 2>&1; then
                        if soar sync; then
                            echo "✅ Soar sync completed."
                        else
                            echo "⚠️  Soar sync failed after install (continuing)."
                        fi
                    fi
                else
                    echo "⚠️  Failed to install Soar from GitHub. You can install it manually from:"
                    echo "    https://github.com/pkgforge/soar/releases"
                fi
            else
                echo "Skipping Soar installation. You can install it later from:"
                echo "    https://github.com/pkgforge/soar/releases"
            fi
        else
            echo "⚠️  curl is not installed; cannot automatically install Soar."
            echo "    Please install curl or install Soar manually from: https://github.com/pkgforge/soar/releases"
        fi
    fi

    echo ""

    echo "=========================================="
    echo "  Homebrew (brew) Updates (optional)"
    echo "=========================================="
    echo ""

    # Try to detect Homebrew in PATH or the default Linuxbrew prefix
    if command -v brew >/dev/null 2>&1 || [ -x "/home/linuxbrew/.linuxbrew/bin/brew" ]; then
        # Normalise brew command path
        if command -v brew >/dev/null 2>&1; then
            BREW_BIN="brew"
        else
            BREW_BIN="/home/linuxbrew/.linuxbrew/bin/brew"
        fi

        echo "Checking for Homebrew updates from GitHub (brew update)..."
        if ! $BREW_BIN update; then
            echo "⚠️  Homebrew 'brew update' failed (continuing without brew upgrade)."
        else
            # After syncing with GitHub, see if anything needs upgrading
            OUTDATED=$($BREW_BIN outdated --quiet 2>/dev/null || true)
            OUTDATED_COUNT=$(printf '%s\n' "$OUTDATED" | sed '/^$/d' | wc -l | tr -d ' ')

            if [ "${OUTDATED_COUNT:-0}" -eq 0 ]; then
                echo "Homebrew is already up to date (no formulae to upgrade)."
            else
                echo "Homebrew has ${OUTDATED_COUNT} outdated formulae; running 'brew upgrade'..."
                if $BREW_BIN upgrade; then
                    echo "✅ Homebrew upgrade completed (upgraded ${OUTDATED_COUNT} formulae)."
                else
                    echo "⚠️  Homebrew 'brew upgrade' failed (continuing)."
                fi
            fi
        fi
    else
        echo "ℹ️  Homebrew (brew) is not installed - skipping brew update/upgrade."
        echo "    To install via helper: sudo zypper-auto-helper --brew"
    fi

    echo ""
    echo "Checking which services need to be restarted..."
    echo ""
    
    # Run zypper ps -s and capture output (even if dup had errors)
    ZYPPER_PS_OUTPUT=$(pkexec zypper ps -s 2>/dev/null || true)
    echo "$ZYPPER_PS_OUTPUT"
    
    # Check if there are any running processes in the output
    if echo "$ZYPPER_PS_OUTPUT" | grep -q "running processes"; then
        echo ""
        echo "ℹ️  Services listed above are using old library versions."
        echo ""
        echo "What this means:"
        echo "  • These services/processes are still running old code in memory"
        echo "  • They should be restarted to use the updated libraries"
        echo ""
        echo "Options:"
        echo "  1. Restart individual services: systemctl restart <service>"
        echo "  2. Reboot your system (recommended for kernel/system updates)"
        echo ""
    else
        echo "✅ No services require restart. You're all set!"
        echo ""
    fi

    if [ "$UPDATE_SUCCESS" = false ]; then
        echo "⚠️  Zypper dup reported errors (see above), but Flatpak/Snap updates were attempted."
        echo ""
    fi
    
    echo "Press Enter to close this window..."
    read -r
}

# Export the function so it's available in subshells
export -f RUN_UPDATE

# Run the update in a terminal
for term in "${TERMINALS[@]}"; do
    if command -v "$term" >/dev/null 2>&1; then
        case "$term" in
            konsole)
                konsole -e bash -c "RUN_UPDATE"
                exit 0
                ;;
            gnome-terminal)
                gnome-terminal -- bash -c "RUN_UPDATE"
                exit 0
                ;;
            kitty|alacritty|xterm)
                "$term" -e bash -c "RUN_UPDATE"
                exit 0
                ;;
        esac
    fi
done

# Fallback: run directly if no terminal found
RUN_UPDATE
EOF

chown "$SUDO_USER:$SUDO_USER" "${INSTALL_SCRIPT_PATH}"
chmod +x "${INSTALL_SCRIPT_PATH}"
log_success "Install helper script created and made executable"

# --- 11b. Create View Changes Script ---
log_info ">>> Creating (user) view changes script: ${VIEW_CHANGES_SCRIPT_PATH}"
update_status "Creating view changes helper script..."
log_debug "Writing view changes script to: ${VIEW_CHANGES_SCRIPT_PATH}"
cat << 'EOF' > "${VIEW_CHANGES_SCRIPT_PATH}"
#!/usr/bin/env bash

# Script to view detailed package changes
# Logging for debugging
LOG_FILE="$HOME/.local/share/zypper-notify/view-changes.log"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] View changes script started" >> "$LOG_FILE"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] DISPLAY=$DISPLAY" >> "$LOG_FILE"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] USER=$USER" >> "$LOG_FILE"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] PWD=$PWD" >> "$LOG_FILE"

# Ensure a usable GUI environment when launched from systemd --user
# Prefer existing vars; only set safe defaults if missing
if [ -z "${XDG_RUNTIME_DIR:-}" ]; then
    export XDG_RUNTIME_DIR="/run/user/$(id -u)"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] XDG_RUNTIME_DIR was empty, set to $XDG_RUNTIME_DIR" >> "$LOG_FILE"
fi
if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]; then
    export DBUS_SESSION_BUS_ADDRESS="unix:path=${XDG_RUNTIME_DIR}/bus"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] DBUS_SESSION_BUS_ADDRESS was empty, set to $DBUS_SESSION_BUS_ADDRESS" >> "$LOG_FILE"
fi
# On Wayland, WAYLAND_DISPLAY is usually set by the session. If both DISPLAY and WAYLAND_DISPLAY
# are empty, fall back to DISPLAY=:0 which works for X11
if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
    export DISPLAY=:0
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Neither DISPLAY nor WAYLAND_DISPLAY set; defaulted DISPLAY to :0" >> "$LOG_FILE"
fi

# Create a temporary script file for the terminal to execute
TMP_SCRIPT=$(mktemp /tmp/zypper-view-changes.XXXXXX.sh)
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Created temp script: $TMP_SCRIPT" >> "$LOG_FILE"

cat > "$TMP_SCRIPT" << 'INNEREOF'
#!/usr/bin/env bash
echo ""
echo "=========================================="
echo "  Package Update Details"
echo "=========================================="
echo ""
echo "Fetching update information..."
echo ""

# Run zypper with details
if pkexec zypper --non-interactive dup --dry-run --details; then
    echo ""
    echo "=========================================="
    echo ""
    echo "This is a preview of what will be updated."
    echo "Click 'Install Now' in the notification to proceed."
    echo ""
else
    echo "⚠️  Could not fetch update details."
    echo ""
fi

echo "Press Enter to close this window..."
read -r

# Clean up temporary script
rm -f "$0"
INNEREOF

chmod +x "$TMP_SCRIPT"

# Try terminals in order  
if command -v konsole >/dev/null 2>&1; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Launching konsole..." >> "$LOG_FILE"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Command: konsole --noclose -e bash $TMP_SCRIPT" >> "$LOG_FILE"
    nohup konsole --noclose -e bash "$TMP_SCRIPT" >> "$LOG_FILE" 2>&1 &
    KONSOLE_PID=$!
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Konsole PID: $KONSOLE_PID" >> "$LOG_FILE"
    sleep 0.5
    if ps -p $KONSOLE_PID > /dev/null 2>&1; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Konsole is running" >> "$LOG_FILE"
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: Konsole exited immediately!" >> "$LOG_FILE"
    fi
elif command -v gnome-terminal >/dev/null 2>&1; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Launching gnome-terminal..." >> "$LOG_FILE"
    gnome-terminal -- "$TMP_SCRIPT" >> "$LOG_FILE" 2>&1 &
    disown
elif command -v kitty >/dev/null 2>&1; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Launching kitty..." >> "$LOG_FILE"
    kitty -e "$TMP_SCRIPT" >> "$LOG_FILE" 2>&1 &
    disown
elif command -v alacritty >/dev/null 2>&1; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Launching alacritty..." >> "$LOG_FILE"
    alacritty -e "$TMP_SCRIPT" >> "$LOG_FILE" 2>&1 &
    disown
elif command -v xterm >/dev/null 2>&1; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Launching xterm..." >> "$LOG_FILE"
    xterm -e "$TMP_SCRIPT" >> "$LOG_FILE" 2>&1 &
    disown
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] No terminal found, running directly" >> "$LOG_FILE"
    "$TMP_SCRIPT" >> "$LOG_FILE" 2>&1
fi
EOF

chown "$SUDO_USER:$SUDO_USER" "${VIEW_CHANGES_SCRIPT_PATH}"
chmod +x "${VIEW_CHANGES_SCRIPT_PATH}"
log_success "View changes helper script created and made executable"

# --- 11c. Create Soar Install Helper (user) ---
SOAR_INSTALL_HELPER_PATH="$USER_BIN_DIR/zypper-soar-install-helper"
log_info ">>> Creating (user) Soar install helper: ${SOAR_INSTALL_HELPER_PATH}"
update_status "Creating Soar install helper script..."
log_debug "Writing Soar helper script to: ${SOAR_INSTALL_HELPER_PATH}"
cat << 'EOF' > "${SOAR_INSTALL_HELPER_PATH}"
#!/usr/bin/env python3
"""
Small helper that shows a notification with an "Install Soar" button.
When clicked, it opens a terminal and runs the official Soar install
command:

  curl -fsSL "https://raw.githubusercontent.com/pkgforge/soar/main/install.sh" | sh
"""

import os
import subprocess
import sys
import traceback
import shutil
import time

try:
    import gi
    gi.require_version("Notify", "0.7")
    from gi.repository import Notify, GLib
except Exception:
    # If PyGObject is not available for some reason, just exit quietly.
    sys.exit(0)


# Best-effort fixups for environment when launched from systemd --user or
# via sudo -u from the installer, so that terminals can attach to the
# correct user session.
if "XDG_RUNTIME_DIR" not in os.environ or not os.environ["XDG_RUNTIME_DIR"]:
    os.environ["XDG_RUNTIME_DIR"] = f"/run/user/{os.getuid()}"
if "DBUS_SESSION_BUS_ADDRESS" not in os.environ or not os.environ["DBUS_SESSION_BUS_ADDRESS"]:
    os.environ["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={os.environ['XDG_RUNTIME_DIR']}/bus"
if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
    # Fallback for X11-only sessions
    os.environ["DISPLAY"] = ":0"
if not os.environ.get("PATH"):
    # Minimal sane PATH so we can discover common terminals
    os.environ["PATH"] = "/usr/local/bin:/usr/bin:/bin"


LOG_PATH = os.path.expanduser("~/.local/share/zypper-notify/soar-install-helper.log")
loop = None  # type: ignore[assignment]


def _log(message: str) -> None:
    """Best-effort logging to a user log file for debugging."""
    try:
        log_dir = os.path.dirname(LOG_PATH)
        os.makedirs(log_dir, exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
    except Exception:
        # Never let logging failures break the helper
        pass


def _open_terminal_with_soar_install() -> None:
    # Use the main helper CLI so behavior is consistent with running
    #   sudo zypper-auto-helper --soar
    # from a regular terminal.
    cmd = (
        "sudo zypper-auto-helper --soar; "
        "echo; echo 'Press Enter to close this window...'; read -r"
    )
    terminals = ["konsole", "gnome-terminal", "kitty", "alacritty", "xterm"]

    _log("Install action triggered; attempting to open terminal for Soar install")
    _log(f"Environment DISPLAY={os.environ.get('DISPLAY')} WAYLAND_DISPLAY={os.environ.get('WAYLAND_DISPLAY')} DBUS_SESSION_BUS_ADDRESS={os.environ.get('DBUS_SESSION_BUS_ADDRESS')}")
    _log(f"PATH={os.environ.get('PATH')}")

    for term in terminals:
        term_path = shutil.which(term)
        _log(f"Checking terminal '{term}': path={term_path}")
        # Use shutil.which instead of external 'which' so we don't depend on
        # that binary existing in a restricted PATH.
        if term_path is not None:
            try:
                _log(f"Trying to launch terminal '{term}' with command: {cmd}")
                if term == "konsole":
                    subprocess.Popen([term, "-e", "bash", "-lc", cmd])
                elif term == "gnome-terminal":
                    subprocess.Popen([term, "--", "bash", "-lc", cmd])
                else:
                    subprocess.Popen([term, "-e", "bash", "-lc", cmd])
                _log(f"Successfully launched terminal '{term}'")
                return
            except Exception as e:
                _log(f"Failed to launch terminal '{term}': {e}")
                # If launching this terminal fails for any reason, try the next one.
                continue

    # Fallback: run in a plain shell if no terminal was detected or all
    # launches failed. This at least ensures the installer runs, even if it
    # isn't in a separate GUI terminal.
    _log("No GUI terminal found or all launches failed; falling back to 'bash -lc'")
    try:
        subprocess.Popen(["bash", "-lc", cmd])
        _log("Started fallback 'bash -lc' successfully")
    except Exception as e:
        _log(f"Failed to start fallback 'bash -lc': {e}")



def _on_action(notification, action_id, user_data):
    global loop
    _log(f"Notification action received: {action_id}")
    if action_id == "install":
        _open_terminal_with_soar_install()
    try:
        notification.close()
    except Exception as e:
        _log(f"Error while closing notification: {e}")
    if loop is not None:
        try:
            loop.quit()
        except Exception as e:
            _log(f"Error while quitting main loop: {e}")



def main() -> None:
    global loop
    try:
        _log("Soar install helper started")
        _log(f"Initial env DISPLAY={os.environ.get('DISPLAY')} WAYLAND_DISPLAY={os.environ.get('WAYLAND_DISPLAY')} DBUS_SESSION_BUS_ADDRESS={os.environ.get('DBUS_SESSION_BUS_ADDRESS')}")
        _log(f"Initial PATH={os.environ.get('PATH')}")

        Notify.init("zypper-auto-helper")
        body = (
            "Soar (optional CLI helper) is not installed.\n\n"
            "Click 'Install Soar' to open a terminal and run the official "
            "install script, or dismiss this notification to skip."
        )
        n = Notify.Notification.new(
            "Zypper Auto-Helper: Install Soar",
            body,
            "dialog-information",
        )
        n.set_timeout(0)  # persistent until action or close
        n.add_action("install", "Install Soar", _on_action, None)

        loop = GLib.MainLoop()
        n.connect("closed", lambda *args: (_log("Notification closed"), loop.quit()))
        n.show()
        _log("Notification shown; entering GLib main loop")
        try:
            loop.run()
        finally:
            _log("Exiting GLib main loop; calling Notify.uninit()")
            Notify.uninit()
    except Exception:
        tb = traceback.format_exc()
        _log(f"Unhandled exception in helper: {tb}")
        try:
            Notify.uninit()
        except Exception as e:
            _log(f"Error during Notify.uninit after exception: {e}")
if __name__ == "__main__":
    main()
EOF

chown "$SUDO_USER:$SUDO_USER" "${SOAR_INSTALL_HELPER_PATH}"
chmod +x "${SOAR_INSTALL_HELPER_PATH}"
log_success "Soar install helper script created and made executable"

# --- 11d. Install script itself as a command ---
log_info ">>> Installing zypper-auto-helper command..."
update_status "Installing command-line interface..."

COMMAND_PATH="/usr/local/bin/zypper-auto-helper"
INSTALLER_SCRIPT_PATH="$0"

# Get the absolute path of the installer script
if [ ! -f "$INSTALLER_SCRIPT_PATH" ]; then
    INSTALLER_SCRIPT_PATH="$(realpath "$0")"
fi

log_debug "Installer script path: $INSTALLER_SCRIPT_PATH"
log_debug "Command installation path: $COMMAND_PATH"

# Copy the installer script to /usr/local/bin
if cp "$INSTALLER_SCRIPT_PATH" "$COMMAND_PATH" >> "${LOG_FILE}" 2>&1; then
    chmod +x "$COMMAND_PATH" >> "${LOG_FILE}" 2>&1
    log_success "Command installed: zypper-auto-helper"
    log_info "You can now run: zypper-auto-helper --help"
else
    log_error "Warning: Could not install command (non-fatal)"
fi

# --- 12. Final self-check ---
log_info ">>> Final syntax self-check..."
update_status "Running final syntax checks..."
run_self_check

# --- 13. Reload user systemd daemon and ensure notifier timer is active ---
USER_BUS_PATH="unix:path=/run/user/$(id -u "$SUDO_USER")/bus"

log_info ">>> Reloading user systemd daemon and (re)starting ${NT_SERVICE_NAME}.timer..."
update_status "Enabling user services..."
log_debug "User bus path: $USER_BUS_PATH"

if sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user daemon-reload >> "${LOG_FILE}" 2>&1; then
    log_success "User systemd daemon reloaded"
    
    log_debug "Enabling user timer: ${NT_SERVICE_NAME}.timer"
    if sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user enable --now "${NT_SERVICE_NAME}.timer" >> "${LOG_FILE}" 2>&1; then
        log_success "User notifier timer enabled and started"
        # Some systemd versions can leave the timer in an 'elapsed' state
        # with no NEXT trigger after unit changes. Force a restart so it
        # gets a fresh schedule and actually fires again for this user.
        log_debug "Restarting user timer to ensure it is scheduled"
        sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user restart "${NT_SERVICE_NAME}.timer" >> "${LOG_FILE}" 2>&1 || true
    else
        log_error "Failed to enable user timer (non-fatal)"
        log_info "You may need to run manually as the target user:"
        log_info "  systemctl --user enable --now ${NT_SERVICE_NAME}.timer"
    fi
else
    log_error "Warning: Could not talk to user systemd (no session bus?)"
    log_info "You may need to run manually as the target user:"
    log_info "  systemctl --user daemon-reload"
    log_info "  systemctl --user enable --now ${NT_SERVICE_NAME}.timer"
fi


# --- 14. Installation Verification (called during install) ---
if [ "${VERIFICATION_ONLY_MODE:-0}" -ne 1 ]; then
    # Only run verification during installation, not in verify-only mode
    # (verify-only mode calls the function directly and exits)
    run_verification_only
    VERIFICATION_EXIT_CODE=$?
else
    # Should never reach here - verify mode exits earlier
    VERIFICATION_EXIT_CODE=0
fi

# --- 14b. Check for Optional Packages ---
log_info ">>> Checking for optional package managers..."
MISSING_PACKAGES=()

if ! command -v flatpak >/dev/null 2>&1; then
    log_info "Flatpak is not installed (optional)"
    MISSING_PACKAGES+=("flatpak")
fi

if ! command -v snap >/dev/null 2>&1; then
    log_info "Snapd is not installed (optional)"
    MISSING_PACKAGES+=("snapd")
fi

# Optional: Soar CLI helper (used to sync metadata after updates)
# Soar is typically installed per-user (for example under ~/.local/bin or
# ~/pkgforge). Detect it using the user's PATH and common install dirs so
# we don't warn when it is already present.
SOAR_PRESENT=0

# 1) Check via the user's PATH
if sudo -u "$SUDO_USER" command -v soar >/dev/null 2>&1; then
    SOAR_PRESENT=1
# 2) Check common per-user install locations
elif [ -x "$SUDO_USER_HOME/.local/bin/soar" ]; then
    SOAR_PRESENT=1
elif [ -d "$SUDO_USER_HOME/pkgforge" ] && \
     find "$SUDO_USER_HOME/pkgforge" -maxdepth 1 -type f -name 'soar*' -perm -u+x 2>/dev/null | grep -q .; then
    SOAR_PRESENT=1
fi

if [ "$SOAR_PRESENT" -eq 0 ]; then
    log_info "Soar CLI is not installed for user $SUDO_USER (optional)"
    MISSING_PACKAGES+=("soar")
fi

# Notify user about missing packages if any
if [ ${#MISSING_PACKAGES[@]} -gt 0 ]; then
    log_info "Optional package managers missing: ${MISSING_PACKAGES[*]}"
    
    # Create notification for user
    MISSING_MSG="The following optional package managers are not installed:\n\n"
    for pkg in "${MISSING_PACKAGES[@]}"; do
        if [ "$pkg" = "flatpak" ]; then
            MISSING_MSG+="• Flatpak - for Flatpak app updates\n  Install: sudo zypper install flatpak\n\n"
        elif [ "$pkg" = "snapd" ]; then
            MISSING_MSG+="• Snapd - for Snap package updates\n  Install: sudo zypper install snapd\n  Enable: sudo systemctl enable --now snapd\n\n"
        fi
    done
    MISSING_MSG+="These are optional. System updates will work without them."
    
    # Send desktop notification to user
    if command -v notify-send >/dev/null 2>&1; then
        sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" notify-send \
            -u normal \
            -t 15000 \
            -i "dialog-information" \
            "Zypper Auto-Helper: Optional Packages" \
            "${MISSING_MSG}" 2>/dev/null || true
    fi

    # If Soar is missing and the helper exists, also show a richer
    # notification with an "Install Soar" button that opens a terminal
    # running the official install script.
    if printf '%s
' "${MISSING_PACKAGES[@]}" | grep -qx 'soar'; then
        # Propagate DISPLAY from the current environment so the helper
        # can open a terminal on the correct graphical session. Without
        # this, the helper fell back to DISPLAY=:0 which may not match
        # the user's real display.
        if sudo -u "$SUDO_USER" DISPLAY="$DISPLAY" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" \
            "$USER_BIN_DIR/zypper-soar-install-helper" >/dev/null 2>&1 & then
            log_debug "Launched Soar install helper notification for user $SUDO_USER"
        fi
    fi
    
    echo "" | tee -a "${LOG_FILE}"
    echo "============================" | tee -a "${LOG_FILE}"
    echo "⚠️  Optional Packages Missing" | tee -a "${LOG_FILE}"
    echo "============================" | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"
    for pkg in "${MISSING_PACKAGES[@]}"; do
        if [ "$pkg" = "flatpak" ]; then
            echo "Flatpak:" | tee -a "${LOG_FILE}"
            echo "  Purpose: Update Flatpak applications" | tee -a "${LOG_FILE}"
            echo "  Install: sudo zypper install flatpak" | tee -a "${LOG_FILE}"
            echo "" | tee -a "${LOG_FILE}"
        elif [ "$pkg" = "snapd" ]; then
            echo "Snapd:" | tee -a "${LOG_FILE}"
            echo "  Purpose: Update Snap packages" | tee -a "${LOG_FILE}"
            echo "  Install: sudo zypper install snapd" | tee -a "${LOG_FILE}"
            echo "  Enable:  sudo systemctl enable --now snapd" | tee -a "${LOG_FILE}"
            echo "" | tee -a "${LOG_FILE}"
        elif [ "$pkg" = "soar" ]; then
            echo "Soar:" | tee -a "${LOG_FILE}"
            echo "  Purpose: Optional CLI helper for keeping metadata in sync after updates" | tee -a "${LOG_FILE}"
            echo "  Install: curl -fsSL \"https://raw.githubusercontent.com/pkgforge/soar/main/install.sh\" | sh" | tee -a "${LOG_FILE}"
            echo "  Usage after install: soar sync" | tee -a "${LOG_FILE}"
            echo "" | tee -a "${LOG_FILE}"
        fi
    done
    echo "Note: These are optional. System updates will work without them." | tee -a "${LOG_FILE}"
    echo "============================" | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"
fi

# --- 15. Final Summary ---
log_success ">>> Installation completed successfully!"
update_status "SUCCESS: Installation completed"

echo "" | tee -a "${LOG_FILE}"
echo "==============================================" | tee -a "${LOG_FILE}"
echo "Installation Summary:" | tee -a "${LOG_FILE}"
echo "  - Command: zypper-auto-helper (installed to /usr/local/bin)" | tee -a "${LOG_FILE}"
echo "  - System service: ${DL_SERVICE_NAME}.timer (enabled)" | tee -a "${LOG_FILE}"
echo "  - User service: ${NT_SERVICE_NAME}.timer (enabled)" | tee -a "${LOG_FILE}"
echo "  - Install logs: ${LOG_DIR}/install-*.log" | tee -a "${LOG_FILE}"
echo "  - Service logs: ${LOG_DIR}/service-logs/" | tee -a "${LOG_FILE}"
echo "  - User logs: ${USER_LOG_DIR}/" | tee -a "${LOG_FILE}"
echo "  - Status file: ${STATUS_FILE}" | tee -a "${LOG_FILE}"
echo "" | tee -a "${LOG_FILE}"
echo "Quick Commands:" | tee -a "${LOG_FILE}"
echo "  sudo zypper-auto-helper --verify        # Check system health" | tee -a "${LOG_FILE}"
echo "  sudo zypper-auto-helper --help          # Show help" | tee -a "${LOG_FILE}"
echo "  cat ${STATUS_FILE}                      # View current status" | tee -a "${LOG_FILE}"
echo "" | tee -a "${LOG_FILE}"
echo "Service Status:" | tee -a "${LOG_FILE}"
echo "  systemctl status ${DL_SERVICE_NAME}.timer" | tee -a "${LOG_FILE}"
echo "  systemctl --user status ${NT_SERVICE_NAME}.timer" | tee -a "${LOG_FILE}"
echo "" | tee -a "${LOG_FILE}"
echo "View Logs:" | tee -a "${LOG_FILE}"
echo "  journalctl -u ${DL_SERVICE_NAME}.service" | tee -a "${LOG_FILE}"
echo "  journalctl --user -u ${NT_SERVICE_NAME}.service" | tee -a "${LOG_FILE}"
echo "  cat ${LOG_FILE}" | tee -a "${LOG_FILE}"
echo "==============================================" | tee -a "${LOG_FILE}"
echo "Completed: $(date)" | tee -a "${LOG_FILE}"
