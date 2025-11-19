#!/bin/bash
#
#       VERSION 47 FULL DEBUG LOGGING AND STATUS REPORTING
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

# --- User Service Config ---
NT_SERVICE_NAME="zypper-notify-user"
NT_SCRIPT_NAME="zypper-notify-updater.py"
INSTALL_SCRIPT_NAME="zypper-run-install"

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

# Optional mode: only run self-check and exit
if [[ "${1:-}" == "--self-check" || "${1:-}" == "--check" ]]; then
    log_info "Self-check mode requested"
    run_self_check
    log_success "Self-check mode completed"
    exit 0
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

cat << EOF > ${DL_SERVICE_FILE}
[Unit]
Description=Download Tumbleweed updates in background
ConditionACPower=true
ConditionNotOnMeteredConnection=true
Wants=network-online.target
After=network-online.target nss-lookup.target

[Service]
Type=oneshot
StandardOutput=append:${LOG_DIR}/service-logs/downloader.log
StandardError=append:${LOG_DIR}/service-logs/downloader-error.log
ExecStart=/usr/bin/zypper --non-interactive --no-gpg-checks refresh
ExecStart=/usr/bin/zypper --non-interactive --no-gpg-checks dup --download-only
EOF
log_success "Downloader service file created"

# --- 6. Create/Update DOWNLOADER (Root Timer) ---
log_info ">>> Creating (root) downloader timer: ${DL_TIMER_FILE}"
log_debug "Writing timer file: ${DL_TIMER_FILE}"
cat << EOF > ${DL_TIMER_FILE}
[Unit]
Description=Run ${DL_SERVICE_NAME} hourly to download updates

[Timer]
OnBootSec=1min
OnUnitActiveSec=1h
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
Description=Run ${NT_SERVICE_NAME} aggressively to check for updates

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
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
# zypper-notify-updater.py (v47 with comprehensive logging)
#
# This script is run as the USER. It uses PyGObject (gi)
# to create a robust, clickable notification.

import sys
import subprocess
import os
import re
from datetime import datetime
from pathlib import Path

DEBUG = os.getenv("ZNH_DEBUG", "").lower() in ("1", "true", "yes", "debug")

# Logging setup
LOG_DIR = Path.home() / ".local" / "share" / "zypper-notify"
LOG_FILE = LOG_DIR / "notifier-detailed.log"
STATUS_FILE = LOG_DIR / "last-run-status.txt"
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5MB

# Ensure log directory exists
LOG_DIR.mkdir(parents=True, exist_ok=True)

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

    # Very simple heuristic: a Battery: line with an ID- marker
    for line in out.splitlines():
        if "Battery:" in line and "ID-" in line:
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
        # --- v47 ENHANCEMENT: Log full error and STDOUT/STDERR on failure ---
        log_error("Policy Block Failure: PolicyKit/PAM refused command")
        update_status("FAILED: PolicyKit/PAM authentication error")
        if e.stderr:
            log_error(f"Policy Error: {e.stderr.strip()}")
        if e.stdout:
            log_debug(f"Command stdout: {e.stdout}")
        return None

def parse_output(output):
    """Parse zypper's output for info."""
    log_debug("Parsing zypper output...")
    
    if "Nothing to do." in output:
        log_info("No updates found in zypper output")
        return None, None

    # Count Packages
    count_match = re.search(r"(\d+) packages to upgrade", output)
    package_count = count_match.group(1) if count_match else "0"

    # Find Snapshot
    snapshot_match = re.search(r"tumbleweed-release.*->\s*([\dTb-]+)", output)
    snapshot = snapshot_match.group(1) if snapshot_match else ""

    log_info(f"Found {package_count} packages to upgrade" + (f" (snapshot: {snapshot})" if snapshot else ""))

    # Build strings
    title = f"Snapshot {snapshot} Ready" if snapshot else "Updates Ready to Install"

    if package_count == "1":
        message = "1 update is pending. Click 'Install' to begin."
    else:
        message = f"{package_count} updates are pending. Click 'Install' to begin."

    return title, message

def on_action(notification, action_id, user_data_script):
    """Callback to run when the button is clicked."""
    log_info("User clicked Install button")
    update_status("User initiated update installation")
    try:
        # Prefer to launch via systemd-run so the process is clearly
        # associated with the user session and not tied to this script.
        try:
            log_debug(f"Launching install script via systemd-run: {user_data_script}")
            subprocess.Popen([
                "systemd-run",
                "--user",
                "--scope",
                user_data_script,
            ])
        except FileNotFoundError:
            # Fallback: run the script directly if systemd-run is not available.
            log_debug(f"Launching install script directly: {user_data_script}")
            subprocess.Popen([user_data_script])
        log_info("Install script launched successfully")
    except Exception as e:
        log_error(f"Failed to launch action script: {e}")
    notification.close()
    GLib.MainLoop().quit()

def main():
    try:
        log_debug("Initializing notification system...")
        Notify.init("zypper-updater")

        output = get_updates()

        # If get_updates() failed (e.g. PolicyKit error), show a visible error notification
        if output is None:
            log_error("Update check failed due to PolicyKit/authentication error")
            update_status("FAILED: Update check failed")
            err_title = "Update check failed"
            err_message = (
                "The updater could not run zypper (likely a PolicyKit or authentication issue).\n"
                "Please run 'zypper dup --dry-run' manually in a terminal to see details."
            )
            n = Notify.Notification.new(err_title, err_message, "dialog-error")
            n.set_timeout(30000)  # 30 seconds
            n.show()
            log_info("Error notification displayed")
            return

        # Empty string means environment was unsafe and zypper was skipped.
        if not output or not output.strip():
            log_info("No zypper run performed (environment not safe). Exiting.")
            return

        title, message = parse_output(output)
        if not title:
            # No updates available: show an informational popup instead of staying silent
            log_info("System is up-to-date. Showing 'no updates found' notification.")
            update_status("SUCCESS: System up-to-date")
            n = Notify.Notification.new(
                "No updates found",
                "Your system is already up to date.",
                "dialog-information",
            )
            n.set_timeout(10000)  # 10 seconds
            n.show()
            return

        log_info("Updates are pending. Sending 'updates ready' reminder.")
        update_status(f"Updates available: {title}")

        # Get the path to the action script
        action_script = os.path.expanduser("~/.local/bin/zypper-run-install")

        # Create the notification
        log_debug(f"Creating notification: {title}")
        n = Notify.Notification.new(title, message, "system-software-update")
        n.set_timeout(30000) # 30 seconds

        # Add the button
        n.add_action("default", "Install", on_action, action_script)

        # We need a main loop to keep the script alive for the button
        loop = GLib.MainLoop()
        n.connect("closed", lambda *args: loop.quit())

        log_info("Displaying update notification with Install button")
        n.show()
        loop.run() # Wait for the notification to be closed or clicked

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

# Simple helper script to run the full zypper dup in a terminal (if available).
TERMINALS=("konsole" "gnome-terminal" "kitty" "alacritty" "xterm")

for term in "${TERMINALS[@]}"; do
    if command -v "$term" >/dev/null 2>&1; then
        case "$term" in
            konsole)
                exec konsole -e pkexec zypper dup
                ;;
            gnome-terminal)
                exec gnome-terminal -- pkexec zypper dup
                ;;
            kitty|alacritty|xterm)
                exec "$term" -e pkexec zypper dup
                ;;
        esac
    fi
done

# Fallback: run pkexec directly if no known terminal is found.
exec pkexec zypper dup
EOF

chown "$SUDO_USER:$SUDO_USER" "${INSTALL_SCRIPT_PATH}"
chmod +x "${INSTALL_SCRIPT_PATH}"
log_success "Install helper script created and made executable"

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
    else
        log_error "Failed to enable user timer (non-fatal)"
    fi
else
    log_error "Warning: Could not talk to user systemd (no session bus?)"
    log_info "You may need to run manually:"
    log_info "  systemctl --user daemon-reload"
    log_info "  systemctl --user enable --now ${NT_SERVICE_NAME}.timer"
fi

# --- 14. Final Summary ---
log_success ">>> Installation completed successfully!"
update_status "SUCCESS: Installation completed"

echo "" | tee -a "${LOG_FILE}"
echo "==============================================" | tee -a "${LOG_FILE}"
echo "Installation Summary:" | tee -a "${LOG_FILE}"
echo "  - System service: ${DL_SERVICE_NAME}.timer (enabled)" | tee -a "${LOG_FILE}"
echo "  - User service: ${NT_SERVICE_NAME}.timer (enabled)" | tee -a "${LOG_FILE}"
echo "  - Install logs: ${LOG_DIR}/install-*.log" | tee -a "${LOG_FILE}"
echo "  - Service logs: ${LOG_DIR}/service-logs/" | tee -a "${LOG_FILE}"
echo "  - User logs: ${USER_LOG_DIR}/" | tee -a "${LOG_FILE}"
echo "  - Status file: ${STATUS_FILE}" | tee -a "${LOG_FILE}"
echo "" | tee -a "${LOG_FILE}"
echo "To view the current status:" | tee -a "${LOG_FILE}"
echo "  cat ${STATUS_FILE}" | tee -a "${LOG_FILE}"
echo "" | tee -a "${LOG_FILE}"
echo "To view service status:" | tee -a "${LOG_FILE}"
echo "  systemctl status ${DL_SERVICE_NAME}.timer" | tee -a "${LOG_FILE}"
echo "  systemctl --user status ${NT_SERVICE_NAME}.timer" | tee -a "${LOG_FILE}"
echo "" | tee -a "${LOG_FILE}"
echo "To view logs:" | tee -a "${LOG_FILE}"
echo "  journalctl -u ${DL_SERVICE_NAME}.service" | tee -a "${LOG_FILE}"
echo "  journalctl --user -u ${NT_SERVICE_NAME}.service" | tee -a "${LOG_FILE}"
echo "  cat ${LOG_FILE}" | tee -a "${LOG_FILE}"
echo "==============================================" | tee -a "${LOG_FILE}"
echo "Completed: $(date)" | tee -a "${LOG_FILE}"
