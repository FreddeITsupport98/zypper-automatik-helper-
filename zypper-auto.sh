#!/bin/bash
#
# install_autodownload.sh (v43 - Final PolicyKit Fix)
#
# This script installs the final architecture and fixes the policy lock.
# It replaces 'sudo' with 'pkexec' in the Python script to ensure
# zypper refresh/dry-run is not instantly blocked by pam_kwallet5.
#
# MUST be run with sudo or as root.

# --- 1. Strict Mode & Config ---
set -euo pipefail

# --- Root/System Service Config ---
DL_SERVICE_NAME="zypper-autodownload"
DL_SERVICE_FILE="/etc/systemd/system/${DL_SERVICE_NAME}.service"
DL_TIMER_FILE="/etc/systemd/system/${DL_SERVICE_NAME}.timer"

# --- User Service Config ---
NT_SERVICE_NAME="zypper-notify-user"
NT_SCRIPT_NAME="zypper-notify-updater.py"
INSTALL_SCRIPT_NAME="zypper-run-install"

# --- 2. Sanity Checks & User Detection ---
echo ">>> Running Sanity Checks..."
if [ "$EUID" -ne 0 ]; then
  echo "Error: This script must be run with sudo or as root."
  exit 1
fi

if [ -z "${SUDO_USER:-}" ]; then
    echo "Error: Could not detect the user. Please run with 'sudo', not as pure root."
    exit 1
fi

SUDO_USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
if [ ! -d "$SUDO_USER_HOME" ]; then
    echo "Error: Could not find home directory for user $SUDO_USER."
    exit 1
fi

# Define user-level paths
USER_CONFIG_DIR="$SUDO_USER_HOME/.config/systemd/user"
USER_BIN_DIR="$SUDO_USER_HOME/.local/bin"
NT_SERVICE_FILE="$USER_CONFIG_DIR/${NT_SERVICE_NAME}.service"
NT_TIMER_FILE="$USER_CONFIG_DIR/${NT_SERVICE_NAME}.timer"
NOTIFY_SCRIPT_PATH="$USER_BIN_DIR/${NT_SCRIPT_NAME}"
INSTALL_SCRIPT_PATH="$USER_BIN_DIR/${INSTALL_SCRIPT_NAME}"

# --- Helper function to check and install ---
check_and_install() {
    local cmd=$1
    local package=$2
    local purpose=$3

    if ! command -v $cmd &> /dev/null; then
        echo "---"
        echo "⚠️  Dependency missing: '$cmd' ($purpose)."
        echo "   This is provided by the package '$package'."
        read -p "   May I install it for you? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "   Installing $package..."
            if ! sudo zypper install -y "$package"; then
                echo "Error: Failed to install $package. Please install it manually and re-run this script."
                exit 1
            fi
        else
            echo "Error: Dependency '$package' is required. Please install it manually and re-run this script."
            exit 1
        fi
    fi
}

# --- 2b. Dependency Checks ---
echo ">>> Checking dependencies..."
check_and_install "nmcli" "NetworkManager" "checking metered connection"
check_and_install "upower" "upower" "checking AC power"
check_and_install "python3" "python3" "running the notifier script"
check_and_install "pkexec" "polkit" "graphical authentication"

# Check Python version (must be 3.7+)
PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if [ "$(echo -e "$PY_VERSION\n3.7" | sort -V | head -n1)" != "3.7" ]; then
    echo "Error: Python 3.7 or newer is required. Found $PY_VERSION."
    exit 1
fi

# Check for PyGobject (the notification library)
if ! python3 -c "import gi" &> /dev/null; then
    echo "---"
    echo "⚠️  Dependency missing: 'python3-gobject' (for notifications)."
    read -p "   May I install it for you? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "   Installing python3-gobject..."
        if ! sudo zypper install -y "python3-gobject"; then
            echo "Error: Failed to install python3-gobject. Please install it manually and re-run this script."
            exit 1
        fi
    else
        echo "Error: Dependency 'python3-gobject' is required. Please install it manually and re-run this script."
        exit 1
    fi
fi
echo "All dependencies passed."

# --- 3. Clean Up ALL Previous Versions (System & User) ---
echo ">>> Cleaning up all old system-wide services..."
systemctl disable --now zypper-autodownload.timer &> /dev/null || true
systemctl stop zypper-autodownload.service &> /dev/null || true
systemctl disable --now zypper-notify.timer &> /dev/null || true
systemctl stop zypper-notify.service &> /dev/null || true
systemctl disable --now zypper-smart-updater.timer &> /dev/null || true
systemctl stop zypper-smart-updater.service &> /dev/null || true
rm -f /usr/local/bin/zypper-run-install*
rm -f /usr/local/bin/notify-updater
rm -f /usr/local/bin/zypper-smart-updater-script
echo "Old system services disabled and files removed."

echo ">>> Cleaning up old user-space services..."
SUDO_USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$SUDO_USER/bus" systemctl --user disable --now zypper-notify-user.timer &> /dev/null || true
rm -f "$SUDO_USER_HOME/.local/bin/zypper-run-install*"
rm -f "$SUDO_USER_HOME/.local/bin/zypper-open-terminal*"
rm -f "$SUDO_USER_HOME/.local/bin/zypper-notify-updater"
rm -f "$SUDO_USER_HOME/.local/bin/zypper-notify-updater.py"
rm -f "$SUDO_USER_HOME/.config/systemd/user/zypper-notify-user."*
echo "Old user services disabled and files removed."

# --- 4. Create/Update DOWNLOADER (Root Service) ---
echo ">>> Creating (root) downloader service: ${DL_SERVICE_FILE}"
cat << EOF > ${DL_SERVICE_FILE}
[Unit]
Description=Download Tumbleweed updates in background
ConditionACPower=true
ConditionNotOnMeteredConnection=true
Wants=network-online.target
After=network-online.target nss-lookup.target

[Service]
Type=oneshot
ExecStart=/usr/bin/zypper --non-interactive --no-gpg-checks refresh
ExecStart=/usr/bin/zypper --non-interactive --no-gpg-checks dup --download-only
EOF

# --- 5. Create/Update DOWNLOADER (Root Timer) ---
echo ">>> Creating (root) downloader timer: ${DL_TIMER_FILE}"
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

# --- 6. Create User Directories ---
echo ">>> Creating user directories (if needed)..."
mkdir -p "$USER_CONFIG_DIR"
chown -R "$SUDO_USER:$SUDO_USER" "$SUDO_USER_HOME/.config"
mkdir -p "$USER_BIN_DIR"
chown -R "$SUDO_USER:$SUDO_USER" "$SUDO_USER_HOME/.local"

# --- 7. Create/Update NOTIFIER (User Service) ---
echo ">>> Creating (user) notifier service: ${NT_SERVICE_FILE}"
cat << EOF > ${NT_SERVICE_FILE}
[Unit]
Description=Notify user of pending Tumbleweed updates
Wants=network-online.target
After=network-online.target nss-lookup.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 ${NOTIFY_SCRIPT_PATH}
ImportEnvironment=DBUS_SESSION_BUS_ADDRESS,DISPLAY
EOF
chown "$SUDO_USER:$SUDO_USER" "${NT_SERVICE_FILE}"

# --- 8. Create/Update NOTIFIER (User Timer) ---
echo ">>> Creating (user) notifier timer: ${NT_TIMER_FILE}"
cat << EOF > ${NT_TIMER_FILE}
[Unit]
Description=Run ${NT_SERVICE_NAME} hourly to check for updates

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
chown "$SUDO_USER:$SUDO_USER" "${NT_TIMER_FILE}"

# --- 9. Create/Update Notification Script (v43 Python) ---
echo ">>> Creating (user) Python notification script: ${NOTIFY_SCRIPT_PATH}"
cat << 'EOF' > ${NOTIFY_SCRIPT_PATH}
#!/usr/bin/env python3
#
# zypper-notify-updater.py (v43 logic)
#
# This script is run as the USER. It uses PyGObject (gi)
# to create a robust, clickable notification.

import sys
import subprocess
import os
import re
try:
    import gi
    gi.require_version("Notify", "0.7")
    from gi.repository import Notify, GLib
except ImportError:
    print("Error: PyGObject (gi) not found. Notification failed.", file=sys.stderr)
    sys.exit(1)

def is_safe():
    """Check for AC power and metered connection."""
    try:
        # Check for AC power
        upower_check = subprocess.run(
            "upower -i $(upower -e | grep 'line_power') | grep -q 'online: *yes'",
            shell=True, check=True
        )
        if upower_check.returncode != 0:
            print("Running on battery. Skipping refresh.")
            return False

        # Check for metered connection
        nmcli_check = subprocess.run(
            "nmcli c show --active | grep -q 'metered.*yes'",
            shell=True
        )
        if nmcli_check.returncode == 0:
            print("Metered connection detected. Skipping refresh.")
            return False

    except Exception as e:
        print(f"Safety check failed: {e}", file=sys.stderr)
        # Fail safe: assume it's not safe
        return False

    return True

def get_updates():
    """Run zypper and return the output."""
    try:
        if is_safe():
            print("Safe to refresh. Running full check...")
            subprocess.run(
                ["pkexec", "zypper", "--non-interactive", "--no-gpg-checks", "refresh"],
                check=True, capture_output=True
            )
        else:
            print("Unsafe. Checking local cache only...")

        result = subprocess.run(
            ["pkexec", "zypper", "--non-interactive", "dup", "--dry-run"],
            check=True, capture_output=True, text=True
        )
        return result.stdout

    except subprocess.CalledProcessError as e:
        # --- v42 ENHANCEMENT: Log full error and STDOUT/STDERR on failure ---
        print(f"Policy Block Failure: PolicyKit/PAM refused command.", file=sys.stderr)
        print(f"Policy Error: {e.stderr.strip()}", file=sys.stderr)
        return None

def parse_output(output):
    """Parse zypper's output for info."""
    if "Nothing to do." in output:
        return None, None

    # Count Packages
    count_match = re.search(r"(\d+) packages to upgrade", output)
    package_count = count_match.group(1) if count_match else "0"

    # Find Snapshot
    snapshot_match = re.search(r"tumbleweed-release.*->\s*([\dTb-]+)", output)
    snapshot = snapshot_match.group(1) if snapshot_match else ""

    # Build strings
    title = f"Snapshot {snapshot} Ready" if snapshot else "Updates Ready to Install"

    if package_count == "1":
        message = "1 update is pending. Click 'Install' to begin."
    else:
        message = f"{package_count} updates are pending. Click 'Install' to begin."

    return title, message

def on_action(notification, action_id, user_data_script):
    """Callback to run when the button is clicked."""
    print("Action clicked. Running install script.")
    try:
        subprocess.Popen([user_data_script])
    except Exception as e:
        print(f"Failed to launch action script: {e}", file=sys.stderr)
    notification.close()
    GLib.MainLoop().quit()

def main():
    try:
        Notify.init("zypper-updater")

        output = get_updates()
        if not output:
            print("No output from zypper. Exiting.")
            sys.exit(0)

        title, message = parse_output(output)
        if not title:
            print("System is up-to-date. No notification needed.")
            sys.exit(0)

        print("Updates are pending. Sending 'updates ready' reminder.")

        # Get the path to the action script
        action_script = os.path.expanduser("~/.local/bin/zypper-run-install")

        # Create the notification
        n = Notify.Notification.new(title, message, "system-software-update")
        n.set_timeout(30000) # 30 seconds

        # Add the button
        n.add_action("default", "Install", on_action, action_script)

        # We need a main loop to keep the script alive for the button
        loop = GLib.MainLoop()
        n.connect("closed", lambda *args: loop.quit())

        n.show()
        loop.run() # Wait for the notification to be closed or clicked

    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)
    finally:
        Notify.uninit()

if __name__ == "__main__":
    main()
