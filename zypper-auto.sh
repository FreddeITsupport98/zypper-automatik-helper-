#!/bin/bash
#
# install_autodownload.sh (v27 - No Button, Final Fix)
#
# This script installs the final, most robust architecture.
# It uses the correct 'systemd --user' model but REMOVES
# the buggy clickable button, which we've proven
# fails on this system.
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
NT_SCRIPT_NAME="zypper-notify-updater"
INSTALL_SCRIPT_NAME="zypper-run-install" # We will clean this up

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
INSTALL_SCRIPT_PATH="$USER_BIN_DIR/${INSTALL_SCRIPT_NAME}" # For cleanup

if ! command -v nmcli &> /dev/null; then
    echo "Error: 'nmcli' command not found. Please install 'NetworkManager'."
    exit 1
fi
if ! command -v upower &> /dev/null; then
    echo "Error: 'upower' command not found. Please install 'upower'."
    exit 1
fi
if ! command -v gdbus &> /dev/null; then
    echo "Error: 'gdbus' command not found. This is a core part of GLib/GIO."
    exit 1
fi
echo "All checks passed. Will install for user: $SUDO_USER"

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

echo ">>> Cleaning up all old user-space services..."
sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$SUDO_USER/bus" systemctl --user disable --now zypper-notify-user.timer &> /dev/null || true
rm -f "$INSTALL_SCRIPT_PATH"
rm -f "$NOTIFY_SCRIPT_PATH"
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
ExecStart=${NOTIFY_SCRIPT_PATH}
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

# --- 9. Create/Update Notification Script (v27 Stable) ---
echo ">>> Creating (user) notification script: ${NOTIFY_SCRIPT_PATH}"
cat << 'EOF' > ${NOTIFY_SCRIPT_PATH}
#!/bin/bash
#
# zypper-notify-updater (v27 logic - Stable, No Button)
#
# This script sends a simple, non-actionable notification
# that is guaranteed to be compatible and to display.

# --- Strict Mode & Safety Trap ---
set -euo pipefail
trap 'exit 0' EXIT # Always exit gracefully

# --- v19.1: Find the graphical D-Bus session ---
export USER_ID=$(id -u)
export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$USER_ID/bus"
echo "Connecting to D-Bus at $DBUS_SESSION_BUS_ADDRESS"

# --- v12: Check connection state (as user) ---
IS_SAFE=true

# Check for AC power (using upower)
if upower -e | grep -q 'line_power'; then
    if ! upower -i $(upower -e | grep 'line_power') | grep -q 'online: *yes'; then
        IS_SAFE=false
        echo "Running on battery. Skipping refresh."
    fi
fi

# Check for metered connection (using nmcli)
if [ "$IS_SAFE" = true ]; then
    if nmcli c show --active | grep -q "metered.*yes"; then
        IS_SAFE=false
        echo "Metered connection detected. Skipping refresh."
    fi
fi

# --- v1Main: Run tiered logic with 'dup --dry-run' ---
ZYPPER_OUTPUT=""
if [ "$IS_SAFE" = true ]; then
    echo "Safe to refresh. Running full check..."
    if ! ZYPPER_OUTPUT=$(sudo zypper --non-interactive --no-gpg-checks refresh 2>&1 && sudo zypper --non-interactive dup --dry-run 2>&1); then
        echo "Failed to run 'sudo zypper' (exit code $?). Skipping."
        exit 0
    fi
else
    echo "Unsafe. Checking local cache only..."
    if ! ZYPPER_OUTPUT=$(sudo zypper --non-interactive dup --dry-run 2>&1); then
        echo "Failed to run 'sudo zypper dup --dry-run' (exit code $?). Skipping."
        exit 0
    fi
fi

# Check if the output contains "Nothing to do."
if echo "$ZYPPER_OUTPUT" | grep -q "Nothing to do."; then
    # "Nothing to do." was found. The system is.
    echo "System is up-to-date. No notification needed."
    exit 0

else
    # "Nothing to do." was NOT found. Updates are pending.

    # --- Count Packages ---
    PACKAGE_COUNT="0"
    if COUNT_LINE=$(echo "$ZYPPER_OUTPUT" | grep 'packages to upgrade'); then
        PACKAGE_COUNT=$(echo "$COUNT_LINE" | awk '{print $1}')
    fi

    # --- Find Snapshot Version ---
    SNAPSHOT_VERSION=""
    if SNAPSHOT_LINE=$(echo "$ZYPPER_OUTPUT" | grep 'tumbleweed-release'); then
        SNAPSHOT_VERSION=$(echo "$SNAPSHOT_LINE" | awk '{print $3}')
    fi

    # --- Build Notification ---
    TITLE="Updates Ready to Install"
    if [ -n "$SNAPSHOT_VERSION" ]; then
        TITLE="Snapshot ${SNAPSHOT_VERSION} Ready"
    fi

    if [ "$PACKAGE_COUNT" -eq 1 ]; then
        MESSAGE="1 update is pending. Run 'sudo zypper dup' to install."
    else
        MESSAGE="$PACKAGE_COUNT updates are pending. Run 'sudo zypper dup' to install."
    fi

    echo "Updates are pending. Sending 'updates ready' reminder."
    # --- v27: Send Simple, Reliable GDBus notification ---
    # We have removed the 'actions' array to prevent the bug.
    gdbus call --session \
        --dest org.freedesktop.Notifications \
        --object-path /org/freedesktop/Notifications \
        --method org.freedesktop.Notifications.Notify \
        "zypper-updater" \
        0 \
        "system-software-update" \
        "$TITLE" \
        "$MESSAGE" \
        "[]" \
        "{}" \
        30000
fi
EOF
chown "$SUDO_USER:$SUDO_USER" "${NOTIFY_SCRIPT_PATH}"
chmod +x ${NOTIFY_SCRIPT_PATH}

# --- 10. Clean up old action script ---
# This file is no longer needed
rm -f "$INSTALL_SCRIPT_PATH"

echo ">>> Reloading systemd daemon (for root)..."
# 11. Reload and enable ROOT services
systemctl daemon-reload
systemctl enable --now ${DL_TIMER_FILE}

echo ""
echo "✅ Success! The (root) downloader is installed."
echo ""
echo "--- ⚠️ FINAL STEP REQUIRED ---"
echo "To finish, you must enable the notifier."
echo "Please run this command as your user (fb):"
echo ""
echo "  systemctl --user daemon-reload && systemctl --user enable --now ${NT_SERVICE_NAME}.timer"
echo ""
