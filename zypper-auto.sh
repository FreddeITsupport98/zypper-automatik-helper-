#!/bin/bash
#
# install_autodownload.sh (v30 - Final, Stable, No Button)
#
# This is the final, stable version. Your logs have proven
# that the clickable button (-A) is not compatible with your
# desktop's session when run from systemd.
# This script removes the broken button for 100% reliability.
#
# MUST be run with sudo or as root.

# --- 1. Strict Mode & Config ---
set -euo pipefail

# --- v30: Single Root Service Config ---
SERVICE_NAME="zypper-smart-updater"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
TIMER_FILE="/etc/systemd/system/${SERVICE_NAME}.timer"

# Our one and only logic script
LOGIC_SCRIPT_PATH="/usr/local/bin/zypper-smart-updater-script"

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

if ! command -v notify-send &> /dev/null; then
    echo "Error: 'notify-send' command not found. Please install 'libnotify-tools'."
    exit 1
fi
if ! command -v nmcli &> /dev/null; then
    echo "Error: 'nmcli' command not found. Please install 'NetworkManager'."
    exit 1
fi
if ! command -v upower &> /dev/null; then
    echo "Error: 'upower' command not found. Please install 'upower'."
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
SUDO_USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$SUDO_USER/bus" systemctl --user disable --now zypper-notify-user.timer &> /dev/null || true
rm -f "$SUDO_USER_HOME/.local/bin/zypper-run-install*"
rm -f "$SUDO_USER_HOME/.local/bin/zypper-notify-updater"
rm -f "$SUDO_USER_HOME/.config/systemd/user/zypper-notify-user."*
echo "Old user services disabled and files removed."

# --- 4. Create/Update Smart Service ---
echo ">>> Creating smart service: ${SERVICE_FILE}"
cat << EOF > ${SERVICE_FILE}
[Unit]
Description=Run Zypper Smart Updater (Download & Notify)
Wants=network-online.target
After=network-online.target nss-lookup.target

[Service]
Type=oneshot
ExecStart=${LOGIC_SCRIPT_PATH}
EOF

# --- 5. Create/Update Timer ---
echo ">>> Creating smart timer: ${TIMER_FILE}"
cat << EOF > ${TIMER_FILE}
[Unit]
Description=Run ${SERVICE_NAME} hourly

[Timer]
OnBootSec=1min
OnUnitActiveSec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF

# --- 6. Create the "Brains" Script (v30 logic) ---
echo ">>> Creating smart updater script: ${LOGIC_SCRIPT_PATH}"
cat << EOF > ${LOGIC_SCRIPT_PATH}
#!/bin/bash
#
# zypper-smart-updater-script (v30 logic)
#
# This script is the stable v23.2. It removes the
# 'pipefail' setting and the '-A' button to ensure
# a notification always appears.

# --- Strict Mode & Safety Trap ---
set -e # Exit on error, but NOT pipefail
trap 'exit 0' EXIT # Always exit gracefully

# --- Check connection state ---
IS_SAFE=true

# Check for AC power (using upower)
if upower -e | grep -q 'line_power'; then
    if ! upower -i \$(upower -e | grep 'line_power') | grep -q 'online: *yes'; then
        IS_SAFE=false
        echo "Running on battery. Skipping download."
    fi
fi

# Check for metered connection (using nmcli)
if [ "\$IS_SAFE" = true ]; then
    if nmcli c show --active | grep -q "metered.*yes"; then
        IS_SAFE=false
        echo "Metered connection detected. Skipping download."
    fi
fi

# --- Run Download Logic ---
if [ "\$IS_SAFE" = true ]; then
    echo "Safe to refresh. Running download..."
    zypper --non-interactive --no-gpg-checks refresh
    zypper --non-interactive --no-gpg-checks dup --download-only
else
    echo "Unsafe. Skipping download step."
fi

# --- Run Notification Logic ---
echo "Checking for pending updates..."
ZYPPER_OUTPUT=""
ZYPPER_OUTPUT=\$(zypper --non-interactive dup --dry-run 2>&1)

# Check if the output contains "Nothing to do."
if echo "\$ZYPPER_OUTPUT" | grep -q "Nothing to do."; then
    echo "System is up-to-date. No notification needed."
    exit 0
else
    # "Nothing to do." was NOT found. Updates are pending.

    # --- Find Active User ---
    USER_NAME=\$(loginctl list-sessions --no-legend | grep 'seat0' | awk '{print \$3}' | head -n 1)
    if [ -z "\$USER_NAME" ]; then
        echo "Could not find a logged-in user on seat0. Cannot notify."
        exit 0 # Exit gracefully
    fi

    USER_ID=\$(id -u "\$USER_NAME")
    DBUS_ADDRESS="unix:path=/run/user/\$USER_ID/bus"
    echo "Found user \$USER_NAME. Sending notification."

    # --- Count Packages ---
    PACKAGE_COUNT="0"
    if COUNT_LINE=\$(echo "\$ZYPPER_OUTPUT" | grep 'packages to upgrade'); then
        PACKAGE_COUNT=\$(echo "\$COUNT_LINE" | awk '{print \$1}')
    fi

    # --- Find Snapshot Version ---
    SNAPSHOT_VERSION=""
    if SNAPSHOT_LINE=\$(echo "\$ZYPPER_OUTPUT" | grep 'tumbleweed-release'); then
        SNAPSHOT_VERSION=\$(echo "\$SNAPSHOT_LINE" | awk '{print \$3}')
    fi

    # --- Build Notification ---
    TITLE="Updates Ready to Install"
    if [ -n "\$SNAPSHOT_VERSION" ]; then
        TITLE="Snapshot \${SNAPSHOT_VERSION} Ready"
    fi

    if [ "\$PACKAGE_COUNT" -eq 1 ]; then
        MESSAGE="1 update is pending. Run 'sudo zypper dup' to install."
    else
        MESSAGE="\$PACKAGE_COUNT updates are pending. Run 'sudo zypper dup' to install."
    fi

    echo "Updates are pending. Sending 'updates ready' reminder."
    # --- v30: Send a SIMPLE, reliable notification ---
    # We have removed the '-A' (action) button
    # which is incompatible with your system.
    sudo -u "\$USER_NAME" DBUS_SESSION_BUS_ADDRESS="\$DBUS_ADDRESS" \
        /usr/bin/notify-send \
        -u normal \
        -i "system-software-update" \
        -t 30000 \
        "\$TITLE" \
        "\$MESSAGE"
fi
EOF

echo ">>> Making script executable..."
# 7. Make the helper script executable
chmod +x ${LOGIC_SCRIPT_PATH}

echo ">>> Reloading systemd daemon..."
# 8. Reload and enable ROOT services
systemctl daemon-reload
systemctl enable --now ${TIMER_FILE}

echo ""
echo "✅ Success!"
echo "The v30 (Stable, No Button) auto-downloader is installed/updated."
echo ""
echo "To check the timer, run:"
echo "systemctl list-timers ${SERVICE_NAME}.timer"
