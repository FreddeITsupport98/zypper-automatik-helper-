#!/bin/bash
#
# install_autodownload.sh (v25 - Action Script Syntax Fix)
#
# This script fixes the final bug: a 'then' was missing
# in the 'zypper-run-install-v24' script, causing it
# to crash when the button was clicked.
#
# MUST be run with sudo or as root.

# --- 1. Strict Mode & Config ---
set -euo pipefail

# --- v25: Single Root Service Config ---
SERVICE_NAME="zypper-smart-updater"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
TIMER_FILE="/etc/systemd/system/${SERVICE_NAME}.timer"

# Our two scripts
LOGIC_SCRIPT_PATH="/usr/local/bin/zypper-smart-updater-script"
INSTALL_SCRIPT_PATH="/usr/local/bin/zypper-run-install-v25" # New cache-buster name

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

# --- 6. Create the "Brains" Script (v25 logic) ---
echo ">>> Creating smart updater script: ${LOGIC_SCRIPT_PATH}"
cat << EOF > ${LOGIC_SCRIPT_PATH}
#!/bin/bash
#
# zypper-smart-updater-script (v25 logic)
#
# This script points to the new v25 action script
# which has the 'then' syntax error fixed.

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
        MESSAGE="1 update is pending. Click 'Install updates' to begin."
    else
        MESSAGE="\$PACKAGE_COUNT updates are pending. Click 'Install updates' to begin."
    fi

    echo "Updates are pending. Sending 'updates ready' reminder."
    # --- v25: Send Actionable Notification ---
    sudo -u "\$USER_NAME" DBUS_SESSION_BUS_ADDRESS="\$DBUS_ADDRESS" \
        /usr/bin/notify-send \
        -u normal \
        -i "system-software-update" \
        -t 30000 \
        -A "Install updates=/usr/local/bin/zypper-run-install-v25" \
        "\$TITLE" \
        "\$MESSAGE"
fi
EOF

# --- 7. Create the Action Script (v25 - 'then' fix) ---
echo ">>> Creating action script: ${INSTALL_SCRIPT_PATH}"
cat << 'EOF' > ${INSTALL_SCRIPT_PATH}
#!/bin/bash
#
# This script is launched by the notification system when the
# "Install updates" button is clicked. It runs AS THE USER.

# Find the user's D-Bus address for graphical applications
export USER_ID=$(id -u)
export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$USER_ID/bus"

# The command to run
RUN_CMD="sudo zypper dup"

# Try to find the best terminal, in order
if command -v konsole &> /dev/null; then
    konsole -e "$RUN_CMD"
elif command -v gnome-terminal &> /dev/null; then
    gnome-terminal -- $SHELL -c "$RUN_CMD"
elif command -v xfce4-terminal &> /dev/null; then
    xfce4-terminal -e "$RUN_CMD"
elif command -v mate-terminal &> /dev/null; then
    mate-terminal -e "$RUN_CMD"
elif command -v xterm &> /dev/null; then
    # --- v25 FIX: Added the missing 'then' ---
    xterm -e "$RUN_CMD"
else
    # Fallback if no known terminal is found
    gdbus call --session \
        --dest org.freedesktop.Notifications \
        --object-path /org/freedesktop/Notifications \
        --method org.freedesktop.Notifications.Notify \
        "zypper-updater" \
        0 \
        "dialog-error" \
        "Could not find terminal" \
        "Please run 'sudo zypper dup' manually." \
        "[]" \
        "{}" \
        5000
fi
EOF

echo ">>> Making scripts executable..."
# 8. Make the helper scripts executable
chmod +x ${LOGIC_SCRIPT_PATH}
chmod +x ${INSTALL_SCRIPT_PATH}

echo ">>> Reloading systemd daemon..."
# 9. Reload and enable ROOT services
systemctl daemon-reload
systemctl enable --now ${TIMER_FILE}

echo ""
echo "✅ Success!"
echo "The v25 (Syntax Fix) auto-downloader is installed/updated."
echo ""
echo "To check the timer, run:"
echo "systemctl list-timers ${SERVICE_NAME}.timer"
