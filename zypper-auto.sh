#!/bin/bash
#
# install_autodownload.sh (v11 - Explicit Cleanup)
#
# This script installs or updates the auto-downloader.
# It now *explicitly cleans up* all previous versions (v1-v10)
# before installing the new decoupled v11 architecture.
#
# MUST be run with sudo or as root.

# --- 1. Strict Mode & Config ---
set -euo pipefail

# Config for v11's two-service architecture
DL_SERVICE_NAME="zypper-autodownload"
DL_SERVICE_FILE="/etc/systemd/system/${DL_SERVICE_NAME}.service"
DL_TIMER_FILE="/etc/systemd/system/${DL_SERVICE_NAME}.timer"

NT_SERVICE_NAME="zypper-notify"
NT_SERVICE_FILE="/etc/systemd/system/${NT_SERVICE_NAME}.service"
NT_TIMER_FILE="/etc/systemd/system/${NT_SERVICE_NAME}.timer"
NOTIFY_SCRIPT_PATH="/usr/local/bin/notify-updater"

# --- 2. Sanity Checks ---
echo ">>> Running Sanity Checks..."
if [ "$EUID" -ne 0 ]; then
  echo "Error: This script must be run with sudo or as root."
  exit 1
fi

if ! command -v notify-send &> /dev/null; then
    echo "Error: 'notify-send' command not found."
    echo "This is required for notifications."
    echo "Please install 'libnotify-tools' first, e.g.:"
    echo "sudo zypper install libnotify-tools"
    exit 1
fi
echo "All checks passed."

# --- 3. NEW: Clean Up ALL Previous Versions ---
echo ">>> Stopping and disabling any old (v1-v10) services..."
# This stops and disables the timer from v1-v9 (the all-in-one)
systemctl disable --now zypper-autodownload.timer &> /dev/null || true
# This stops and disables the new timer (in case of re-run)
systemctl disable --now zypper-notify.timer &> /dev/null || true

# Just in case, stop the services themselves
systemctl stop zypper-autodownload.service &> /dev/null || true
systemctl stop zypper-notify.service &> /dev/null || true

# Note: We don't delete the files here, as we will overwrite them.
#       This step is just to clean up systemd's state.
echo "Old services disabled."

# --- 4. Create/Update DOWNLOADER Service ---
echo ">>> Creating downloader service file: ${DL_SERVICE_FILE}"
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

# --- 5. Create/Update DOWNLOADER Timer ---
echo ">>> Creating downloader timer file: ${DL_TIMER_FILE}"
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

# --- 6. Create/Update NOTIFIER Service ---
echo ">>> Creating notifier service file: ${NT_SERVICE_FILE}"
cat << EOF > ${NT_SERVICE_FILE}
[Unit]
Description=Notify user of pending Tumbleweed updates
Wants=network-online.target
After=network-online.target nss-lookup.target

[Service]
Type=oneshot
ExecStart=${NOTIFY_SCRIPT_PATH}
EOF

# --- 7. Create/Update NOTIFIER Timer ---
echo ">>> Creating notifier timer file: ${NT_TIMER_FILE}"
cat << EOF > ${NT_TIMER_FILE}
[Unit]
Description=Run ${NT_SERVICE_NAME} hourly to check for updates

[Timer]
# Runs at a 5-minute offset from the downloader
OnBootSec=5min
OnUnitActiveSec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF

# --- 8. Create/Update Notification Script ---
echo ">>> Creating notification helper script: ${NOTIFY_SCRIPT_PATH}"
cat << 'EOF' > ${NOTIFY_SCRIPT_PATH}
#!/bin/bash
#
# notify-updater (v11 logic)
#
# This script is run by its *own timer* (zypper-notify.service).
# It just checks for pending updates and notifies. It does not download.

# --- Strict Mode & Safety Trap ---
set -euo pipefail
trap 'exit 0' EXIT # Always exit gracefully

# --- Find the active user ---
USER_NAME=$(loginctl list-sessions --no-legend | grep 'seat0' | awk '{print $3}' | head -n 1)
if [ -z "$USER_NAME" ]; then
    echo "Could not find a logged-in user on seat0. Cannot notify."
    exit 0 # Exit gracefully
fi

USER_ID=$(id -u "$USER_NAME")
if [ -z "$USER_ID" ]; then
    echo "Could not find UID for $USER_NAME. Cannot notify."
    exit 0 # Exit gracefully
fi

DBUS_ADDRESS="unix:path=/run/user/$USER_ID/bus"

# --- Check if updates are pending and count them ---
# We MUST refresh here, as we can't be sure the downloader ran.
ZYPPER_OUTPUT=""
if ! ZYPPER_OUTPUT=$(zypper --non-interactive --no-gpg-checks refresh 2>&1 && zypper --non-interactive list-updates --dup 2>&1); then
    echo "Failed to run zypper (exit code $?)."
    echo "Repos might be locked or network is down. Skipping notification."
    exit 0 # Exit gracefully
fi

# Check if the output contains "Nothing to do."
if echo "$ZYPPER_OUTPUT" | grep -q "Nothing to do."; then
    # "Nothing to do." was found. The system is up-to-date.
    echo "System is up-to-date. No notification needed."
    exit 0

else
    # "Nothing to do." was NOT found. Updates are pending.

    # --- Count Packages ---
    PACKAGE_COUNT=$(echo "$ZYPPER_OUTPUT" | grep ' | ' | grep -v 'Repository' | grep -v 'S |' | wc -l)

    # --- Find Snapshot Version ---
    SNAPSHOT_VERSION=""
    if SNAPSHOT_LINE=$(echo "$ZYPPER_OUTPUT" | grep 'tumbleweed-release'); then
        SNAPSHOT_VERSION=$(echo "$SNAPSHOT_LINE" | awk '{print $7}')
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
    sudo -u "$USER_NAME" DBUS_SESSION_BUS_ADDRESS="$DBUS_ADDRESS" \
        /usr/bin/notify-send \
        -u normal \
        -i "system-software-update" \
        "$TITLE" \
        "$MESSAGE"
fi
EOF

echo ">>> Making notification script executable..."
# 9. Make the helper script executable
chmod +x ${NOTIFY_SCRIPT_PATH}

echo ">>> Reloading systemd daemon..."
# 10. Reload systemd to read the new files
systemctl daemon-reload

echo ">>> Enabling and starting new timers..."
# 11. Enable and start both timers
systemctl enable --now ${DL_TIMER_FILE}
systemctl enable --now ${NT_TIMER_FILE}

echo ""
echo "✅ Success!"
echo "The decoupled auto-downloader and reminder system is installed/updated."
echo ""
echo "To check the timers, run:"
echo "systemctl list-timers ${DL_SERVICE_NAME}.timer ${NT_SERVICE_NAME}.timer"
