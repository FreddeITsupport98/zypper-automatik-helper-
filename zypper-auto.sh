#!/bin/bash
#
# install_autodownload.sh (v9 - Snapshot Version)
#
# This script installs or updates the auto-downloader.
# It is "bulletproof" and:
# 1. Checks for root, dependencies, AC power, and metered connections.
# 2. Downloads updates in the background.
# 3. Notifies you with the *number* of packages and the *new snapshot version*.
# 4. Reminds you until you install them.
#
# MUST be run with sudo or as root.

# --- 1. Strict Mode & Config ---
set -euo pipefail

SERVICE_NAME="zypper-autodownload"
NOTIFY_SCRIPT_PATH="/usr/local/bin/notify-updater"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
TIMER_FILE="/etc/systemd/system/${SERVICE_NAME}.timer"

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

# --- 3. Create/Update .service file ---
if [ -f "$SERVICE_FILE" ]; then
    echo ">>> Service file found. Overwriting..."
else
    echo ">>> Creating systemd service file: ${SERVICE_FILE}"
fi
cat << EOF > ${SERVICE_FILE}
[Unit]
Description=Download Tumbleweed updates in background
# Do not run on battery
ConditionACPower=true
# Do not run on metered connections (e.g., mobile hotspot)
ConditionNotOnMeteredConnection=true
Wants=network-online.target
After=network-online.target nss-lookup.target

[Service]
Type=oneshot
ExecStart=/usr/bin/zypper --non-interactive --no-gpg-checks refresh
ExecStart=/usr/bin/zypper --non-interactive --no-gpg-checks dup --download-only
ExecStartPost=${NOTIFY_SCRIPT_PATH}
EOF

# --- 4. Create/Update .timer file ---
if [ -f "$TIMER_FILE" ]; then
    echo ">>> Timer file found. Overwriting..."
else
    echo ">>> Creating systemd timer file: ${TIMER_FILE}"
fi
cat << EOF > ${TIMER_FILE}
[Unit]
Description=Run ${SERVICE_NAME} hourly to download updates

[Timer]
# Your custom values:
OnBootSec=1min
OnUnitActiveSec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF

# --- 5. Create/Update notification script ---
if [ -f "$NOTIFY_SCRIPT_PATH" ]; then
    echo ">>> Notification script found. Overwriting..."
else
    echo ">>> Creating notification helper script: ${NOTIFY_SCRIPT_PATH}"
fi
cat << 'EOF' > ${NOTIFY_SCRIPT_PATH}
#!/bin/bash
#
# notify-updater (v9 logic - Snapshot Version)
#
# This script notifies the user *only* if updates are pending,
# and includes the package count and new snapshot version.

# --- Strict Mode & Safety Trap ---
set -euo pipefail
# This trap ensures that even if this script fails,
# it will exit with '0' and not cause the main service to fail.
trap 'exit 0' EXIT

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
# We don't need 'zypper refresh' because the main service just did it.
# Capture output and exit code separately to handle errors.
ZYPPER_OUTPUT=""
if ! ZYPPER_OUTPUT=$(zypper --non-interactive list-updates --dup 2>&1); then
    echo "Failed to run 'zypper list-updates' (exit code $?)."
    echo "Repos might be locked or network is down. Skipping notification."
    exit 0 # Exit gracefully, caught by trap
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
    # Look for the 'tumbleweed-release' package in the output
    if SNAPSHOT_LINE=$(echo "$ZYPPER_OUTPUT" | grep 'tumbleweed-release'); then
        # The new version is the 7th field in the table row
        # e.g.: S | ... | tumbleweed-release | package | ... -> 20251110-0 | ...
        SNAPSHOT_VERSION=$(echo "$SNAPSHOT_LINE" | awk '{print $7}')
    fi

    # --- Build Notification ---
    TITLE="Updates Ready to Install"
    
    if [ -n "$SNAPSHOT_VERSION" ]; then
        # If we found a snapshot, use it in the title
        TITLE="Snapshot ${SNAPSHOT_VERSION} Ready"
    fi

    if [ "$PACKAGE_COUNT" -eq 1 ]; then
        MESSAGE="1 update is downloaded. Run 'sudo zypper dup' to install."
    else
        MESSAGE="$PACKAGE_COUNT updates are downloaded. Run 'sudo zypper dup' to install."
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
# 6. Make the helper script executable
chmod +x ${NOTIFY_SCRIPT_PATH}

echo ">>> Reloading systemd daemon..."
# 7. Reload systemd to read the new files
systemctl daemon-reload

echo ">>> (Re)starting the timer..."
# 8. Enable and start the timer
systemctl enable --now ${TIMER_FILE}

echo ""
echo "✅ Success!"
echo "The bulletproof auto-downloader and reminder system is installed/updated."
echo ""
echo "To check the timer status, run:"
echo "systemctl list-timers ${SERVICE_NAME}.timer"