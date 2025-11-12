#!/bin/bash
#
# install_autodownload.sh (v12.2 - nmcli Fix)
#
# This script installs or updates the auto-downloader.
# Fixes a compatibility issue with different nmcli versions
# by using 'connection.metered' instead of 'GENERAL.METERED'.
#
# MUST be run with sudo or as root.

# --- 1. Strict Mode & Config ---
set -euo pipefail

# Config for the two-service architecture
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
echo "All checks passed."

# --- 3. Clean Up ALL Previous Versions ---
echo ">>> Cleaning up any old/previous versions..."

systemctl disable --now zypper-autodownload.timer &> /dev/null || true
systemctl stop zypper-autodownload.service &> /dev/null || true
systemctl disable --now zypper-notify.timer &> /dev/null || true
systemctl stop zypper-notify.service &> /dev/null || true

echo "Old services disabled. Ready to install."

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

# --- 8. Create/Update Notification Script (v12.2 nmcli Fix) ---
echo ">>> Creating notification helper script: ${NOTIFY_SCRIPT_PATH}"
cat << 'EOF' > ${NOTIFY_SCRIPT_PATH}
#!/bin/bash
#
# notify-updater (v12.2 logic - Hybrid Check + nmcli Fix)
#
# This script is run by its *own timer* (zypper-notify.service).
# It checks connection state to decide *how* to check for updates.
