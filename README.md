# Zypper Auto-Downloader for Tumbleweed

![openSUSE Tumbleweed](https://img.shields.io/badge/openSUSE-Tumbleweed-73ba25?style=for-the-badge&logo=opensuse)

A smart, "bulletproof" `systemd` service that automates `zypper dup` downloads for openSUSE Tumbleweed and sends rich desktop notifications when updates are ready to install.

---

## 🎯 The Goal

On a rolling-release distribution like Tumbleweed, updates are frequent and can be large. This script automates the most time-consuming part: the **download**.

It runs `zypper dup --download-only` in the background on a timer. When you are finally ready to update, the packages are already cached on your machine. This turns a potential 10-minute download and update process into a 1-minute installation.

## ✨ Key Features

* **Fully Automated:** Runs on a `systemd` timer (defaults to hourly) and starts automatically at boot.
* **Smart Notifications:** Sends a desktop notification **only** if updates are found. It's silent if your system is already up-to-date.
* **Rich Information:** The notification isn't just "updates ready"—it tells you:
    * The new **Tumbleweed Snapshot version** (e.g., `20251110-0`).
    * The **total number of packages** that were downloaded.
* **Daily Reminder:** If you don't install the updates, it will gently remind you every time it runs and finds pending packages.
* **"Bulletproof" Safety:**
    * **AC Power Check:** The service will **not** run if your laptop is on battery power.
    * **Metered Connection Check:** Will **not** run if you are on a metered network (like a mobile hotspot), saving your data.
    * **Graceful Errors:** The installer and notification scripts handle errors (like `zypper` locks or no network) without failing the service.

---

## 🛠️ How It Works: The Technical Details

The installer script creates three files that work together.

### 1. The Installer: `install_autodownload.sh`

* **Idempotent:** The script is safe to re-run. It checks for existing files and overwrites them, making updates easy.
* **Dependency Check:** It first verifies that `notify-send` (from `libnotify-tools`) is installed before proceeding.
* **Strict Error Handling:** Uses `set -euo pipefail` to exit immediately if any command fails during installation.

### 2. The Service: `/etc/systemd/system/zypper-autodownload.service`

This is the main "worker" unit. It's a `Type=oneshot` service, meaning it runs its commands and then stops.

```ini
[Unit]
Description=Download Tumbleweed updates in background
# --- Safety Conditions ---
ConditionACPower=true
ConditionNotOnMeteredConnection=true
Wants=network-online.target
After=network-online.target nss-lookup.target

[Service]
Type=oneshot
ExecStart=/usr/bin/zypper --non-interactive --no-gpg-checks refresh
ExecStart=/usr/bin/zypper --non-interactive --no-gpg-checks dup --download-only
ExecStartPost=/usr/local/bin/notify-updater

[Unit]
Description=Run zypper-autodownload hourly to download updates

[Timer]
OnBootSec=1min
OnUnitActiveSec=1h
Persistent=true

[Install]
WantedBy=timers.target

Here is a full, technical README for your GitHub repository.

This is written in Markdown. You can copy and paste this entire block of text directly into your README.md file on GitHub, and it will be formatted perfectly.

Markdown

# Zypper Auto-Downloader for Tumbleweed

![openSUSE Tumbleweed](https://img.shields.io/badge/openSUSE-Tumbleweed-73ba25?style=for-the-badge&logo=opensuse)

A smart, "bulletproof" `systemd` service that automates `zypper dup` downloads for openSUSE Tumbleweed and sends rich desktop notifications when updates are ready to install.

---

## 🎯 The Goal

On a rolling-release distribution like Tumbleweed, updates are frequent and can be large. This script automates the most time-consuming part: the **download**.

It runs `zypper dup --download-only` in the background on a timer. When you are finally ready to update, the packages are already cached on your machine. This turns a potential 10-minute download and update process into a 1-minute installation.

## ✨ Key Features

* **Fully Automated:** Runs on a `systemd` timer (defaults to hourly) and starts automatically at boot.
* **Smart Notifications:** Sends a desktop notification **only** if updates are found. It's silent if your system is already up-to-date.
* **Rich Information:** The notification isn't just "updates ready"—it tells you:
    * The new **Tumbleweed Snapshot version** (e.g., `20251110-0`).
    * The **total number of packages** that were downloaded.
* **Daily Reminder:** If you don't install the updates, it will gently remind you every time it runs and finds pending packages.
* **"Bulletproof" Safety:**
    * **AC Power Check:** The service will **not** run if your laptop is on battery power.
    * **Metered Connection Check:** Will **not** run if you are on a metered network (like a mobile hotspot), saving your data.
    * **Graceful Errors:** The installer and notification scripts handle errors (like `zypper` locks or no network) without failing the service.

---

## 🛠️ How It Works: The Technical Details

The installer script creates three files that work together.

### 1. The Installer: `install_autodownload.sh`

* **Idempotent:** The script is safe to re-run. It checks for existing files and overwrites them, making updates easy.
* **Dependency Check:** It first verifies that `notify-send` (from `libnotify-tools`) is installed before proceeding.
* **Strict Error Handling:** Uses `set -euo pipefail` to exit immediately if any command fails during installation.

### 2. The Service: `/etc/systemd/system/zypper-autodownload.service`

This is the main "worker" unit. It's a `Type=oneshot` service, meaning it runs its commands and then stops.

```ini
[Unit]
Description=Download Tumbleweed updates in background
# --- Safety Conditions ---
ConditionACPower=true
ConditionNotOnMeteredConnection=true
Wants=network-online.target
After=network-online.target nss-lookup.target

[Service]
Type=oneshot
ExecStart=/usr/bin/zypper --non-interactive --no-gpg-checks refresh
ExecStart=/usr/bin/zypper --non-interactive --no-gpg-checks dup --download-only
ExecStartPost=/usr/local/bin/notify-updater
ConditionACPower=true: Ensures it only runs when plugged in.

ConditionNotOnMeteredConnection=true: Prevents data usage on hotspots.

ExecStartPost=: The key to the system. After the download successfully completes, it runs the notify-updater script.

3. The Timer: /etc/systemd/system/zypper-autodownload.timer
This is the scheduler. It is the only unit you need to enable. It triggers the .service file based on your schedule.

Ini, TOML

[Unit]
Description=Run zypper-autodownload hourly to download updates

[Timer]
OnBootSec=1min
OnUnitActiveSec=1h
Persistent=true

[Install]
WantedBy=timers.target
OnBootSec=1min: Runs 1 minute after you boot up.

OnUnitActiveSec=1h: Runs every hour (relative to the last run).

Persistent=true: If the computer was off and missed a run, it will run as soon as it boots (after the OnBootSec delay).

4. The Notifier: /usr/local/bin/notify-updater
This is the "brains" of the operation. It's a bash script that:

Finds the User: Uses loginctl to find the active graphical user (e.g., fb) and their D-Bus address to send a notification.

Checks for Updates: Runs zypper --non-interactive list-updates --dup to get the list of pending packages.

Parses the Output:

It checks for "Nothing to do." If found, the script exits silently.

If updates are pending, it parses the zypper output to find the tumbleweed-release package and extracts the new snapshot version.

It counts the total number of package lines to get a package count.

Sends the Notification: Uses sudo -u $USER_NAME ... notify-send to send the rich notification to your desktop.

🚀 Installation
You can install this system by running the installer script.

Download the latest installer script (e.g., install_autodownload.sh).

Make it executable:

Bash

chmod +x install_autodownload.sh
Run it with sudo:

Bash

sudo ./install_autodownload.sh
The script will check for dependencies, create all three files, reload the systemd daemon, and start the timer.

Usage
Wait. The service runs in the background. You don't have to do anything.

Get Notified. You will get a notification only when new updates have been downloaded.


Getty Images
> **Snapshot 20251110-0 Ready**
> 12 updates are downloaded. Run 'sudo zypper dup' to install.
Update. When you're ready, open a terminal and run your update. It will be incredibly fast because the packages are already cached.

Bash

sudo zypper dup
Verifying the Service
Bash

# Check that the timer is enabled and see when it runs next
systemctl list-timers zypper-autodownload.timer

# Check the status of the last service run
systemctl status zypper-autodownload.service

# View the detailed logs from the service (refresh, download, and notification)
journalctl -u zypper-autodownload.service
🔧 Configuration
Changing the Timer
If you want to check daily instead of hourly, simply edit the timer file:

Bash

sudoedit /etc/systemd/system/zypper-autodownload.timer
Change the [Timer] section to run daily at 3 PM, for example:

Ini, TOML

[Timer]
# OnBootSec=1min
# OnUnitActiveSec=1h
OnCalendar=15:00
Persistent=true
After saving, reload systemd and restart the timer:

Bash

sudo systemctl daemon-reload
sudo systemctl restart zypper-autodownload.timer
🗑️ Uninstallation
To remove the service and all its components:

Bash

# 1. Stop and disable the timer
sudo systemctl disable --now zypper-autodownload.timer

# 2. Remove the files
sudo rm /etc/systemd/system/zypper-autodownload.service
sudo rm /etc/systemd/system/zypper-autodownload.timer
sudo rm /usr/local/bin/notify-updater

# 3. Reload the systemd daemon
sudo systemctl daemon-reload
