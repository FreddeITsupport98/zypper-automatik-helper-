# Zypper Auto-Downloader for Tumbleweed

![openSUSE Tumbleweed](https://img.shields.io/badge/openSUSE-Tumbleweed-73ba25?style=for-the-badge&logo=opensuse)

A "bulletproof" `systemd` architecture that automates `zypper dup` downloads, provides persistent, battery-safe notifications, and cleanly upgrades any previous version.

---

## 🎯 The Goal

On a rolling-release distribution like Tumbleweed, updates are frequent and can be large. This script automates the most time-consuming part: the **download**.

It runs `zypper dup --download-only` in the background, but only when it's safe. When you're ready to update, the packages are already cached. This turns a potential 10-minute download and update process into a 1-minute installation.

## ✨ Key Features

* **Decoupled Architecture:** Two separate services: a "safe" downloader and a "smart" notifier.
* **Safe Downloads:** The downloader service will **only** run when you are on **AC Power** and **not** on a **Metered Connection**.
* **Persistent Reminders:** The notifier service runs every hour and will *always* remind you if updates are pending, even on battery.
* **"Bulletproof" Safety (v12 Hybrid Logic):** The notifier is smart.
    * If you're on battery/metered, it **skips `zypper refresh`** (saving power/data) and just checks your local cache for updates.
    * If you're on AC power, it runs a full `zypper refresh` to get the latest info.
* **Rich Notifications:** Notifications are silent if you're up-to-date, but show the **Tumbleweed Snapshot version** and **package count** when updates are ready.
* **Automatic Upgrader:** The installer script is idempotent and will **cleanly stop, disable, and overwrite any previous version** (v1-v11).
* **Dependency Checks:** The installer verifies that `notify-send`, `nmcli`, and `upower` are all present before installing.

---

## 🛠️ How It Works: The v12 Architecture

This is a two-service system to provide both safety and persistence.

### 1. The Installer: `install_autodownload.sh`

* **Cleanup:** Explicitly stops and disables all timers/services from *any* previous version to ensure a clean state.
* **Idempotent:** Safe to re-run. It will simply overwrite the components with the latest version.
* **Dependency Check:** Verifies that `libnotify-tools`, `NetworkManager`, and `upower` are installed.
* **Error Handling:** Uses `set -euo pipefail` to stop immediately if anything goes wrong.

### 2. The Downloader: `zypper-autodownload`

This service's only job is to download packages when it's safe.

* **Service: `/etc/systemd/system/zypper-autodownload.service`**
    * This `Type=oneshot` service runs `zypper refresh` and `zypper dup --download-only`.
    * It will **only** start if `ConditionACPower=true` and `ConditionNotOnMeteredConnection=true` are met.
* **Timer: `/etc/systemd/system/zypper-autodownload.timer`**
    * This timer runs `OnBootSec=1min` and `OnUnitActiveSec=1h`, attempting to trigger the service every hour.

### 3. The Notifier: `zypper-notify`

This service's job is to check for updates and remind you, no matter what.

* **Service: `/etc/systemd/system/zypper-notify.service`**
    * A simple `Type=oneshot` service with **no conditions**. Its only job is to run the main script.
* **Timer: `/etc/systemd/system/zypper-notify.timer`**
    * This timer runs on a 5-minute offset (e.g., `OnBootSec=5min`) to ensure it runs *after* the downloader has had a chance.

### 4. The "Brains": `/usr/local/bin/notify-updater`

This is the "v12 Hybrid" script and the core of the system. It is run by the `zypper-notify.service` every hour.

1.  **Finds User:** Uses `loginctl` to find the active graphical user.
2.  **Checks Safety:** It runs its *own* checks using `upower` (for battery) and `nmcli` (for metered networks).
3.  **Runs Hybrid Logic:**
    * **If "Safe" (AC power, not metered):** It runs `zypper refresh` AND `zypper list-updates` to get the freshest data.
    * **If "Unsafe" (On battery or metered):** It **skips `zypper refresh`** and *only* runs `zypper list-updates` to check the local cache.
4.  **Parses Output:** If it finds "Nothing to do," it exits silently. Otherwise, it counts the packages, finds the `tumbleweed-release` version, and builds the notification.
5.  **Sends Notification:** Sends the rich, informative popup to your desktop.

---

## 📜 Revision History (v1-v12)

This script has evolved significantly:

* **v1-v9:** Started as a single service. We iteratively added features like package counts (v5), idempotency (v6), dependency checks (v7), metered connection checks (v8), and the snapshot version (v9). **These versions are now obsolete.**
* **v10-v11:** Introduced the **decoupled two-service architecture**, separating the downloader from the notifier. This fixed a flaw where you wouldn't get reminders on battery. The installer was also given a cleanup step (v11).
* **v12 (Current):** Perfected the design. The notifier now runs a **"hybrid check"**—it still runs on battery (for reminders), but is smart enough to *skip* `zypper refresh` to save power and data.

---

## 🚀 Installation / Upgrading

The script is idempotent. You can run this on a fresh install *or* on a PC with an older version.

1.  Download the latest `install_autodownload.sh` script.
2.  Make it executable:
    ```bash
    chmod +x install_autodownload.sh
    ```
3.  Run it with `sudo`:
    ```bash
    sudo ./install_autodownload.sh
    ```
The script will handle all cleanup, dependency checks, and installation.

## 🏃 Usage

1.  **Wait.** The services run in the background.
2.  **Get Notified.** You will get a notification *only* when new updates are pending.
    > **Snapshot 20251110-0 Ready**
    > 12 updates are pending. Run 'sudo zypper dup' to install.
3.  **Update.** When you're ready, open a terminal. The packages will (most likely) be pre-downloaded, making the update incredibly fast.
    ```bash
    sudo zypper dup
    ```

### Verifying the Service

```bash
# Check that both timers are enabled and see when they run next
systemctl list-timers zypper-autodownload.timer zypper-notify.timer

# Check the status of the last DOWNLOADER run
systemctl status zypper-autodownload.service

# Check the status of the last NOTIFIER run
systemctl status zypper-notify.service

# View the detailed logs from the smart notification script
journalctl -u zypper-notify.service

🔧 Configuration
Changing the Timers
You can edit the timers to change the schedule (e.g., from hourly to daily).

Bash

# Edit the downloader's schedule:
sudoedit /etc/systemd/system/zypper-autodownload.timer

# Edit the notifier's schedule:
sudoedit /etc/systemd/system/zypper-notify.timer
After saving, reload systemd and restart the timers:

Bash

sudo systemctl daemon-reload
sudo systemctl restart zypper-autodownload.timer
sudo systemctl restart zypper-notify.timer
🗑️ Uninstallation
To completely remove the v12 system:

Bash

# 1. Stop and disable both timers
sudo systemctl disable --now zypper-autodownload.timer
sudo systemctl disable --now zypper-notify.timer

# 2. Remove all systemd files
sudo rm /etc/systemd/system/zypper-autodownload.service
sudo rm /etc/systemd/system/zypper-autodownload.timer
sudo rm /etc/systemd/system/zypper-notify.service
sudo rm /etc/systemd/system/zypper-notify.timer

# 3. Remove the main script
sudo rm /usr/local/bin/notify-updater

# 4. Reload the systemd daemon
sudo systemctl daemon-reload
