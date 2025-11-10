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
