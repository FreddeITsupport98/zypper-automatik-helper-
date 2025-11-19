# Zypper Auto-Downloader for Tumbleweed

![openSUSE Tumbleweed](https://img.shields.io/badge/openSUSE-Tumbleweed-73ba25?style=for-the-badge&logo=opensuse)

A robust `systemd` architecture that automates `zypper dup` downloads, provides persistent, battery-safe **user notifications**, and cleanly upgrades any previous version.

-----

## 🐞 Reporting Issues?

**If you need help, please include the relevant logs!** See the [Reporting Issues on GitHub](#reporting-issues-on-github) section for which logs to include.

-----

## 🎯 The Goal

On a rolling-release distribution like Tumbleweed, updates are frequent and can be large. This script automates the most time-consuming part: the **download**.

It runs `zypper dup --download-only` in the background, but only when it's safe. When you're ready to update, the packages are already cached. This turns a potential 10-minute download and update process into a 1-minute, authenticated installation.

## ✨ Key Features (v47 Architecture)

* **Decoupled Architecture:** Two separate services: a "safe" root-level downloader and a "smart" **user-level** notifier.
* **User-Space Notifier:** Runs as a user service (`~/.config/systemd/user`) so it can reliably talk to your desktop session (D-Bus) and show clickable notifications.
* **Safe Downloads (Root):** The downloader service only runs when `ConditionACPower=true` and `ConditionNotOnMeteredConnection=true` are satisfied.
* **Smart Safety Logic (User):** The notifier Python script uses `upower`, `inxi` and `nmcli` with extra heuristics to distinguish real laptops from desktops/UPS setups (including laptops that only expose a battery device without a separate `line_power` entry), and to avoid false "metered" or "on battery" positives.
* **Comprehensive Logging (NEW in v47):** Full debug logging for installation, system services, and user notifier with automatic log rotation and persistent status tracking.
* **Persistent Reminders:** The user notifier service runs on a configurable schedule (default: *aggressive* every minute) and will remind you whenever updates are pending.
* **Hybrid Refresh Logic:**
    * If it's unsafe (on battery or metered), it **skips `zypper refresh`** and only checks the existing cache via `zypper dup --dry-run`.
    * If it's safe, it runs a full `zypper refresh` first, then `zypper dup --dry-run`.
* **Clickable Install:** The rich, Python-based notification is **clickable**. Clicking the "Install" button runs `~/.local/bin/zypper-run-install`, which opens a terminal and executes `pkexec zypper dup`.
* **Automatic Upgrader:** The installer is idempotent and will **cleanly stop, disable, and overwrite any previous version** (v1–v46) to ensure a clean migration.
* **Dependency Checks:** The installer verifies all necessary dependencies (`nmcli`, `upower`, `inxi`, `python3-gobject`, `pkexec`) are present and offers to install them if they are missing.

-----

## 🛠️ How It Works: The v47 Architecture

This is a two-service system to provide both safety (Downloader) and persistence/user interaction (Notifier).

### 1. The Installer: `zypper-auto.sh`

* **Cleanup:** Explicitly stops and disables all timers/services from *any* previous version to ensure a clean state.
* **User Detection:** Reliably determines the `$SUDO_USER`'s home directory to place the user-specific systemd files and scripts (`~/.config/systemd/user`, `~/.local/bin`).
* **Enables Root Timer:** After writing the units, it runs `systemctl daemon-reload` and `systemctl enable --now zypper-autodownload.timer` automatically.

### 2. The Downloader (Root Service)

This service's only job is to download packages when it's safe.

* **Service:** `/etc/systemd/system/zypper-autodownload.service`
    * This service runs `zypper refresh` and `zypper dup --download-only`.
    * It will **only** start if `ConditionACPower=true` and `ConditionNotOnMeteredConnection=true` are met.
* **Timer:** `/etc/systemd/system/zypper-autodownload.timer`
    * Default: `OnBootSec=1min`, `OnUnitActiveSec=1h` (downloads once per hour when it’s safe).
    * You can edit this with `sudoedit /etc/systemd/system/zypper-autodownload.timer` and reload via `sudo systemctl daemon-reload && sudo systemctl restart zypper-autodownload.timer`.

### 3. The Notifier (User Service)

This service's job is to check for updates and remind you, running as your standard user.

* **Service:** `~/.config/systemd/user/zypper-notify-user.service`
    * Runs the Python script `~/.local/bin/zypper-notify-updater.py`.
    * Because it runs in user-space, it has the correct D-Bus environment variables to display notifications reliably.
* **Timer:** `~/.config/systemd/user/zypper-notify-user.timer`
    * Default (aggressive): `OnBootSec=1min`, `OnUnitActiveSec=1min` (checks for updates roughly once per minute).
    * You can tone this down (for example, to `OnUnitActiveSec=1h`) using:
      ```bash
      systemctl --user edit --full zypper-notify-user.timer
      systemctl --user daemon-reload
      systemctl --user restart zypper-notify-user.timer
      ```

### 4. The "Brains": `~/.local/bin/zypper-notify-updater.py`

This Python script is the core of the system, run by the `zypper-notify-user.service` on the schedule defined by the user timer.

1.  **Checks Safety:** Uses `inxi`, `upower` and `nmcli` with extra heuristics to:
    * distinguish laptops (real internal battery + AC adapter) from desktops/UPS/embedded setups,
    * reliably classify any system with a real battery as a laptop, even when `upower` does not expose a `line_power` device,
    * treat desktops as always on AC for safety decisions,
    * treat NetworkManager failures as "unmetered" to avoid random false positives.
2.  **Runs Zypper:** Executes `pkexec zypper refresh` (if safe) and always runs `pkexec zypper dup --dry-run` to check for pending updates. On laptops, "safe" explicitly means **on AC and not on a metered connection**.
3.  **Parses Output:** Counts packages and finds the latest Tumbleweed snapshot version.
4.  **Sends Clickable Notification:** Uses PyGObject to send a rich notification with the snapshot version and an **"Install"** button.
5.  **Launches Terminal (Action):** Clicking "Install" runs the `~/.local/bin/zypper-run-install` script via `systemd-run --user --scope`, which launches your preferred terminal (`konsole`, `gnome-terminal`, etc.) to execute `pkexec zypper dup` interactively.
6.  **Debug Mode:** If `ZNH_DEBUG=1` (or `true/yes/debug`) is set in the environment, extra debug logs (e.g. `upower` / `nmcli` / `inxi` decisions) are printed to the journal.

-----

## 🚀 Installation / Upgrading

The script is idempotent. You can run this on a fresh install *or* on a PC with an older version.

1.  Download the latest `zypper-auto.sh` script.
2.  Make it executable:
    ```bash
    chmod +x zypper-auto.sh
    ```
3.  Run it with `sudo`. The script will handle all cleanup, dependency checks, and the installation of the root service.
    ```bash
    sudo ./zypper-auto.sh
    ```
4.  **Crucial Final Step:** The installer cannot enable user-level services. You must run this command **as your regular user** (do not use `sudo`) to enable the notifier timer:
    ```bash
    systemctl --user daemon-reload && systemctl --user enable --now zypper-notify-user.timer
    ```

You're done! The root downloader is enabled, and the user notifier is ready.

-----

## 🏃 Usage

1.  **Wait.** The services run in the background. By default, the downloader runs hourly (configurable) and the notifier checks for updates every minute (also configurable via its systemd timer).
2.  **Get Notified.** You will get a notification *only* when new updates are pending.
    > **Snapshot 20251110-0 Ready**
    > 12 updates are pending. Click 'Install' to begin.
3.  **Install.** Click the **"Install"** button in the notification. This will open a terminal and prompt you for authentication to run `zypper dup`.

### Quick Status Check

You can check the current status at any time without running commands:

```bash
# Check installation/system status
cat /var/log/zypper-auto/last-status.txt

# Check notifier status
cat ~/.local/share/zypper-notify/last-run-status.txt
```

### Debugging

If you want more verbose logging from the notifier script (for example, to see detailed `upower`/`nmcli` decisions), enable debug mode:

```bash
export ZNH_DEBUG=1
systemctl --user restart zypper-notify-user.service
journalctl --user -u zypper-notify-user.service -n 50 --no-pager
```

### Verifying the Services

```bash
# 1. Check Root Timer (Downloader)
# Should show "active" and the next scheduled run time
systemctl list-timers zypper-autodownload.timer

# 2. Check User Timer (Notifier)
# Must be run as your regular user. Should show "active" and the next scheduled run time.
systemctl --user list-timers zypper-notify-user.timer

# 3. Check the status of the last DOWNLOADER run
systemctl status zypper-autodownload.service

# 4. View the detailed logs from the smart notification script
journalctl --user -u zypper-notify-user.service

# Edit the root downloader's schedule:
sudoedit /etc/systemd/system/zypper-autodownload.timer

# Edit the user notifier's schedule:
systemctl --user edit --full zypper-notify-user.timer

# For the root downloader:
sudo systemctl daemon-reload
sudo systemctl restart zypper-autodownload.timer

# For the user notifier (as your regular user):
systemctl --user daemon-reload
systemctl --user restart zypper-notify-user.timer
```

-----

## 📊 Logging & Monitoring (v47)

Version 47 introduces comprehensive logging to help you understand what's happening without needing to run commands.

### Log Locations

#### System Logs (Root Services)
**Location:** `/var/log/zypper-auto/`

| File | Purpose | What It Contains |
|------|---------|------------------|
| `install-YYYYMMDD-HHMMSS.log` | Installation logs | Complete log of each installation run with timestamps, all commands executed, and their results |
| `last-status.txt` | Current status | The most recent status message (e.g., "SUCCESS: Installation completed") |
| `service-logs/downloader.log` | Downloader output | Output from the background download service (`zypper refresh` and `zypper dup --download-only`) |
| `service-logs/downloader-error.log` | Downloader errors | Error output from the downloader service |

#### User Logs (Notifier Service)
**Location:** `~/.local/share/zypper-notify/`

| File | Purpose | What It Contains |
|------|---------|------------------|
| `notifier-detailed.log` | Complete notifier activity | All notifier operations: environment checks, safety decisions, update checks, errors with full tracebacks |
| `notifier-detailed.log.old` | Previous log backup | Previous log file (created when main log exceeds 5MB) |
| `last-run-status.txt` | Last run status | Status of the most recent notifier run (e.g., "Updates available: Snapshot 20251110-0 Ready") |
| `notifier.log` | Systemd stdout | Standard output captured by systemd |
| `notifier-error.log` | Systemd stderr | Standard error captured by systemd |

### What Gets Logged

#### Installation Phase
- ✅ Sanity checks (root privileges, user detection)
- ✅ Dependency verification and installation
- ✅ Old service cleanup
- ✅ Service/timer creation
- ✅ File permissions and ownership
- ✅ Syntax validation
- ✅ Final status summary

#### Runtime (Notifier Service)
- ✅ **Environment Detection:** Form factor (laptop/desktop), battery status, AC power state
- ✅ **Safety Checks:** Why updates are allowed or skipped (battery, metered connection, etc.)
- ✅ **Update Checks:** When zypper runs, what it finds, how many packages
- ✅ **Notifications:** What notifications are shown to the user
- ✅ **User Actions:** When the Install button is clicked
- ✅ **Errors:** Full error messages with Python tracebacks for debugging

### How to Access Logs

#### View Current Status (No Commands Needed)
```bash
# System/installation status
cat /var/log/zypper-auto/last-status.txt

# Notifier status (what's happening with update checks)
cat ~/.local/share/zypper-notify/last-run-status.txt
```

#### View Full Installation Log
```bash
# View the most recent installation
ls -lt /var/log/zypper-auto/install-*.log | head -1 | awk '{print $NF}' | xargs cat

# Or specify a date
cat /var/log/zypper-auto/install-20251119-183000.log
```

#### View Downloader Service Logs
```bash
# See what the background downloader is doing
sudo cat /var/log/zypper-auto/service-logs/downloader.log

# Check for download errors
sudo cat /var/log/zypper-auto/service-logs/downloader-error.log

# Or use journalctl for systemd-managed logs
journalctl -u zypper-autodownload.service
```

#### View Notifier Logs
```bash
# View detailed notifier activity log
cat ~/.local/share/zypper-notify/notifier-detailed.log

# View just recent entries (last 50 lines)
tail -50 ~/.local/share/zypper-notify/notifier-detailed.log

# Watch the log in real-time
tail -f ~/.local/share/zypper-notify/notifier-detailed.log

# View systemd service logs
journalctl --user -u zypper-notify-user.service

# View just the last run
journalctl --user -u zypper-notify-user.service -n 50 --no-pager
```

#### Search Logs for Specific Issues
```bash
# Find all errors in notifier log
grep "\[ERROR\]" ~/.local/share/zypper-notify/notifier-detailed.log

# Check why updates were skipped
grep "SKIPPED" ~/.local/share/zypper-notify/notifier-detailed.log

# See environment detection history
grep "Form factor detected" ~/.local/share/zypper-notify/notifier-detailed.log

# Find when updates were available
grep "packages to upgrade" ~/.local/share/zypper-notify/notifier-detailed.log
```

### Log Rotation & Cleanup

**Automatic cleanup happens on every installation:**
- Installation logs: Keep only the **last 10** log files
- Service logs: Rotate when exceeding **50MB**
- Notifier logs: Rotate when exceeding **5MB**

No manual maintenance required!

### Understanding Log Entries

Each log entry has a timestamp and severity level:

```
[2025-11-19 18:30:45] [INFO] Starting update check...
[2025-11-19 18:30:46] [DEBUG] Checking AC power status (form_factor: laptop)
[2025-11-19 18:30:46] [INFO] AC power detected: plugged in
[2025-11-19 18:30:47] [INFO] Environment is safe for updates
[2025-11-19 18:30:50] [INFO] Found 12 packages to upgrade (snapshot: 20251119)
[2025-11-19 18:30:51] [ERROR] Failed to show notification: [error details]
```

**Severity Levels:**
- `INFO` - Normal operation, status updates
- `DEBUG` - Detailed information for troubleshooting (only visible with `ZNH_DEBUG=1`)
- `ERROR` - Something went wrong, includes details
- `SUCCESS` - Operation completed successfully (installation logs only)

-----

## 📚 Additional Resources

### Reporting Issues on GitHub

**If you encounter a problem, please include these logs in your GitHub issue:**

#### For Installation Problems:
```bash
# 1. Most recent installation log (REQUIRED)
cat $(ls -t /var/log/zypper-auto/install-*.log | head -1)

# 2. Installation status (REQUIRED)
cat /var/log/zypper-auto/last-status.txt
```

#### For Notification/Update Check Problems:
```bash
# 1. Detailed notifier log (REQUIRED)
cat ~/.local/share/zypper-notify/notifier-detailed.log

# 2. Last run status (REQUIRED)
cat ~/.local/share/zypper-notify/last-run-status.txt

# 3. Systemd service status (HELPFUL)
systemctl --user status zypper-notify-user.service

# 4. Recent systemd logs (HELPFUL)
journalctl --user -u zypper-notify-user.service -n 100 --no-pager
```

#### For Download Problems:
```bash
# 1. Downloader logs (REQUIRED)
sudo cat /var/log/zypper-auto/service-logs/downloader.log
sudo cat /var/log/zypper-auto/service-logs/downloader-error.log

# 2. Service status (HELPFUL)
systemctl status zypper-autodownload.service
```

**Also include:**
- Your openSUSE Tumbleweed version: `cat /etc/os-release`
- Python version: `python3 --version`
- Description of the problem and what you expected to happen

**⚠️ IMPORTANT:** Please **redact any personal information** (usernames, hostnames, network names) before posting logs publicly!

### Troubleshooting Common Issues

**Problem: Updates not being downloaded**
- Check if the downloader timer is active: `systemctl status zypper-autodownload.timer`
- Check the downloader log for errors: `sudo cat /var/log/zypper-auto/service-logs/downloader-error.log`
- Verify conditions are met (AC power, not metered): Check systemd conditions

**Problem: Not receiving notifications**
- Check notifier timer: `systemctl --user status zypper-notify-user.timer`
- Check for errors: `cat ~/.local/share/zypper-notify/notifier-detailed.log | grep ERROR`
- Check last run status: `cat ~/.local/share/zypper-notify/last-run-status.txt`
- Verify PyGObject is installed: `python3 -c "import gi"`

**Problem: Updates skipped on laptop**
- Check if on battery: `cat ~/.local/share/zypper-notify/notifier-detailed.log | grep "AC power"`
- Check for metered connection: `grep "metered" ~/.local/share/zypper-notify/notifier-detailed.log`
- The system is working as designed - updates only run on AC power and unmetered connections

### Version History

- **v47** (2025-11-19): Added comprehensive logging system with automatic rotation
- **v46**: AC battery detection logical fix
- **v45**: Architecture improvements and user-space notifier
- **v43**: Enhanced Python notification script
- **v42**: PolicyKit/PAM error logging enhancements
- Earlier versions: Initial development and refinements

-----

## 🗑️ Uninstallation

```bash
# 1. Stop and disable the root timer
sudo systemctl disable --now zypper-autodownload.timer

# 2. Stop and disable the user timer (run as regular user)
systemctl --user disable --now zypper-notify-user.timer

# 3. Remove all systemd files and scripts
sudo rm /etc/systemd/system/zypper-autodownload.service
sudo rm /etc/systemd/system/zypper-autodownload.timer

# Replace $HOME with your actual home directory (or run as regular user)
rm -f $HOME/.config/systemd/user/zypper-notify-user.service
rm -f $HOME/.config/systemd/user/zypper-notify-user.timer
rm -f $HOME/.local/bin/zypper-notify-updater.py
rm -f $HOME/.local/bin/zypper-run-install

# 4. (Optional) Remove logs
sudo rm -rf /var/log/zypper-auto
rm -rf $HOME/.local/share/zypper-notify
rm -rf $HOME/.cache/zypper-notify

# 5. Reload the systemd daemons
sudo systemctl daemon-reload
systemctl --user daemon-reload
```
