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

## ✨ Key Features (v58 Architecture)

* **Command-Line Interface (v51):** New `zypper-auto-helper` command provides easy access to all management functions:
    * Auto-installed to `/usr/local/bin/zypper-auto-helper`
    * Shell aliases automatically configured for Bash, Zsh, and Fish
    * Commands: `--verify`, `--repair`, `--diagnose`, `--check`, `--help`
* **Advanced Verification & Auto-Repair (v51):** Comprehensive 12-point health check system:
    * Verifies services, scripts, permissions, processes, and cache
    * Multi-stage auto-repair with retry logic (up to 3 attempts per issue)
    * Deep health checks: active + enabled + triggers scheduled
    * Nuclear options for complete service resets when needed
    * Accessible via `zypper-auto-helper --verify` after installation
* **Real-Time Download Progress (v51–v56):** Enhanced progress tracking with visual feedback:
* Background downloader writes precise status (`refreshing`, `downloading:TOTAL:SIZE:DOWNLOADED:PERCENT`, `complete`, `idle`)
* Notifier shows a live-updating progress bar while downloads are in progress
* Cache-aware logic skips fake progress when `zypper` reports everything is already in cache
* High-priority downloads (nice -20, ionice realtime)
* **Smart Notification Management (v51–v56):** Prevents notification spam and keeps state consistent:
    * Synchronous notification IDs prevent duplicate popups
    * "No updates" notification shown only once until state changes
    * Download status notifications replace each other smoothly
* **Robust Zypper Error Handling (v54–v57):** Distinguishes between zypper locks, PolicyKit/auth failures, and solver/interaction errors (e.g. vendor conflicts) and guides you with appropriate notifications. Zypper locks are detected via both the canonical error message *and* zypp lockfiles, so the downloader/notifier will gracefully back off (and retry later) when a manual `zypper` or YaST is running. When the background downloader hits a solver conflict it preserves any downloaded RPMs in the cache and triggers a persistent "updates require your decision" notification with an **Install Now** action, showing how many updates are pending and a short package preview once a transaction can be summarised.
* **Soar / Flatpak / Snap / Homebrew Integration (v55–v58):** Every `zypper dup` / `zypper update` run via the helper or wrapper automatically chains Flatpak updates, Snap refresh (if installed), a Soar stable-version check + `soar sync` + `soar update` (if installed), and a Homebrew `brew update` followed by conditional `brew upgrade`, so system packages, runtimes, Soar-managed apps, and Homebrew formulae stay aligned after system updates. Optional Soar/Homebrew helper commands are provided via `zypper-auto-helper --soar` and `zypper-auto-helper --brew`.
* **Smarter Optional Tool Detection (v55):** Optional helpers like Flatpak, Snap, and Soar are detected using the *user's* PATH and common per-user locations (e.g. `~/.local/bin`, `~/pkgforge`) to avoid false "missing" warnings when they are already installed.
* **Improved Snapper Detection (v55–v56):** Recognises Tumbleweed's default root snapper configuration, treats `snapper list` permission errors ("No permissions.") as "snapshots exist but are root-only", and surfaces the current Snapper state (configured/missing/snapshots available) directly in the update notification.
* **More Robust Notifier Timer (v55–v56):** Uses calendar-based scheduling plus an automatic timer restart after installation so the user systemd timer (`zypper-notify-user.timer`) no longer gets stuck in an `active (elapsed)` state with no next trigger.
* **Manual Update Wrapper (v51):** Automatic post-update checks for manual updates:
    * Wraps `sudo zypper dup` command automatically
    * Runs `zypper ps -s` after successful updates
    * Provides guidance on service restarts and reboots
    * Works across all shells (Bash, Zsh, Fish)
* **Decoupled Architecture:** Two separate services: a "safe" root-level downloader and a "smart" **user-level** notifier.
* **User-Space Notifier:** Runs as a user service (`~/.config/systemd/user`) so it can reliably talk to your desktop session (D-Bus) and show clickable notifications.
* **Stage-Based Download Progress (v50):** Real-time notifications showing download stages:
    * **"Checking for updates..."** - Refreshing repositories
    * **"Downloading updates... (X of Y packages)"** - Active download with real-time progress
    * **"✅ Downloads Complete!"** - Download finished with duration and package preview
    * **"Updates Ready to Install"** - Ready to apply with snapshot info
* **Smart Download Detection (v49):** Only downloads and notifies when updates are actually available, eliminating false "downloading" notifications.
* **Safe Downloads (Root):** The downloader service is a simple, root-only worker that always runs at low priority and logs to `/var/log/zypper-auto`; network/AC safety decisions are enforced in the user-space notifier.
* **Smart Safety Logic (User):** The notifier Python script uses `upower`, `inxi` and `nmcli` with extra heuristics to distinguish real laptops from desktops/UPS setups (including laptops that only expose a battery device without a separate `line_power` entry), and to avoid false "metered" or "on battery" positives. On laptops it only refreshes/inspects updates on AC power and non‑metered connections.
* **Fixed Battery Detection (v48):** Corrected logic that was incorrectly identifying laptops as desktops, now properly detects batteries via `inxi` output.
* **Persistent Notifications (v48):** Update notifications now persist until user interaction or timeout by keeping a GLib main loop active.
* **Environment Change Awareness (v53):** Tracks when your machine switches between AC/battery or metered/unmetered connections and shows "updates paused" / "conditions now safe" notifications accordingly.
* **Snooze & Quiet Hours (v53):** Lets you snooze update reminders for 1h, 4h, or 1 day via notification buttons, with state stored under `~/.cache/zypper-notify`.
* **Safety Preflight Checks (v53):** Before showing "Install" it checks root filesystem free space, Btrfs snapshots (snapper), and basic network health and adds warnings to the notification if something looks risky.
* **Post-Update Service Check:** After updates complete, automatically runs `zypper ps -s` to show which services need restart and provides reboot guidance.
* **Comprehensive Logging:** Full debug logging for installation, system services, and user notifier with automatic log rotation and persistent status tracking.
* **Clickable Install:** The rich, Python-based notification is **clickable**. Clicking the "Install" button runs `~/.local/bin/zypper-run-install`, which opens a terminal and executes `pkexec zypper dup`.
* **Automatic Upgrader:** The installer is idempotent and will **cleanly stop, disable, and overwrite any previous version** (v1–v58) to ensure a clean migration.
* **Dependency Checks:** The installer verifies all necessary dependencies (`nmcli`, `upower`, `inxi`, `python3-gobject`, `pkexec`) are present and offers to install them if they are missing.
* **Safe Scripted Uninstaller (v58):** New `--uninstall-zypper-helper` mode in `zypper-auto.sh` / `zypper-auto-helper` removes all helper services, timers, binaries, user scripts, aliases, logs and caches with a confirmation prompt by default, plus advanced flags:
  * `--yes` / `-y` / `--non-interactive` – skip the prompt and proceed non-interactively
  * `--dry-run` – show exactly what would be removed without making any changes
  * `--keep-logs` – leave `/var/log/zypper-auto` installation/service logs intact while still clearing caches
  * It **never** removes `snapd`, Flatpak, Soar, Homebrew itself, or any zypper configuration such as `/etc/zypp/zypper.conf`.

-----

## 🛠️ How It Works: The v58 Architecture

This is a two-service system to provide both safety (Downloader) and persistence/user interaction (Notifier).

### 1. The Installer: `zypper-auto.sh`

* **Cleanup:** Explicitly stops and disables all timers/services from *any* previous version to ensure a clean state.
* **User Detection:** Reliably determines the `$SUDO_USER`'s home directory to place the user-specific systemd files and scripts (`~/.config/systemd/user`, `~/.local/bin`).
* **Enables Root Timer:** After writing the units, it runs `systemctl daemon-reload` and `systemctl enable --now zypper-autodownload.timer` automatically.

### 2. The Downloader (Root Service)

This service's only job is to download packages when it's safe, and report progress stages.

* **Service:** `/etc/systemd/system/zypper-autodownload.service`
    * This service runs `zypper refresh` and `zypper dup --download-only`.
    * It writes stage information to `/var/log/zypper-auto/download-status.txt`:
        * `refreshing` - Repositories being refreshed
        * `downloading:X` - Downloading X packages (includes count)
        * `complete` - Ready for installation
        * `idle` - No updates available
    * It will **only** start if `ConditionACPower=true` and `ConditionNotOnMeteredConnection=true` are met.
* **Timer:** `/etc/systemd/system/zypper-autodownload.timer`
    * Default schedule is derived from the config option `DL_TIMER_INTERVAL_MINUTES` in `/etc/zypper-auto.conf` (allowed values: 1,5,10,15,30,60).
    * For example:
        * `1`  → runs minutely
        * `10` → runs every 10 minutes (`OnCalendar=*:0/10`)
        * `60` → runs hourly (`OnCalendar=hourly`)

### 3. The Notifier (User Service)

This service's job is to check for updates and remind you, running as your standard user.

* **Service:** `~/.config/systemd/user/zypper-notify-user.service`
    * Runs the Python script `~/.local/bin/zypper-notify-updater.py`.
    * Because it runs in user-space, it has the correct D-Bus environment variables to display notifications reliably.
* **Timer:** `~/.config/systemd/user/zypper-notify-user.timer`
    * Default schedule is derived from `NT_TIMER_INTERVAL_MINUTES` in `/etc/zypper-auto.conf` (same allowed values as above).
    * By changing `NT_TIMER_INTERVAL_MINUTES` (e.g. to 10 or 60) and re-running the installer, you can control how often the notifier checks and pops notifications.

### 4. The "Brains": `~/.local/bin/zypper-notify-updater.py`

This Python script is the core of the system, run by the `zypper-notify-user.service` on the schedule defined by the user timer.

1.  **Checks Download Stage:** Reads `/var/log/zypper-auto/download-status.txt` to determine if downloads are in progress:
    * `refreshing` → Shows "Checking for updates..." notification
    * `downloading:X` → Shows "Downloading X packages..." notification with count
    * `complete` or `idle` → Proceeds to normal update check
2.  **Checks Safety:** Uses `inxi`, `upower` and `nmcli` with extra heuristics to:
    * distinguish laptops (real internal battery + AC adapter) from desktops/UPS/embedded setups,
    * reliably classify any system with a real battery as a laptop, even when `upower` does not expose a `line_power` device,
    * treat desktops as always on AC for safety decisions,
    * treat NetworkManager failures as "unmetered" to avoid random false positives.
3.  **Runs Zypper:** Executes `pkexec zypper refresh` (if safe) and always runs `pkexec zypper dup --dry-run` to check for pending updates. On laptops, "safe" explicitly means **on AC and not on a metered connection**.
4.  **Parses Output:** Counts packages and finds the latest Tumbleweed snapshot version.
5.  **Sends Clickable Notification:** Uses PyGObject to send a rich notification with the snapshot version and an **"Install"** button.
6.  **Launches Terminal (Action):** Clicking "Install" runs the `~/.local/bin/zypper-run-install` script via `systemd-run --user --scope`, which launches your preferred terminal (`konsole`, `gnome-terminal`, etc.) to execute `pkexec zypper dup` interactively.
7.  **Post-Update Check:** After update completes, runs `zypper ps -s` to show which services need restart and provides reboot guidance if needed.
8.  **Debug Mode:** If `ZNH_DEBUG=1` (or `true/yes/debug`) is set in the environment, extra debug logs (e.g. `upower` / `nmcli` / `inxi` decisions) are printed to the journal.
9.  **Manual-Intervention Helper (v54+):** When `pkexec zypper dup --dry-run` or the background downloader encounter a solver/interaction problem (such as a vendor conflict), the notifier shows a dedicated, persistent "Updates require your decision" notification. It:
    - Includes a concise summary of the problem (first `Problem:` line when available).
    - Attempts to parse the dry-run output to show how many updates are pending and a short package preview, so you still see *what* is waiting to be installed even though zypper needs your choice.
    - Provides an **"Install Now"** / **"Open Helper"** action that launches `~/.local/bin/zypper-run-install` so you can resolve the conflict interactively in a terminal, plus snooze and "View Changes" actions.

-----

## 🚀 Installation / Upgrading

The script is idempotent. You can run this on a fresh install *or* on a PC with an older version.

1.  Download the latest `zypper-auto.sh` script.
2.  Make it executable:
    ```bash
    chmod +x zypper-auto.sh
    ```
3.  Run it with `sudo`. The script will handle everything automatically:
    ```bash
    sudo ./zypper-auto.sh install
    ```

**That's it!** The installer now:
- Installs the `zypper-auto-helper` command to `/usr/local/bin`
- Adds shell aliases to your `.bashrc`, `.zshrc`, or Fish config
- Enables both root and user services automatically
- Runs comprehensive verification and auto-repair
- Reports any issues and fixes them automatically

### Using the Installed Command

After installation (restart your shell or run `source ~/.bashrc`), you can use:

```bash
zypper-auto-helper --help          # Show help
zypper-auto-helper --verify        # Run health check and auto-repair
zypper-auto-helper --repair        # Alias for --verify
zypper-auto-helper --diagnose      # Alias for --verify
zypper-auto-helper --check         # Syntax check only
zypper-auto-helper install         # Reinstall/upgrade
zypper-auto-helper --reset-config  # Reset /etc/zypper-auto.conf to documented defaults (with backup)
zypper-auto-helper --soar          # Install/upgrade the optional Soar CLI helper
zypper-auto-helper --brew          # Install/upgrade Homebrew (brew) for the system/user
zypper-auto-helper --uninstall-zypper-helper  # Remove only this helper's services/scripts/logs
```

You normally run `zypper-auto-helper` **without** `sudo`; it will prompt for elevation internally when needed.

### Configuration File: `/etc/zypper-auto.conf`

The installer reads an optional config file at `/etc/zypper-auto.conf` on every run.
If the file does not exist, it generates a documented default template. You can
safely edit this file and re-run `sudo ./zypper-auto.sh install` to apply
changes.

Key options include:

- **Post-update helpers**
  - `ENABLE_FLATPAK_UPDATES` / `ENABLE_SNAP_UPDATES` / `ENABLE_SOAR_UPDATES` /
    `ENABLE_BREW_UPDATES` – `true` / `false` flags to control whether Flatpak,
    Snap, Soar and Homebrew helpers run after `zypper dup`.

- **Timer intervals**
  - `DL_TIMER_INTERVAL_MINUTES` – how often the root downloader runs
    (allowed: `1,5,10,15,30,60`).
  - `NT_TIMER_INTERVAL_MINUTES` – how often the user notifier runs.
  - The installer converts these into appropriate `OnCalendar` values, e.g.
    `*:0/10` for every 10 minutes or `hourly` for 60.

- **Caching / snooze**
  - `CACHE_EXPIRY_MINUTES` – how long a cached `zypper dup --dry-run` result
    is considered valid before forcing a fresh check.
  - `SNOOZE_SHORT_HOURS`, `SNOOZE_MEDIUM_HOURS`, `SNOOZE_LONG_HOURS` – actual
    durations used by the `1h` / `4h` / `1d` snooze buttons in the desktop
    notification.

- **Zypper solver flags**
  - `DUP_EXTRA_FLAGS` – extra arguments appended to every `zypper dup` invocation
    run by the helper, for **both** the background downloader (`dup --download-only`)
    and the notifier (`dup --dry-run`). This is the right place to add flags such
    as `--allow-vendor-change` or `--from <repo>` without editing the scripts.
  - Do **not** include `--non-interactive`, `--download-only`, or `--dry-run` here;
    those are added automatically by the helper where appropriate.

If any values are invalid, the installer falls back to safe defaults, logs the
warnings, updates `last-status.txt`, and attempts to show a small desktop
notification suggesting `zypper-auto-helper --reset-config`.

### Config Health & Stale Configs

Over time, new versions add new keys to `/etc/zypper-auto.conf`. To keep
behaviour predictable, the installer performs a basic **config health check**
whenever it runs:

- If the config file is **missing** → a fresh, fully documented template is
  generated.
- If the config file **exists but is missing newer keys** (for example
  `DUP_EXTRA_FLAGS`) → the installer:
  - Detects which keys are missing.
  - Logs a warning listing each missing key and a short description of the
    affected feature.
  - Adds the warning to `CONFIG_WARNINGS` so it appears in
    `/var/log/zypper-auto/last-status.txt`.
  - Tries to send a desktop notification suggesting:
    `sudo zypper-auto-helper --reset-config`.
  - Applies safe defaults for those keys at runtime so the installer and
    services continue to work.

If you see a warning that `/etc/zypper-auto.conf` is from an older version and
lists missing keys, the **recommended fix** is:

```bash
sudo zypper-auto-helper --reset-config
sudo ./zypper-auto.sh install
```

This backs up your existing config and regenerates it with all current options
and comments.

-----

## 🏃 Usage

1.  **Wait.** The services run in the background. By default, both the downloader and notifier run every minute. You can change their frequency via `/etc/zypper-auto.conf` (`DL_TIMER_INTERVAL_MINUTES` / `NT_TIMER_INTERVAL_MINUTES`) and re-run `sudo ./zypper-auto.sh install`.
2.  **Get Notified.** You will get a notification *only* when new updates are pending.
    > **Snapshot 20251110-0 Ready**
    > 12 updates are pending. Click 'Install' to begin.
3.  **Install.** Click the **"Install"** button in the notification. This will open a terminal and prompt you for authentication to run `zypper dup`.

### Quick Status Check

You can check the current status at any time:

```bash
# Run comprehensive health check and auto-repair
zypper-auto-helper --verify

# Check installation/system status
cat /var/log/zypper-auto/last-status.txt

# Check notifier status
cat ~/.local/share/zypper-notify/last-run-status.txt

# Check download progress
cat /var/log/zypper-auto/download-status.txt
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

# 5. Change schedules via the config file (recommended):
sudoedit /etc/zypper-auto.conf
# Adjust DL_TIMER_INTERVAL_MINUTES / NT_TIMER_INTERVAL_MINUTES, then re-run:
sudo ./zypper-auto.sh install

# 6. (Advanced) Reload timers manually if you edited units yourself:
sudo systemctl daemon-reload
sudo systemctl restart zypper-autodownload.timer
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

- **v58** (2025-12-31): **Scripted Uninstaller, External Config & Log Control**
  - 📝 **Short:** Safer uninstall, externalised config (including `DUP_EXTRA_FLAGS`), smarter config health warnings, and improved solver-conflict notifications that keep cached downloads and guide you to resolve conflicts.
  - 🗑️ **NEW: Safe scripted uninstaller** – `sudo ./zypper-auto.sh --uninstall-zypper-helper` (or `sudo zypper-auto-helper --uninstall-zypper-helper`) now removes all helper components (root timers/services, helper binaries, user systemd units, helper scripts, aliases, logs and caches) in a single, logged operation with a clear header and summary.
  - ⚙️ **NEW: Advanced uninstall flags** – `--yes` / `-y` / `--non-interactive` skip the confirmation prompt for automated or non-interactive environments; `--dry-run` shows exactly what **would** be removed without making any changes; `--keep-logs` preserves `/var/log/zypper-auto` install/service logs for debugging while still clearing per-user notifier caches.
  - 🧹 **IMPROVED: Clean systemd state on uninstall** – system and user units are stopped, disabled, removed from disk, and their "failed" states cleared via `systemctl reset-failed`/`systemctl --user reset-failed` so `systemctl status` no longer reports stale failures after uninstall.
  - 🧾 **NEW: External configuration file** – `/etc/zypper-auto.conf` now holds documented settings for post-update helpers (Flatpak/Snap/Soar/Brew), log retention, notifier cache/snooze behaviour, timer intervals, and per-installation zypper behaviour, so users can tweak behaviour without editing the script.
  - 🕒 **NEW: Config-driven timer intervals** – `DL_TIMER_INTERVAL_MINUTES` and `NT_TIMER_INTERVAL_MINUTES` (allowed: `1,5,10,15,30,60`) control how often the downloader and notifier run; the installer converts these into appropriate `OnCalendar` expressions.
  - 🧩 **NEW: `DUP_EXTRA_FLAGS` support** – a new `DUP_EXTRA_FLAGS` key in `/etc/zypper-auto.conf` lets you append extra solver flags (such as `--allow-vendor-change` or `--from <repo>`) to every `zypper dup` run by the helper (background downloader and notifier) without modifying the scripts.
  - 🚨 **NEW: Config validation & reset helper** – invalid values in `/etc/zypper-auto.conf` automatically fall back to safe defaults, are logged, surfaced in `last-status.txt`, and trigger a small desktop notification suggesting `zypper-auto-helper --reset-config`. A new `--reset-config` CLI mode resets the config to defaults with a timestamped backup.

- **v57** (2025-12-28): **Soar Stable Updater, Homebrew Integration & Notification UX**
  - 🧭 **NEW: Smarter Soar stable updater** – the helper and wrapper now compare `soar --version` against GitHub’s latest stable release tag (`releases/latest`) and only re-run the official Soar installer when a newer stable version exists, then run `soar sync` and `soar update`.
  - 🍺 **NEW: Homebrew `--brew` helper mode** – `sudo ./zypper-auto.sh --brew` (or `sudo zypper-auto-helper --brew`) now installs Homebrew on Linux for the target user if missing, or, when brew is already installed, runs `brew update` followed by `brew outdated --quiet` and `brew upgrade` only when there are outdated formulae, with clear log messages.
  - 🔗 **NEW: Homebrew wrapper integration** – the `zypper-with-ps` wrapper now treats `dup`, `dist-upgrade` and `update` as full updates and, after Flatpak/Snap/Soar steps, runs `brew update` and conditionally `brew upgrade`, with Soar-style status messages ("Homebrew is already up to date" vs "upgraded N formulae").
  - 🧩 **IMPROVED: Soar & Homebrew UX** – Soar’s GitHub API check no longer emits noisy `curl: (23)` errors and both Soar and Homebrew remain fully optional; if either tool is not installed, the scripts simply log a short hint instead of failing.
  - 📡 **IMPROVED: Downloader/Notifier coordination** – the downloader writes structured status (`refreshing`, `downloading:…`, `complete:…`, `idle`), handles zypper locks gracefully (marking itself idle and letting timers retry), and the notifier shows live progress, a cached-aware "✅ Downloads Complete!" notification, and a separate persistent "Snapshot XXXXXXXX Ready" notification for installation.
  - 🧱 **IMPROVED: Snapper status reporting** – Snapper root configs are detected more reliably; `snapper list` permission errors are treated as "snapshots exist (root-only)" rather than "not configured", and the current Snapper state is always surfaced in the update notification.
  - ⏱️ **IMPROVED: Timer defaults** – both the root downloader and user notifier timers now default to a simple minutely `OnCalendar` schedule for more predictable behaviour, instead of `OnActiveSec`-based intervals that could end up `active (elapsed)` with no next trigger.

- **v55** (2025-12-27): **Soar Integration, Smarter Detection & Timer Fixes**
  - 🔗 **NEW: Soar integration** – every `zypper dup` triggered via the helper or the shell wrapper now runs Flatpak updates, Snap refresh, and an optional `soar sync` step so app runtimes and Soar-managed apps stay in sync with system updates.
  - 🧩 **NEW: Optional Soar guidance & install helper** – if Soar is not installed for the user, the installer logs and (optionally) notifies with the exact install command (`curl -fsSL "https://raw.githubusercontent.com/pkgforge/soar/main/install.sh" | sh`), suggests `soar sync`, and shows a rich desktop notification with an **"Install Soar"** button that opens a terminal and runs the installer for you.
  - 🧭 **NEW: Smarter optional-tool detection & stable Soar updater** – Flatpak, Snap, and Soar are now detected using the user's PATH and common per-user locations (like `~/.local/bin` and `~/pkgforge`) to avoid false "missing" warnings; if Soar is already present, the install helper notification is suppressed. When Soar *is* installed, the wrapper/GUI helper now compares `soar --version` against GitHub’s latest stable release tag (`releases/latest`) and only re-runs the Soar installer when a newer stable version exists, then runs `soar sync`.
  - 📸 **IMPROVED: Snapper detection** – `snapper list-configs` is inspected so the default `root` config on Tumbleweed is recognised, and `snapper list` permission errors ("No permissions.") are treated as "snapper configured (root) but snapshots require root permissions to view" rather than "not configured".
  - ⏱️ **IMPROVED: Notifier timer behaviour** – the user timer now uses `OnActiveSec` plus an automatic restart after install so it no longer gets stuck in an `active (elapsed)` state with no future trigger.
- **v54** (2025-12-25): **Robust Conflict Handling & Helper Integration**
  - 🧠 **NEW: Smarter zypper error handling** that distinguishes PolicyKit/authentication failures, zypper locks, and normal solver/interaction errors.
  - 🧩 **NEW: "Updates require manual decision" notification** when `zypper dup --dry-run` needs interactive choices (e.g. vendor conflicts), including the first `Problem:` line from zypper output.
  - 🖱️ **NEW: "Open Helper" action button** on manual-intervention notifications that launches `zypper-run-install` in a terminal so you can resolve issues immediately.
  - 🔁 **FIXED: Stale downloader status handling** – old `refreshing` / `downloading:` states in `/var/log/zypper-auto/download-status.txt` are ignored after 5 minutes so the notifier always runs a fresh check.
- **v53** (2025-12-25): **Snooze Controls & Environment-Aware Safety Preflight**
  - ✨ **NEW: Snooze buttons (1h / 4h / 1d)** in the notification with persistent state under `~/.cache/zypper-notify`, so you can temporarily pause reminders.
  - 🔔 **NEW: Environment change notifications** when AC/battery or metered status changes, explaining why downloads are paused or allowed.
  - 🛡️ **NEW: Safety preflight checks** for disk space, Btrfs snapshots (snapper), and basic network quality, with warnings appended to the update notification instead of failing silently.
  - 👀 **NEW: "View Changes" helper** launched from the notification to show `zypper dup --dry-run --details` in a terminal.
  - ℹ️ **NEW: Optional Flatpak/Snap detection** after install with a desktop notification describing how to enable them for app updates.
- **v51** (2025-12-23): **Major Update - Command-Line Interface & Advanced Diagnostics**
  - ✨ **NEW: `zypper-auto-helper` command** - Installed to `/usr/local/bin` with automatic shell aliases
  - 🔧 **NEW: Advanced Verification System** - 12-point health check with multi-stage auto-repair
  - 🚀 **NEW: Real-Time Progress** - Download notifications update every 5 seconds with progress bar
  - 🎯 **NEW: Smart Cache Detection** - Doesn't notify about downloads if packages already cached
  - 🔄 **NEW: Manual Update Wrapper** - `sudo zypper dup` automatically runs post-update checks
  - 🚫 **NEW: Duplicate Prevention** - Synchronous notification IDs prevent popup spam
  - ⚡ **IMPROVED: High-Priority Downloads** - nice -20 and ionice realtime for faster downloads
  - 🛠️ **IMPROVED: Installation** - Fully automatic, no manual user service enabling required
  - 📊 **IMPROVED: Status Tracking** - Better progress reporting with percentage and package count
- **v50** (2025-11-20): Added stage-based download notifications with package count display
- **v49** (2025-11-20): Smart download detection - only notifies when updates are actually being downloaded
- **v48** (2025-11-20): Fixed battery detection logic (laptops no longer misidentified as desktops) and notification persistence (popups no longer disappear instantly)
- **v47** (2025-11-19): Added comprehensive logging system with automatic rotation
- **v46**: AC battery detection logical fix
- **v45**: Architecture improvements and user-space notifier
- **v43**: Enhanced Python notification script
- **v42**: PolicyKit/PAM error logging enhancements
- Earlier versions: Initial development and refinements

-----

## 🗑️ Uninstallation

### Recommended: Scripted Uninstaller (v58+)

Use the built-in uninstaller to safely remove all helper components:

```bash
# Run from the directory containing zypper-auto.sh
sudo ./zypper-auto.sh --uninstall-zypper-helper

# Or using the installed helper command
sudo zypper-auto-helper --uninstall-zypper-helper
```

By default this will:
- Stop and disable the root timers/services (`zypper-autodownload`, `zypper-cache-cleanup`)
- Stop and disable the user notifier timer/service for your user
- Remove all helper systemd unit files and helper binaries
- Remove user helper scripts, shell aliases, and Fish config snippets
- Clear notifier caches and (by default) old helper logs under `/var/log/zypper-auto`
- Reload both system and user systemd daemons and clear any "failed" states

#### Advanced Uninstall Flags

You can customise the behaviour with optional flags:

```bash
# Skip the confirmation prompt (non-interactive)
sudo ./zypper-auto.sh --uninstall-zypper-helper --yes
# or
sudo ./zypper-auto.sh --uninstall-zypper-helper --non-interactive

# Show what WOULD be removed, but make no changes
sudo ./zypper-auto.sh --uninstall-zypper-helper --dry-run

# Keep logs under /var/log/zypper-auto for debugging
sudo ./zypper-auto.sh --uninstall-zypper-helper --yes --keep-logs

# Flags can be combined as needed
sudo ./zypper-auto.sh --uninstall-zypper-helper --dry-run --keep-logs
```

### Manual Uninstall (Advanced / Legacy)

If you prefer or need to remove components manually, the equivalent steps are:

```bash
# 1. Stop and disable the root timers
sudo systemctl disable --now zypper-autodownload.timer
sudo systemctl disable --now zypper-cache-cleanup.timer

# 2. Stop and disable the user timer (run as regular user)
systemctl --user disable --now zypper-notify-user.timer

# 3. Remove all systemd files and scripts
sudo rm /etc/systemd/system/zypper-autodownload.service
sudo rm /etc/systemd/system/zypper-autodownload.timer
sudo rm /etc/systemd/system/zypper-cache-cleanup.service
sudo rm /etc/systemd/system/zypper-cache-cleanup.timer
sudo rm /usr/local/bin/zypper-download-with-progress
sudo rm /usr/local/bin/zypper-auto-helper

# Replace $HOME with your actual home directory (or run as regular user)
rm -f $HOME/.config/systemd/user/zypper-notify-user.service
rm -f $HOME/.config/systemd/user/zypper-notify-user.timer
rm -f $HOME/.local/bin/zypper-notify-updater.py
rm -f $HOME/.local/bin/zypper-run-install
rm -f $HOME/.local/bin/zypper-with-ps
rm -f $HOME/.local/bin/zypper-view-changes
rm -f $HOME/.config/fish/conf.d/zypper-wrapper.fish
rm -f $HOME/.config/fish/conf.d/zypper-auto-helper-alias.fish

# Remove shell aliases from config files
sed -i '/# Zypper wrapper for auto service check/d' $HOME/.bashrc $HOME/.zshrc 2>/dev/null
sed -i '/alias zypper=/d' $HOME/.bashrc $HOME/.zshrc 2>/dev/null
sed -i '/# zypper-auto-helper command alias/d' $HOME/.bashrc $HOME/.zshrc 2>/dev/null
sed -i '/alias zypper-auto-helper=/d' $HOME/.bashrc $HOME/.zshrc 2>/dev/null

# 4. (Optional) Remove logs
sudo rm -rf /var/log/zypper-auto
rm -rf $HOME/.local/share/zypper-notify
rm -rf $HOME/.cache/zypper-notify

# 5. Reload the systemd daemons
sudo systemctl daemon-reload
systemctl --user daemon-reload
```
