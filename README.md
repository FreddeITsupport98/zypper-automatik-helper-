![Zypper Auto-Helper screenshot](icon/Screenshot_20260205_091408.png)

# Zypper Auto-Downloader for Tumbleweed

![openSUSE Tumbleweed](https://img.shields.io/badge/openSUSE-Tumbleweed-73ba25?style=for-the-badge&logo=opensuse)

Welcome to the **Zypper Auto-Helper** community project – a batteries‑included automation layer for openSUSE Tumbleweed that turns "`zypper dup` nights" into a quick, predictable routine.

This repository provides a robust `systemd` architecture and CLI that:
- Pre‑downloads Tumbleweed snapshots safely in the background.
- Notifies you like a modern desktop app (with snooze, progress bars, and rich actions).
- Wraps manual `zypper dup` runs with extra safety rails, service checks, and reboot advice.
- Adds self‑healing and diagnostics so you can trust it on real, everyday systems.

If you like opinionated, **safety‑first** automation – with clear logs and an easy way back via Snapper – you’re in the right place.

-----

## 🐞 Reporting Issues?

**If you need help, please include the relevant logs!** See the [Reporting Issues on GitHub](#reporting-issues-on-github) section for which logs to include.

-----

## 🎯 The Goal

On a rolling-release distribution like Tumbleweed, updates are frequent and can be large. This script automates the most time-consuming part: the **download**.

It runs `zypper dup --download-only` in the background, but only when it's safe. When you're ready to update, the packages are already cached. This turns a potential 10-minute download and update process into a 1-minute, authenticated installation.

## ✨ Key Features (v58 Architecture)

* **Safe Duplicate RPM Cleanup (Wrapper + CLI):** Automatically and manually cleans up broken duplicate RPMs that block `zypper dup`, with:
    * **Whitelist mode** for known-problematic third‑party apps (default: `insync`).
    * Optional **third‑party mode** that only touches non‑SUSE vendors and never touches critical packages (`kernel-*`, `glibc`, `systemd`, `filesystem`, `gpg-pubkey*`, etc.).
    * Architecture‑aware detection (`NAME + ARCH`) so legitimate multi‑arch installs (x86_64 + i686) are never flagged as conflicts.
    * `rpm -e --test --noscripts` dependency pre‑flight before every erase.
    * **Automatic Snapper snapshot** in the wrapper before third‑party cleanup, and optional snapshot in manual mode.
    * Unified audit log at `/var/log/zypper-auto/duplicate-cleanup.log` for both automatic wrapper cleanup and `zypper-auto-helper --rm-conflict` runs.
* **Modern Reboot Detection:** After `zypper dup`, the wrapper runs `zypper ps -s` to show services using old libraries **and** calls `zypper needs-reboot` to tell you explicitly whether a system reboot is required (with an optional `notify-send` desktop alert).
* **Fish-Safe `sudo zypper`:** A small Fish `sudo` wrapper transparently redirects `sudo zypper ...` to the safe `zypper-with-ps` wrapper, so both `zypper dup` and `sudo zypper dup` always benefit from the same safety logic.

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
* **Soar / Flatpak / Snap / Homebrew / pipx Integration (v55–v61):** Every `zypper dup` / `zypper update` run via the helper or wrapper automatically chains Flatpak updates, Snap refresh (if installed), a Soar stable-version check + `soar sync` + `soar update` (if installed), a Homebrew `brew update` followed by conditional `brew upgrade`, **and** (when enabled) `pipx upgrade-all` so that system packages, runtimes, Soar-managed apps, Homebrew formulae, and pipx‑managed Python CLI tools stay aligned after system updates. Optional helper commands are provided via `zypper-auto-helper --soar`, `zypper-auto-helper --brew`, and `zypper-auto-helper --pip-package` (alias: `--pipx`).
* **Snap/Flatpak Setup Helper (v62+):** `zypper-auto-helper --setup-SF` installs/configures Snapd and Flatpak (including common Flatpak remotes like Flathub) and, when `discover6` (KDE Discover) is present, optionally removes it with a detailed explanation so that only the zypper-based helper manages system updates and offline upgrades.
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
* **Stage-Based Download Progress (v50–v61):** Real-time notifications showing download stages:
    * **"Checking for updates..."** - Refreshing repositories
    * **"Downloading updates... (X of Y packages)"** - Active download with real-time progress
    * **(Download complete)** - Completion info is attached to the main **"Updates Ready"** notification to avoid duplicate popups
    * **"Updates Ready to Install"** - Ready to apply with snapshot info
* **Smart Download Detection (v49–v61):** Only downloads and notifies when updates are actually available, eliminating false "downloading" notifications. In v61 the notifier additionally re-checks `zypper dup --dry-run` when the downloader reports `complete:` and suppresses the "✅ Downloads Complete!" popup if there are no remaining updates, avoiding stale completion notifications after you have already installed everything manually.
* **Safe Downloads (Root):** The downloader service is a simple, root-only worker that always runs at low priority and logs to `/var/log/zypper-auto`; network/AC safety decisions are enforced in the user-space notifier.
* **Smart Safety Logic (User):** The notifier Python script uses `/sys/class/power_supply`, `upower` and `nmcli` with extra heuristics to distinguish real laptops from desktops/UPS setups (including laptops that only expose a battery device without a separate `line_power` entry), and to avoid false "metered" or "on battery" positives. On laptops it only refreshes/inspects updates on AC power and non‑metered connections.
* **Fixed Battery Detection (v48+):** Corrected logic that was incorrectly identifying laptops as desktops, now detects batteries via `/sys/class/power_supply` with an `upower` fallback.
* **Persistent Notifications (v48):** Update notifications now persist until user interaction or timeout by keeping a GLib main loop active.
* **Environment Change Awareness (v53):** Tracks when your machine switches between AC/battery or metered/unmetered connections and shows "updates paused" / "conditions now safe" notifications accordingly.
* **Snooze & Quiet Hours (v53):** Lets you snooze update reminders for 1h, 4h, or 1 day via notification buttons, with state stored under `~/.cache/zypper-notify`.
* **Safety Preflight Checks (v53):** Before showing "Install" it checks root filesystem free space, Btrfs snapshots (snapper), and basic network health and adds warnings to the notification if something looks risky.
* **Post-Update Service Check:** After updates complete, automatically runs `zypper ps -s` to show which services need restart and provides reboot guidance.
* **Comprehensive Logging:** Full debug logging for installation, system services, and user notifier with automatic log rotation and persistent status tracking.
* **Clickable Install:** The rich, Python-based notification is **clickable**. Clicking the "Install" button runs `~/.local/bin/zypper-run-install`, which opens a terminal and executes `pkexec zypper dup`.
* **Automatic Upgrader:** The installer is idempotent and will **cleanly stop, disable, and overwrite any previous version** (v1–v58) to ensure a clean migration.
* **Dependency Checks:** The installer verifies all necessary dependencies (`nmcli`, `upower`, `python3-gobject`, `pkexec`) are present and offers to install them if they are missing.
* **Safe Scripted Uninstaller (v58+):** New `--uninstall-zypper-helper` mode (alias: `--uninstall-zypper`) in `zypper-auto.sh` / `zypper-auto-helper` removes all helper services, timers (including the auto-verify health-check timer), binaries, user scripts, aliases, logs and caches with a confirmation prompt by default, plus advanced flags:
*  * `--yes` / `-y` / `--non-interactive` – skip the prompt and proceed non-interactively
*  * `--dry-run` – show exactly what would be removed without making any changes
*  * `--keep-logs` – leave `/var/log/zypper-auto` installation/service logs intact (including the `status.html` dashboard) while still clearing caches
*  * `--keep-hooks` – leave custom hook scripts under `/etc/zypper-auto/hooks` intact
*  * It **never** removes `snapd`, Flatpak, Soar, Homebrew itself, or any zypper configuration such as `/etc/zypp/zypper.conf`.

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
    * It will **only** start if `ConditionACPower=true` is met, and it will **skip** running on metered connections (detected via `nmcli` / NetworkManager).
* **Timer:** `/etc/systemd/system/zypper-autodownload.timer`
*    * Default schedule is derived from the config option `DL_TIMER_INTERVAL_MINUTES` in `/etc/zypper-auto.conf` (allowed values: 1,5,10,15,30,60).
*    * For example:
*        * `1`  → runs minutely
*        * `10` → runs every 10 minutes (`OnCalendar=*:0/10`)
*        * `60` → runs hourly (`OnCalendar=hourly`)
*
### 3. Periodic Verification / Auto-Repair Service

In addition to the downloader, a small root service periodically runs the same
12-point verification and auto-repair logic as `zypper-auto-helper --verify`:

* **Service:** `/etc/systemd/system/zypper-auto-verify.service`
* Runs `zypper-auto-helper --verify` as a oneshot root service.
    * Logs to `/var/log/zypper-auto/service-logs/verify.log`.
    * Uses `python3 -B -m py_compile` for syntax checks so verification still works under systemd hardening (it won’t try to write `__pycache__/*.pyc` into the user’s home).
    * Automatically resets failed states for the core units it manages and,
      when configured, sends a short desktop notification whenever it fixes
      one or more issues.
    * Performs safety checks such as cleaning up stale `/run/zypp.pid`
      locks (when the PID is no longer running) and running
      `zypper clean --all` when free space on `/` falls below ~1 GiB.
* **Timer:** `/etc/systemd/system/zypper-auto-verify.timer`
    * Default schedule is derived from `VERIFY_TIMER_INTERVAL_MINUTES` in
      `/etc/zypper-auto.conf` (allowed values: `1,5,10,15,30,60`). The
      installer converts this into a simple calendar schedule in the same
      way as the downloader timer (minutely, hourly, or `*:0/N`).

### 4. The Notifier (User Service)

* **Service:** `~/.config/systemd/user/zypper-notify-user.service`
    * Runs the Python script `~/.local/bin/zypper-notify-updater.py`.
    * Because it runs in user-space, it has the correct D-Bus environment variables to display notifications reliably.
* **Timer:** `~/.config/systemd/user/zypper-notify-user.timer`
    * Default schedule is derived from `NT_TIMER_INTERVAL_MINUTES` in `/etc/zypper-auto.conf` (same allowed values as above).
    * By changing `NT_TIMER_INTERVAL_MINUTES` (e.g. to 10 or 60) and re-running the installer, you can control how often the notifier checks and pops notifications.

### 5. The "Brains": `~/.local/bin/zypper-notify-updater.py`

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
zypper-auto-helper --help           # Show help
zypper-auto-helper --verify         # Run health check and auto-repair
zypper-auto-helper --repair         # Alias for --verify
zypper-auto-helper --diagnose       # Alias for --verify
zypper-auto-helper --check          # Syntax check only
zypper-auto-helper install          # Reinstall/upgrade
zypper-auto-helper --reset-config   # Reset /etc/zypper-auto.conf to documented defaults (with backup)
zypper-auto-helper --reset-downloads  # Clear cached download/notifier state and restart timers (alias: --reset-state)

# Optional helpers
zypper-auto-helper --soar           # Install/upgrade the optional Soar CLI helper
zypper-auto-helper --brew           # Install/upgrade Homebrew (brew) for the system/user
zypper-auto-helper --pip-package    # Install/guide pipx and manage Python CLI tools (alias: --pipx)

# Diagnostics & debugging
zypper-auto-helper debug            # Interactive debug/diagnostics tools menu
zypper-auto-helper --logs           # Show tails of installer, service, and notifier logs
zypper-auto-helper --live-logs      # Follow installer/service/notifier logs in real time
zypper-auto-helper --diag-logs-on   # Enable background diagnostics follower (aggregated diag-YYYY-MM-DD.log)
zypper-auto-helper --diag-logs-off  # Disable diagnostics follower
zypper-auto-helper --snapshot-state # Capture one-shot diagnostics snapshot into today's diag log
zypper-auto-helper --diag-bundle    # Create compressed diagnostics bundle tarball in your home
zypper-auto-helper --show-logs      # Open diagnostics logs folder in a file manager (when available)
zypper-auto-helper --test-notify    # Send a test desktop notification to verify GUI/DBus wiring

# Scripted uninstaller
zypper-auto-helper --uninstall-zypper-helper  # Remove only this helper's services/scripts/logs (alias: --uninstall-zypper)
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
    `ENABLE_BREW_UPDATES` / `ENABLE_PIPX_UPDATES` – `true` / `false` flags to
    control whether Flatpak, Snap, Soar, Homebrew, and pipx helpers run after
    `zypper dup`. When `ENABLE_PIPX_UPDATES=true` and `pipx` is installed, the
    wrapper and Ready‑to‑Install helper automatically run `pipx upgrade-all`
    after system updates to keep Python command‑line tools up to date.

- **Timer intervals**
  - `DL_TIMER_INTERVAL_MINUTES` – how often the root downloader runs
    (allowed **only**: `1,5,10,15,30,60`; any other value is ignored and
    replaced with a safe default).
  - `NT_TIMER_INTERVAL_MINUTES` – how often the user notifier runs (same
    allowed set and behaviour as above).
  - `VERIFY_TIMER_INTERVAL_MINUTES` – how often the root verification/auto‑repair
    service runs (again, allowed **only**: `1,5,10,15,30,60`).
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

- **Lock handling & downloader behaviour**
  - `LOCK_RETRY_MAX_ATTEMPTS` – how many times the Ready-to-Install helper should
    retry when zypper/Yast holds the system management lock before giving up and
    showing a friendly message. Each attempt waits a bit longer than the previous
    one. Default: `10`.
  - `LOCK_RETRY_INITIAL_DELAY_SECONDS` – base delay (in seconds) used for the first
    lock retry. Subsequent retries multiply this base (1×, 2×, 3×, …). Set to `0`
    to fail fast when the lock is held. Default: `1`.
  - `LOCK_REMINDER_ENABLED` – when `true` (default), the notifier shows a small
    "Updates paused while zypper is running" notification on every check while
    zypper/YaST holds the system management lock. When `false`, lock situations
    are logged but no desktop popup is shown.
  - `NO_UPDATES_REMINDER_REPEAT_ENABLED` – when `true` (default), identical
    "No updates found" notifications may be re-shown on later checks while the
    system remains fully up to date. When `false`, the "No updates" message is
    shown once per state and then suppressed until new updates appear.
  - `UPDATES_READY_REMINDER_REPEAT_ENABLED` – when `true` (default), identical
    "Snapshot XXXX Ready" / "Updates ready" notifications may be re-shown on
    later checks while the same snapshot is still pending. When `false`, each
    "Updates ready" state only generates one popup until the snapshot changes.
  - `VERIFY_NOTIFY_USER_ENABLED` – when `true` (default), the periodic
    verification/auto‑repair service sends a short desktop notification when it
    detects and fixes at least one issue; when `false`, verification remains
    fully automatic but quiet.
  - `DOWNLOADER_DOWNLOAD_MODE` – controls how the background downloader behaves.
    This value is **case-sensitive** and must be exactly:
      - `full`        – (default) run `zypper dup --download-only` to prefetch all
        packages into the cache.
      - `detect-only` – only run `zypper dup --dry-run` to detect whether updates
        are available; no pre-download is done. Useful on bandwidth-limited
        systems or when you only want notifications and manual installs.

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
    `zypper-auto-helper --reset-config`.
  - Applies safe defaults for those keys at runtime so the installer and
    services continue to work.

If you see a warning that `/etc/zypper-auto.conf` is from an older version and
lists missing keys, the **recommended fix** is:

```bash
zypper-auto-helper --reset-config
sudo ./zypper-auto.sh install
```

This backs up your existing config and regenerates it with all current options
and comments.

-----

## 🛡️ Safe Duplicate RPM Cleanup & Conflict Resolution

Broken third‑party RPMs (especially those with buggy `%preun`/`%postun` scripts) can block `zypper dup` with errors like "failed to execute /usr/bin/fish" or "package specifies multiple versions". The helper includes a **two‑layer duplicate cleanup system** designed to fix these problems safely.

### Modes and Configuration

Controlled via `/etc/zypper-auto.conf`:

- `AUTO_DUPLICATE_RPM_CLEANUP_PACKAGES="insync ..."`
  - Whitelist of package **names** that are allowed to be auto‑cleaned when multiple versions are installed.
  - Intended for leaf, third‑party apps you know are safe to remove with `--noscripts` (e.g. `insync`).
- `AUTO_DUPLICATE_RPM_MODE="whitelist|thirdparty|both"`
  - `whitelist` (default, safest): only cleans packages in `AUTO_DUPLICATE_RPM_CLEANUP_PACKAGES`.
  - `thirdparty`: auto‑detects duplicate packages whose **Vendor** is *not* SUSE/openSUSE/Packman/NVIDIA/Intel/OBS and attempts to clean older versions.
  - `both`: runs whitelist cleanup first, then third‑party cleanup.

### Safety Rails (Apply to Both Wrapper & CLI)

Regardless of mode, duplicate cleanup obeys the following guard rails:

- **Arch-aware duplicates:** Duplicates are detected per `NAME + ARCH` so legitimate multi‑arch installs (e.g. `foo.x86_64` + `foo.i686`) are preserved.
- **Critical package protection:** Names matching
  `^kernel-`, `glibc`, `systemd`, `grub`, `shim`, `mokutil`, `nvidia`, `filesystem`
  are never touched, even in third‑party mode.
- **GPG key protection:** Packages starting with `gpg-pubkey` are always skipped.
- **Trusted vendor whitelist:** Vendors containing `openSUSE`, `SUSE`, `Packman`, `NVIDIA`, `Intel`, `obs://build.opensuse.org`, etc. are considered trusted; their duplicates are **never** auto‑removed in third‑party mode.
- **Dependency pre-flight:** Every candidate removal runs
  `rpm -e --test --noscripts` (via sudo when needed). If the test reports
  dependency failures, the package is skipped and logged.
- **Sanity limit:** If more than 10 distinct duplicate `(NAME, ARCH)` pairs are
  detected, the cleanup aborts with a warning instead of performing mass
  deletions (this is treated as a sign of a possibly corrupted RPM database).

### Automatic Cleanup (Wrapper: `zypper-with-ps`)

When you run `zypper dup` (or, in Fish, even `sudo zypper dup`) the helper
actually invokes the wrapper script `~/.local/bin/zypper-with-ps`, which:

1. Publishes a short "downloading" status for the GUI notifier.
2. Waits politely if another zypper/YaST instance holds the system management lock.
3. Runs **whitelist and/or third‑party duplicate cleanup** according to
   `AUTO_DUPLICATE_RPM_MODE` and the safety rails above.
4. In `thirdparty`/`both` modes, takes a **Snapper single snapshot** (`-t single -p`)
   before cleaning third‑party duplicates, when `snapper` is available and idle.
5. Runs your requested `zypper` command (`dup`, `dist-upgrade`, or `update`).
6. Executes the post‑update helper chain (Flatpak, Snap, Soar, Homebrew, pipx).
7. Runs `zypper ps -s` and the modern reboot check (`zypper needs-reboot`) and
   prints a clear summary of services to restart and whether a full reboot is
   required.

All automatic duplicate cleanups performed by the wrapper are written to a
persistent audit log:

- **Audit file:** `/var/log/zypper-auto/duplicate-cleanup.log`
  - Includes timestamps, whether the cleanup came from the wrapper or manual
    CLI, which packages were removed or skipped, vendor information, and
    snapshot creation status.

### Manual Cleanup (CLI: `zypper-auto-helper --rm-conflict`)

Sometimes you want to **fix conflicts first**, then run updates normally. For
that, use the dedicated CLI mode:

```bash
# Run as root or via the installed alias (which adds sudo automatically)
zypper-auto-helper --rm-conflict
```

This command:

1. Prints the current duplicate cleanup mode (`whitelist`, `thirdparty`, or `both`).
2. Attempts to create a **Snapper single snapshot** with description
   `zypper-auto: duplicate RPM cleanup (--rm-conflict)` before any changes
   (if `snapper` is installed and not already running).
3. Runs the same whitelist + optional third‑party cleanup logic as the wrapper
   (including all safety rails: critical package/GPG/vendor protection,
   arch‑aware duplicates, dependency pre‑flight, and sanity limits).
4. Logs all actions both to the normal install log and to the unified audit log
   at `/var/log/zypper-auto/duplicate-cleanup.log` with a `[rm-conflict]` tag.

**Recommended workflow when you hit a stubborn RPM conflict:**

```bash
# 1. Clean up safe duplicates first
zypper-auto-helper --rm-conflict

# 2. Then run your normal upgrade
zypper dup
# or if you prefer explicit sudo (especially in Fish)
sudo zypper dup
```

In Fish, the installed `sudo` wrapper ensures that `sudo zypper ...` still goes
through the safe `zypper-with-ps` wrapper, so you get the same duplicate cleanup,
post‑update helpers, and reboot guidance as with plain `zypper ...`.

-----

## 🏃 Usage

1.  **Wait.** The services run in the background. By default, both the downloader and notifier run every minute. You can change their frequency via `/etc/zypper-auto.conf` (`DL_TIMER_INTERVAL_MINUTES` / `NT_TIMER_INTERVAL_MINUTES`) and re-run `sudo ./zypper-auto.sh install`.
2.  **Get Notified.** You will get a notification *only* when new updates are pending.
3.    > **Snapshot 20251110-0 Ready**
4.    > 12 updates are pending. Click 'Install' to begin.
5.  **Install.** Click the **"Install"** button in the notification. This will open a terminal and prompt you for authentication to run `zypper dup`.

### Quick Status & Safe Reset

You can check the current status and, if needed, safely clear stale state:

```bash
# Run comprehensive health check and auto-repair
zypper-auto-helper --verify

# Check installation/system status
cat /var/log/zypper-auto/last-status.txt

# Check notifier status
cat ~/.local/share/zypper-notify/last-run-status.txt

# Check download progress
cat /var/log/zypper-auto/download-status.txt

# If notifications or status get "stuck", clear cached state and restart timers
zypper-auto-helper --reset-downloads   # alias: --reset-state
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

## 👩‍💻 Developer / Contributor Testing

This repository includes two small helpers designed to make reproducing and
debugging behaviour easier for contributors:

### 1. Notification UI Test Harness (`test.py`)

Located in the repo root, `test.py` exercises the full notification flow
without touching systemd units or zypper itself:

```bash
python3 test.py
```

What it does:

- Simulates the main **happy path** notification stages:
  - "Checking for updates…"
  - "Downloading updates…" with a progress bar
  - "✅ Downloads Complete!" summary
  - Persistent "Snapshot XXXXXXXX Ready" notification with **Install**,
    **View Changes**, and **Snooze 1h/4h/1d** buttons.
- Simulates the main **error/edge-case** notifications:
  - Solver/interaction error ("Updates require your decision") with an
    **Install Now** action.
  - PolicyKit/authentication failure ("Update check failed").
  - Config warning ("zypper-auto-helper config warnings – run
    `zypper-auto-helper --reset-config`").
- Uses the same `on_action` callback shape as the real notifier so that
  clicking **Install** attempts to run `~/.local/bin/zypper-run-install` or,
  if missing, falls back to opening `konsole`.

All activity is logged to `test.log` in the repo root (ignored by Git). Each
run is wrapped in clear markers:

```text
================ RUN 20260105-212612 START ================
...
================ RUN 20260105-212612 END ==================
```

The log includes:

- Python version and key environment variables (`DISPLAY`, `WAYLAND_DISPLAY`,
  `XDG_SESSION_TYPE`, `USER`, `HOME`, `PWD`).
- For each notification: title, body preview, icon name, timeout, and (when
  relevant) the helper script path that would be launched.
- For each action click: action id, resolved script path, whether it exists and
  is executable, PID of any launched helper/terminal process, and full
  tracebacks for any failures.

### 2. Integration Test Script (`integration-test.sh`)

Also in the repo root, `integration-test.sh` performs a higher-level
integration test of the installed helper, timers and configuration.

> **Important:** This script is **non-destructive** with respect to your
> persistent configuration. It temporarily tweaks `/etc/zypper-auto.conf` to
> inject a known-bad value, but always restores your original config before
> exiting (even if a later step fails).

Run it as root:

```bash
cd /path/to/zypper-automatik-helper-
sudo ./integration-test.sh
```

What it checks:

- Presence and executability of core components:
  - `/usr/local/bin/zypper-auto-helper`
  - `/usr/local/bin/zypper-download-with-progress`
  - User scripts such as `~/.local/bin/zypper-notify-updater.py`,
    `~/.local/bin/zypper-run-install`, `~/.local/bin/zypper-with-ps` (if
    installed for the primary user).
- Root/systemd units:
  - `zypper-autodownload.timer` / `zypper-autodownload.service` (enabled/active).
  - `zypper-cache-cleanup.timer` / `zypper-cache-cleanup.service`.
- User systemd units (for the primary non-root user, when detectable):
  - `zypper-notify-user.timer` (enabled/active).
- CLI health:
  - `zypper-auto-helper --check` (syntax/self-check).
  - `zypper-auto-helper --verify` (12‑point verification and auto‑repair).

Config validation test:

- Ensures `/etc/zypper-auto.conf` exists (running `zypper-auto-helper install`
  if needed).
- Backs it up to a timestamped file such as
  `/etc/zypper-auto.conf.integration-backup-YYYYMMDD-HHMMSS`.
- Rewrites `DOWNLOADER_DOWNLOAD_MODE` to an intentionally invalid value
  (`"INVALID-MODE"`).
- Runs a full `zypper-auto-helper install` to force `load_config` and
  `CONFIG_WARNINGS` to execute.
- Locates the newest `install-*.log` in `/var/log/zypper-auto/` and verifies
  that:
  - An `Invalid DOWNLOADER_DOWNLOAD_MODE=...` line appears.
  - An aggregate warning about one or more invalid settings in
    `/etc/zypper-auto.conf` was recorded.
- Restores the original `/etc/zypper-auto.conf` from the backup and runs a
  final `zypper-auto-helper --check` to confirm the restored config is healthy.

The integration script writes a concise, timestamped console log and is safe to
run repeatedly on development systems.

-----

## 🧪 Advanced Diagnostics & CLI Tools

The helper includes a small diagnostics toolkit built around aggregated log followers, one-shot snapshots, and compact bundles. These tools are especially useful when filing bug reports or debugging tricky issues.

### Core Diagnostics Commands

- `zypper-auto-helper --logs`
  - Prints the last ~40 lines from:
    - The most recent installer log under `/var/log/zypper-auto/install-*.log`
    - All helper service logs under `/var/log/zypper-auto/service-logs/*.log`
    - The notifier log `~/.local/share/zypper-notify/notifier-detailed.log` (when present)
  - Safe to run repeatedly; does not follow logs, just shows current tails.

- `zypper-auto-helper --live-logs`
  - Follows logs in real time until you press `Ctrl+C`.
  - If the diagnostics follower is running and today's aggregated file exists, it follows:
    - `/var/log/zypper-auto/diagnostics/diag-YYYY-MM-DD.log`
  - Otherwise, it follows the same set of logs as `--logs` (installer + service + notifier logs) with `tail -F`.

- `zypper-auto-helper --diag-logs-on` / `--diag-logs-off`
  - `--diag-logs-on` starts a tiny background systemd unit (`zypper-auto-diag-logs.service`) that:
    - Follows helper service logs and the notifier log (when present).
    - Also follows the helper's `trace.log`, which includes mirrored structured install/verify output.
      This ensures the aggregated diagnostics log continues to capture new installs even though each
      install uses a new `install-YYYYMMDD-HHMMSS.log` filename.
    - Tags each line with its source (`[SRC=INSTALL]`, `[SRC=DOWNLOADER]`, `[SRC=NOTIFIER]`, etc.).
    - Writes everything into a daily diagnostics file:
      - `/var/log/zypper-auto/diagnostics/diag-YYYY-MM-DD.log`
      - The writer is **auto-rotating**: at midnight it seamlessly starts writing to the new day's file
        without needing a service restart.
    - Keeps only ~10 days of diagnostics logs, pruning older files automatically.
  - `--diag-logs-off` stops the background follower and marks diagnostics as disabled in `last-status.txt`.

- `zypper-auto-helper --snapshot-state`
  - Captures a one-shot snapshot of the helper and system state into today's diagnostics log, including:
    - `systemctl status` for core system units (`zypper-autodownload.*`, `zypper-auto-verify.*`).
    - `systemctl --user status` for the notifier units (for the primary user).
    - The current `download-status.txt` contents and metadata (mtime, size).
    - The user's `last-run-status.txt` from the notifier (when present).
    - Root filesystem free space and basic NetworkManager connectivity summary.
    - A truncated (`head -n 50`) `zypper dup --dry-run` preview.
  - All of this is appended under a clearly delimited `SNAPSHOT STATE` block with the current `RUN=...` identifier.

- `zypper-auto-helper --diag-bundle`
  - Creates a single compressed tarball containing the most relevant diagnostics artifacts, written to your home directory:
    - `~/zypper-auto-diag-YYYYMMDD-HHMMSS.tar.xz`
  - Contents typically include:
    - All diagnostics logs from `/var/log/zypper-auto/diagnostics/` (last ~10 days).
    - The current `last-status.txt` summary.
    - Up to the 3 most recent `install-*.log` files.
    - The notifier's `notifier-detailed.log` and `last-run-status.txt` (when present).
    - The current `/etc/zypper-auto.conf` and the installer script itself for version context.
  - Ideal for attaching to GitHub issues (after redacting any personal data).

- `zypper-auto-helper --show-logs`
  - Ensures `/var/log/zypper-auto/diagnostics/` exists and is user-readable.
  - When `xdg-open` is available, opens the diagnostics folder in your default file manager as the primary user, so you can browse logs graphically.

- `zypper-auto-helper --test-notify`
  - Runs a self-test of the desktop notification pipeline for the primary user.
  - Uses the real notifier Python script (`zypper-notify-updater.py --test-notify`) to send a test notification via D-Bus.
  - Useful to confirm GUI/notification wiring without waiting for real updates.

- `zypper-auto-helper debug` (or `--debug-menu`)
  - Launches an interactive TUI-style menu with options to:
    - Toggle the diagnostics follower on/off.
    - View live diagnostics logs (either the aggregated daily log or raw installer/service/notifier logs).
    - Capture a diagnostics snapshot (`--snapshot-state`).
    - Create a diagnostics bundle (`--diag-bundle`).
    - Open the diagnostics logs directory in a file manager.
    - Run the notification self-test (`--test-notify`).
  - Designed for humans: it avoids killing the helper process when exiting log views and always returns cleanly to the menu.

These tools do **not** modify your configuration or timers; they only read logs, inspect status, and, in the case of the follower, create additional diagnostics log files under `/var/log/zypper-auto/diagnostics/`.

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

#### Helper (Installer / Verify / Repair) Log Format

The bash helper writes structured log lines like:

```text
[INFO] 2026-02-08 20:29:27 [RUN=R20260208T202927-12345] Starting installation...
[WARN] 2026-02-08 20:29:30 [RUN=R20260208T202927-12345] Config key missing: DUP_EXTRA_FLAGS (using safe default)
[ERROR] 2026-02-08 20:29:34 [RUN=R20260208T202927-12345] zypper dup failed: lock held by YaST
```

Notes:
- `RUN=...` is a per-invocation correlation ID. It lets you grep *all* related lines across install logs, the aggregated daily diagnostics log, and the journal.
- When a GUI action triggers a root operation, some lines may also include `TID=...` (Trace ID) so you can correlate the click/action with the backend work.

#### Notifier (Python) Log Format

The notifier’s detailed log now includes a run tag too:

```text
[2026-02-08 20:29:35] [INFO] [RUN=...] Starting notifier check
```

- If the notifier is started by systemd, it will automatically use systemd’s `INVOCATION_ID` as its RUN ID.
- If the helper triggers a notifier action directly (e.g. `--test-notify`), it passes `ZNH_RUN_ID` so the Python log lines share the same `RUN=...` value as the helper.

#### Severity Levels
- `INFO` - Normal operation, status updates
- `WARN` - Non-fatal issues and degraded states (safe fallbacks)
- `DEBUG` - Detailed troubleshooting output (only emitted when debug mode is enabled)
- `ERROR` - Something went wrong, includes details
- `SUCCESS` - Operation completed successfully

#### Guarded command execution (installer / verify)

Most critical operations (systemctl enable/restart, zypper maintenance commands, etc.) are executed via a guarded wrapper that captures stdout/stderr. By default it logs a clean SUCCESS/ERROR summary line; if a command fails, its full captured output is immediately dumped to both the install log and stderr so you can see *why* it failed without tailing.

Notes:
- To also persist successful command output (very verbose), run with `--debug` or set `ZYPPER_AUTO_GUARDED_LOG_SUCCESS_OUTPUT=1`.

#### Journald / syslog integration (best-effort)

The helper emits structured lines to the system journal (without changing the existing file logs), tagged as `zypper-auto-helper`. In addition:
- The root downloader emits key lifecycle/error summaries as `[DOWNLOADER] ...` lines.
- The Python notifier emits **ERROR** lines to the journal by default (errors-only), so crashes are visible in `journalctl`.

Useful commands:

```bash
# Root/system journal (structured helper + downloader summaries + notifier errors)
journalctl -t zypper-auto-helper -n 200 --no-pager

# User notifier unit journal (stdout/stderr from the user service)
journalctl --user -u zypper-notify-user.service -n 200 --no-pager
```

#### Remote monitoring (webhooks)

You can optionally configure a webhook endpoint to receive success/failure notifications.

1) Edit `/etc/zypper-auto.conf` and set:
- `WEBHOOK_URL="..."` (leave empty to disable)

Supported formats are auto-detected:
- Discord webhooks
- Slack incoming webhooks
- ntfy.sh topics

Test it (one-shot):

```bash
sudo WEBHOOK_TITLE="Test" WEBHOOK_MESSAGE="Hello from zypper-auto-helper" zypper-auto-helper --send-webhook
```

Security note: treat `WEBHOOK_URL` like a secret token.

#### Extensibility (pre/post hook scripts)

Drop executable hook scripts into:
- `/etc/zypper-auto/hooks/pre.d/`  (runs before interactive updates)
- `/etc/zypper-auto/hooks/post.d/` (runs after successful interactive updates)

The installer also drops safe **template examples** (not executable) so users can quickly enable hooks:
- `/etc/zypper-auto/hooks/pre.d/00-example-pre.sh.example`
- `/etc/zypper-auto/hooks/post.d/00-example-post.sh.example`

Enable a template by copying it to a new filename and making it executable:

```bash
sudo cp /etc/zypper-auto/hooks/pre.d/00-example-pre.sh.example /etc/zypper-auto/hooks/pre.d/10-my-pre-hook.sh
sudo chmod +x /etc/zypper-auto/hooks/pre.d/10-my-pre-hook.sh

sudo cp /etc/zypper-auto/hooks/post.d/00-example-post.sh.example /etc/zypper-auto/hooks/post.d/90-my-post-hook.sh
sudo chmod +x /etc/zypper-auto/hooks/post.d/90-my-post-hook.sh
```

Hook failures are **non-fatal** and will be logged.

#### HTML status dashboard

A simple static status page is generated (when `DASHBOARD_ENABLED=true`):
- Root copy: `/var/log/zypper-auto/status.html`
- User copy: `~/.local/share/zypper-notify/status.html`

Open it in your browser:

```bash
xdg-open ~/.local/share/zypper-notify/status.html
```

You can regenerate it anytime:

```bash
sudo zypper-auto-helper --dashboard
```

#### Console output (interactive)

When you run the helper manually in a terminal, it also prints a readable, color-coded console stream, while keeping the on-disk logs plain text.

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

**Problem: "Install Now" action does nothing / closes immediately**
- Check the Ready-to-Install helper log: `tail -n 200 ~/.local/share/zypper-notify/run-install.log`
- Safe smoke test (does NOT run updates):
  - `ZYPPER_TRACE_ID=TEST-123 ZNH_RUN_ID=TEST-123 ~/.local/bin/zypper-run-install --selftest`
  - Or, to mimic the notifier launch style: `systemd-run --user --scope --setenv=ZYPPER_TRACE_ID=TEST-123 --setenv=ZNH_RUN_ID=TEST-123 ~/.local/bin/zypper-run-install --selftest`

**Problem: Updates skipped on laptop**
- Check if on battery: `cat ~/.local/share/zypper-notify/notifier-detailed.log | grep "AC power"`
- Check for metered connection: `grep "metered" ~/.local/share/zypper-notify/notifier-detailed.log`
- The system is working as designed - updates only run on AC power and unmetered connections

### Version History

- **v62** (2026-01-21): **State Reset Helper & Typo-Safe CLI**
  - 🧼 **NEW: Download/notifier state reset helper** – `zypper-auto-helper --reset-downloads` (alias: `--reset-state`) now clears downloader state files (`download-status.txt`, `download-last-check.txt`, `download-start-time.txt`, `dry-run-last.txt`) and user notifier caches (`last-run-status.txt`, `last_notification.txt`, etc.), then reloads and restarts the core timers/services. This is a safe, "soft" reset for fixing stale "X updates pending" notifications without reinstalling.
  - 🧯 **IMPROVED: CLI safety for typos** – unknown option-like arguments (such as `--bre` or `-reset`) are now rejected **before** any installation/sanity work runs, printing a short "Unknown option" message and a pointer to `--help` instead of silently falling back to a full install.

- **v61** (2026-01-09): **pipx Integration, Reminder Controls & Smarter Download Completion**
  - 🐍 **NEW: pipx helper and automatic upgrades** – added a dedicated `zypper-auto-helper --pip-package` (alias: `--pipx`) mode that installs `python3-pipx` via zypper (on request), runs `pipx ensurepath`, and can optionally run `pipx upgrade-all` for the target user. This makes pipx the recommended/default way to manage Python command‑line tools like `yt-dlp`, `black`, `ansible`, and `httpie`.
  - 📦 **NEW: Config‑driven pipx post‑update step** – a new `ENABLE_PIPX_UPDATES` flag in `/etc/zypper-auto.conf` controls whether the zypper wrapper (`zypper-with-ps`) and the Ready‑to‑Install helper (`zypper-run-install`) run `pipx upgrade-all` after each `zypper dup`, so your pipx‑managed tools stay in sync with system updates.
  - 🔔 **NEW: Reminder control flags** – added `LOCK_REMINDER_ENABLED`, `NO_UPDATES_REMINDER_REPEAT_ENABLED`, and `UPDATES_READY_REMINDER_REPEAT_ENABLED` so you can choose whether lock notifications, "No updates found" messages, and "Updates ready" popups repeat on every check or only once per state.
  - 🩺 **NEW: Configurable auto‑verification timer & repair notifications** – added `VERIFY_TIMER_INTERVAL_MINUTES` to control how often the root health‑check service runs (using the same minute‑based presets as other timers) and `VERIFY_NOTIFY_USER_ENABLED` to toggle a short desktop notification whenever the periodic auto‑repair fixes at least one issue.
  - 🛠️ **IMPROVED: Auto‑repair robustness** – the verification helper now resets failed states on the core systemd units before attempting repairs, cleans up stale `/run/zypp.pid` locks when the recorded PID is no longer running, and runs `zypper clean --all` when free space on `/` falls below ~1 GiB (with a follow‑up check).
  - 🧠 **IMPROVED: "Downloads Complete" notification logic** – the notifier now re‑runs `pkexec zypper dup --dry-run` when it sees a `complete:` status from the downloader and **suppresses** the "✅ Downloads Complete!" popup if zypper reports "Nothing to do." This prevents misleading completion notifications after you have already installed all updates manually.
  - 🧹 **FIXED: duplicate Soar summary header** – the zypper wrapper no longer prints a second stray "Soar (stable) Update & Sync" header after the pipx section; Soar’s update/sync block now appears exactly once in the post‑update flow.

- **v59** (2026-01-02): **Ready-to-Install Konsole Fix & Install Helper Diagnostics**
  - 🪟 **FIXED: "Install Now" window closing immediately in Konsole** – the Ready-to-Install helper now runs via a dedicated `zypper-run-install --inner` mode inside the spawned terminal instead of relying on exported shell functions, so the Konsole window stays open reliably until you press Enter.
  - 📜 **NEW: `run-install.log` for install helper** – every Ready-to-Install run is logged to `~/.local/share/zypper-notify/run-install.log` with environment, terminal selection, and `pkexec zypper dup` status, making it much easier to debug installer-window issues.
  - 🧭 **IMPROVED: Soar detection in wrappers & helper** – the Soar post-update steps and the install helper now detect Soar from common per-user locations (like `~/.local/bin/soar` and `~/pkgforge`) before offering to install it, avoiding false "Soar is not installed" prompts when it is actually present.
  - 🧪 **IMPROVED: Test harness integration** – the Python test script and notifier paths now exercise the same helper/terminal flow as real updates, so Ready-to-Install behaviour can be reproduced and debugged consistently.

- **v58** (2025-12-31): **Scripted Uninstaller, External Config & Log Control**
  - 📝 **Short:** Safer uninstall, externalised config (including `DUP_EXTRA_FLAGS`), smarter config health warnings, and improved solver-conflict notifications that keep cached downloads and guide you to resolve conflicts.
  - 🗑️ **NEW: Safe scripted uninstaller** – `sudo ./zypper-auto.sh --uninstall-zypper-helper` (or `zypper-auto-helper --uninstall-zypper-helper`) now removes all helper components (root timers/services, helper binaries, user systemd units, helper scripts, aliases, logs and caches) in a single, logged operation with a clear header and summary.
  - ⚙️ **NEW: Advanced uninstall flags** – `--yes` / `-y` / `--non-interactive` skip the confirmation prompt for automated or non-interactive environments; `--dry-run` shows exactly what **would** be removed without making any changes; `--keep-logs` preserves `/var/log/zypper-auto` install/service logs for debugging while still clearing per-user notifier caches.
  - 🧹 **IMPROVED: Clean systemd state on uninstall** – system and user units are stopped, disabled, removed from disk, and their "failed" states cleared via `systemctl reset-failed`/`systemctl --user reset-failed` so `systemctl status` no longer reports stale failures after uninstall.
  - 🧾 **NEW: External configuration file** – `/etc/zypper-auto.conf` now holds documented settings for post-update helpers (Flatpak/Snap/Soar/Brew), log retention, notifier cache/snooze behaviour, timer intervals, and per-installation zypper behaviour, so users can tweak behaviour without editing the script.
  - 🕒 **NEW: Config-driven timer intervals** – `DL_TIMER_INTERVAL_MINUTES` and `NT_TIMER_INTERVAL_MINUTES` (allowed: `1,5,10,15,30,60`) control how often the downloader and notifier run; the installer converts these into appropriate `OnCalendar` expressions.
  - 🧩 **NEW: `DUP_EXTRA_FLAGS` support** – a new `DUP_EXTRA_FLAGS` key in `/etc/zypper-auto.conf` lets you append extra solver flags (such as `--allow-vendor-change` or `--from <repo>`) to every `zypper dup` run by the helper (background downloader and notifier) without modifying the scripts.
  - 🚨 **NEW: Config validation & reset helper** – invalid values in `/etc/zypper-auto.conf` automatically fall back to safe defaults, are logged, surfaced in `last-status.txt`, and trigger a small desktop notification suggesting `zypper-auto-helper --reset-config`. A new `--reset-config` CLI mode resets the config to defaults with a timestamped backup.

- **v57** (2025-12-28): **Soar Stable Updater, Homebrew Integration & Notification UX**
  - 🧭 **NEW: Smarter Soar stable updater** – the helper and wrapper now compare `soar --version` against GitHub’s latest stable release tag (`releases/latest`) and only re-run the official Soar installer when a newer stable version exists, then run `soar sync` and `soar update`.
  - 🍺 **NEW: Homebrew `--brew` helper mode** – `sudo ./zypper-auto.sh --brew` (or `zypper-auto-helper --brew`) now installs Homebrew on Linux for the target user if missing, or, when brew is already installed, runs `brew update` followed by `brew outdated --quiet` and `brew upgrade` only when there are outdated formulae, with clear log messages.
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
# Run from the directory containing zypper-auto.sh (as root)
sudo ./zypper-auto.sh --uninstall-zypper-helper

# Or using the installed helper command (typically without sudo via shell alias)
zypper-auto-helper --uninstall-zypper-helper
# Shorthand alias:
zypper-auto-helper --uninstall-zypper
```

By default this will:
- Stop and disable the root timers/services (`zypper-autodownload`, `zypper-cache-cleanup`, `zypper-auto-verify`)
- Stop and disable the user notifier timer/service for your user
- Remove all helper systemd unit files and helper binaries
- Remove user helper scripts, shell aliases, and Fish config snippets
- Remove custom hook scripts under `/etc/zypper-auto/hooks` (if present)
- Clear notifier caches and (by default) old helper logs under `/var/log/zypper-auto` (this includes the generated `status.html` dashboard)
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

# Keep logs under /var/log/zypper-auto for debugging (including status.html dashboard)
sudo ./zypper-auto.sh --uninstall-zypper-helper --yes --keep-logs

# Keep hook scripts under /etc/zypper-auto/hooks
sudo ./zypper-auto.sh --uninstall-zypper-helper --yes --keep-hooks

# Flags can be combined as needed
sudo ./zypper-auto.sh --uninstall-zypper-helper --dry-run --keep-logs --keep-hooks
```

### Manual Uninstall (Advanced / Legacy)

If you prefer or need to remove components manually, the equivalent steps are:

```bash
# 1. Stop and disable the root timers
sudo systemctl disable --now zypper-autodownload.timer
sudo systemctl disable --now zypper-cache-cleanup.timer
sudo systemctl disable --now zypper-auto-verify.timer

# 2. Stop and disable the user timer (run as regular user)
systemctl --user disable --now zypper-notify-user.timer

# 3. Remove all systemd files and scripts
sudo rm /etc/systemd/system/zypper-autodownload.service
sudo rm /etc/systemd/system/zypper-autodownload.timer
sudo rm /etc/systemd/system/zypper-cache-cleanup.service
sudo rm /etc/systemd/system/zypper-cache-cleanup.timer
sudo rm /etc/systemd/system/zypper-auto-verify.service
sudo rm /etc/systemd/system/zypper-auto-verify.timer
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
