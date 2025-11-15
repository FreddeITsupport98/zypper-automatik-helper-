Zypper Auto-Downloader for TumbleweedA robust systemd architecture that automates zypper dup downloads, provides persistent, battery-safe user notifications, and cleanly upgrades any previous version.🎯 The GoalOn a rolling-release distribution like Tumbleweed, updates are frequent and can be large. This script automates the most time-consuming part: the download.It runs zypper dup --download-only in the background, but only when it's safe. When you're ready to update, the packages are already cached. This turns a potential 10-minute download and update process into a 1-minute, authenticated installation.✨ Key Features (v41.1 Architecture)Decoupled Architecture: Two separate services: a "safe" root-level downloader and a "smart" user-level notifier.User-Space Notifier: The notifier now runs as a user service (~/.config/systemd/user), ensuring it has proper access to the desktop environment (D-Bus) for reliable, clickable notifications.Safe Downloads: The root downloader service will only run when you are on AC Power and not on a Metered Connection.Persistent Reminders: The user notifier service runs every hour and will always remind you if updates are pending, even on battery.Hybrid Logic: The notifier script is smart:If you're on battery/metered, it skips zypper refresh (saving power/data) and checks the local cache.If you're on AC power, it runs a full zypper refresh to get the latest info before checking.Clickable Install: The rich, Python-based desktop notification is clickable. Clicking the "Install" button immediately launches a terminal, prompts for your password via pkexec, and starts the zypper dup.Automatic Upgrader: The installer script is idempotent and will cleanly stop, disable, and overwrite any previous version (v1-v40) to ensure a clean migration.Dependency Checks: The installer verifies all necessary dependencies (nmcli, upower, python3-gobject) are present and offers to install them if they are missing.🛠️ How It Works: The v41.1 ArchitectureThis is a two-service system to provide both safety (Downloader) and persistence/user interaction (Notifier).1. The Installer: zypper-auto.shCleanup: Explicitly stops and disables all timers/services from any previous version to ensure a clean state.User Detection: Reliably determines the $SUDO_USER's home directory to place the user-specific systemd files and scripts (~/.config/systemd/user, ~/.local/bin).2. The Downloader (Root Service)This service's only job is to download packages when it's safe.Service: /etc/systemd/system/zypper-autodownload.serviceThis service runs zypper refresh and zypper dup --download-only.It will only start if ConditionACPower=true and ConditionNotOnMeteredConnection=true are met.Timer: /etc/systemd/system/zypper-autodownload.timerRuns OnBootSec=1min and OnUnitActiveSec=1h, attempting to trigger the service every hour.3. The Notifier (User Service)This service's job is to check for updates and remind you, running as your standard user.Service: ~/.config/systemd/user/zypper-notify-user.serviceRuns the Python script ~/.local/bin/zypper-notify-updater.py.Because it runs in user-space, it has the correct D-Bus environment variables to display notifications reliably.Timer: ~/.config/systemd/user/zypper-notify-user.timerRuns on a 5-minute offset (e.g., OnBootSec=5min) to ensure it runs after the downloader has had a chance.4. The "Brains": ~/.local/bin/zypper-notify-updater.pyThis Python script is the core of the system, run by the zypper-notify-user.service every hour.Checks Safety: Uses upower and nmcli to determine if a refresh is safe (Hybrid Logic).Runs Zypper: Executes pkexec zypper refresh (if safe) and pkexec zypper dup --dry-run to check for pending updates.Parses Output: Counts packages, finds the latest Tumbleweed Snapshot version.Sends Clickable Notification: Uses PyGObject to send a rich notification with the Snapshot version and an "Install" button.Launches Terminal (Action): Clicking "Install" runs the ~/.local/bin/zypper-run-install script, which launches your preferred terminal (konsole, gnome-terminal, etc.) to execute pkexec zypper dup interactively.🚀 Installation / UpgradingThe script is idempotent. You can run this on a fresh install or on a PC with an older version.Download the latest zypper-auto.sh script.Make it executable:chmod +x zypper-auto.sh
Run it with sudo. The script will handle all cleanup, dependency checks, and the installation of the root service.sudo ./zypper-auto.sh
Crucial Final Step: The installer cannot enable user-level services. You must run this command as your regular user (do not use sudo) to enable the notifier timer:systemctl --user daemon-reload && systemctl --user enable --now zypper-notify-user.timer
You're done! The root downloader is enabled, and the user notifier is ready.🏃 UsageWait. The services run in the background. The downloader attempts to run hourly when conditions are safe.Get Notified. You will get a notification only when new updates are pending.Snapshot 20251110-0 Ready12 updates are pending. Click 'Install' to begin.Install. Click the "Install" button in the notification. This will open a terminal and prompt you for authentication to run zypper dup.Verifying the Services# 1. Check Root Timer (Downloader)
# Should show "active" and the next scheduled run time
systemctl list-timers zypper-autodownload.timer

# 2. Check User Timer (Notifier)
# Must be run as your regular user. Should show "active" and the next scheduled run time.
systemctl --user list-timers zypper-notify-user.timer

# 3. Check the status of the last DOWNLOADER run
systemctl status zypper-autodownload.service

# 4. View the detailed logs from the smart notification script
journalctl --user -u zypper-notify-user.service
🔧 Configuration: Changing the TimersYou can edit the timers to change the schedule (e.g., from hourly to daily).# Edit the root downloader's schedule:
sudoedit /etc/systemd/system/zypper-autodownload.timer

# Edit the user notifier's schedule:
systemctl --user edit --full zypper-notify-user.timer
After saving, reload systemd and restart the timers:# For the root downloader:
sudo systemctl daemon-reload
sudo systemctl restart zypper-autodownload.timer

# For the user notifier (as your regular user):
systemctl --user daemon-reload
systemctl --user restart zypper-notify-user.timer
🗑️ UninstallationTo completely remove the v41.1 system:# 1. Stop and disable the root timer
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

# 4. Reload the systemd daemons
sudo systemctl daemon-reload
systemctl --user daemon-reload
