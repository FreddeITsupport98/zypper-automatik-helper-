# Release v47 - Comprehensive Logging & Monitoring

**Release Date:** November 19, 2025

## 🎯 Overview

Version 47 introduces a complete logging and monitoring system, making it easy to understand what the script is doing and troubleshoot any issues without needing to run multiple commands.

## ✨ New Features

### 📊 Comprehensive Logging System

- **Installation Logs** - Complete timestamped logs of every installation run
  - Location: `/var/log/zypper-auto/install-YYYYMMDD-HHMMSS.log`
  - Captures all commands executed and their results
  - Includes sanity checks, dependency verification, and service creation

- **Service Logs** - Background service activity logging
  - Downloader: `/var/log/zypper-auto/service-logs/downloader.log`
  - Downloader errors: `/var/log/zypper-auto/service-logs/downloader-error.log`
  - User notifier: `~/.local/share/zypper-notify/notifier-detailed.log`

- **Status Tracking** - Real-time status files
  - Installation status: `/var/log/zypper-auto/last-status.txt`
  - Notifier status: `~/.local/share/zypper-notify/last-run-status.txt`
  - Check status anytime with `cat` - no commands needed!

### 🔄 Automatic Log Rotation

- Installation logs: Keep only last **10 files**
- Service logs: Rotate at **50MB**
- Notifier logs: Rotate at **5MB**
- Cleanup happens automatically on every installation
- No manual maintenance required

### 🐛 Enhanced Error Reporting

- Full Python tracebacks for debugging
- Detailed error messages with context
- Exit codes and command output captured
- Environment state logged (battery, AC power, metered connection)

## 📝 What Gets Logged

### Installation Phase
- ✅ Root privilege checks
- ✅ User detection and home directory validation
- ✅ Dependency installation (with user responses)
- ✅ Old service cleanup
- ✅ Service and timer file creation
- ✅ Permission and ownership changes
- ✅ Syntax validation
- ✅ Systemd daemon reloads

### Runtime (Notifier Service)
- ✅ Environment detection (laptop/desktop, battery status)
- ✅ AC power and metered connection checks
- ✅ Safety decisions (why updates are skipped)
- ✅ Zypper refresh and dry-run execution
- ✅ Update detection and package counts
- ✅ Notification display
- ✅ User actions (Install button clicks)
- ✅ All errors with full details

## 📚 Documentation Updates

### README.md Enhancements
- New **"Logging & Monitoring"** section with comprehensive tables
- **"Reporting Issues on GitHub"** section with clear instructions
- Log access examples and search patterns
- Troubleshooting guide using logs
- Version history updated

### GitHub Issue Templates
- **Bug Report Template** - Pre-formatted with all required log commands
- **Feature Request Template** - Structured format for suggestions
- Clear reminders to redact personal information

## 🚀 Quick Start

### Check Current Status
```bash
# Installation/system status
cat /var/log/zypper-auto/last-status.txt

# Notifier status
cat ~/.local/share/zypper-notify/last-run-status.txt
```

### View Detailed Logs
```bash
# Most recent installation
cat $(ls -t /var/log/zypper-auto/install-*.log | head -1)

# Notifier activity
cat ~/.local/share/zypper-notify/notifier-detailed.log

# Downloader activity
sudo cat /var/log/zypper-auto/service-logs/downloader.log
```

### Find Issues
```bash
# Find all errors
grep "\[ERROR\]" ~/.local/share/zypper-notify/notifier-detailed.log

# Check why updates were skipped
grep "SKIPPED" ~/.local/share/zypper-notify/notifier-detailed.log

# See environment detection
grep "Form factor detected" ~/.local/share/zypper-notify/notifier-detailed.log
```

## 🔧 Installation

Same as previous versions - the script is idempotent and will upgrade cleanly:

```bash
chmod +x zypper-auto.sh
sudo ./zypper-auto.sh
systemctl --user daemon-reload && systemctl --user enable --now zypper-notify-user.timer
```

## ⚠️ Breaking Changes

**None!** This is a fully backward-compatible update. All existing functionality remains unchanged.

## 🐞 Bug Fixes

- Improved error handling with better logging
- More robust environment detection logging
- Clearer status messages throughout execution

## 📦 Files Changed

- `zypper-auto.sh` - Enhanced with comprehensive logging functions
- `README.md` - Complete documentation overhaul with logging details
- `.github/ISSUE_TEMPLATE/bug_report.md` - New issue template (NEW)
- `.github/ISSUE_TEMPLATE/feature_request.md` - New feature request template (NEW)

## 🙏 Feedback

If you encounter any issues, please use the new bug report template and include the relevant logs as described in the [README](README.md#reporting-issues-on-github).

## 📋 Version History

- **v47** (2025-11-19): Comprehensive logging system
- **v46**: AC battery detection logical fix
- **v45**: Architecture improvements and user-space notifier
- **v43**: Enhanced Python notification script
- **v42**: PolicyKit/PAM error logging enhancements

---

## Installation

Download and run:
```bash
wget https://github.com/YOUR_USERNAME/zypper-automatik-helper-/raw/main/zypper-auto.sh
chmod +x zypper-auto.sh
sudo ./zypper-auto.sh
systemctl --user daemon-reload && systemctl --user enable --now zypper-notify-user.timer
```

Or clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/zypper-automatik-helper-.git
cd zypper-automatik-helper-
chmod +x zypper-auto.sh
sudo ./zypper-auto.sh
systemctl --user daemon-reload && systemctl --user enable --now zypper-notify-user.timer
```

---

**Full Changelog**: [v46...v47](https://github.com/YOUR_USERNAME/zypper-automatik-helper-/compare/v46...v47)
