---
name: Bug Report
about: Report a problem with zypper-auto-helper
title: '[BUG] '
labels: bug
assignees: ''
---

## Describe the Problem
<!-- A clear description of what went wrong and what you expected to happen -->



## System Information
**openSUSE Version:**
```bash
# Output of: cat /etc/os-release

```

**Python Version:**
```bash
# Output of: python3 --version

```

**Script Version:**
<!-- Check the version in zypper-auto.sh, look for "VERSION XX" in the header -->
Version: 

## Logs

<!-- ⚠️ IMPORTANT: Please REDACT any personal information (usernames, hostnames, network names) before posting! -->

### Installation Logs (if installation failed)
<details>
<summary>Click to expand installation logs</summary>

```bash
# Output of: cat $(ls -t /var/log/zypper-auto/install-*.log | head -1)

```

```bash
# Output of: cat /var/log/zypper-auto/last-status.txt

```
</details>

### Notifier Logs (if notifications not working or update checks failing)
<details>
<summary>Click to expand notifier logs</summary>

```bash
# Output of: cat ~/.local/share/zypper-notify/notifier-detailed.log

```

```bash
# Output of: cat ~/.local/share/zypper-notify/last-run-status.txt

```

```bash
# Output of: systemctl --user status zypper-notify-user.service

```

```bash
# Output of: journalctl --user -u zypper-notify-user.service -n 100 --no-pager

```
</details>

### Downloader Logs (if downloads not happening)
<details>
<summary>Click to expand downloader logs</summary>

```bash
# Output of: sudo cat /var/log/zypper-auto/service-logs/downloader.log

```

```bash
# Output of: sudo cat /var/log/zypper-auto/service-logs/downloader-error.log

```

```bash
# Output of: systemctl status zypper-autodownload.service

```
</details>

## Additional Context
<!-- Add any other relevant information about the problem here -->

