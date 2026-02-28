![Scrub-GHOST](Icon/images.png)

# Scrub-GHOST
`scrub-ghost` is a safety-focused maintenance tool for Boot Loader Specification (BLS) entry cleanup on openSUSE (commonly `sd-boot` with entries under `/boot/efi/loader/entries`).

[**This tool is now discontinued and merged with Zypper Auto Repo!**](https://github.com/FreddeITsupport98/zypper-automatik-helper-)

It is designed to remove or quarantine *obviously stale* boot menu entries ("ghost" entries, stale snapper snapshots, etc.) while avoiding the common failure mode of deleting something you still need.

This repository provides:
- `scrub.sh`: the tool itself (interactive menu + CLI)
- `install.sh`: installer for the **command** (and optional integration management)
- Optional, independent integrations:
  - systemd unit/timer (weekly run)
  - zypp commit hook (run after zypper transactions)

## Disclaimer / high-stakes warning
Bootloaders are high-stakes. If you remove the wrong files you can end up with a system that won’t boot.

This tool defaults to **dry-run** and uses **backups**. Still:
- Always run `--dry-run` first.
- Keep at least one known-good boot entry.
- Know how to restore (see "Recovery" below).

## Quick start
Supported distros:
- openSUSE Tumbleweed
- openSUSE Slowroll
- openSUSE immutable variants (e.g. MicroOS/Aeon/Kalpa)

Not supported:
- openSUSE Leap (the script will refuse to run)

Dry-run scan (recommended first):
- `sudo ./scrub.sh --dry-run`

Important:
- This script requires **bash**. Do not run it with `sh` (use `sudo ./scrub.sh ...` or `sudo bash ./scrub.sh ...`).

Interactive menu:
- `sudo ./scrub.sh --menu`

Recommended for most users:
- Use the menu’s **Smart Auto-Fix** option. It performs a quiet analysis first (JSON-based), shows a scorecard (boot storage health + ghosts/duplicates/stale/uninstalled), and shows a small progress indicator while analysis is running. Then it runs only the actions you choose.
  - `FIX` applies safe fixes (ghosts + duplicates)
  - `ALL` includes stale snapshot pruning
  - `K` adds uninstalled-kernel pruning (aggressive; requires confirmation)

Smart behavior highlights:
- Shows **boot storage health** (useful when /boot or ESP is full).
- Shows **boot redundancy** (how many unique kernel versions have at least one bootable BLS entry). If you only have 1, Smart Auto-Fix will require an extra confirmation.
- Checks **GRUB default entry health** (saved_entry) and can fix a broken saved default by setting it to the latest detected kernel entry.
- Checks **bootloader drift**: if `grub.cfg` is older than the newest BLS entry, it will show `STALE` and offers an `UPDATE` action (runs `grub2-mkconfig`).
- Shows an **orphaned images** estimate (kernel/initrd files in `BOOT_DIR` that are not referenced by any current BLS entry).
- If orphaned images are detected, Smart Auto-Fix offers an **ORPHANS** action to **quarantine** them (move into the backup folder; reversible).
- Offers **Smart Repair** suggestions when it finds entries where the kernel exists but the initrd is missing/corrupt (suggested `dracut --force --kver ...`). These are reported as `ZOMBIE-INITRD` and are **not removed by default**. Smart Auto-Fix also offers a `REPAIR` action to run the required `dracut` commands for you.
- Offers an **Active Healer** option to reinstall RPM-owned corrupt kernel packages (runs `zypper in -f ...` after confirmation).
- Offers a **Vacuum advisor** to identify excess installed kernel packages (not running, not latest) and optionally remove them via `zypper rm ...`. Vacuum respects pinning (pinned kernels are never suggested for removal).
- Supports **pinning**: entries listed in `ENTRIES_DIR/.scrub-ghost-pinned` are never modified/pruned.
- After applying a fix, it automatically **re-scans** to verify the counts dropped.
- Duplicate detection uses a two-pass index so it keeps the “best” candidate automatically (prefers pinned/snapshot/kernel/default entries; otherwise keeps the newest mtime).
- If a kernel image is detected as corrupt (0 bytes **or** RPM checksum mismatch) and it is owned by an RPM, the tool suggests a repair command (`zypper in -f <pkg>`).

Safe cleanup (moves entries to a backup directory; does not hard-delete):
- `sudo ./scrub.sh --force --prune-stale-snapshots`

List backups:
- `sudo ./scrub.sh --list-backups`

Validate latest backup:
- `sudo ./scrub.sh --validate-latest`

Restore (validated):
- `sudo ./scrub.sh --restore-best`

## What is a “ghost” entry?
A BLS entry is treated as a *ghost* when it references a kernel path (the `linux` / `linuxefi` line) that does not exist on disk.

## What is a “stale snapper” entry?
A BLS entry is treated as *stale snapshot* when it references `/.snapshots/<N>/snapshot` but snapshot `<N>` no longer exists.

The tool verifies snapshot existence via:
- `/.snapshots/<N>/snapshot` directory, and/or
- `snapper --no-dbus list` (if snapper is available)

## Safety guardrails
The tool contains multiple guardrails to avoid creating an unbootable state:

- Dry-run by default.
- Before modifying entries (`--force` / `--delete`), it creates:
  - a filesystem backup of the whole current entries set
  - an optional snapper snapshot (best-effort)
- Running kernel & latest installed kernel protection:
  - the entry matching `uname -r` (running kernel) is protected
  - the entry matching the newest version seen under `/lib/modules` / `/usr/lib/modules` is also protected
- Bootloader default protection (GRUB):
  - if GRUB is in use and `grub2-editenv list` reports a `saved_entry`, the matching BLS entry is treated as protected
- Restore validation:
  - restore is blocked unless the backup passes validation (unless you pass `--restore-anyway`)

## Output / colors
When output is a terminal (TTY):
- Green: OK
- Red: GHOST / STALE-SNAPSHOT / OLD backups
- Yellow: UNINSTALLED-KERNEL warnings
- Blue: PROTECTED / SKIP actions

Disable colors:
- `--no-color`

## Logging
The tool logs to the console and also writes a log file.

Default log file:
- `/var/log/scrub-ghost.log`

Enable debug logging:
- `--debug`

Override the log file path:
- `--log-file /path/to/file.log`

## Interactive menu
Start the menu:
- `sudo ./scrub.sh --menu`

The menu is organized as:
- Scan
- Clean (safe move + backups)
- Backups/Restore
- Settings
- Paths/advanced
- Danger zone (permanent deletes)
- Install/uninstall

The menu is intended for humans.
For automation, prefer the CLI.

## CLI reference (most used)
Scan:
- `sudo ./scrub.sh --dry-run`

Generate shell completion (no root required):
- `./scrub.sh --completion zsh`
- `./scrub.sh --completion bash`

Clean safely (move to backup):
- `sudo ./scrub.sh --force`

Also prune stale snapper snapshot entries:
- `sudo ./scrub.sh --force --prune-stale-snapshots`

Prune entries for kernels not installed anymore (requires confirmation):
- `sudo ./scrub.sh --force --prune-uninstalled --confirm-uninstalled`

Prune duplicate entries (same linux+initrd+options payload):
- `sudo ./scrub.sh --force --prune-duplicates`

Prune zombie initrd entries (kernel exists but initrd missing/corrupt) (NOT recommended; prefer repair):
- `sudo ./scrub.sh --force --prune-zombies`

Machine-readable output (JSON to stdout; logs go to stderr):
- `sudo ./scrub.sh --dry-run --json`

Hard delete (dangerous):
- `sudo ./scrub.sh --delete [--prune-stale-snapshots] [--prune-uninstalled --confirm-uninstalled]`

Optional: rebuild/update bootloader metadata after changes:
- `--rebuild-grub` (runs `grub2-mkconfig`)
- `--update-sdboot` (runs `sdbootutil update-kernels`)

Backups:
- `sudo ./scrub.sh --list-backups`
- `sudo ./scrub.sh --validate-latest`
- `sudo ./scrub.sh --validate-pick 2`

Restore (validated):
- `sudo ./scrub.sh --restore-latest`
- `sudo ./scrub.sh --restore-best`
- `sudo ./scrub.sh --restore-pick 2`
- `sudo ./scrub.sh --restore-from /var/backups/scrub-ghost/bls-entries-YYYYMMDD-HHMMSS`

Restore options:
- Additive restore is the default (does not delete newer entries).
- `--clean-restore` will remove extra current entries not present in the backup.

Restore copy behavior:
- The restore path uses a best-effort copy strategy (try archive/preserve attributes; fall back to a plain copy) so restores work even when the entries directory is on FAT32 (ESP) and metadata preservation fails.
- `--restore-anyway` bypasses failed restore validation.

Backup rotation:
- `--keep-backups N` (default: 5; `0` disables rotation)

## Backups: where they go
Backups are created under:
- `/var/backups/scrub-ghost/bls-entries-YYYYMMDD-HHMMSS/`

Inside each backup:
- `full/` contains all `.conf` files copied from the entries directory
- `manifest.txt` includes basic metadata (timestamps, machine-id, etc.)

The tool also maintains:
- `/var/backups/scrub-ghost/latest` symlink (best-effort)

## Recovery (“oh no” plan)
If your boot menu is missing entries:

1) Boot any working entry (or a rescue environment).
2) Restore from the newest valid backup:
- `sudo scrub-ghost --restore-best --rebuild-grub`

If no backup validates but you still want to restore anyway (dangerous):
- `sudo scrub-ghost --restore-latest --restore-anyway --rebuild-grub`

## Live ISO rescue / chroot mode
If your installed system won’t boot normally, you can run the tool from a Live ISO and chroot into the installed system.

Start the wizard:
- `sudo ./scrub.sh --rescue`

The wizard:
- scans for Linux filesystem partitions via `lsblk` (btrfs/ext3/ext4/xfs)
- mounts the selected device at `/mnt/scrub-ghost-rescue` (default mount)
- bind-mounts `/dev`, `/proc`, `/sys` (and best-effort `/run`)
- runs `mount -a` inside the chroot (best effort) to mount `/boot`, `/boot/efi`, etc
- injects and starts `scrub.sh --menu` inside the chroot

Exit the menu to return to the Live ISO; the wizard will unmount everything best-effort.

## Install the command (optional)
Install/upgrade the command to `/usr/local/bin/scrub-ghost`:
- `sudo ./install.sh`

Uninstall everything (command + integration bits):
- `sudo ./install.sh --uninstall`

Install will also refresh existing integrations by default (if they are already present). You can disable refresh:
- `sudo ./install.sh --no-update-systemd --no-update-zypp`

Remove integrations without removing the command:
- `sudo ./install.sh --remove-systemd`
- `sudo ./install.sh --remove-zypp`

## Systemd integration (optional, independent)
Systemd is installed independently and is not tied to where `scrub.sh` lives.

Standalone note: if you downloaded only `scrub.sh` (without the full repo), the interactive menu can still install/remove systemd integration using built-in templates.

Install systemd unit/timer + wrapper:
- `sudo ./systemd/install-systemd.sh`

Enable the weekly timer:
- `sudo ./systemd/install-systemd.sh --enable-timer`

Remove systemd integration:
- `sudo ./systemd/install-systemd.sh --uninstall`

Configuration:
- `/etc/default/scrub-ghost` or `/etc/sysconfig/scrub-ghost`

The systemd unit executes a wrapper at:
- `/usr/local/libexec/scrub-ghost/run-systemd`

That wrapper reads:
- `SCRUB_GHOST_BIN` (path to scrub-ghost)
- `SCRUB_GHOST_ARGS=(...)` (bash array of args)

## Zypper (zypp) integration (optional, independent)
Standalone note: if you downloaded only `scrub.sh` (without the full repo), the interactive menu can still install/remove the hook using built-in templates.

Install hook:
- `sudo ./zypp/install-zypp-hook.sh`

Remove hook:
- `sudo ./zypp/install-zypp-hook.sh --uninstall`

## Notes
- **Argument validation:** unknown options (or options missing required values) will print an error and exit. Use `-h` or `--help` to see the full usage.
- **Shell requirement:** the script must be executed by `bash` (the menu and CLI use bash arrays and other bash features). Running it via `sh` will fail.
- **Pinning / manual overrides:** if `ENTRIES_DIR/.scrub-ghost-pinned` exists, any entry listed in it will be treated as `PINNED` and will never be moved/deleted. You can manage this file via the menu: `Settings -> Manage pinned entries`.
  You can pin by:
  - filename (e.g. `abcd.conf`)
  - entry id (e.g. `abcd`)
  - kernel version string (e.g. `6.9.1-1-default`)
  Lines can be commented with `#`.
- Ghost/broken entry detection checks not only the `linux` path but also `initrd` (if present) and `devicetree` (if present). If any referenced file is missing, the entry is flagged as a ghost/broken entry. If an entry has multiple `initrd` lines, **all** initrds must exist.
- **Quoted values:** BLS allows quoted values containing spaces (e.g. `linux "/EFI/My Folder/linux.efi"`). The parser supports this for path-like keys.
- **Corruption detection:** a kernel file that exists but is **0 bytes** is treated as broken (common when the ESP runs out of space). If the kernel file is owned by an RPM package, the tool also runs a lightweight `rpm -Vf` check and flags **checksum mismatches** as corrupt (`CORRUPT-CSUM`).
- **Initrd X-Ray:** if `file(1)` is available, initrds are also sanity-checked by MIME type. If an initrd exists but doesn’t look like an `application/*` archive payload, the entry is flagged as broken (`CORRUPT-INITRD`).
- **Auditing:** when the tool moves/deletes entries, it also writes best-effort audit lines to the system journal via `logger` (tag: `scrub-ghost`).
- **Kernel version parsing:** the tool understands both sd-boot style paths (`/distro/<kver>/...`) and flat BLS/GRUB-style paths (`/vmlinuz-<kver>`). If it cannot confidently determine a kernel version, it will avoid classifying entries as `UNINSTALLED-KERNEL` (too risky) and will report that the modules check was skipped.
- **Kernel protection matching:** protection checks avoid substring false positives (e.g. `6.8.1` will not accidentally match `6.8.10`).
- **Latest installed kernel detection:** uses `sort -V` when available; otherwise falls back to a conservative bash numeric comparison so “latest kernel protection” still works in minimal/rescue shells. The fallback only considers module directory names that start with a numeric version (skips odd/unparsable names).
- **Mountpoints with spaces:** mount detection decodes the `\040`-style escaping used in `/proc/mounts`, and mountpoint/options parsing uses a non-space delimiter so remount logic works even when mountpoints contain spaces.
- **Snapshot detection:** snapshot numbers are extracted only from real BLS lines (`linux`/`linuxefi`/`options`), so snapshot-like strings in comments won’t accidentally protect an entry.
- **Backup moves across filesystems:** when entries are moved to a backup directory on a different filesystem, the tool uses an explicit copy+verify+delete flow (instead of relying on non-atomic cross-device `mv`).
- On read-only systems (MicroOS/Aeon), when applying changes the tool will try a temporary remount `rw` for the mountpoints containing the entries directory and backup root, then restore `ro` on exit. Disable this behavior with `--no-remount-rw`.
- On MicroOS/Aeon, `/usr/local` may be read-only; use a transactional environment (e.g. `transactional-update shell`) for installs/integrations.
- On immutable openSUSE variants, package operations invoked by the menu (e.g. `HEAL` / `VACUUM`) will automatically use `transactional-update pkg install/remove` and will tell you when a reboot is required.
- `git` is not required to run the tool.
- You should treat `--delete`, `--clean-restore`, and `--restore-anyway` as danger flags. `--clean-restore` is implemented defensively (it avoids deleting extra entries that still have a valid kernel present). When enabled, restore will print a preview of which extra entries it would remove and requires you to type `YES` before it deletes anything.
