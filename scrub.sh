#!/usr/bin/env bash

# IMPORTANT: this script requires bash. Do not run it with `sh`.
# (If invoked via `sh scrub.sh ...`, the shebang is bypassed and bash-specific syntax will break.)
if [ -z "${BASH_VERSION:-}" ]; then
  echo "ERROR: This script must be run with bash (not sh)." >&2
  echo "Try: sudo bash $0 --menu" >&2
  echo "Or:  chmod +x $0 && sudo ./$0 --menu" >&2
  exit 2
fi

# If bash was invoked via the /bin/sh entrypoint (common on some distros), refuse.
# Users should run via the shebang (./scrub.sh) or explicitly via bash.
# This prevents subtle behavior differences and avoids confusing support cases.
_bash_argv0="${BASH_ARGV0:-}"
_bash_bin_base="$(basename "${BASH:-}" 2>/dev/null || true)"
if [ "$_bash_argv0" = "sh" ] || [ "$_bash_bin_base" = "sh" ] || [ "$_bash_bin_base" = "dash" ]; then
  echo "ERROR: Do not run via 'sh'. Use: sudo bash ./scrub.sh --menu (or make it executable and run ./scrub.sh)." >&2
  exit 2
fi

# Stable script path for re-invoking ourselves from the menu.
SCRIPT_SELF="${BASH_SOURCE[0]:-$0}"
if command -v readlink >/dev/null 2>&1; then
  SCRIPT_SELF="$(readlink -f -- "$SCRIPT_SELF" 2>/dev/null || printf '%s' "$SCRIPT_SELF")"
fi

# Safer BLS entry scrubber for openSUSE (Tumbleweed)
# - Defaults to dry-run
# - When forced, moves ghost entries to a backup directory (no hard delete)
# - Avoids false positives when the entry already uses /boot/… paths
# - Protects Snapper snapshot entries when the snapshot subvolume exists


ENTRIES_DIR=""
ENTRIES_DIR_SET=false

# Root directory used to resolve BLS paths like /vmlinuz-… or /EFI/…
# If not provided, it will be derived from ENTRIES_DIR (two dirs up).
BOOT_DIR=""
BOOT_DIR_SET=false

DRY_RUN=true
DELETE_MODE="backup" # "backup" or "delete"
BACKUP_DIR=""        # if empty, a timestamped dir under BACKUP_ROOT will be used
BACKUP_DIR_SET=false

REBUILD_GRUB=false
UPDATE_SDBOOT=false
GRUB_CFG="/boot/grub2/grub.cfg"
GRUB_CFG_SET=false

# Read-only FS guard (MicroOS/Aeon): attempt temporary remount rw when applying changes
AUTO_REMOUNT_RW=true

# Backup root (never inside ENTRIES_DIR by default)
BACKUP_ROOT="/var/backups/scrub-ghost"

# Backup rotation
KEEP_BACKUPS=5

# Mode
ACTION="scan"  # scan | list-backups | restore | validate | rescue
RESTORE_FROM=""
RESTORE_PICK=""        # 1 = newest, 2 = second newest, etc.
RESTORE_ANYWAY=false
RESTORE_BEST=false
CLEAN_RESTORE=false

# Rescue / chroot mode (Live ISO helper)
RESCUE_MOUNT_POINT="/mnt/scrub-ghost-rescue"
RESCUE_SHIM_PATH="/tmp/scrub-rescue-shim.sh"

# Safety guardrails
RUNNING_KERNEL_VER=""
LATEST_INSTALLED_VER=""

# Output
COLOR=true
VERBOSE=false

# Machine-readable output
JSON_OUTPUT=false
LOG_TO_STDERR=false

# Logging
DEBUG=false
LOG_FILE="/var/log/scrub-ghost.log"
LOG_FILE_SET=false

# Interactive menu
MENU_REQUESTED=false
NO_MENU=false

# Completion output
PRINT_COMPLETION=false
COMPLETION_SHELL="zsh"

# Verification / pruning knobs
VERIFY_SNAPSHOTS=true
VERIFY_KERNEL_MODULES=true
PRUNE_STALE_SNAPSHOTS=false
PRUNE_UNINSTALLED_KERNELS=false
PRUNE_DUPLICATES=false
PRUNE_ZOMBIES=false
CONFIRM_PRUNE_UNINSTALLED=false

# Backup knobs (enabled automatically when applying changes)
AUTO_BACKUP=true
AUTO_SNAPPER_BACKUP=true
SNAPPER_BACKUP_ID=""

# Filled at runtime (if snapper exists)
declare -A SNAPSHOT_NUM_SET
SNAPPER_AVAILABLE=false

usage() {
  cat <<'USAGE'
Usage: scrub.sh [options]

Scans Boot Loader Specification (BLS) entries under /boot/loader/entries and
identifies "ghost" entries that reference a missing kernel image.

NOTE: This script requires bash. Do not run it with `sh`.

Default is DRY-RUN (no changes).

Options:
  --dry-run              Scan only (default)
  --force                Apply changes (moves ghost/stale entries to backup dir)
  --delete               Permanently delete ghost entries (implies --force)
  --backup-dir DIR       Backup directory to move pruned entries into (default: auto)
  --backup-root DIR      Root directory used for automatic backups (default: /var/backups/scrub-ghost)
  --keep-backups N        Keep last N backups under backup root (default: 5; 0 disables rotation)
  --entries-dir DIR      BLS entries directory (default: auto-detect)
  --boot-dir DIR         Root dir used to resolve BLS paths (default: derived from entries dir)
  --rebuild-grub         Run grub2-mkconfig after changes
  --grub-cfg PATH        Output path for grub2-mkconfig (default: /boot/grub2/grub.cfg)
  --update-sdboot        Run sdbootutil update-kernels after changes (optional)
  --no-remount-rw        Do not attempt temporary remount rw when entries/backup live on a read-only FS
  --completion [SHELL]   Print a shell completion script (SHELL: zsh|bash; default: zsh) and exit
  --json                 Emit machine-readable JSON to stdout (logs go to stderr; implies --no-color)
  --no-color             Disable colored output
  --verbose              Print extra details (including validation failures in --list-backups)
  --debug                Enable debug logging
  --log-file PATH         Write logs to PATH (default: /var/log/scrub-ghost.log)

Interactive:
  --menu                 Start interactive menu
  --rescue               Run the rescue/chroot wizard (intended for Live ISO environments)

Easy restore:
  --list-backups         List backup folders under backup root (numbered)
  --restore-latest       Restore BLS entries from the latest backup (validated)
  --restore-pick N       Restore from backup number N shown by --list-backups (validated)
  --restore-best         Restore from the newest backup that passes validation
  --restore-from DIR     Restore BLS entries from a specific backup directory (validated)
  --clean-restore        When restoring, delete extra current entries not present in the backup (dangerous)
  --restore-anyway       Override failed validation (dangerous)

Validation only (no changes):
  --validate-latest      Validate latest backup without restoring
  --validate-pick N      Validate backup number N shown by --list-backups
  --validate-from DIR    Validate a specific backup without restoring

Backup (runs automatically on --force/--delete):
  --no-backup             Do not create a filesystem backup copy of entries before changes
  --no-snapper-backup     Do not create a snapper snapshot before changes

Verification / pruning (all safe by default; pruning requires --force):
  --no-verify-snapshots   Don't verify snapper snapshot numbers
  --no-verify-modules     Don't verify kernel modules dirs for the entry's kernel version
  --prune-stale-snapshots Move/delete snapper entries whose snapshot number doesn't exist
  --prune-uninstalled     Move/delete entries whose kernel modules dir is missing (requires --confirm-uninstalled)
  --prune-duplicates      Move/delete duplicate entries with identical boot payload (linux+initrd+options)
  --prune-zombies         Move/delete "zombie" entries (kernel exists but initrd missing/corrupt) (recommended: repair instead)
  --confirm-uninstalled   Required extra safety flag to actually prune uninstalled-kernel entries

  -h, --help             Show this help

Examples:
  sudo ./scrub.sh
  sudo ./scrub.sh --force --prune-stale-snapshots
  sudo ./scrub.sh --list-backups
  sudo ./scrub.sh --validate-latest
  sudo ./scrub.sh --restore-pick 2
  sudo ./scrub.sh --restore-best
  sudo ./scrub.sh --restore-from /var/backups/scrub-ghost/bls-entries-YYYYMMDD-HHMMSS
USAGE
}

print_completion() {
  local shell="${1:-zsh}"
  case "$shell" in
    zsh)
      cat <<'EOF'
#compdef scrub-ghost scrub.sh

_arguments -s \
  '--help[show help]' \
  '--dry-run[scan only (default)]' \
  '--force[apply changes (move to backup)]' \
  '--delete[permanently delete (implies --force)]' \
  '--backup-dir=[backup directory]:dir:_files -/' \
  '--backup-root=[backup root directory]:dir:_files -/' \
  '--keep-backups=[keep last N backups]' \
  '--entries-dir=[BLS entries directory]:dir:_files -/' \
  '--boot-dir=[boot root directory]:dir:_files -/' \
  '--rebuild-grub[run grub2-mkconfig after changes]' \
  '--grub-cfg=[grub2-mkconfig output path]:file:_files' \
  '--update-sdboot[run sdbootutil update-kernels after changes]' \
  '--no-remount-rw[do not attempt temporary remount rw]' \
  '--json[emit machine-readable JSON to stdout]' \
  '--no-color[disable colored output]' \
  '--verbose[verbose output]' \
  '--debug[debug logging]' \
  '--log-file=[log file path]:file:_files' \
  '--menu[start interactive menu]' \
  '--rescue[run rescue/chroot wizard (live ISO)]' \
  '--list-backups[list backups]' \
  '--restore-latest[restore from latest backup]' \
  '--restore-best[restore from best backup]' \
  '--restore-pick=[restore pick number]' \
  '--restore-from=[restore from directory]:dir:_files -/' \
  '--clean-restore[delete extra current entries on restore]' \
  '--restore-anyway[restore even if validation fails]' \
  '--validate-latest[validate latest backup]' \
  '--validate-pick=[validate pick number]' \
  '--validate-from=[validate from directory]:dir:_files -/' \
  '--no-backup[disable filesystem entry backup]' \
  '--no-snapper-backup[disable snapper backup]' \
  '--no-verify-snapshots[disable snapper snapshot verification]' \
  '--no-verify-modules[disable kernel modules verification]' \
  '--prune-stale-snapshots[prune stale snapper entries (requires --force)]' \
  '--prune-uninstalled[prune uninstalled-kernel entries (requires --confirm-uninstalled)]' \
  '--prune-duplicates[prune duplicate boot entries]' \
  '--prune-zombies[prune zombie entries (kernel OK, initrd missing/corrupt)]' \
  '--confirm-uninstalled[extra confirmation for --prune-uninstalled]' \
  '--completion=[print completion script]:shell:(zsh bash)'
EOF
      ;;
    bash)
      cat <<'EOF'
# bash completion for scrub-ghost / scrub.sh
_scrub_ghost_complete() {
  local cur
  cur="${COMP_WORDS[COMP_CWORD]}"
  local opts="--dry-run --force --delete --backup-dir --backup-root --keep-backups --entries-dir --boot-dir --rebuild-grub --grub-cfg --update-sdboot --no-remount-rw --json --no-color --verbose --debug --log-file --menu --rescue --list-backups --restore-latest --restore-best --restore-pick --restore-from --clean-restore --restore-anyway --validate-latest --validate-pick --validate-from --no-backup --no-snapper-backup --no-verify-snapshots --no-verify-modules --prune-stale-snapshots --prune-uninstalled --prune-duplicates --prune-zombies --confirm-uninstalled --completion --help"
  COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
}

complete -F _scrub_ghost_complete scrub-ghost scrub.sh
EOF
      ;;
    *)
      printf 'ERROR: unknown shell for --completion: %s\n' "$shell" >&2
      return 2
      ;;
  esac
}

C_RESET=""
C_BOLD=""
C_RED=""
C_GREEN=""
C_YELLOW=""
C_BLUE=""
C_DIM=""

log_to_file() {
  # Best effort: write to LOG_FILE without ANSI codes.
  [[ -n "$LOG_FILE" ]] || return 0

  # Avoid noisy "Permission denied" errors before init_logging() picks a writable path.
  local dir
  dir="$(dirname -- "$LOG_FILE")"
  if [[ -e "$LOG_FILE" ]]; then
    [[ -w "$LOG_FILE" ]] || return 0
  else
    [[ -w "$dir" ]] || return 0
  fi

  # Strip ANSI escapes before writing to file.
  # Prefer sed -E for portability (BSD/macOS); fall back to sed -r (GNU).
  local line
  line="$(
    printf '%b' "$*" | {
      sed -E 's/\x1B\[[0-9;]*[mK]//g' 2>/dev/null || sed -r 's/\x1B\[[0-9;]*[mK]//g'
    }
  )"
  printf '%s %s\n' "$(date -Is)" "$line" >>"$LOG_FILE" 2>/dev/null || true
}

init_logging() {
  # Try requested file first; if not writable, fall back.
  if [[ -z "$LOG_FILE" ]]; then
    return 0
  fi

  local dir
  dir="$(dirname -- "$LOG_FILE")"
  mkdir -p -- "$dir" 2>/dev/null || true
  touch -- "$LOG_FILE" 2>/dev/null || true

  if [[ ! -w "$LOG_FILE" ]]; then
    # Fall back to BACKUP_ROOT (usually writable as root) then /tmp
    LOG_FILE="$BACKUP_ROOT/scrub-ghost.log"
    mkdir -p -- "$BACKUP_ROOT" 2>/dev/null || true
    touch -- "$LOG_FILE" 2>/dev/null || true

    if [[ ! -w "$LOG_FILE" ]]; then
      LOG_FILE="/tmp/scrub-ghost.log"
      touch -- "$LOG_FILE" 2>/dev/null || true
    fi
  fi
}

init_colors() {
  # Enable colors only when stdout is a TTY and the user hasn't disabled it.
  if [[ "$COLOR" != true ]]; then
    return 0
  fi
  if [[ ! -t 1 ]]; then
    return 0
  fi
  if [[ -n "${NO_COLOR:-}" ]]; then
    return 0
  fi

  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_DIM=$'\033[2m'
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
}

log() {
  if [[ "$LOG_TO_STDERR" == true ]]; then
    printf '%b\n' "$*" >&2
  else
    printf '%b\n' "$*"
  fi
  log_to_file "$*"
}
warn() {
  if [[ "$LOG_TO_STDERR" == true ]]; then
    printf '%bWARN:%b %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2
  else
    printf '%bWARN:%b %s\n' "$C_YELLOW" "$C_RESET" "$*"
  fi
  log_to_file "WARN: $*"
}
err() {
  printf '%bERROR:%b %s\n' "$C_RED" "$C_RESET" "$*" >&2
  log_to_file "ERROR: $*"
}
debug() {
  if [[ "$DEBUG" == true ]]; then
    if [[ "$LOG_TO_STDERR" == true ]]; then
      printf '%bDEBUG:%b %s\n' "$C_BLUE" "$C_RESET" "$*" >&2
    else
      printf '%bDEBUG:%b %s\n' "$C_BLUE" "$C_RESET" "$*"
    fi
    log_to_file "DEBUG: $*"
  fi
}

check_supported_os_or_die() {
  # This tool is intentionally scoped to openSUSE (Tumbleweed/Slowroll/immutable variants).
  # Refuse to run on openSUSE Leap to avoid untested behavior.
  local id="" name="" variant="" version_id="" id_like=""

  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    id="${ID:-}"
    name="${NAME:-}"
    variant="${VARIANT_ID:-}"
    version_id="${VERSION_ID:-}"
    id_like="${ID_LIKE:-}"
  else
    err "Unsupported OS: /etc/os-release not found"
    exit 1
  fi

  local is_opensuse=false
  if [[ "$id" == opensuse* ]]; then
    is_opensuse=true
  elif [[ "$name" == *openSUSE* ]]; then
    is_opensuse=true
  fi

  if [[ "$is_opensuse" != true ]]; then
    err "Unsupported OS: this tool only runs on openSUSE (detected: ID='${id:-unknown}' NAME='${name:-unknown}')"
    exit 1
  fi

  local is_leap=false
  if [[ "$id" == *leap* || "$variant" == *leap* || "$name" == *Leap* ]]; then
    is_leap=true
  fi

  if [[ "$is_leap" == true ]]; then
    err "Unsupported openSUSE variant: Leap (detected: ID='${id:-unknown}' NAME='${name:-unknown}' VERSION_ID='${version_id:-unknown}')"
    err "This script supports openSUSE Tumbleweed/Slowroll and openSUSE immutable variants (e.g. MicroOS/Aeon/Kalpa)."
    exit 1
  fi

  debug "OS check: ok (ID='${id:-unknown}' NAME='${name:-unknown}' VARIANT_ID='${variant:-}' VERSION_ID='${version_id:-}')"
}

log_audit() {
  # Sends critical actions to the system journal (best effort)
  local msg="$1"
  if command -v logger >/dev/null 2>&1; then
    logger -t "scrub-ghost" -p user.notice -- "$msg" 2>/dev/null || true
  fi
}

json_escape() {
  local s="$1"

  # Prefer a robust escaper if available (handles ASCII control chars 0x00-0x1F).
  # This keeps --json output valid even if content contains unexpected control bytes.
  if command -v perl >/dev/null 2>&1; then
    # NOTE: bash strings can't contain NUL bytes; this still covers the control range
    # that can realistically appear in filenames/config text.
    printf '%s' "$s" | perl -pe '
      s/\\/\\\\/g;
      s/"/\\"/g;
      s/\r/\\r/g;
      s/\n/\\n/g;
      s/\t/\\t/g;
      s/([\x00-\x08\x0b\x0c\x0e-\x1f])/sprintf("\\u%04x", ord($1))/ge;
    '
    return 0
  fi

  # Fallback: common escapes only.
  # Also strip other ASCII control chars (best effort) so JSON stays parseable.
  # (Bash strings cannot contain NUL bytes anyway.)
  s=$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037' 2>/dev/null || printf '%s' "$s")
  s=${s//\\/\\\\}
  s=${s//"/\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

json_add_result() {
  # Args: file status kernel initrd devicetree snapshot kver action details
  [[ "$JSON_OUTPUT" == true ]] || return 0

  local file="$1" status="$2" kernel="$3" initrd="$4" dtb="$5" snap="$6" kver="$7" action="$8" details="$9"

  JSON_RESULTS+=(
    "{\"file\":\"$(json_escape "$file")\",\"status\":\"$(json_escape "$status")\",\"kernel\":\"$(json_escape "$kernel")\",\"initrd\":\"$(json_escape "$initrd")\",\"devicetree\":\"$(json_escape "$dtb")\",\"snapshot\":\"$(json_escape "$snap")\",\"kver\":\"$(json_escape "$kver")\",\"action\":\"$(json_escape "$action")\",\"details\":\"$(json_escape "$details")\"}"
  )
}

json_emit() {
  [[ "$JSON_OUTPUT" == true ]] || return 0

  printf '{"timestamp":"%s","entries_dir":"%s","boot_dir":"%s","mode":"%s","delete_mode":"%s","results":[' \
    "$(date -Is)" "$(json_escape "$ENTRIES_DIR")" "$(json_escape "$BOOT_DIR")" \
    "$( [[ "$DRY_RUN" == true ]] && echo DRY-RUN || echo APPLY )" "$(json_escape "$DELETE_MODE")"

  local first=true
  local item
  for item in "${JSON_RESULTS[@]}"; do
    if [[ "$first" == true ]]; then
      first=false
    else
      printf ','
    fi
    printf '%s' "$item"
  done

  printf '],"summary":{"ok":%d,"ghost":%d,"zombie_initrd":%d,"pinned":%d,"stale_snapshot":%d,"uninstalled_kernel":%d,"duplicate_found":%d,"duplicate_pruned":%d,"protected_snapshots":%d,"protected_kernels":%d,"skipped":%d,"changed":%d}}\n' \
    "$ok_count" "$ghost_count" "$zombie_initrd_count" "$pinned_count" "$stale_snapshot_count" "$uninstalled_kernel_count" \
    "$duplicate_found_count" "$duplicate_pruned_count" "$protected_count" "$protected_kernel_count" \
    "$skipped_count" "$moved_or_deleted_count"
}

ts_now() { date +%Y%m%d-%H%M%S; }

# Robust BLS parsing helpers (ignore comments/blank lines)
bls_get_path() {
  # $1 = key regex (lowercase), $2 = file
  local key_re="$1"
  local file="$2"

  # BLS keys are case-insensitive; values may be quoted and may contain spaces.
  # If quoted, we extract the first quoted string. If unquoted, we take the first token.
  awk -v re="$key_re" '
    /^[[:space:]]*#/ {next}
    NF < 2 {next}
    tolower($1) ~ re {
      $1=""
      val=$0
      sub(/^[[:space:]]+/, "", val)

      if (val ~ /^"/) {
        # Double-quoted value (may contain spaces)
        if (match(val, /^"[^"]*"/)) {
          val = substr(val, RSTART+1, RLENGTH-2)
        }
      } else if (val ~ /^\x27/) {
        # Single-quoted value (treat similarly)
        if (match(val, /^\x27[^\x27]*\x27/)) {
          val = substr(val, RSTART+1, RLENGTH-2)
        }
      } else {
        # Unquoted: take first whitespace-delimited token
        split(val, tokens, /[[:space:]]+/)
        val = tokens[1]
      }

      print val
      exit
    }
  ' "$file" 2>/dev/null || true
}

bls_get_all_paths() {
  # $1 = key regex (lowercase), $2 = file
  # Prints all values for repeated BLS keys (e.g. multiple initrd lines).
  local key_re="$1"
  local file="$2"

  awk -v re="$key_re" '
    /^[[:space:]]*#/ {next}
    NF < 2 {next}
    tolower($1) ~ re {
      $1=""
      val=$0
      sub(/^[[:space:]]+/, "", val)

      if (val ~ /^"/) {
        if (match(val, /^"[^"]*"/)) {
          val = substr(val, RSTART+1, RLENGTH-2)
        }
      } else if (val ~ /^\x27/) {
        if (match(val, /^\x27[^\x27]*\x27/)) {
          val = substr(val, RSTART+1, RLENGTH-2)
        }
      } else {
        split(val, tokens, /[[:space:]]+/)
        val = tokens[1]
      }

      print val
    }
  ' "$file" 2>/dev/null || true
}

bls_get_rest_of_line() {
  # $1 = key regex (lowercase), $2 = file
  # Prints everything after the key token (used for "options" lines).
  local key_re="$1"
  local file="$2"
  awk -v re="$key_re" '
    /^[[:space:]]*#/ {next}
    tolower($1) ~ re {
      $1=""
      sub(/^[[:space:]]+/, "")
      print
      exit
    }
  ' "$file" 2>/dev/null || true
}

bls_linux_path() { bls_get_path '^linux(efi)?$' "$1"; }
bls_initrd_path() { bls_get_path '^initrd$' "$1"; }
bls_initrd_paths() { bls_get_all_paths '^initrd$' "$1"; }
bls_devicetree_path() { bls_get_path '^devicetree$' "$1"; }
bls_options_line() { bls_get_rest_of_line '^options$' "$1"; }

payload_signature() {
  # Stable signature for duplicate detection
  local raw="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "$raw" | sha256sum | awk '{print $1}'
  else
    # Fallback (still works, but can be large)
    printf '%s' "$raw"
  fi
}

# Kernel guardrails
GRUB_DEFAULT_ID=""

get_grub_default_id() {
  # Best-effort: returns saved_entry from grubenv.
  # On some setups this won't match BLS filenames; we only use exact matches.
  if command -v grub2-editenv >/dev/null 2>&1; then
    grub2-editenv list 2>/dev/null | awk -F= '$1=="saved_entry" {print $2; exit}' || true
  fi
}

entry_is_grub_default() {
  local entry_file="$1"
  [[ -n "$entry_file" && -n "$GRUB_DEFAULT_ID" ]] || return 1
  local base_id
  base_id="$(basename -- "$entry_file" .conf)"
  [[ "$base_id" == "$GRUB_DEFAULT_ID" ]]
}

kver_base_numeric() {
  # Extract leading numeric version part (e.g. "6.8.1" from "6.8.1-default").
  local v="$1"
  if [[ "$v" =~ ^([0-9]+(\.[0-9]+)*) ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

kver_build_numeric() {
  # Extract a numeric build suffix after a dash (e.g. "1" from "6.8.1-1-default").
  local v="$1"
  if [[ "$v" =~ ^[0-9]+(\.[0-9]+)*-([0-9]+) ]]; then
    printf '%s\n' "${BASH_REMATCH[2]}"
    return 0
  fi
  printf '0\n'
}

kver_is_newer() {
  # Returns 0 if $1 is newer than $2 using a conservative numeric comparison.
  # Handles common kernel module dir names like:
  #   6.8.1-default, 6.8.10-default, 6.8.1-1-default
  local a="$1" b="$2"
  [[ -n "$a" && -n "$b" ]] || return 1

  local abase bbase
  abase="$(kver_base_numeric "$a" 2>/dev/null || true)"
  bbase="$(kver_base_numeric "$b" 2>/dev/null || true)"
  [[ -n "$abase" && -n "$bbase" ]] || return 1

  local IFS='.'
  local -a av bv
  read -r -a av <<<"$abase"
  read -r -a bv <<<"$bbase"

  local i alen blen max
  alen=${#av[@]}
  blen=${#bv[@]}
  max=$(( alen > blen ? alen : blen ))

  for (( i=0; i<max; i++ )); do
    local ai bi
    ai=${av[$i]:-0}
    bi=${bv[$i]:-0}
    if (( 10#$ai > 10#$bi )); then
      return 0
    elif (( 10#$ai < 10#$bi )); then
      return 1
    fi
  done

  # Base numeric equal; compare numeric build suffix when present.
  local abuild bbuild
  abuild="$(kver_build_numeric "$a" 2>/dev/null || true)"
  bbuild="$(kver_build_numeric "$b" 2>/dev/null || true)"
  if [[ "$abuild" =~ ^[0-9]+$ && "$bbuild" =~ ^[0-9]+$ ]]; then
    if (( 10#$abuild > 10#$bbuild )); then
      return 0
    fi
  fi

  return 1
}

rpm_kernel_uname_r_candidates() {
  # Prints candidate kernel-uname-r values from RPM provides, one per line.
  # Example output: 6.8.1-1-default
  command -v rpm >/dev/null 2>&1 || return 1

  local pkg
  for pkg in kernel-default kernel-preempt kernel-longterm; do
    rpm -q "$pkg" >/dev/null 2>&1 || continue

    # Example line: kernel-uname-r = 6.8.1-1-default
    rpm -q --provides "$pkg" 2>/dev/null | awk '
      $1=="kernel-uname-r" && $2=="=" {print $3}
    ' || true
  done
}

compute_kernel_guardrails() {
  RUNNING_KERNEL_VER="$(uname -r 2>/dev/null || true)"

  local rpm_latest=""
  if command -v rpm >/dev/null 2>&1; then
    local cand
    while IFS= read -r cand; do
      [[ -n "$cand" ]] || continue
      if ! kver_base_numeric "$cand" >/dev/null 2>&1; then
        continue
      fi
      if [[ -z "$rpm_latest" ]]; then
        rpm_latest="$cand"
      else
        if kver_is_newer "$cand" "$rpm_latest"; then
          rpm_latest="$cand"
        fi
      fi
    done < <(rpm_kernel_uname_r_candidates 2>/dev/null || true)

    # Only accept RPM-derived "latest" if it actually has modules present.
    if [[ -n "$rpm_latest" ]] && ! modules_dir_exists_for_kver "$rpm_latest"; then
      debug "RPM latest candidate has no modules dir; ignoring: $rpm_latest"
      rpm_latest=""
    fi
  fi

  # Prefer modules list (more reliable on sd-boot setups than vmlinuz-* in /boot)
  # Portability: sort -V is a GNU extension; in minimal/rescue environments it may not exist.
  local have_sort_v=false
  if printf '1\n2\n' | sort -V >/dev/null 2>&1; then
    have_sort_v=true
  fi

  local modules_latest=""
  if [[ "$have_sort_v" == true ]]; then
    modules_latest="$(
      {
        ls -1 /lib/modules 2>/dev/null || true
        ls -1 /usr/lib/modules 2>/dev/null || true
      } | awk 'NF{print}' | sort -uV | tail -n 1
    )"
  else
    # Fallback: conservative numeric compare in bash.
    # Only consider versions we can parse numerically; skip odd names so they can't "win" by accident.
    local max_ver=""
    local d
    for d in /lib/modules/* /usr/lib/modules/*; do
      [[ -d "$d" ]] || continue
      local ver
      ver="${d##*/}"
      [[ -n "$ver" ]] || continue

      # Skip versions that don't start with a numeric segment.
      if ! kver_base_numeric "$ver" >/dev/null 2>&1; then
        debug "latest-kernel fallback: skipping unparsable module dir: $ver"
        continue
      fi

      if [[ -z "$max_ver" ]]; then
        max_ver="$ver"
      else
        if kver_is_newer "$ver" "$max_ver"; then
          max_ver="$ver"
        fi
      fi
    done

    if [[ -z "$max_ver" && -n "$RUNNING_KERNEL_VER" ]]; then
      # Last-resort safety: at least protect the running kernel.
      max_ver="$RUNNING_KERNEL_VER"
      debug "latest-kernel fallback: no parseable module dirs found; using running kernel as latest: $max_ver"
    fi

    modules_latest="$max_ver"
    debug "sort -V not available; using bash fallback latest-installed-kernel detection: ${modules_latest:-unknown}"
  fi

  # Choose best candidate (RPM-aware if available).
  if [[ -n "$rpm_latest" && -n "$modules_latest" ]]; then
    if kver_is_newer "$rpm_latest" "$modules_latest"; then
      LATEST_INSTALLED_VER="$rpm_latest"
    else
      LATEST_INSTALLED_VER="$modules_latest"
    fi
  elif [[ -n "$rpm_latest" ]]; then
    LATEST_INSTALLED_VER="$rpm_latest"
  else
    LATEST_INSTALLED_VER="$modules_latest"
  fi

  # Bootloader awareness: saved GRUB default (best effort)
  GRUB_DEFAULT_ID="$(get_grub_default_id 2>/dev/null || true)"
  [[ -n "$GRUB_DEFAULT_ID" ]] && debug "GRUB saved_entry: $GRUB_DEFAULT_ID"

  debug "Running kernel: ${RUNNING_KERNEL_VER:-unknown}"
  debug "Latest installed kernel: ${LATEST_INSTALLED_VER:-unknown}"
}

rotate_backups() {
  # Remove old backup directories to avoid filling BACKUP_ROOT.
  [[ "$KEEP_BACKUPS" =~ ^[0-9]+$ ]] || return 0
  [[ "$KEEP_BACKUPS" -gt 0 ]] || return 0

  local dirs
  mapfile -t dirs < <(ls -1dt "$BACKUP_ROOT"/bls-entries-* 2>/dev/null || true)

  local total="${#dirs[@]}"
  if [[ "$total" -le "$KEEP_BACKUPS" ]]; then
    return 0
  fi

  local i
  for (( i=KEEP_BACKUPS; i<total; i++ )); do
    local d="${dirs[$i]}"
    [[ -n "$d" ]] || continue

    # Safety: only remove expected paths
    case "$d" in
      "$BACKUP_ROOT"/bls-entries-*)
        debug "Rotating backups: removing $d"
        rm -rf -- "$d" 2>/dev/null || true
        ;;
      *)
        warn "Rotate backups: refusing to remove unexpected path: $d"
        ;;
    esac
  done
}

latest_backup_dir() {
  # Prefer explicit latest symlink; otherwise pick newest matching directory.
  if [[ -d "$BACKUP_ROOT/latest" ]]; then
    printf '%s\n' "$BACKUP_ROOT/latest"
    return 0
  fi

  ls -1dt "$BACKUP_ROOT"/bls-entries-* 2>/dev/null | head -n 1 || true
}

pick_nth_backup_dir() {
  local n="$1"
  [[ "$n" =~ ^[0-9]+$ ]] || return 1
  [[ "$n" -ge 1 ]] || return 1

  ls -1dt "$BACKUP_ROOT"/bls-entries-* 2>/dev/null | sed -n "${n}p" || true
}

list_backups() {
  mkdir -p -- "$BACKUP_ROOT" 2>/dev/null || true
  if ! ls -1d "$BACKUP_ROOT"/bls-entries-* >/dev/null 2>&1; then
    log "No backups found under: $BACKUP_ROOT"
    exit 0
  fi

  log "Backups under: $BACKUP_ROOT"
  log "(Use: --restore-pick N or --validate-pick N)"
  log "${C_DIM}GREEN = recommended (passes validation). RED = old/bad (fails validation).${C_RESET}"
  if [[ "$VERBOSE" == false ]]; then
    log "${C_DIM}(Tip: add --verbose to show why a backup is marked OLD.)${C_RESET}"
  fi

  local i=1
  while IFS= read -r d; do
    [[ -n "$d" ]] || continue

    local count
    count="$(ls -1 "$d"/full/*.conf 2>/dev/null | wc -l || true)"

    local sid=""
    local mid=""
    if [[ -f "$d/manifest.txt" ]]; then
      sid="$(awk -F= '$1=="snapper_backup_id" {print $2; exit}' "$d/manifest.txt" 2>/dev/null || true)"
      mid="$(awk -F= '$1=="machine_id" {print $2; exit}' "$d/manifest.txt" 2>/dev/null || true)"
    fi

    local extra=""
    [[ -n "$sid" ]] && extra+=" snapper=#$sid"
    [[ -n "$mid" ]] && extra+=" machine_id=${mid:0:8}…"

    local status_tag=""
    local status_color="$C_GREEN"
    if [[ "$VERBOSE" == true ]]; then
      if validate_backup_bootability "$d"; then
        status_tag="[OK]"
        status_color="$C_GREEN"
      else
        status_tag="[OLD]"
        status_color="$C_RED"
      fi
    else
      if VALIDATE_QUIET=true validate_backup_bootability "$d" >/dev/null 2>&1; then
        status_tag="[OK]"
        status_color="$C_GREEN"
      else
        status_tag="[OLD]"
        status_color="$C_RED"
      fi
    fi

    if [[ -f "$d/manifest.txt" ]]; then
      log "${status_color}${status_tag}${C_RESET} $i) $d (full entries: $count)$extra"
    else
      log "${status_color}${status_tag}${C_RESET} $i) $d (full entries: $count; no manifest)"
    fi

    i=$((i + 1))
  done < <(ls -1dt "$BACKUP_ROOT"/bls-entries-* 2>/dev/null)
}

validate_backup_structure() {
  # Integrity check: backup looks like a backup (not necessarily bootable).
  local src="$1"
  [[ -d "$src" ]] || return 1
  [[ -d "$src/full" ]] || return 1
  compgen -G "$src/full/*.conf" >/dev/null || return 1

  local bad=0
  for f in "$src"/full/*.conf; do
    local kp
    kp="$(bls_linux_path "$f")"
    if [[ -z "$kp" ]]; then
      bad=$((bad + 1))
    fi
  done

  [[ "$bad" -eq 0 ]]
}

validate_backup_bootability() {
  # Strong validation: try to ensure the restored set won't obviously be broken.
  # Checks:
  # - each entry has linux path and it exists now
  # - initrd(s) (if present) exist now (BLS can include multiple initrd lines)
  # - snapper snapshots referenced still exist (if verification enabled)
  # - machine-id match if manifest provides it
  local src="$1"
  local quiet="${VALIDATE_QUIET:-false}"

  if ! validate_backup_structure "$src"; then
    if [[ "$quiet" == true ]]; then
      return 1
    fi
    err "validate: backup structure invalid: $src"
    return 1
  fi

  local this_mid=""
  if [[ -f /etc/machine-id ]]; then
    this_mid="$(tr -d '\n' </etc/machine-id 2>/dev/null || true)"
  fi

  local manifest_mid=""
  if [[ -f "$src/manifest.txt" ]]; then
    manifest_mid="$(awk -F= '$1=="machine_id" {print $2; exit}' "$src/manifest.txt" 2>/dev/null || true)"
  fi

  if [[ -n "$manifest_mid" && -n "$this_mid" && "$manifest_mid" != "$this_mid" ]]; then
    if [[ "$quiet" == true ]]; then
      return 1
    fi
    err "validate: machine-id mismatch (backup is from a different install)"
    err "validate: this=$this_mid backup=$manifest_mid"
    return 1
  fi

  local missing_kernel=0
  local missing_initrd=0
  local missing_dt=0
  local missing_snapshot=0

  for f in "$src"/full/*.conf; do
    local kp
    kp="$(bls_linux_path "$f")"
    local kfull
    kfull="$(resolve_boot_path "$kp" || true)"
    if [[ -z "$kfull" || ! -s "$kfull" ]]; then
      missing_kernel=$((missing_kernel + 1))
    fi

    # BLS allows multiple initrd lines; treat as missing if ANY initrd is missing.
    declare -a ips
    ips=()
    mapfile -t ips < <(bls_initrd_paths "$f")
    if (( ${#ips[@]} > 0 )); then
      local ip
      local any_missing=false
      for ip in "${ips[@]}"; do
        [[ -n "$ip" ]] || continue
        local ifull
        ifull="$(resolve_boot_path "$ip" || true)"
        if [[ -z "$ifull" || ! -s "$ifull" ]]; then
          any_missing=true
          break
        fi
      done
      if [[ "$any_missing" == true ]]; then
        missing_initrd=$((missing_initrd + 1))
      fi
    fi

    local dtp
    dtp="$(bls_devicetree_path "$f")"
    if [[ -n "$dtp" ]]; then
      local dtfull
      dtfull="$(resolve_boot_path "$dtp" || true)"
      if [[ -z "$dtfull" || ! -s "$dtfull" ]]; then
        missing_dt=$((missing_dt + 1))
      fi
    fi

    if [[ "$VERIFY_SNAPSHOTS" == true ]]; then
      local sn
      sn="$(snapshot_num_from_entry "$f")"
      if [[ -n "$sn" ]]; then
        if ! snapshot_exists "$sn"; then
          missing_snapshot=$((missing_snapshot + 1))
        fi
      fi
    fi
  done

  if [[ "$missing_kernel" -ne 0 || "$missing_initrd" -ne 0 || "$missing_dt" -ne 0 || "$missing_snapshot" -ne 0 ]]; then
    if [[ "$quiet" == true ]]; then
      return 1
    fi
    err "validate: failed: missing kernel=$missing_kernel initrd=$missing_initrd devicetree=$missing_dt snapshots=$missing_snapshot"
    return 1
  fi

  return 0
}

pick_best_backup_dir() {
  # Choose newest backup that passes bootability validation.
  local d
  while IFS= read -r d; do
    [[ -n "$d" ]] || continue
    if validate_backup_bootability "$d"; then
      printf '%s\n' "$d"
      return 0
    fi
  done < <(ls -1dt "$BACKUP_ROOT"/bls-entries-* 2>/dev/null)

  return 1
}

restore_entries_from_backup() {
  local src="$1"
  if [[ -z "$src" ]]; then
    err "restore: missing source directory"
    exit 2
  fi
  if [[ ! -d "$src" ]]; then
    err "restore: backup dir not found: $src"
    exit 1
  fi

  if ! validate_backup_structure "$src"; then
    err "restore: invalid backup structure: $src"
    exit 1
  fi

  if ! validate_backup_bootability "$src"; then
    if [[ "$RESTORE_ANYWAY" == false ]]; then
      err "restore blocked: backup failed validation"
      err "Use --restore-anyway to override"
      exit 1
    fi
    warn "Proceeding despite failed validation (--restore-anyway)"
  fi

  debug "Restoring entries from '$src' into '$ENTRIES_DIR'"

  # Backup current entries before replacing.
  local ts
  ts="$(ts_now)"
  local pre_dir="$BACKUP_ROOT/restore-pre-$ts"
  mkdir -p -- "$pre_dir"

  if compgen -G "$ENTRIES_DIR/*.conf" >/dev/null; then
    cp -a -- "$ENTRIES_DIR"/*.conf "$pre_dir/" 2>/dev/null || \
    cp -p -- "$ENTRIES_DIR"/*.conf "$pre_dir/" 2>/dev/null || \
    cp -- "$ENTRIES_DIR"/*.conf "$pre_dir/"
  fi

  # Restore strategy:
  # - Default: additive (copy/overwrite from backup, but DO NOT remove newer entries)
  # - Optional: --clean-restore removes extra entries not present in backup (defensively)
  declare -A wanted
  local bf
  for bf in "$src"/full/*.conf; do
    local base
    base="$(basename -- "$bf")"
    wanted["$base"]=1
  done

  # Clean-restore preview (always show what would be deleted; require explicit confirmation).
  declare -a clean_remove
  clean_remove=()
  if [[ "$CLEAN_RESTORE" == true ]]; then
    local cur
    for cur in "$ENTRIES_DIR"/*.conf; do
      [[ -e "$cur" ]] || continue
      local base
      base="$(basename -- "$cur")"
      if [[ -z "${wanted[$base]+x}" ]]; then
        local kp kfull
        kp="$(bls_linux_path "$cur")"
        kfull="$(resolve_boot_path "$kp" 2>/dev/null || true)"

        if [[ -n "$RUNNING_KERNEL_VER" ]] && path_mentions_kver "$kp" "$RUNNING_KERNEL_VER"; then
          [[ "$VERBOSE" == true ]] && warn "clean-restore preview: KEEP (mentions running kernel): $base"
          continue
        fi
        if [[ -n "$kfull" && -s "$kfull" ]]; then
          [[ "$VERBOSE" == true ]] && warn "clean-restore preview: KEEP (kernel exists): $base"
          continue
        fi

        clean_remove+=("$cur")
      fi
    done

    if (( ${#clean_remove[@]} > 0 )); then
      log ""
      warn "clean-restore preview: ${#clean_remove[@]} extra entry file(s) would be removed:" 
      local f
      for f in "${clean_remove[@]}"; do
        warn "  REMOVE: $(basename -- "$f")"
      done
      log ""
      log "Type YES to proceed with restore + clean-restore deletions:" 
      local yn
      read -r -p "> " yn </dev/tty || true
      if [[ "$yn" != "YES" ]]; then
        err "Cancelled restore (clean-restore not confirmed)."
        exit 1
      fi
    else
      [[ "$VERBOSE" == true ]] && log "clean-restore preview: no extra broken entries to remove."
    fi
  fi

  # Copy/overwrite from backup
  for bf in "$src"/full/*.conf; do
    local base
    base="$(basename -- "$bf")"
    cp -a -- "$bf" "$ENTRIES_DIR/$base" 2>/dev/null || \
    cp -p -- "$bf" "$ENTRIES_DIR/$base" 2>/dev/null || \
    cp -- "$bf" "$ENTRIES_DIR/$base"
  done

  # Apply clean-restore deletions (defensive: remove only entries that looked broken in the preview)
  if [[ "$CLEAN_RESTORE" == true && ${#clean_remove[@]} -gt 0 ]]; then
    local f
    for f in "${clean_remove[@]}"; do
      [[ -e "$f" ]] || continue
      warn "clean-restore: removing extra broken entry: $(basename -- "$f")"
      rm -f -- "$f"
    done
  fi

  log "Restore complete."
  log "- Restored from: $src"
  log "- Previous entries saved to: $pre_dir"
}

resolve_boot_path() {
  # Resolves a BLS path to a concrete path on disk.
  # BLS commonly uses paths like /vmlinuz-… or /EFI/… (relative to $BOOT_DIR).
  # Some setups already include /boot/….
  local p="$1"

  if [[ -z "$p" ]]; then
    return 1
  fi

  if [[ "$p" == /* ]]; then
    if [[ "$p" == "${BOOT_DIR%/}/"* ]]; then
      printf '%s\n' "$p"
    else
      printf '%s\n' "${BOOT_DIR%/}$p"
    fi
  else
    printf '%s\n' "${BOOT_DIR%/}/$p"
  fi
}

snapshot_dir_from_entry() {
  # Extracts a Snapper snapshot dir like /.snapshots/123/snapshot (if present).
  # IMPORTANT: only consider real BLS lines (linux/linuxefi/options), not comments.
  # Returns the first match on stdout.
  awk '
    /^[[:space:]]*#/ {next}
    NF < 2 {next}
    tolower($1) ~ /^(linux(efi)?|options)$/ {
      if (match($0, /\/\.snapshots\/[0-9]+\/snapshot/)) {
        print substr($0, RSTART, RLENGTH)
        exit
      }
    }
  ' "$1" 2>/dev/null || true
}

snapshot_num_from_entry() {
  # Returns the snapshot number (digits only) if the entry references /.snapshots/<n>/snapshot
  # Only consider real BLS lines (linux/linuxefi/options), not comments.
  local n
  n="$(
    awk '
      /^[[:space:]]*#/ {next}
      NF < 2 {next}
      tolower($1) ~ /^(linux(efi)?|options)$/ {
        if (match($0, /\/\.snapshots\/[0-9]+\/snapshot/)) {
          s = substr($0, RSTART, RLENGTH)
          gsub(/[^0-9]/, "", s)
          print s
          exit
        }
      }
    ' "$1" 2>/dev/null
  )"
  [[ -n "$n" ]] && printf '%s\n' "$n" || true
}

kernel_version_from_linux_path() {
  # Best-effort kernel version extraction from a BLS "linux" path.
  # Supports both:
  # - sd-boot style (openSUSE): /distro/<KVER>/linux-<hash>
  # - flat GRUB/BLS style:      /vmlinuz-<KVER>
  local p="$1"
  p="${p#/}"

  # 1) Segment approach (sd-boot style): /<distro>/<kver>/<kernel>
  local rest="${p#*/}"
  if [[ "$rest" != "$p" ]]; then
    local kver="${rest%%/*}"
    if [[ -n "$kver" && "$kver" != "$rest" ]]; then
      printf '%s\n' "$kver"
      return 0
    fi
  fi

  # 2) Flat approach based on basename: vmlinuz-6.14.2-default, linux-6.8.1-...
  local base="${p##*/}"
  local cand=""
  case "$base" in
    vmlinuz-*) cand="${base#vmlinuz-}" ;;
    linux-*)   cand="${base#linux-}" ;;
    kernel-*)  cand="${base#kernel-}" ;;
    bzImage-*) cand="${base#bzImage-}" ;;
    *) cand="" ;;
  esac

  # Strip common suffixes when present.
  cand="${cand%.efi}"
  cand="${cand%.gz}"
  cand="${cand%.xz}"

  # Require at least one digit to avoid returning hashes like "linux-<hash>".
  if [[ -n "$cand" && "$cand" =~ [0-9] ]]; then
    printf '%s\n' "$cand"
    return 0
  fi

  return 1
}

path_mentions_kver() {
  # Heuristic: if the linux path string contains the kernel version, treat it as a match.
  # Must avoid substring false positives (e.g. 6.8.1 matching 6.8.10).
  local p="$1"
  local kver="$2"
  [[ -n "$p" && -n "$kver" ]] || return 1

  # Escape for bash regex (avoid sed/perl dependency here).
  local kver_esc=""
  local i ch
  for (( i=0; i<${#kver}; i++ )); do
    ch="${kver:$i:1}"
    case "$ch" in
      \\|.|^|\$|\||'?'|'*'|'+'|'('|')'|'{'|'}'|'['|']')
        kver_esc+="\\$ch"
        ;;
      *)
        kver_esc+="$ch"
        ;;
    esac
  done

  # Boundary rule: must not be preceded by a digit, and must be followed by a non-digit (or end).
  # This prevents: "6.8.1" matching "6.8.10".
  if [[ "$p" =~ (^|[^0-9])${kver_esc}([^0-9]|$) ]]; then
    return 0
  fi
  return 1
}

modules_dir_exists_for_kver() {
  local kver="$1"
  [[ -n "$kver" ]] || return 1
  [[ -d "/lib/modules/$kver" || -d "/usr/lib/modules/$kver" ]]
}

load_snapper_snapshot_set() {
  if command -v snapper >/dev/null 2>&1; then
    SNAPPER_AVAILABLE=true
    while IFS= read -r raw; do
      raw="${raw//[^0-9]/}"
      [[ -n "$raw" ]] && SNAPSHOT_NUM_SET["$raw"]=1
    done < <(snapper --no-dbus list 2>/dev/null | awk '/^[[:space:]]*[0-9]+/ {print $1}')
  fi
}

snapshot_exists() {
  # True if snapshot exists either on-disk or in snapper list output.
  local n="$1"
  [[ -n "$n" ]] || return 1

  if [[ -d "/.snapshots/$n/snapshot" ]]; then
    return 0
  fi

  if [[ "$SNAPPER_AVAILABLE" == true && -n "${SNAPSHOT_NUM_SET[$n]+x}" ]]; then
    return 0
  fi

  return 1
}

# Read-only filesystem handling (MicroOS/Aeon)
# We only ever attempt remount on non-root mountpoints.
#
# This is best-effort and only used when applying changes.

declare -A REMOUNT_WAS_RO
REMOUNTED_MOUNTPOINTS=()

mount_info_for_path() {
  # Prints: "<mountpoint>|<options>" or nothing.
  local p="$1"

  if command -v findmnt >/dev/null 2>&1; then
    # Use an explicit delimiter so mountpoints containing spaces are unambiguous.
    # util-linux findmnt supports --output-separator.
    local out
    out="$(findmnt -no TARGET,OPTIONS --output-separator '|' -T "$p" 2>/dev/null | head -n 1 || true)"
    if [[ -n "$out" && "$out" == *"|"* ]]; then
      printf '%s\n' "$out"
      return 0
    fi

    # Fallback if --output-separator isn't supported: use -P (key="value") format.
    out="$(findmnt -Pno TARGET,OPTIONS -T "$p" 2>/dev/null | head -n 1 || true)"
    if [[ -n "$out" ]]; then
      local mp opts
      mp="$(printf '%s\n' "$out" | sed -n 's/.*TARGET="\([^"]*\)".*/\1/p')"
      opts="$(printf '%s\n' "$out" | sed -n 's/.*OPTIONS="\([^"]*\)".*/\1/p')"
      if [[ -n "$mp" ]]; then
        printf '%s|%s\n' "$mp" "$opts"
        return 0
      fi
    fi
  fi

  # Fallback: parse /proc/mounts and pick the longest matching mountpoint prefix.
  # NOTE: /proc/mounts encodes spaces as octal escapes (e.g. \040). Decode for comparisons.
  local best_mp=""
  local best_opts=""
  while read -r dev mp fstype opts rest; do
    [[ -n "$mp" ]] || continue

    # Decode octal escapes used in /proc/mounts.
    local mp_dec
    mp_dec="$(printf '%b' "$mp")"

    if [[ "$p" == "$mp_dec" || "$p" == "$mp_dec"/* ]]; then
      if [[ ${#mp_dec} -gt ${#best_mp} ]]; then
        best_mp="$mp_dec"
        best_opts="$opts"
      fi
    fi
  done </proc/mounts

  if [[ -n "$best_mp" ]]; then
    printf '%s|%s\n' "$best_mp" "$best_opts"
    return 0
  fi

  return 1
}

mount_opts_have_ro() {
  local opts="$1"
  [[ ",$opts," == *,ro,* ]]
}

restore_remounted_mountpoints() {
  local mp
  for mp in "${REMOUNTED_MOUNTPOINTS[@]}"; do
    [[ -n "$mp" ]] || continue
    if [[ "${REMOUNT_WAS_RO[$mp]+x}" == x ]]; then
      debug "Restoring read-only mount: $mp"
      mount -o remount,ro "$mp" 2>/dev/null || true
    fi
  done
}

maybe_temp_remount_rw_for_path() {
  # $1 = path, $2 = human label
  local p="$1"
  local label="$2"

  [[ "$AUTO_REMOUNT_RW" == true ]] || return 0

  local info mp opts
  info="$(mount_info_for_path "$p" 2>/dev/null || true)"

  # Expected format: <mountpoint>|<options>
  if [[ "$info" == *"|"* ]]; then
    mp="${info%%|*}"
    opts="${info#*|}"
  else
    # Backward/unknown format fallback (best effort)
    mp="${info%% *}"
    opts="${info#* }"
  fi

  [[ -n "$mp" ]] || return 0

  if mount_opts_have_ro "$opts"; then
    # Never attempt to remount root rw in this tool.
    if [[ "$mp" == "/" ]]; then
      err "$label lives on a read-only root filesystem (/)."
      err "Refusing to remount / rw. On MicroOS/Aeon, run from a writable environment (e.g. transactional-update shell) or ensure /boot(/efi) is mounted rw."
      exit 1
    fi

    # Avoid remounting the same mountpoint multiple times.
    if [[ -n "${REMOUNT_WAS_RO[$mp]+x}" ]]; then
      return 0
    fi

    debug "Remounting rw: $mp (for $label)"
    if mount -o remount,rw "$mp" 2>/dev/null; then
      REMOUNT_WAS_RO["$mp"]=1
      REMOUNTED_MOUNTPOINTS+=("$mp")
      trap restore_remounted_mountpoints EXIT
      log "${C_DIM}remount:${C_RESET} $mp -> rw (${label}; path=$p)"
    else
      err "Could not remount $mp rw (needed for $label)"
      exit 1
    fi
  fi
}

kb_available_for_path() {
  local p="$1"
  df -Pk "$p" 2>/dev/null | awk 'NR==2 {print $4; exit}' || true
}

kb_required_for_entries_backup() {
  # Rough estimate: entries are small, but ESP can be tight. Use a conservative multiplier.
  local entries_kb
  entries_kb="$(du -sk -- "$ENTRIES_DIR" 2>/dev/null | awk '{print $1}' || true)"
  [[ "$entries_kb" =~ ^[0-9]+$ ]] || entries_kb=64

  # multiplier + small fixed headroom
  printf '%s\n' $(( entries_kb * 3 + 10240 ))
}

preflight_backup_space_or_die() {
  local target="$1"
  local need_kb avail_kb
  need_kb="$(kb_required_for_entries_backup)"
  avail_kb="$(kb_available_for_path "$target")"

  [[ "$avail_kb" =~ ^[0-9]+$ ]] || return 0

  if [[ "$avail_kb" -lt "$need_kb" ]]; then
    err "Not enough free space for backups on: $target"
    err "Need ~${need_kb}KB, have ${avail_kb}KB."
    err "Tip: set --backup-root to a larger filesystem or use --no-backup (not recommended)."
    exit 1
  fi
}

append_trap() {
  # Append a handler to an existing trap (best effort).
  # $1 = handler, $2 = signal
  local handler="$1"
  local sig="$2"

  local existing
  existing="$(trap -p "$sig" 2>/dev/null | awk -F"'" '{print $2}' || true)"

  if [[ -n "$existing" ]]; then
    trap "$existing; $handler" "$sig"
  else
    trap "$handler" "$sig"
  fi
}

scan_btrfs_partitions() {
  # Backwards-compatible wrapper (older name). Prefer scan_linux_partitions.
  scan_linux_partitions
}

scan_linux_partitions() {
  # Prints lines: "<dev> <fstype> <size> <uuid> <mountpoint>"
  # Example: /dev/nvme0n1p2 btrfs 100G 0123-... /mnt
  if ! command -v lsblk >/dev/null 2>&1; then
    return 1
  fi

  # Filter for common Linux filesystems to avoid listing swap/ESP.
  lsblk -pnro NAME,FSTYPE,SIZE,UUID,MOUNTPOINT 2>/dev/null | awk '$2 ~ /^(btrfs|ext[34]|xfs)$/ {print}' || true
}

cleanup_rescue_mounts() {
  # Idempotent best-effort cleanup.
  ( set +e

    [[ -n "${RESCUE_MOUNT_POINT:-}" ]] || return 0

    if command -v mountpoint >/dev/null 2>&1; then
      mountpoint -q -- "$RESCUE_MOUNT_POINT" || return 0
    fi

    # Try recursive unmount first.
    umount -R -- "$RESCUE_MOUNT_POINT" 2>/dev/null || umount --recursive -- "$RESCUE_MOUNT_POINT" 2>/dev/null || true

    # Fallback: unmount common bind mounts in reverse-ish order.
    for mp in \
      "$RESCUE_MOUNT_POINT/dev/pts" \
      "$RESCUE_MOUNT_POINT/dev" \
      "$RESCUE_MOUNT_POINT/proc" \
      "$RESCUE_MOUNT_POINT/sys" \
      "$RESCUE_MOUNT_POINT/run"; do
      umount -l -- "$mp" 2>/dev/null || true
    done

    umount -l -- "$RESCUE_MOUNT_POINT" 2>/dev/null || true
  )
}

setup_rescue_bind_mounts() {
  local root="$1"

  mkdir -p -- "$root/dev" "$root/proc" "$root/sys" "$root/dev/pts" "$root/run"

  mount --rbind /dev "$root/dev"
  mount --rbind /proc "$root/proc"
  mount --rbind /sys "$root/sys"

  # /run is important for some tools; best effort.
  mount --rbind /run "$root/run" 2>/dev/null || true

  if command -v mount >/dev/null 2>&1; then
    mount --make-rslave "$root/dev" 2>/dev/null || true
    mount --make-rslave "$root/proc" 2>/dev/null || true
    mount --make-rslave "$root/sys" 2>/dev/null || true
    mount --make-rslave "$root/run" 2>/dev/null || true
  fi
}

inject_self_into_chroot() {
  local root="$1"
  local dest="$root$RESCUE_SHIM_PATH"

  mkdir -p -- "$(dirname -- "$dest")"

  # Copy script contents rather than relying on cp from potentially odd mount sources.
  if ! cat -- "$0" >"$dest" 2>/dev/null; then
    cp -- "$0" "$dest"
  fi
  chmod 0755 -- "$dest"
}

perform_rescue_chroot() {
  local dev="$1"

  if [[ -z "$dev" ]]; then
    err "rescue: no device selected"
    return 1
  fi
  if [[ ! -b "$dev" ]]; then
    err "rescue: not a block device: $dev"
    return 1
  fi

  mkdir -p -- "$RESCUE_MOUNT_POINT"

  log "Mounting target root (btrfs default subvolume): $dev -> $RESCUE_MOUNT_POINT"
  mount -- "$dev" "$RESCUE_MOUNT_POINT"

  append_trap cleanup_rescue_mounts EXIT
  append_trap cleanup_rescue_mounts INT
  append_trap cleanup_rescue_mounts TERM

  setup_rescue_bind_mounts "$RESCUE_MOUNT_POINT"
  inject_self_into_chroot "$RESCUE_MOUNT_POINT"

  log "Entering chroot. Inside chroot we'll run: mount -a (best effort), then start scrub-ghost menu."
  log "Exit the menu to return here and unmount everything."

  chroot "$RESCUE_MOUNT_POINT" /bin/bash -c "mount -a 2>/dev/null || true; exec $RESCUE_SHIM_PATH --menu" </dev/tty

  cleanup_rescue_mounts
}

menu_rescue_wizard() {
  log ""
  log "${C_BOLD}Rescue / chroot wizard${C_RESET}"
  log "This is intended for running from a Live ISO to chroot into an installed system."
  log ""

  local -a lines
  mapfile -t lines < <(scan_linux_partitions || true)

  if (( ${#lines[@]} == 0 )); then
    warn "No Linux filesystem partitions found via lsblk."
    warn "If your root is encrypted, unlock it first (e.g., cryptsetup open), then re-run." 
    return 1
  fi

  log "Detected Linux filesystem partitions:"
  local idx=1
  local line
  for line in "${lines[@]}"; do
    local dev="" fstype="" size="" uuid="" mnt=""
    IFS=' ' read -r dev fstype size uuid mnt <<<"$line"
    [[ -z "$mnt" ]] && mnt="-"
    log "  $idx) $dev  size=$size  uuid=$uuid  mounted=$mnt"
    idx=$((idx + 1))
  done

  log ""
  log "Pick a number to mount+chroot, or type a device path (e.g. /dev/nvme0n1p2), or 'q' to cancel."

  local choice
  read -r -p "> " choice </dev/tty || return 1

  if [[ "$choice" == "q" || "$choice" == "quit" ]]; then
    log "Cancelled."
    return 0
  fi

  local dev=""
  if [[ "$choice" =~ ^[0-9]+$ ]]; then
    local n="$choice"
    if (( n < 1 || n > ${#lines[@]} )); then
      err "Invalid selection: $n"
      return 1
    fi
    line="${lines[$((n-1))]}"
    IFS=' ' read -r dev _rest <<<"$line"
  else
    dev="$choice"
  fi

  log ""
  log "About to chroot into: $dev"
  log "Type YES to continue:"
  local yn
  read -r -p "> " yn </dev/tty || true
  if [[ "$yn" != "YES" ]]; then
    log "Cancelled."
    return 0
  fi

  perform_rescue_chroot "$dev"
}

main() {
  set -euo pipefail
  IFS=$'\n\t'

  # Allow --help/--completion without requiring root.
  local args=("$@")
  local i
  for (( i=0; i<${#args[@]}; i++ )); do
    case "${args[$i]}" in
      -h|--help)
        usage
        return 0
        ;;
      --completion)
        local sh="zsh"
        if (( i+1 < ${#args[@]} )) && [[ "${args[$((i+1))]}" != --* ]]; then
          sh="${args[$((i+1))]}"
        fi
        print_completion "$sh"
        return $?
        ;;
    esac
  done

  ORIG_ARGC=$#

  require_arg() {
    # $1=option name, $2=next token
    local opt="$1"
    local val="${2-}"
    if [[ -z "$val" || "$val" == --* ]]; then
      err "Option $opt requires a value. Use -h or --help."
      exit 2
    fi
  }

# Argument parsing
while [[ $# -gt 0 ]]; do
  case "$1" in
    --menu)
      MENU_REQUESTED=true
      ;;
    --rescue)
      ACTION="rescue"
      ;;
    --no-menu)
      NO_MENU=true
      ;;
    --verbose)
      VERBOSE=true
      ;;
    --debug)
      DEBUG=true
      ;;
    --log-file)
      require_arg "$1" "${2-}"
      shift
      LOG_FILE="$1"
      LOG_FILE_SET=true
      ;;
    --no-color)
      COLOR=false
      ;;
    --json)
      JSON_OUTPUT=true
      ;;
    --dry-run)
      DRY_RUN=true
      ;;
    --force)
      DRY_RUN=false
      ;;
    --delete)
      DRY_RUN=false
      DELETE_MODE="delete"
      ;;
    --backup-dir)
      require_arg "$1" "${2-}"
      shift
      BACKUP_DIR="$1"
      BACKUP_DIR_SET=true
      ;;
    --backup-root)
      require_arg "$1" "${2-}"
      shift
      BACKUP_ROOT="$1"
      ;;
    --keep-backups)
      require_arg "$1" "${2-}"
      shift
      KEEP_BACKUPS="$1"
      ;;
    --entries-dir)
      require_arg "$1" "${2-}"
      shift
      ENTRIES_DIR="$1"
      ENTRIES_DIR_SET=true
      ;;
    --boot-dir)
      require_arg "$1" "${2-}"
      shift
      BOOT_DIR="$1"
      BOOT_DIR_SET=true
      ;;
    --rebuild-grub)
      REBUILD_GRUB=true
      ;;
    --update-sdboot)
      UPDATE_SDBOOT=true
      ;;
    --no-remount-rw)
      AUTO_REMOUNT_RW=false
      ;;
    --completion)
      PRINT_COMPLETION=true
      if [[ -n "${2:-}" && "${2:-}" != --* ]]; then
        shift
        COMPLETION_SHELL="${1:-zsh}"
      fi
      ;;
    --grub-cfg)
      require_arg "$1" "${2-}"
      shift
      GRUB_CFG="$1"
      GRUB_CFG_SET=true
      ;;

    --list-backups)
      ACTION="list-backups"
      ;;
    --restore-latest)
      ACTION="restore"
      RESTORE_FROM="__LATEST__"
      ;;
    --restore-pick)
      ACTION="restore"
      require_arg "$1" "${2-}"
      shift
      RESTORE_PICK="$1"
      ;;
    --restore-best)
      ACTION="restore"
      RESTORE_BEST=true
      ;;
    --restore-from)
      ACTION="restore"
      require_arg "$1" "${2-}"
      shift
      RESTORE_FROM="$1"
      ;;
    --clean-restore)
      CLEAN_RESTORE=true
      ;;
    --restore-anyway)
      RESTORE_ANYWAY=true
      ;;

    --validate-latest)
      ACTION="validate"
      RESTORE_FROM="__LATEST__"
      ;;
    --validate-pick)
      ACTION="validate"
      require_arg "$1" "${2-}"
      shift
      RESTORE_PICK="$1"
      ;;
    --validate-from)
      ACTION="validate"
      require_arg "$1" "${2-}"
      shift
      RESTORE_FROM="$1"
      ;;

    --no-backup)
      AUTO_BACKUP=false
      ;;
    --no-snapper-backup)
      AUTO_SNAPPER_BACKUP=false
      ;;

    --no-verify-snapshots)
      VERIFY_SNAPSHOTS=false
      ;;
    --no-verify-modules)
      VERIFY_KERNEL_MODULES=false
      ;;
    --prune-stale-snapshots)
      PRUNE_STALE_SNAPSHOTS=true
      ;;
    --prune-uninstalled)
      PRUNE_UNINSTALLED_KERNELS=true
      ;;
    --prune-duplicates)
      PRUNE_DUPLICATES=true
      ;;
    --prune-zombies)
      PRUNE_ZOMBIES=true
      ;;
    --confirm-uninstalled)
      CONFIRM_PRUNE_UNINSTALLED=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      err "Unknown argument: $1. Use -h or --help."
      exit 2
      ;;
  esac
  shift

done

  # Root check (after parsing so typos fail fast with a helpful message).
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    err "Please run as root (sudo). Use -h or --help."
    return 1
  fi

# Initialize colors/logging once we parsed flags.
# (Rescue mode needs this before checking for BLS entries.)
init_colors
init_logging
if [[ -n "$LOG_FILE" ]]; then
  debug "Logging to: $LOG_FILE"
fi

# Enforce supported distro/variant.
check_supported_os_or_die

if [[ "$ACTION" == "rescue" ]]; then
  menu_rescue_wizard
  return $?
fi

if [[ "$ENTRIES_DIR_SET" == false ]]; then
  # openSUSE commonly mounts the ESP at /boot/efi (sd-boot) and Fedora-like setups use /boot.
  for d in /boot/loader/entries /boot/efi/loader/entries /efi/loader/entries; do
    if [[ -d "$d" ]]; then
      ENTRIES_DIR="$d"
      break
    fi
  done
fi

if [[ -z "$ENTRIES_DIR" || ! -d "$ENTRIES_DIR" ]]; then
  err "Entries dir not found. Tried: /boot/loader/entries, /boot/efi/loader/entries, /efi/loader/entries"
  err "(or pass --entries-dir DIR)"
  exit 1
fi

if [[ "$BOOT_DIR_SET" == false ]]; then
  BOOT_DIR="$(dirname "$(dirname "$ENTRIES_DIR")")"
fi

if [[ ! -d "$BOOT_DIR" ]]; then
  warn "Boot root dir not found: $BOOT_DIR (path checks may be wrong)"
fi

# If JSON output is enabled, keep stdout machine-readable by sending logs to stderr.
# (Only supported for the main scan/apply flow; not for list/validate/restore subcommands.)
if [[ "$JSON_OUTPUT" == true ]]; then
  if [[ "$ACTION" != "scan" ]]; then
    JSON_OUTPUT=false
  else
    COLOR=false
    LOG_TO_STDERR=true
  fi
fi


# Validate keep-backups value
if ! [[ "$KEEP_BACKUPS" =~ ^[0-9]+$ ]]; then
  warn "Invalid --keep-backups value: '$KEEP_BACKUPS' (using 5)"
  KEEP_BACKUPS=5
fi

# Compute kernel safety guardrails (running/latest)
compute_kernel_guardrails

if [[ "$VERIFY_SNAPSHOTS" == true ]]; then
  load_snapper_snapshot_set
fi

prompt_enter_to_continue() {
  # Intentionally show the prompt via log(), since `read -p` prints to stderr and can be hidden.
  log "${C_DIM}Press Enter to continue...${C_RESET}"
  # shellcheck disable=SC2162
  read -r _ </dev/tty 2>/dev/null || true
}

build_common_flags() {
  COMMON_FLAGS=()

  [[ "$COLOR" == false ]] && COMMON_FLAGS+=("--no-color")
  [[ "$JSON_OUTPUT" == true ]] && COMMON_FLAGS+=("--json")
  [[ "$VERBOSE" == true ]] && COMMON_FLAGS+=("--verbose")
  [[ "$DEBUG" == true ]] && COMMON_FLAGS+=("--debug")

  # Keep log file consistent across invocations
  if [[ -n "$LOG_FILE" ]]; then
    COMMON_FLAGS+=("--log-file" "$LOG_FILE")
  fi

  # Restore behavior knobs
  [[ "$RESTORE_ANYWAY" == true ]] && COMMON_FLAGS+=("--restore-anyway")
  [[ "$CLEAN_RESTORE" == true ]] && COMMON_FLAGS+=("--clean-restore")

  # Rebuild grub after apply operations (restore/clean)
  [[ "$REBUILD_GRUB" == true ]] && COMMON_FLAGS+=("--rebuild-grub")
  [[ "$UPDATE_SDBOOT" == true ]] && COMMON_FLAGS+=("--update-sdboot")
  [[ "$AUTO_REMOUNT_RW" == false ]] && COMMON_FLAGS+=("--no-remount-rw")
  if [[ "$GRUB_CFG_SET" == true ]]; then
    COMMON_FLAGS+=("--grub-cfg" "$GRUB_CFG")
  fi

  [[ "$AUTO_BACKUP" == false ]] && COMMON_FLAGS+=("--no-backup")
  [[ "$AUTO_SNAPPER_BACKUP" == false ]] && COMMON_FLAGS+=("--no-snapper-backup")

  [[ "$VERIFY_SNAPSHOTS" == false ]] && COMMON_FLAGS+=("--no-verify-snapshots")
  [[ "$VERIFY_KERNEL_MODULES" == false ]] && COMMON_FLAGS+=("--no-verify-modules")
  [[ "$PRUNE_DUPLICATES" == true ]] && COMMON_FLAGS+=("--prune-duplicates")

  # Keep using same backup root if user changed it
  [[ -n "$BACKUP_ROOT" ]] && COMMON_FLAGS+=("--backup-root" "$BACKUP_ROOT")
  [[ -n "$KEEP_BACKUPS" ]] && COMMON_FLAGS+=("--keep-backups" "$KEEP_BACKUPS")

  # If user explicitly set backup dir, preserve it
  [[ "$BACKUP_DIR_SET" == true ]] && COMMON_FLAGS+=("--backup-dir" "$BACKUP_DIR")

  # Preserve manual directory overrides if used
  [[ "$ENTRIES_DIR_SET" == true ]] && COMMON_FLAGS+=("--entries-dir" "$ENTRIES_DIR")
  [[ "$BOOT_DIR_SET" == true ]] && COMMON_FLAGS+=("--boot-dir" "$BOOT_DIR")
}

build_common_flags_minimal() {
  # Common flags for menu automation that should NOT depend on pruning toggles.
  # (Advanced users can still enable pruning via the existing clean submenu/settings.)
  COMMON_FLAGS=()

  [[ "$COLOR" == false ]] && COMMON_FLAGS+=("--no-color")
  [[ "$VERBOSE" == true ]] && COMMON_FLAGS+=("--verbose")
  [[ "$DEBUG" == true ]] && COMMON_FLAGS+=("--debug")

  if [[ -n "$LOG_FILE" ]]; then
    COMMON_FLAGS+=("--log-file" "$LOG_FILE")
  fi

  [[ "$REBUILD_GRUB" == true ]] && COMMON_FLAGS+=("--rebuild-grub")
  [[ "$UPDATE_SDBOOT" == true ]] && COMMON_FLAGS+=("--update-sdboot")
  [[ "$AUTO_REMOUNT_RW" == false ]] && COMMON_FLAGS+=("--no-remount-rw")
  if [[ "$GRUB_CFG_SET" == true ]]; then
    COMMON_FLAGS+=("--grub-cfg" "$GRUB_CFG")
  fi

  [[ "$AUTO_BACKUP" == false ]] && COMMON_FLAGS+=("--no-backup")
  [[ "$AUTO_SNAPPER_BACKUP" == false ]] && COMMON_FLAGS+=("--no-snapper-backup")

  [[ "$VERIFY_SNAPSHOTS" == false ]] && COMMON_FLAGS+=("--no-verify-snapshots")
  [[ "$VERIFY_KERNEL_MODULES" == false ]] && COMMON_FLAGS+=("--no-verify-modules")

  [[ -n "$BACKUP_ROOT" ]] && COMMON_FLAGS+=("--backup-root" "$BACKUP_ROOT")
  [[ -n "$KEEP_BACKUPS" ]] && COMMON_FLAGS+=("--keep-backups" "$KEEP_BACKUPS")

  [[ "$BACKUP_DIR_SET" == true ]] && COMMON_FLAGS+=("--backup-dir" "$BACKUP_DIR")

  [[ "$ENTRIES_DIR_SET" == true ]] && COMMON_FLAGS+=("--entries-dir" "$ENTRIES_DIR")
  [[ "$BOOT_DIR_SET" == true ]] && COMMON_FLAGS+=("--boot-dir" "$BOOT_DIR")
}

LAST_SUBCOMMAND_RC=0

_restore_errexit() {
  # $1 = had_errexit (0/1)
  local had_errexit="$1"
  if [[ "$had_errexit" -eq 1 ]]; then
    set -e
  else
    set +e
  fi
}

run_sub() {
  build_common_flags

  # Menu runs with `set -e` in some code paths; never let a failed subcommand abort the menu.
  local had_errexit=0
  [[ "$-" == *e* ]] && had_errexit=1

  local rc
  set +e
  SCRUB_GHOST_NO_MENU=1 bash "$SCRIPT_SELF" --no-menu "${COMMON_FLAGS[@]}" "$@"
  rc=$?
  _restore_errexit "$had_errexit"

  LAST_SUBCOMMAND_RC=$rc

  if [[ "$rc" -ne 0 ]]; then
    err "Subcommand failed (exit=$rc). Run with --debug or check the log file for details."
  fi

  # Always return success to callers in menu context.
  return 0
}

run_sub_minimal() {
  build_common_flags_minimal

  local had_errexit=0
  [[ "$-" == *e* ]] && had_errexit=1

  local rc
  set +e
  SCRUB_GHOST_NO_MENU=1 bash "$SCRIPT_SELF" --no-menu "${COMMON_FLAGS[@]}" "$@"
  rc=$?
  _restore_errexit "$had_errexit"

  LAST_SUBCOMMAND_RC=$rc

  if [[ "$rc" -ne 0 ]]; then
    err "Subcommand failed (exit=$rc). Run with --debug or check the log file for details."
  fi

  return 0
}

# --- SMART IMPROVEMENTS START ---

is_kernel_rpm_installed() {
  local kver="$1"
  [[ -n "$kver" ]] || return 1

  # If rpm command exists, check the database via kernel-uname-r provide.
  if command -v rpm >/dev/null 2>&1; then
    if rpm -q --whatprovides "kernel-uname-r = $kver" >/dev/null 2>&1; then
      return 0
    fi
    return 1
  fi

  # Fallback: if no rpm command, assume installed (conservative)
  return 0
}

recommend_action() {
  local count="$1"
  local type="$2"

  if ! [[ "$count" =~ ^[0-9]+$ ]]; then
    count=0
  fi

  if [[ "$count" -eq 0 ]]; then
    printf '%bNone found%b' "$C_GREEN" "$C_RESET"
    return 0
  fi

  case "$type" in
    ghost)
      printf '%b%d found%b -> %bClean (Safe)%b' "$C_RED" "$count" "$C_RESET" "$C_BOLD" "$C_RESET"
      ;;
    duplicate)
      printf '%b%d found%b -> %bPrune (Safe)%b' "$C_YELLOW" "$count" "$C_RESET" "$C_BOLD" "$C_RESET"
      ;;
    zombie)
      printf '%b%d found%b -> %bRepair (dracut suggested)%b' "$C_YELLOW" "$count" "$C_RESET" "$C_DIM" "$C_RESET"
      ;;
    stale)
      printf '%b%d found%b -> %bKeep (Manual review suggested)%b' "$C_YELLOW" "$count" "$C_RESET" "$C_DIM" "$C_RESET"
      ;;
    uninstalled)
      printf '%b%d found%b -> %bKeep (Requires confirmation)%b' "$C_YELLOW" "$count" "$C_RESET" "$C_DIM" "$C_RESET"
      ;;
    *)
      printf '%d' "$count"
      ;;
  esac
}

check_boot_storage_health() {
  # Get usage percentage of the filesystem holding $BOOT_DIR
  local usage
  usage="$(df --output=pcent "$BOOT_DIR" 2>/dev/null | tail -n 1 | tr -dc '0-9' || true)"

  [[ -z "$usage" ]] && usage=0

  if [[ "$usage" -ge 90 ]]; then
    printf '%bCRITICAL (%s%%%%)%b' "$C_RED" "$usage" "$C_RESET"
    return 2
  elif [[ "$usage" -ge 75 ]]; then
    printf '%bWARNING (%s%%%%)%b' "$C_YELLOW" "$usage" "$C_RESET"
    return 1
  else
    printf '%bHEALTHY (%s%%%%)%b' "$C_GREEN" "$usage" "$C_RESET"
    return 0
  fi
}

initrd_mime_type() {
  local p="$1"
  command -v file >/dev/null 2>&1 || return 1
  file --brief --mime-type -- "$p" 2>/dev/null || true
}

initrd_looks_valid() {
  # Best-effort: initrds should look like an "application/*" payload (gzip/zstd/cpio/etc).
  # This catches cases where the initrd file exists but is obviously not a real archive.
  local p="$1"
  [[ -n "$p" && -s "$p" ]] || return 1

  if command -v file >/dev/null 2>&1; then
    local mt
    mt="$(initrd_mime_type "$p")"
    [[ -n "$mt" && "$mt" == application/* ]]
    return $?
  fi

  # If file(1) isn't available, treat as OK if it exists+non-empty.
  return 0
}

check_kernel_redundancy() {
  # Count how many unique kernel versions have at least one valid BLS entry.
  # We only count entries where the kernel file resolves and exists on disk.
  declare -A valid_kvers
  local f
  for f in "$ENTRIES_DIR"/*.conf; do
    [[ -e "$f" ]] || continue

    local kp
    kp="$(bls_linux_path "$f")"
    [[ -n "$kp" ]] || continue

    local kfull
    kfull="$(resolve_boot_path "$kp" 2>/dev/null || true)"
    [[ -n "$kfull" && -s "$kfull" ]] || continue

    local kv
    kv="$(kernel_version_from_linux_path "$kp" 2>/dev/null || true)"
    [[ -n "$kv" ]] && valid_kvers["$kv"]=1
  done

  local count="${#valid_kvers[@]}"

  if [[ "$count" -lt 2 ]]; then
    printf '%bCRITICAL (Only %d valid kernel)%b' "$C_RED" "$count" "$C_RESET"
    return 2
  elif [[ "$count" -eq 2 ]]; then
    printf '%bMINIMAL (%d kernels)%b' "$C_YELLOW" "$count" "$C_RESET"
    return 1
  else
    printf '%bHEALTHY (%d kernels)%b' "$C_GREEN" "$count" "$C_RESET"
    return 0
  fi
}

scan_orphaned_files() {
  # Reports orphaned kernel-ish images under BOOT_DIR that are not referenced by any current BLS entry.
  # Output: "None" or "<count> files (~<mb>MB)"
  declare -A referenced

  local f
  for f in "$ENTRIES_DIR"/*.conf; do
    [[ -e "$f" ]] || continue

    local k
    k="$(bls_linux_path "$f")"
    [[ -n "$k" ]] && referenced["$(basename -- "$k")"]=1

    declare -a ips
    ips=()
    mapfile -t ips < <(bls_initrd_paths "$f")
    local ip
    for ip in "${ips[@]}"; do
      [[ -n "$ip" ]] && referenced["$(basename -- "$ip")"]=1
    done

    local dt
    dt="$(bls_devicetree_path "$f")"
    [[ -n "$dt" ]] && referenced["$(basename -- "$dt")"]=1
  done

  local orphan_count=0
  local orphan_space=0

  if command -v find >/dev/null 2>&1; then
    local p
    while IFS= read -r p; do
      [[ -n "$p" && -f "$p" ]] || continue
      local base
      base="$(basename -- "$p")"
      if [[ -z "${referenced[$base]+x}" ]]; then
        orphan_count=$((orphan_count + 1))
        local size
        size="$(stat -c %s -- "$p" 2>/dev/null || echo 0)"
        [[ "$size" =~ ^[0-9]+$ ]] || size=0
        orphan_space=$((orphan_space + size))
      fi
    done < <(
      find "$BOOT_DIR" -maxdepth 4 -type f \( \
        -name 'vmlinuz-*' -o -name 'linux-*' -o -name 'initrd-*' -o -name 'initramfs-*' \
      \) 2>/dev/null || true
    )
  else
    local p
    for p in "$BOOT_DIR"/vmlinuz-* "$BOOT_DIR"/linux-* "$BOOT_DIR"/initrd-* "$BOOT_DIR"/initramfs-*; do
      [[ -e "$p" && -f "$p" ]] || continue
      local base
      base="$(basename -- "$p")"
      if [[ -z "${referenced[$base]+x}" ]]; then
        orphan_count=$((orphan_count + 1))
        local size
        size="$(stat -c %s -- "$p" 2>/dev/null || echo 0)"
        [[ "$size" =~ ^[0-9]+$ ]] || size=0
        orphan_space=$((orphan_space + size))
      fi
    done
  fi

  local mb=$(( orphan_space / 1024 / 1024 ))
  if [[ "$orphan_count" -gt 0 ]]; then
    printf '%s files (~%sMB)\n' "$orphan_count" "$mb"
  else
    printf 'None\n'
  fi
}

list_orphaned_files() {
  # Prints full paths (one per line) for orphaned kernel-ish files under BOOT_DIR.
  declare -A referenced

  local f
  for f in "$ENTRIES_DIR"/*.conf; do
    [[ -e "$f" ]] || continue

    local k
    k="$(bls_linux_path "$f")"
    [[ -n "$k" ]] && referenced["$(basename -- "$k")"]=1

    declare -a ips
    ips=()
    mapfile -t ips < <(bls_initrd_paths "$f")
    local ip
    for ip in "${ips[@]}"; do
      [[ -n "$ip" ]] && referenced["$(basename -- "$ip")"]=1
    done

    local dt
    dt="$(bls_devicetree_path "$f")"
    [[ -n "$dt" ]] && referenced["$(basename -- "$dt")"]=1
  done

  if command -v find >/dev/null 2>&1; then
    local p
    while IFS= read -r -d '' p; do
      [[ -n "$p" && -f "$p" ]] || continue
      local base
      base="$(basename -- "$p")"
      if [[ -z "${referenced[$base]+x}" ]]; then
        printf '%s\n' "$p"
      fi
    done < <(
      find "$BOOT_DIR" -maxdepth 4 -type f \( \
        -name 'vmlinuz-*' -o -name 'linux-*' -o -name 'initrd-*' -o -name 'initramfs-*' \
      \) -print0 2>/dev/null || true
    )
  else
    local p
    for p in "$BOOT_DIR"/vmlinuz-* "$BOOT_DIR"/linux-* "$BOOT_DIR"/initrd-* "$BOOT_DIR"/initramfs-*; do
      [[ -e "$p" && -f "$p" ]] || continue
      local base
      base="$(basename -- "$p")"
      if [[ -z "${referenced[$base]+x}" ]]; then
        printf '%s\n' "$p"
      fi
    done
  fi
}

quarantine_orphaned_files() {
  # Moves orphaned kernel-ish files into a backup folder (reversible).
  local orphan_list
  orphan_list="$(list_orphaned_files 2>/dev/null || true)"
  if [[ -z "$orphan_list" ]]; then
    log "No orphaned images found."
    return 0
  fi

  maybe_temp_remount_rw_for_path "$BOOT_DIR" "boot dir"

  # Create a standard backup dir so users can restore easily.
  if [[ "$AUTO_BACKUP" == true ]]; then
    backup_entries_tree
  else
    ensure_backup_dir
  fi

  local dest_dir="$BACKUP_DIR/orphans"
  maybe_temp_remount_rw_for_path "$dest_dir" "orphan backup dir"
  mkdir -p -- "$dest_dir"

  local moved=0
  local p
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    if [[ -e "$p" ]]; then
      if move_entry_to_backup_dir "$p" "$dest_dir"; then
        moved=$((moved + 1))
      else
        warn "Failed to quarantine: $p"
      fi
    fi
  done <<<"$orphan_list"

  log "Quarantined $moved orphan image(s) to: $dest_dir"
  log "(If needed, you can copy them back manually from that folder.)"
}

pinned_config_path() {
  printf '%s\n' "$ENTRIES_DIR/.scrub-ghost-pinned"
}

is_pinned() {
  # A pin can be:
  #  - the full filename (e.g. "abcdef.conf")
  #  - the entry id (filename without .conf)
  #  - a kernel version string (optional; only checked when provided)
  local entry_file="$1"
  local entry_kver="${2-}"

  local pin_file
  pin_file="$(pinned_config_path)"
  [[ -f "$pin_file" ]] || return 1

  local entry_name entry_id
  entry_name=""
  entry_id=""
  if [[ -n "$entry_file" ]]; then
    entry_name="$(basename -- "$entry_file")"
    entry_id="$(basename -- "$entry_file" .conf)"
  fi

  local pins
  pins="$(awk '
    /^[[:space:]]*#/ {next}
    NF==0 {next}
    {gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print}
  ' "$pin_file" 2>/dev/null || true)"

  [[ -n "$pins" ]] || return 1

  if printf '%s\n' "$pins" | grep -Fxq -- "$entry_name"; then
    return 0
  fi
  if printf '%s\n' "$pins" | grep -Fxq -- "$entry_id"; then
    return 0
  fi
  if [[ -n "$entry_kver" ]] && printf '%s\n' "$pins" | grep -Fxq -- "$entry_kver"; then
    return 0
  fi

  return 1
}

is_kver_pinned() {
  local kver="$1"
  [[ -n "$kver" ]] || return 1

  local pin_file
  pin_file="$(pinned_config_path)"
  [[ -f "$pin_file" ]] || return 1

  awk '
    /^[[:space:]]*#/ {next}
    NF==0 {next}
    {gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print}
  ' "$pin_file" 2>/dev/null | grep -Fxq -- "$kver"
}

kver_has_pinned_entry() {
  # Returns 0 if any BLS entry matching this kver is pinned (by filename/id/kver).
  local kver="$1"
  [[ -n "$kver" ]] || return 1

  # If the kver itself is pinned, that should block vacuum.
  if is_kver_pinned "$kver"; then
    return 0
  fi

  local f
  for f in "$ENTRIES_DIR"/*.conf; do
    [[ -e "$f" ]] || continue

    local kp
    kp="$(bls_linux_path "$f")"
    [[ -n "$kp" ]] || continue

    local kv
    kv="$(kernel_version_from_linux_path "$kp" 2>/dev/null || true)"

    if [[ -n "$kv" && "$kv" == "$kver" ]]; then
      is_pinned "$f" "$kv" && return 0
    elif path_mentions_kver "$kp" "$kver"; then
      is_pinned "$f" "$kver" && return 0
    fi
  done

  return 1
}

check_default_entry_health() {
  # Checks if GRUB saved_entry points to an existing BLS file.
  local def_id
  def_id="${GRUB_DEFAULT_ID:-}"
  [[ -z "$def_id" ]] && def_id="$(get_grub_default_id 2>/dev/null || true)"

  if [[ -z "$def_id" ]]; then
    printf '%bN/A%b' "$C_DIM" "$C_RESET"
    return 0
  fi

  local expected="$ENTRIES_DIR/${def_id}.conf"
  if [[ ! -e "$expected" ]]; then
    printf '%bBROKEN (Points to missing: %s)%b' "$C_RED" "$def_id" "$C_RESET"
    return 2
  fi

  printf '%bHEALTHY (%s)%b' "$C_GREEN" "$def_id" "$C_RESET"
  return 0
}

check_grub_freshness() {
  # Returns 0 if Fresh, 1 if Stale (grub.cfg older than newest entry), 2 if Missing
  # Output is a colored status string.
  if [[ -z "${GRUB_CFG:-}" || ! -f "$GRUB_CFG" ]]; then
    printf '%bMISSING%b' "$C_RED" "$C_RESET"
    return 2
  fi

  local grub_mtime
  grub_mtime="$(stat -c %Y -- "$GRUB_CFG" 2>/dev/null || echo 0)"
  [[ "$grub_mtime" =~ ^[0-9]+$ ]] || grub_mtime=0

  local newest_entry=0
  local f
  for f in "$ENTRIES_DIR"/*.conf; do
    [[ -e "$f" ]] || continue
    local tm
    tm="$(stat -c %Y -- "$f" 2>/dev/null || echo 0)"
    [[ "$tm" =~ ^[0-9]+$ ]] || tm=0
    if (( tm > newest_entry )); then
      newest_entry=$tm
    fi
  done

  # Allow a small buffer for FS jitter.
  if (( newest_entry > (grub_mtime + 5) )); then
    printf '%bSTALE (Config older than entries)%b' "$C_YELLOW" "$C_RESET"
    return 1
  fi

  printf '%bFRESH%b' "$C_GREEN" "$C_RESET"
  return 0
}

scan_repairable_kvers() {
  # Prints unique kernel versions that appear repairable via dracut.
  local cmds
  cmds="$(scan_repairable_entries 2>/dev/null || true)"
  [[ -n "$cmds" ]] || return 0
  # Expected format: "sudo dracut --force --kver <kver>"
  printf '%s\n' "$cmds" | awk 'NF{print $NF}' | sort -u
}

scan_excess_kernels() {
  # Prints installed kernel package NEVRAs that look safe to remove (capacity planning).
  # Criteria: installed via RPM, NOT running, NOT the latest detected kernel.
  command -v rpm >/dev/null 2>&1 || return 0

  local run_ver
  run_ver="${RUNNING_KERNEL_VER:-$(uname -r 2>/dev/null || true)}"
  local lat_ver
  lat_ver="${LATEST_INSTALLED_VER:-}"

  # Consider common openSUSE kernel flavors.
  declare -a base_pkgs
  base_pkgs=(kernel-default kernel-preempt kernel-longterm)

  declare -a excess
  excess=()

  local base
  for base in "${base_pkgs[@]}"; do
    rpm -q "$base" >/dev/null 2>&1 || continue

    local nevra
    while IFS= read -r nevra; do
      [[ -n "$nevra" ]] || continue

      # Try to map package -> kernel-uname-r provide.
      local provides
      provides="$(rpm -q --provides "$nevra" 2>/dev/null | awk '$1=="kernel-uname-r" && $2=="=" {print $3; exit}' || true)"

      # If we can't determine the provide, skip (conservative).
      [[ -n "$provides" ]] || continue

      if [[ -n "$run_ver" && "$provides" == "$run_ver" ]]; then
        continue
      fi
      if [[ -n "$lat_ver" && "$provides" == "$lat_ver" ]]; then
        continue
      fi

      # Respect pinning: if this kernel version (or any matching entry) is pinned, never suggest removing it.
      if kver_has_pinned_entry "$provides"; then
        continue
      fi

      # Candidate for removal: pass NEVRA without arch when possible.
      excess+=("$nevra")
    done < <(rpm -q "$base" --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' 2>/dev/null || true)
  done

  if (( ${#excess[@]} > 0 )); then
    printf '%s\n' "${excess[@]}" | sort -u
  fi
}

find_entry_id_for_kver() {
  # $1=kver -> prints entry id (basename without .conf) of the first matching BLS entry.
  local kver="$1"
  [[ -n "$kver" ]] || return 1

  local f
  for f in "$ENTRIES_DIR"/*.conf; do
    [[ -e "$f" ]] || continue

    local kp
    kp="$(bls_linux_path "$f")"
    [[ -n "$kp" ]] || continue

    local kv
    kv="$(kernel_version_from_linux_path "$kp" 2>/dev/null || true)"
    if [[ -n "$kv" && "$kv" == "$kver" ]]; then
      basename -- "$f" .conf
      return 0
    fi

    if path_mentions_kver "$kp" "$kver"; then
      basename -- "$f" .conf
      return 0
    fi
  done

  return 1
}

rpm_file_digest_mismatch() {
  # Returns 0 if rpm -Vf indicates a digest mismatch for this file.
  local p="$1"
  command -v rpm >/dev/null 2>&1 || return 1
  [[ -n "$p" && -f "$p" ]] || return 1

  local out
  out="$(rpm -Vf -- "$p" 2>/dev/null || true)"
  [[ -n "$out" ]] || return 1

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    local flags path
    flags="${line%%[[:space:]]*}"
    path="$(awk '{print $NF}' <<<"$line")"
    if [[ "$path" == "$p" && "$flags" == *5* ]]; then
      return 0
    fi
  done <<<"$out"

  return 1
}

# --- FINAL POLISH START ---

detect_transactional_update() {
  # True when transactional-update exists AND / is mounted read-only.
  # This is how MicroOS/Aeon/Kalpa behave in normal operation.
  command -v transactional-update >/dev/null 2>&1 || return 1

  local info opts
  info="$(mount_info_for_path "/" 2>/dev/null || true)"
  opts=""
  if [[ "$info" == *"|"* ]]; then
    opts="${info#*|}"
  fi

  [[ -n "$opts" ]] || return 1
  mount_opts_have_ro "$opts"
}

run_pkg_manager() {
  # $1 = action: install|remove
  # remaining args = package names (or NEVRAs)
  local action="$1"
  shift || true

  declare -a pkgs
  pkgs=("$@")

  if (( ${#pkgs[@]} == 0 )); then
    err "run_pkg_manager: no packages provided"
    return 1
  fi

  if detect_transactional_update; then
    log "${C_YELLOW}Immutable System Detected:${C_RESET} Using transactional-update (reboot required)."
    log "Running: transactional-update pkg $action ${pkgs[*]}"

    if transactional-update pkg "$action" "${pkgs[@]}"; then
      log ""
      log "${C_GREEN}Success!${C_RESET} Changes will apply after the next reboot."
      log "${C_DIM}(The script cannot re-scan these changes until you reboot.)${C_RESET}"
      return 2
    else
      err "transactional-update failed."
      return 1
    fi
  fi

  if ! command -v zypper >/dev/null 2>&1; then
    err "zypper not found."
    return 1
  fi

  local z_cmd
  z_cmd="in"
  if [[ "$action" == "remove" ]]; then
    z_cmd="rm"
  fi

  declare -a flags
  flags=(-n)
  if [[ "$action" == "install" ]]; then
    flags+=(-f)
  fi

  log "Running: zypper ${flags[*]} $z_cmd ${pkgs[*]}"
  if zypper "${flags[@]}" "$z_cmd" "${pkgs[@]}"; then
    return 0
  else
    err "zypper failed."
    return 1
  fi
}

# --- FINAL POLISH END ---

scan_corrupt_kernel_packages() {
  # Prints unique RPM package *names* that own kernel images which look corrupt.
  # Corrupt = 0 bytes OR rpm digest mismatch.
  command -v rpm >/dev/null 2>&1 || return 0

  local -a targets
  targets=()

  local f
  for f in "$ENTRIES_DIR"/*.conf; do
    [[ -e "$f" ]] || continue

    local kp kfull
    kp="$(bls_linux_path "$f")"
    [[ -n "$kp" ]] || continue

    kfull="$(resolve_boot_path "$kp" 2>/dev/null || true)"
    [[ -n "$kfull" && -f "$kfull" ]] || continue

    local corrupt=false
    if [[ ! -s "$kfull" ]]; then
      corrupt=true
    elif rpm_file_digest_mismatch "$kfull"; then
      corrupt=true
    fi

    if [[ "$corrupt" == true ]]; then
      local owners
      owners="$(rpm -qf --queryformat '%{NAME}\n' -- "$kfull" 2>/dev/null || true)"
      if [[ -n "$owners" && "$owners" != *"not owned"* ]]; then
        while IFS= read -r o; do
          [[ -n "$o" ]] || continue
          targets+=("$o")
        done <<<"$owners"
      fi
    fi
  done

  if (( ${#targets[@]} == 0 )); then
    return 0
  fi

  printf '%s\n' "${targets[@]}" | sort -u
}

scan_repairable_entries() {
  # Scans for entries where kernel exists but one or more initrds are missing/invalid.
  # Prints suggested dracut commands (one per kver), or nothing.
  declare -A seen_kver

  local f
  for f in "$ENTRIES_DIR"/*.conf; do
    [[ -e "$f" ]] || continue

    local kp
    kp="$(bls_linux_path "$f")"
    [[ -n "$kp" ]] || continue

    local kfull
    kfull="$(resolve_boot_path "$kp" 2>/dev/null || true)"
    [[ -n "$kfull" && -s "$kfull" ]] || continue

    declare -a ips
    ips=()
    mapfile -t ips < <(bls_initrd_paths "$f")

    # If no initrds are specified, don't guess; skip.
    (( ${#ips[@]} > 0 )) || continue

    local missing=false
    local ip ifull
    for ip in "${ips[@]}"; do
      [[ -n "$ip" ]] || continue
      ifull="$(resolve_boot_path "$ip" 2>/dev/null || true)"
      if [[ -z "$ifull" || ! -s "$ifull" ]]; then
        missing=true
        continue
      fi
      if ! initrd_looks_valid "$ifull"; then
        missing=true
      fi
    done

    if [[ "$missing" == true ]]; then
      local kver
      kver="$(kernel_version_from_linux_path "$kp" 2>/dev/null || true)"
      if [[ -n "$kver" && -z "${seen_kver[$kver]+x}" ]]; then
        seen_kver["$kver"]=1
        printf 'sudo dracut --force --kver %s\n' "$kver"
      fi
    fi
  done
}

json_summary_int() {
  # $1=json $2=key -> prints integer (or 0)
  local json="$1"
  local key="$2"

  local v
  v="$(printf '%s' "$json" | grep -o "\"$key\":[0-9]\+" 2>/dev/null | head -n 1 | cut -d: -f2 || true)"
  if [[ "$v" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$v"
  else
    printf '0\n'
  fi
}

# --- SMART IMPROVEMENTS END ---

menu_header() {
  log ""
  log "${C_BOLD}scrub-ghost interactive menu${C_RESET}"
  log "Entries: $ENTRIES_DIR"
  log "Boot:    $BOOT_DIR"
  log "Backup:  $BACKUP_ROOT"
  log "Log:     ${LOG_FILE:-disabled}"
  log ""
}

menu_auto_fix() {
  # Smart Auto-Fix runs many "status" checks that intentionally return non-zero.
  # Ensure the menu never exits due to `set -e`.
  set +e

  progress_init() {
    PROGRESS_TOTAL="$1"
    PROGRESS_CUR=0
    PROGRESS_ACTIVE=false
    PROGRESS_AT_EOL=false

    # Only show progress when stdout is a TTY.
    if [[ -t 1 ]]; then
      PROGRESS_ACTIVE=true
    fi
  }

  progress_tick() {
    # $1 = label
    local label="$1"
    [[ "${PROGRESS_ACTIVE:-false}" == true ]] || return 0

    PROGRESS_AT_EOL=false

    PROGRESS_CUR=$((PROGRESS_CUR + 1))
    local pct=$(( PROGRESS_CUR * 100 / PROGRESS_TOTAL ))

    local width=24
    local filled=$(( pct * width / 100 ))
    local empty=$(( width - filled ))

    local bar
    bar="$(printf '%*s' "$filled" '' | tr ' ' '#')$(printf '%*s' "$empty" '' | tr ' ' '-')"

    # Draw on its own line below the "Analyzing..." text.
    printf '\r[%s] %3d%%  %s\033[K' "$bar" "$pct" "$label"

    if [[ "$PROGRESS_CUR" -ge "$PROGRESS_TOTAL" ]]; then
      printf '\n'
      PROGRESS_AT_EOL=true
    fi
  }

  progress_finish() {
    # Ensure we end the progress line before printing normal log lines.
    [[ "${PROGRESS_ACTIVE:-false}" == true ]] || return 0
    if [[ "${PROGRESS_AT_EOL:-false}" != true ]]; then
      printf '\n'
    fi
    PROGRESS_ACTIVE=false
    PROGRESS_AT_EOL=true
  }

  while true; do
    menu_header
    log "${C_BOLD}Smart Auto-Fix${C_RESET}"
    log "Analyzing system state..."

    progress_init 10

    progress_tick "Boot storage health"
    local storage_status storage_rc
    storage_status="$(check_boot_storage_health)"
    storage_rc=$?

    progress_tick "Kernel redundancy"
    local redundancy_status redundancy_rc
    redundancy_status="$(check_kernel_redundancy)"
    redundancy_rc=$?

    progress_tick "Default entry health"
    local def_health def_health_rc
    def_health="$(check_default_entry_health)"
    def_health_rc=$?

    progress_tick "GRUB config freshness"
    local grub_status grub_rc
    grub_status="$(check_grub_freshness)"
    grub_rc=$?

    progress_tick "Dry-run JSON scan"
    build_common_flags_minimal
    local json_output
    json_output="$(SCRUB_GHOST_NO_MENU=1 bash "$SCRIPT_SELF" --no-menu \
      --dry-run --json --no-color \
      --prune-duplicates --prune-stale-snapshots --prune-uninstalled \
      "${COMMON_FLAGS[@]}" --log-file /dev/null 2>/dev/null || true)"

    progress_tick "Parse counts"
    local n_ghost n_zombie n_stale n_dupe n_uninstall
    n_ghost="$(json_summary_int "$json_output" ghost)"
    n_zombie="$(json_summary_int "$json_output" zombie_initrd)"
    n_stale="$(json_summary_int "$json_output" stale_snapshot)"
    n_dupe="$(json_summary_int "$json_output" duplicate_found)"
    n_uninstall="$(json_summary_int "$json_output" uninstalled_kernel)"

    progress_tick "Scan orphaned images"
    local orphans orphan_count
    orphans="$(scan_orphaned_files 2>/dev/null || printf 'None\n')"
    orphan_count=0
    if [[ "$orphans" != "None" ]]; then
      orphan_count="$(printf '%s' "$orphans" | awk '{print $1}' | tr -dc '0-9' || echo 0)"
      [[ "$orphan_count" =~ ^[0-9]+$ ]] || orphan_count=0
    fi

    progress_tick "Detect repairable zombies"
    local repair_suggestions
    repair_suggestions="$(scan_repairable_entries 2>/dev/null || true)"

    progress_tick "Scan corrupt kernel RPMs"
    local corrupt_pkg_list corrupt_pkg_count
    corrupt_pkg_list="$(scan_corrupt_kernel_packages 2>/dev/null || true)"
    corrupt_pkg_count=0
    if [[ -n "$corrupt_pkg_list" ]]; then
      corrupt_pkg_count="$(printf '%s\n' "$corrupt_pkg_list" | wc -l | tr -dc '0-9' || echo 0)"
    fi

    progress_tick "Scan excess kernels"
    local excess_list excess_count
    excess_list="$(scan_excess_kernels 2>/dev/null || true)"
    excess_count=0
    if [[ -n "$excess_list" ]]; then
      excess_count="$(printf '%s\n' "$excess_list" | wc -l | tr -dc '0-9' || echo 0)"
    fi

    progress_finish

    log ""
    log "${C_BOLD}Analysis Results & Recommendations:${C_RESET}"
    log "---------------------------------------------------"
    log " 0. Boot Storage:        $storage_status"
    log " 0. Boot Redundancy:     $redundancy_status"
    log " 0. Default Entry:       $def_health"
    log " 0. GRUB Config:         $grub_status"
    log " 1. Ghost Entries:       $(recommend_action \"$n_ghost\" ghost)"
    log " 1b. Zombie Initrd:      $(recommend_action "$n_zombie" zombie)"
    log " 2. Duplicate Entries:   $(recommend_action "$n_dupe" duplicate)"
    log " 3. Stale Snapshots:     $(recommend_action "$n_stale" stale)"
    log " 4. Uninstalled Kernels: $(recommend_action "$n_uninstall" uninstalled)"
    log " 5. Orphaned Images:     ${C_YELLOW}${orphans}${C_RESET}"
    log "---------------------------------------------------"

    if [[ "$redundancy_rc" -eq 2 ]]; then
      warn "Boot redundancy is CRITICAL (only one valid kernel). Avoid aggressive cleanup until you install/keep a fallback kernel."
    elif [[ "$redundancy_rc" -eq 1 ]]; then
      warn "Boot redundancy is MINIMAL (two kernels). Consider keeping at least one extra fallback before aggressive cleanup."
    fi

    if [[ "$def_health_rc" -eq 2 ]]; then
      warn "GRUB saved default entry is BROKEN. Consider fixing it (SET-DEF) to avoid unpredictable boots."
    fi

    if [[ "$storage_rc" -eq 2 && "$n_uninstall" -gt 0 ]]; then
      warn "Boot storage is CRITICAL; consider option 'K' to prune uninstalled-kernel entries (aggressive)."
    fi

    if [[ "$orphan_count" -gt 0 ]]; then
      log "${C_DIM}Tip: Orphaned images are files in BOOT_DIR with no current BLS entry.${C_RESET}"
      log "${C_DIM}     Use ${C_BOLD}ORPHANS${C_RESET}${C_DIM} to quarantine them (move to backup; reversible).${C_RESET}"
      log "${C_DIM}     Or use ${C_BOLD}VACUUM${C_RESET}${C_DIM} to remove old kernel packages (often cleans them up too).${C_RESET}"
    fi

    if [[ -n "$repair_suggestions" ]]; then
      log ""
      log "${C_YELLOW}SMART REPAIR:${C_RESET} Found valid kernels with missing/corrupt initrds."
      log "Instead of deleting those entries, you can attempt to repair initrds with:"
      while IFS= read -r cmd; do
        [[ -n "$cmd" ]] || continue
        log "  ${C_DIM}$cmd${C_RESET}"
      done <<<"$repair_suggestions"
    fi

    local total_safe total_issues
    total_safe=$((n_ghost + n_dupe))
    total_issues=$((n_ghost + n_dupe + n_zombie + n_stale + n_uninstall))

    # Treat the system as "clean" only if there are no actionable recommendations.
    if [[ "$total_issues" -eq 0 && "$excess_count" -eq 0 && "$corrupt_pkg_count" -eq 0 && -z "$repair_suggestions" && "$orphan_count" -eq 0 && "$def_health_rc" -ne 2 && "$grub_rc" -ne 1 ]]; then
      log "${C_GREEN}System is clean! No actions needed.${C_RESET}"
      prompt_enter_to_continue
      return 0
    fi

    log ""
    log "Options:"
    if [[ "$def_health_rc" -eq 2 && -n "$LATEST_INSTALLED_VER" ]]; then
      log "  ${C_BOLD}SET-DEF${C_RESET}) Correct default entry (set to latest: $LATEST_INSTALLED_VER)"
    fi
    if [[ "$grub_rc" -eq 1 ]]; then
      log "  ${C_BOLD}UPDATE${C_RESET})  Update GRUB config (rebuild: grub2-mkconfig)"
    fi
    if [[ "$corrupt_pkg_count" -gt 0 ]]; then
      log "  ${C_BOLD}HEAL${C_RESET})    Reinstall corrupt kernel packages ($corrupt_pkg_count)"
    fi
    if [[ -n "$repair_suggestions" ]]; then
      log "  ${C_BOLD}REPAIR${C_RESET})  Resurrect zombie entries (run dracut)"
    fi
    if [[ "$excess_count" -gt 0 ]]; then
      log "  ${C_BOLD}VACUUM${C_RESET})  Free disk space (remove $excess_count old kernel packages)"
    fi
    if [[ "$orphan_count" -gt 0 ]]; then
      log "  ${C_BOLD}ORPHANS${C_RESET}) Quarantine orphaned images (move to backup; reversible)"
    fi
    if [[ "$total_safe" -gt 0 ]]; then
      log "  ${C_BOLD}FIX${C_RESET})  Apply SAFE fixes only (Ghosts + Duplicates)"
    fi
    log "  ${C_BOLD}ALL${C_RESET})  Apply ALL fixes (includes Stale Snapshots)"
    log "  ${C_BOLD}K${C_RESET})    Also prune uninstalled kernels (aggressive; requires YES + --confirm-uninstalled)"
    log "  ${C_BOLD}Z${C_RESET})    Remove zombie initrd entries (NOT recommended; prefer repair)"
    log "  ${C_BOLD}S${C_RESET})    View detailed dry-run output"
    log "  ${C_BOLD}B${C_RESET})    Back"

    local choice
    read -r -p "> " choice </dev/tty || return 0

    case "$choice" in
      SET-DEF|set-def|setdef|SETDEF)
        if [[ "$def_health_rc" -ne 2 ]]; then
          log "Default entry looks healthy (nothing to fix)."
          prompt_enter_to_continue
          continue
        fi
        if [[ -z "$LATEST_INSTALLED_VER" ]]; then
          err "Cannot set default: latest kernel version not detected."
          prompt_enter_to_continue
          continue
        fi

        local latest_id
        latest_id="$(find_entry_id_for_kver "$LATEST_INSTALLED_VER" 2>/dev/null || true)"
        if [[ -z "$latest_id" ]]; then
          err "Could not find a BLS entry for latest kernel version: $LATEST_INSTALLED_VER"
          prompt_enter_to_continue
          continue
        fi

        if ! command -v grub2-set-default >/dev/null 2>&1; then
          err "grub2-set-default not found."
          prompt_enter_to_continue
          continue
        fi

        log "Running: grub2-set-default '$latest_id'"
        if grub2-set-default "$latest_id"; then
          GRUB_DEFAULT_ID="$latest_id"
          log "${C_GREEN}Fixed! Default is now $latest_id${C_RESET}"
        else
          err "Failed to set default."
        fi
        prompt_enter_to_continue
        continue
        ;;

      UPDATE|update)
        if [[ "$grub_rc" -ne 1 ]]; then
          log "GRUB config looks fresh (nothing to update)."
          prompt_enter_to_continue
          continue
        fi
        if ! command -v grub2-mkconfig >/dev/null 2>&1; then
          err "grub2-mkconfig not found."
          prompt_enter_to_continue
          continue
        fi

        log "About to run: grub2-mkconfig -o $GRUB_CFG"
        log "Type YES to proceed:"
        local yn
        read -r -p "> " yn </dev/tty || true
        if [[ "$yn" == "YES" ]]; then
          maybe_temp_remount_rw_for_path "$GRUB_CFG" "grub.cfg"
          if grub2-mkconfig -o "$GRUB_CFG"; then
            log "${C_GREEN}Success!${C_RESET}"
          else
            err "Failed to update GRUB config."
          fi
        else
          log "Cancelled."
        fi
        prompt_enter_to_continue
        continue
        ;;

      HEAL|heal)
        if [[ "$corrupt_pkg_count" -le 0 ]]; then
          log "No RPM-owned corrupt kernel packages detected."
          prompt_enter_to_continue
          continue
        fi

        log "${C_BOLD}Active Repair${C_RESET}"
        log "About to reinstall packages:"
        while IFS= read -r p; do
          [[ -n "$p" ]] || continue
          log "  ${C_DIM}$p${C_RESET}"
        done <<<"$corrupt_pkg_list"

        log "Type YES to proceed:" 
        local yn
        read -r -p "> " yn </dev/tty || true
        if [[ "$yn" == "YES" ]]; then
          declare -a pkgs
          pkgs=()
          mapfile -t pkgs < <(printf '%s\n' "$corrupt_pkg_list" | awk 'NF{print}' | sort -u)

          if (( ${#pkgs[@]} > 0 )); then
            run_pkg_manager "install" "${pkgs[@]}"
            local rc=$?

            if [[ "$rc" -eq 0 ]]; then
              log "Reinstall complete. Re-scanning..."
              sleep 1
              continue
            elif [[ "$rc" -eq 2 ]]; then
              prompt_enter_to_continue
              continue
            fi
          fi
        else
          log "Cancelled."
        fi

        prompt_enter_to_continue
        ;;

      REPAIR|repair)
        if [[ -z "$repair_suggestions" ]]; then
          log "No repairable zombie entries found."
          prompt_enter_to_continue
          continue
        fi
        if ! command -v dracut >/dev/null 2>&1; then
          err "dracut not found."
          prompt_enter_to_continue
          continue
        fi

        log "Starting automated initrd repair (dracut)..."
        log "Type YES to proceed:"
        local yn
        read -r -p "> " yn </dev/tty || true
        if [[ "$yn" != "YES" ]]; then
          log "Cancelled."
          prompt_enter_to_continue
          continue
        fi

        local kver
        while IFS= read -r kver; do
          [[ -n "$kver" ]] || continue
          log "Running: dracut --force --kver $kver"
          if ! dracut --force --kver "$kver"; then
            warn "dracut failed for kver=$kver"
          fi
        done < <(scan_repairable_kvers)

        log "${C_GREEN}Repairs complete.${C_RESET} Re-scanning..."
        sleep 1
        continue
        ;;

      ORPHANS|orphans|O|o)
        if [[ "$orphan_count" -le 0 ]]; then
          log "No orphaned images detected."
          prompt_enter_to_continue
          continue
        fi

        local orphan_list
        orphan_list="$(list_orphaned_files 2>/dev/null || true)"
        if [[ -z "$orphan_list" ]]; then
          log "No orphaned images detected."
          prompt_enter_to_continue
          continue
        fi

        log "${C_BOLD}Orphaned Images (preview)${C_RESET}"
        log "These files are in BOOT_DIR but are not referenced by any current BLS entry:"

        local shown=0
        local total_bytes=0
        local p
        while IFS= read -r p; do
          [[ -n "$p" ]] || continue
          local sz
          sz="$(stat -c %s -- "$p" 2>/dev/null || echo 0)"
          [[ "$sz" =~ ^[0-9]+$ ]] || sz=0
          total_bytes=$((total_bytes + sz))

          if [[ "$shown" -lt 50 ]]; then
            shown=$((shown + 1))
            local mb=$(( sz / 1024 / 1024 ))
            log "  ${C_DIM}$p${C_RESET} (${mb}MB)"
          fi
        done <<<"$orphan_list"

        if [[ "$orphan_count" -gt 50 ]]; then
          log "  ${C_DIM}... and $((orphan_count - 50)) more${C_RESET}"
        fi

        local total_mb=$(( total_bytes / 1024 / 1024 ))
        log ""
        log "Total (estimated): $orphan_count file(s) (~${total_mb}MB)"
        log ""
        log "This will MOVE the files into a backup folder under:"
        log "  $BACKUP_ROOT"
        log "(Reversible: you can copy them back if needed.)"
        log ""
        log "Type ORPHANS to proceed, or anything else to cancel:"
        local yn
        read -r -p "> " yn </dev/tty || true
        if [[ "$yn" == "ORPHANS" ]]; then
          quarantine_orphaned_files
          log ""
          log "Re-scanning..."
          sleep 1
          continue
        else
          log "Cancelled."
        fi

        prompt_enter_to_continue
        ;;

      VACUUM|vacuum)
        if [[ "$excess_count" -le 0 ]]; then
          log "No excess kernel packages detected."
          prompt_enter_to_continue
          continue
        fi

        log "${C_BOLD}Vacuum Advisor${C_RESET}"
        log "The following kernel packages look removable (not running, not latest):"
        while IFS= read -r p; do
          [[ -n "$p" ]] || continue
          log "  ${C_DIM}$p${C_RESET}"
        done <<<"$excess_list"

        log ""
        log "Type RUN to execute removal now, or anything else to cancel:"
        local yn
        read -r -p "> " yn </dev/tty || true
        if [[ "$yn" == "RUN" ]]; then
          declare -a pkgs
          pkgs=()
          mapfile -t pkgs < <(printf '%s\n' "$excess_list" | awk 'NF{print}' | sort -u)

          if (( ${#pkgs[@]} > 0 )); then
            run_pkg_manager "remove" "${pkgs[@]}"
            local rc=$?

            if [[ "$rc" -eq 0 ]]; then
              log "Vacuum complete. Re-scanning..."
              sleep 1
              continue
            elif [[ "$rc" -eq 2 ]]; then
              prompt_enter_to_continue
              continue
            fi
          fi
        else
          log "Cancelled."
        fi

        prompt_enter_to_continue
        ;;

      FIX|fix|F|f)
        if [[ "$total_safe" -eq 0 ]]; then
          log "No safe fixes available."
          prompt_enter_to_continue
          continue
        fi

        if [[ "$redundancy_rc" -eq 2 ]]; then
          warn "Redundancy is CRITICAL. Type YES to continue anyway:"
          local yn
          read -r -p "> " yn </dev/tty || true
          if [[ "$yn" != "YES" ]]; then
            log "Cancelled."
            prompt_enter_to_continue
            continue
          fi
        fi

        # Safe plan: ghosts always cleaned by --force; add duplicate pruning only if needed.
        local -a args
        args=(--force)
        [[ "$n_dupe" -gt 0 ]] && args+=(--prune-duplicates)

        run_sub_minimal "${args[@]}"
        log ""
        log "${C_BOLD}Verifying fixes...${C_RESET}"
        sleep 1
        continue
        ;;

      ALL|all|A|a)
        if [[ "$redundancy_rc" -eq 2 ]]; then
          warn "Redundancy is CRITICAL. Type YES to continue anyway:"
          local yn
          read -r -p "> " yn </dev/tty || true
          if [[ "$yn" != "YES" ]]; then
            log "Cancelled."
            prompt_enter_to_continue
            continue
          fi
        fi

        # Includes stale snapshots (more aggressive). Only include flags that are relevant.
        local -a args
        args=(--force)
        [[ "$n_dupe" -gt 0 ]] && args+=(--prune-duplicates)
        [[ "$n_stale" -gt 0 ]] && args+=(--prune-stale-snapshots)

        run_sub_minimal "${args[@]}"
        log ""
        log "${C_BOLD}Verifying fixes...${C_RESET}"
        sleep 1
        continue
        ;;

      K|k)
        if [[ "$redundancy_rc" -eq 2 ]]; then
          warn "Redundancy is CRITICAL. Type YES to continue anyway:"
          local yn
          read -r -p "> " yn </dev/tty || true
          if [[ "$yn" != "YES" ]]; then
            log "Cancelled."
            prompt_enter_to_continue
            continue
          fi
        fi

        log "${C_RED}WARNING:${C_RESET} This can remove entries for kernels where modules are missing."
        if command -v rpm >/dev/null 2>&1; then
          log "RPM database is available; the script already avoids pruning when it cannot determine kver."
        else
          warn "rpm not found; proceeding without RPM double-check (conservative safeguards still apply)."
        fi

        log "Type YES to confirm pruning uninstalled kernels:" 
        local yn
        read -r -p "> " yn </dev/tty || true
        if [[ "$yn" == "YES" ]]; then
          run_sub_minimal --force --prune-duplicates --prune-stale-snapshots --prune-uninstalled --confirm-uninstalled
          log ""
          log "${C_BOLD}Verifying fixes...${C_RESET}"
          sleep 1
          continue
        else
          log "Cancelled."
        fi
        prompt_enter_to_continue
        ;;

      Z|z)
        if [[ "$n_zombie" -le 0 ]]; then
          log "No zombie initrd entries found."
          prompt_enter_to_continue
          continue
        fi

        warn "Zombie initrd entries are often repairable. Prefer running the suggested dracut command(s)."
        log "Type ZOMBIE to confirm removal (enables --prune-zombies):"
        local yn
        read -r -p "> " yn </dev/tty || true
        if [[ "$yn" == "ZOMBIE" ]]; then
          run_sub_minimal --force --prune-zombies
          log ""
          log "${C_BOLD}Verifying fixes...${C_RESET}"
          sleep 1
          continue
        else
          log "Cancelled."
        fi
        prompt_enter_to_continue
        ;;

      S|s)
        run_sub_minimal --dry-run --prune-duplicates --prune-stale-snapshots --prune-uninstalled
        prompt_enter_to_continue
        ;;

      B|b|back)
        return 0
        ;;

      *)
        log "Invalid option."
        prompt_enter_to_continue
        ;;
    esac
  done
}

menu_clean() {
  while true; do
    menu_header
    log "Clean (safe mode: moves entries to backup; creates backups first)"
    log "0) Smart Auto-Fix (recommended)"
    log "1) Prune stale Snapper entries"
    log "2) Remove ghosts only"
    log "3) Prune stale Snapper + uninstalled-kernel entries (requires YES)"
    log "4) Prune uninstalled-kernel entries only (requires YES)"
    log "5) Prune duplicate entries (linux+initrd+options)"
    log "6) Back"

    local choice
    read -r -p "> " choice </dev/tty || return 0

    case "$choice" in
      0)
        menu_auto_fix
        ;;
      1)
        run_sub --force --prune-stale-snapshots
        prompt_enter_to_continue
        ;;
      2)
        run_sub --force
        prompt_enter_to_continue
        ;;
      3)
        log "Type YES to proceed (stale snapshots + uninstalled kernels):"
        local yn
        read -r -p "> " yn </dev/tty || true
        if [[ "$yn" == "YES" ]]; then
          run_sub --force --prune-stale-snapshots --prune-uninstalled --confirm-uninstalled
        else
          log "Cancelled."
        fi
        prompt_enter_to_continue
        ;;
      4)
        log "Type YES to proceed (uninstalled kernels):"
        local yn
        read -r -p "> " yn </dev/tty || true
        if [[ "$yn" == "YES" ]]; then
          run_sub --force --prune-uninstalled --confirm-uninstalled
        else
          log "Cancelled."
        fi
        prompt_enter_to_continue
        ;;
      5)
        run_sub --force --prune-duplicates
        prompt_enter_to_continue
        ;;
      6)
        return 0
        ;;
      *)
        log "Invalid option."
        prompt_enter_to_continue
        ;;
    esac
  done
}

menu_backups() {
  while true; do
    menu_header
    log "Backups"
    log "1) List backups"
    log "2) Validate backups (submenu)"
    log "3) Restore backups (submenu)"
    log "4) Back"

    local choice
    read -r -p "> " choice </dev/tty || return 0

    case "$choice" in
      1) run_sub --list-backups; prompt_enter_to_continue ;;
      2) menu_validate ;;
      3) menu_restore ;;
      4) return 0 ;;
      *) log "Invalid option."; prompt_enter_to_continue ;;
    esac
  done
}

menu_paths() {
  while true; do
    menu_header
    log "Paths / advanced"
    log "(Tip: type 'auto' to reset to auto-detect)"
    log "1) Set entries dir override (currently: ${ENTRIES_DIR_SET:+$ENTRIES_DIR})"
    log "2) Set boot dir override    (currently: ${BOOT_DIR_SET:+$BOOT_DIR})"
    log "3) Set backup root          (currently: $BACKUP_ROOT)"
    log "4) Set backup dir override  (currently: ${BACKUP_DIR_SET:+$BACKUP_DIR})"
    log "5) Set log file             (currently: $LOG_FILE)"
    log "6) Toggle rebuild grub       (currently: $REBUILD_GRUB)"
    log "7) Set grub cfg path         (currently: $GRUB_CFG)"
    log "8) Toggle sdbootutil update  (currently: $UPDATE_SDBOOT)"
    log "9) Toggle auto remount rw    (currently: $AUTO_REMOUNT_RW)"
    log "10) Back"

    local choice
    read -r -p "> " choice </dev/tty || return 0

    case "$choice" in
      1)
        local v
        read -r -p "Entries dir: " v </dev/tty || true
        if [[ "$v" == "auto" ]]; then
          ENTRIES_DIR_SET=false
          ENTRIES_DIR=""
        elif [[ -n "$v" ]]; then
          ENTRIES_DIR_SET=true
          ENTRIES_DIR="$v"
        fi
        ;;
      2)
        local v
        read -r -p "Boot dir: " v </dev/tty || true
        if [[ "$v" == "auto" ]]; then
          BOOT_DIR_SET=false
          BOOT_DIR=""
        elif [[ -n "$v" ]]; then
          BOOT_DIR_SET=true
          BOOT_DIR="$v"
        fi
        ;;
      3)
        local v
        read -r -p "Backup root: " v </dev/tty || true
        [[ -n "$v" ]] && BACKUP_ROOT="$v"
        ;;
      4)
        local v
        read -r -p "Backup dir: " v </dev/tty || true
        if [[ "$v" == "auto" ]]; then
          BACKUP_DIR_SET=false
          BACKUP_DIR=""
        elif [[ -n "$v" ]]; then
          BACKUP_DIR_SET=true
          BACKUP_DIR="$v"
        fi
        ;;
      5)
        local v
        read -r -p "Log file path: " v </dev/tty || true
        [[ -n "$v" ]] && LOG_FILE="$v"
        init_logging
        ;;
      6)
        REBUILD_GRUB=$([[ "$REBUILD_GRUB" == true ]] && echo false || echo true)
        ;;
      7)
        local v
        read -r -p "GRUB cfg path: " v </dev/tty || true
        if [[ -n "$v" ]]; then
          GRUB_CFG="$v"
          GRUB_CFG_SET=true
        fi
        ;;
      8)
        UPDATE_SDBOOT=$([[ "$UPDATE_SDBOOT" == true ]] && echo false || echo true)
        ;;
      9)
        AUTO_REMOUNT_RW=$([[ "$AUTO_REMOUNT_RW" == true ]] && echo false || echo true)
        ;;
      10) return 0 ;;
      *) log "Invalid option." ;;
    esac

    prompt_enter_to_continue
  done
}

menu_danger() {
  while true; do
    menu_header
    log "${C_RED}DANGER ZONE${C_RESET} (permanent deletes)"
    log "1) DELETE ghosts only"
    log "2) DELETE stale Snapper entries"
    log "3) DELETE uninstalled-kernel entries"
    log "4) Back"

    local choice
    read -r -p "> " choice </dev/tty || return 0

    case "$choice" in
      1)
        log "Type DELETE to confirm:"; local yn; read -r -p "> " yn </dev/tty || true
        [[ "$yn" == "DELETE" ]] && run_sub --delete || log "Cancelled."
        prompt_enter_to_continue
        ;;
      2)
        log "Type DELETE to confirm:"; local yn; read -r -p "> " yn </dev/tty || true
        [[ "$yn" == "DELETE" ]] && run_sub --delete --prune-stale-snapshots || log "Cancelled."
        prompt_enter_to_continue
        ;;
      3)
        log "Type DELETE to confirm:"; local yn; read -r -p "> " yn </dev/tty || true
        [[ "$yn" == "DELETE" ]] && run_sub --delete --prune-uninstalled --confirm-uninstalled || log "Cancelled."
        prompt_enter_to_continue
        ;;
      4) return 0 ;;
      *) log "Invalid option."; prompt_enter_to_continue ;;
    esac
  done
}

systemd_install_builtin() {
  # Installs systemd unit+timer + wrapper. Does NOT enable the timer automatically.
  # Writes example config only if the user doesn't already have one.
  local libexec_dir="/usr/local/libexec/scrub-ghost"
  local wrapper="$libexec_dir/run-systemd"

  if [[ ! -w "/usr/local" ]]; then
    err "/usr/local is not writable (likely a read-only root filesystem)."
    if command -v transactional-update >/dev/null 2>&1; then
      err "On MicroOS/Aeon, run installs inside a transactional update environment (e.g. 'transactional-update shell' then re-run)."
    fi
    return 1
  fi

  mkdir -p -- "$libexec_dir"

  cat >"$wrapper" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

if [[ -f /etc/sysconfig/scrub-ghost ]]; then
  # shellcheck disable=SC1091
  . /etc/sysconfig/scrub-ghost
elif [[ -f /etc/default/scrub-ghost ]]; then
  # shellcheck disable=SC1091
  . /etc/default/scrub-ghost
fi

: "${SCRUB_GHOST_BIN:=/usr/local/bin/scrub-ghost}"

if declare -p SCRUB_GHOST_ARGS >/dev/null 2>&1; then
  :
else
  SCRUB_GHOST_ARGS=(--force --prune-stale-snapshots --keep-backups 5 --no-color)
fi

exec "$SCRUB_GHOST_BIN" "${SCRUB_GHOST_ARGS[@]}"
EOF

  chmod 0755 -- "$wrapper"

  cat >/etc/systemd/system/scrub-ghost.service <<'EOF'
[Unit]
Description=Clean up ghost BLS entries (scrub-ghost)
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/scrub-ghost/run-systemd
StandardOutput=journal
StandardError=journal
EOF

  cat >/etc/systemd/system/scrub-ghost.timer <<'EOF'
[Unit]
Description=Run scrub-ghost weekly

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
EOF

  if [[ ! -f /etc/default/scrub-ghost && ! -f /etc/sysconfig/scrub-ghost ]]; then
    local bin
    bin="$(command -v scrub-ghost 2>/dev/null || true)"
    [[ -z "$bin" ]] && bin="/usr/local/bin/scrub-ghost"

    cat >/etc/default/scrub-ghost <<EOF
# scrub-ghost systemd configuration
# You may also use: /etc/sysconfig/scrub-ghost

SCRUB_GHOST_BIN="$bin"
SCRUB_GHOST_ARGS=(
  --force
  --prune-stale-snapshots
  --keep-backups 5
  --no-color
)
EOF
    chmod 0644 -- /etc/default/scrub-ghost
    log "Installed default config: /etc/default/scrub-ghost"
  else
    log "Config already exists; leaving it unchanged."
  fi

  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
  fi
}

systemd_remove_builtin() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now scrub-ghost.timer 2>/dev/null || true
  fi
  rm -f -- /etc/systemd/system/scrub-ghost.service /etc/systemd/system/scrub-ghost.timer 2>/dev/null || true
  rm -rf -- /usr/local/libexec/scrub-ghost 2>/dev/null || true
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload 2>/dev/null || true
  fi
}

zypp_install_builtin() {
  if [[ ! -w "/usr/local" ]]; then
    err "/usr/local is not writable (likely a read-only root filesystem)."
    if command -v transactional-update >/dev/null 2>&1; then
      err "On MicroOS/Aeon, run installs inside a transactional update environment (e.g. 'transactional-update shell' then re-run)."
    fi
    return 1
  fi

  install -d -m 0755 -- /etc/zypp/commit.d
  cat >/etc/zypp/commit.d/50-scrub-ghost <<'EOF'
#!/bin/sh
# Run scrub-ghost after zypper operations
# NOTE: Keep this fast; this runs after every zypp commit.

BIN="/usr/local/bin/scrub-ghost"
LOG="/var/log/scrub-ghost-zypp.log"

if [ -x "$BIN" ]; then
  "$BIN" --force --prune-stale-snapshots --no-color >>"$LOG" 2>&1 || true
fi
EOF
  chmod 0755 -- /etc/zypp/commit.d/50-scrub-ghost
}

zypp_remove_builtin() {
  rm -f -- /etc/zypp/commit.d/50-scrub-ghost 2>/dev/null || true
}

systemd_install_or_update() {
  local src
  src="$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")"
  local inst
  inst="$(dirname -- "$src")/systemd/install-systemd.sh"

  if [[ -x "$inst" ]]; then
    "$inst"
  else
    warn "Systemd installer script not found (standalone mode). Using built-in installer."
    systemd_install_builtin
  fi
}

systemd_remove() {
  local src
  src="$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")"
  local inst
  inst="$(dirname -- "$src")/systemd/install-systemd.sh"

  if [[ -x "$inst" ]]; then
    "$inst" --uninstall
  else
    warn "Systemd installer script not found (standalone mode). Removing known paths."
    systemd_remove_builtin
  fi
}

zypp_install_or_update() {
  local src
  src="$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")"
  local inst
  inst="$(dirname -- "$src")/zypp/install-zypp-hook.sh"

  if [[ -x "$inst" ]]; then
    "$inst"
  else
    warn "Zypp installer script not found (standalone mode). Using built-in installer."
    zypp_install_builtin
  fi
}

zypp_remove() {
  local src
  src="$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")"
  local inst
  inst="$(dirname -- "$src")/zypp/install-zypp-hook.sh"

  if [[ -x "$inst" ]]; then
    "$inst" --uninstall
  else
    zypp_remove_builtin
  fi
}

menu_install() {
  while true; do
    menu_header
    log "Install / uninstall"
    log "(Integrations are optional and installed independently.)"
    log "1) Install/upgrade command to /usr/local/bin/scrub-ghost"
    log "2) Uninstall command /usr/local/bin/scrub-ghost"
    log ""
    log "3) Install/update systemd unit+timer (optional)"
    log "4) Remove systemd unit+timer (optional)"
    log ""
    log "5) Install/update zypp hook (optional)"
    log "6) Remove zypp hook (optional)"
    log ""
    log "7) Back"

    local choice
    read -r -p "> " choice </dev/tty || return 0

    # Ignore empty/whitespace-only input (common when the user just pressed Enter to continue).
    choice="${choice//$'\r'/}"
    if [[ -z "${choice//[[:space:]]/}" ]]; then
      continue
    fi
    choice="${choice//[[:space:]]/}"

    debug "menu_main: choice='$choice'"

    case "$choice" in
      1)
        local src
        src="$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")"
        local dest="/usr/local/bin/scrub-ghost"
        if [[ ! -f "$src" ]]; then
          err "Cannot locate script path for install: $src"
          prompt_enter_to_continue
          continue
        fi
        mkdir -p -- /usr/local/bin 2>/dev/null || true
        if [[ ! -w "/usr/local/bin" ]]; then
          err "/usr/local/bin is not writable (likely a read-only root filesystem)."
          if command -v transactional-update >/dev/null 2>&1; then
            err "On MicroOS/Aeon, install via: transactional-update shell (then re-run this menu), or run the installer inside a transactional update."
          fi
          prompt_enter_to_continue
          continue
        fi

        install -m 0755 -- "$src" "$dest"
        log "Installed: $dest"

        # If integrations are already present, refresh them (update in place)
        if [[ -f /etc/systemd/system/scrub-ghost.service || -d /usr/local/libexec/scrub-ghost ]]; then
          systemd_install_or_update || true
          log "Updated existing systemd integration."
        fi
        if [[ -f /etc/zypp/commit.d/50-scrub-ghost ]]; then
          zypp_install_or_update || true
          log "Updated existing zypp hook."
        fi

        log "Try: sudo scrub-ghost --help"
        prompt_enter_to_continue
        ;;
      2)
        local dest="/usr/local/bin/scrub-ghost"
        if [[ -e "$dest" ]]; then
          log "Type DELETE to uninstall $dest:"
          local yn
          read -r -p "> " yn </dev/tty || true
          if [[ "$yn" == "DELETE" ]]; then
            rm -f -- "$dest"
            log "Removed: $dest"
          else
            log "Cancelled."
          fi
        else
          log "Not installed: $dest"
        fi
        prompt_enter_to_continue
        ;;
      3)
        systemd_install_or_update
        log "Installed/updated systemd integration."
        prompt_enter_to_continue
        ;;
      4)
        systemd_remove
        log "Removed systemd integration."
        prompt_enter_to_continue
        ;;
      5)
        zypp_install_or_update
        log "Installed/updated zypp hook."
        prompt_enter_to_continue
        ;;
      6)
        zypp_remove
        log "Removed zypp hook."
        prompt_enter_to_continue
        ;;
      7)
        return 0
        ;;
      *)
        log "Invalid option."
        prompt_enter_to_continue
        ;;
    esac
  done
}

menu_main() {
  # The interactive menu should never crash the whole script because a sub-command fails.
  # `main()` runs with set -e; turn it off inside menu loops.
  set +e

  while true; do
    menu_header
    log "1) Scan (dry-run)"
    log "2) Smart Auto-Fix (recommended)"
    log "3) Clean (submenu)"
    log "4) Backups / Restore (submenu)"
    log "5) Settings (submenu)"
    log "6) Paths / advanced (submenu)"
    log "7) Danger zone (submenu)"
    log "8) Install / uninstall (command only)"
    log "9) Completion (submenu)"
    log "10) Rescue / chroot wizard (Live ISO)"
    log "0) Exit"
    log ""

    local choice
    read -r -p "> " choice </dev/tty || return 0

    case "$choice" in
      1)
        run_sub --dry-run
        debug "menu_main: scan finished (LAST_SUBCOMMAND_RC=$LAST_SUBCOMMAND_RC)"
        prompt_enter_to_continue
        ;;
      2) menu_auto_fix ;;
      3) menu_clean ;;
      4) menu_backups ;;
      5) menu_settings ;;
      6) menu_paths ;;
      7) menu_danger ;;
      8) menu_install ;;
      9) menu_completion ;;
      10) menu_rescue_wizard ; prompt_enter_to_continue ;;
      0) return 0 ;;
      *) log "Invalid option: '$choice'."; prompt_enter_to_continue ;;
    esac
  done
}

menu_completion() {
  while true; do
    menu_header
    log "Completion scripts (printed to stdout)"
    log "1) Print zsh completion"
    log "2) Print bash completion"
    log "3) Back"

    local choice
    read -r -p "> " choice </dev/tty || return 0

    case "$choice" in
      1) run_sub --completion zsh ; prompt_enter_to_continue ;;
      2) run_sub --completion bash ; prompt_enter_to_continue ;;
      3) return 0 ;;
      *) log "Invalid option."; prompt_enter_to_continue ;;
    esac
  done
}

menu_validate() {
  while true; do
    menu_header
    log "Validate backups"
    log "1) Validate latest"
    log "2) Validate pick number"
    log "3) Validate from path"
    log "4) Back"

    local choice
    read -r -p "> " choice </dev/tty || return 0

    case "$choice" in
      1)
        run_sub --validate-latest
        prompt_enter_to_continue
        ;;
      2)
        local n
        read -r -p "Pick number: " n </dev/tty || true
        run_sub --validate-pick "$n"
        prompt_enter_to_continue
        ;;
      3)
        local p
        read -r -p "Backup dir path: " p </dev/tty || true
        run_sub --validate-from "$p"
        prompt_enter_to_continue
        ;;
      4)
        return 0
        ;;
      *)
        log "Invalid option."
        prompt_enter_to_continue
        ;;
    esac
  done
}

menu_restore() {
  while true; do
    menu_header
    log "Restore backups (validated)"
    log "Restore options: clean_restore=$CLEAN_RESTORE restore_anyway=$RESTORE_ANYWAY"
    log "1) Restore latest"
    log "2) Restore best (newest passing validation)"
    log "3) Restore pick number"
    log "4) Restore from path"
    log "5) Toggle clean restore (delete extras; shows preview + requires YES on restore)"
    log "6) Toggle restore anyway (dangerous)"
    log "7) Back"

    local choice
    read -r -p "> " choice </dev/tty || return 0

    case "$choice" in
      1)
        run_sub --restore-latest
        prompt_enter_to_continue
        ;;
      2)
        run_sub --restore-best
        prompt_enter_to_continue
        ;;
      3)
        run_sub --list-backups
        local n
        read -r -p "Pick number: " n </dev/tty || true
        run_sub --restore-pick "$n"
        prompt_enter_to_continue
        ;;
      4)
        local p
        read -r -p "Backup dir path: " p </dev/tty || true
        run_sub --restore-from "$p"
        prompt_enter_to_continue
        ;;
      5)
        if [[ "$CLEAN_RESTORE" == false ]]; then
          log "Type YES to enable clean restore (will delete extra broken entries not present in the backup):"
          local yn
          read -r -p "> " yn </dev/tty || true
          [[ "$yn" == "YES" ]] && CLEAN_RESTORE=true
        else
          CLEAN_RESTORE=false
        fi
        ;;
      6)
        if [[ "$RESTORE_ANYWAY" == false ]]; then
          log "Type YES to enable restore-anyway:"; local yn; read -r -p "> " yn </dev/tty || true
          [[ "$yn" == "YES" ]] && RESTORE_ANYWAY=true
        else
          RESTORE_ANYWAY=false
        fi
        ;;
      7)
        return 0
        ;;
      *)
        log "Invalid option."
        prompt_enter_to_continue
        ;;
    esac
  done
}

menu_pins() {
  while true; do
    menu_header

    local pin_file
    pin_file="$(pinned_config_path)"

    log "Pinned entries manager"
    log "Pin file: $pin_file"
    log ""
    log "Pins can be:"
    log "  - filename (e.g. abcd.conf)"
    log "  - entry id  (e.g. abcd)"
    log "  - kernel version (e.g. 6.9.1-1-default)"
    log ""
    log "1) View pins"
    log "2) Add pin"
    log "3) Remove pin"
    log "4) Edit pin file (opens $EDITOR)"
    log "5) Back"

    local choice
    read -r -p "> " choice </dev/tty || return 0

    case "$choice" in
      1)
        if [[ -f "$pin_file" ]]; then
          log ""
          log "Pins:"
          local n
          n=0
          while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            n=$((n + 1))
            log "  $n) $line"
          done < <(
            awk '
              /^[[:space:]]*#/ {next}
              NF==0 {next}
              {gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print}
            ' "$pin_file" 2>/dev/null || true
          )
          if [[ "$n" -eq 0 ]]; then
            log "  (none)"
          fi
        else
          log "No pin file found."
        fi
        prompt_enter_to_continue
        ;;

      2)
        maybe_temp_remount_rw_for_path "$ENTRIES_DIR" "entries dir (pin file)"
        mkdir -p -- "$ENTRIES_DIR" 2>/dev/null || true
        touch -- "$pin_file" 2>/dev/null || true

        log "Enter pin to add (exact match):"
        local pin
        read -r -p "> " pin </dev/tty || true
        pin="$(printf '%s' "$pin" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"

        if [[ -z "$pin" ]]; then
          log "Cancelled."
          prompt_enter_to_continue
          continue
        fi
        if [[ "$pin" =~ [[:space:]] ]]; then
          err "Pins must not contain whitespace (use exact filename/id/kver)."
          prompt_enter_to_continue
          continue
        fi

        if awk '
          /^[[:space:]]*#/ {next}
          NF==0 {next}
          {gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print}
        ' "$pin_file" 2>/dev/null | grep -Fxq -- "$pin"; then
          log "Already pinned: $pin"
          prompt_enter_to_continue
          continue
        fi

        printf '%s\n' "$pin" >>"$pin_file" 2>/dev/null || {
          err "Failed to write: $pin_file"
          prompt_enter_to_continue
          continue
        }

        log "Pinned: $pin"
        prompt_enter_to_continue
        ;;

      3)
        if [[ ! -f "$pin_file" ]]; then
          log "No pin file found."
          prompt_enter_to_continue
          continue
        fi

        declare -a pins
        pins=()
        mapfile -t pins < <(
          awk '
            /^[[:space:]]*#/ {next}
            NF==0 {next}
            {gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print}
          ' "$pin_file" 2>/dev/null || true
        )

        if (( ${#pins[@]} == 0 )); then
          log "No pins to remove."
          prompt_enter_to_continue
          continue
        fi

        log "Select pin to remove:"
        local i
        for (( i=0; i<${#pins[@]}; i++ )); do
          log "  $((i+1))) ${pins[$i]}"
        done
        local n
        read -r -p "> " n </dev/tty || true
        if ! [[ "$n" =~ ^[0-9]+$ ]] || (( n < 1 || n > ${#pins[@]} )); then
          err "Invalid selection."
          prompt_enter_to_continue
          continue
        fi

        local target
        target="${pins[$((n-1))]}"

        log "Type YES to remove '$target':"
        local yn
        read -r -p "> " yn </dev/tty || true
        if [[ "$yn" != "YES" ]]; then
          log "Cancelled."
          prompt_enter_to_continue
          continue
        fi

        maybe_temp_remount_rw_for_path "$ENTRIES_DIR" "entries dir (pin file)"

        local tmp
        tmp="$pin_file.tmp.$$"
        awk -v target="$target" '
          {
            orig=$0
            line=$0
            sub(/^[[:space:]]+/, "", line)
            sub(/[[:space:]]+$/, "", line)
            if (line ~ /^#/ || line == "") { print orig; next }
            if (line == target) { next }
            print orig
          }
        ' "$pin_file" >"$tmp" 2>/dev/null || {
          err "Failed to update pin file."
          rm -f -- "$tmp" 2>/dev/null || true
          prompt_enter_to_continue
          continue
        }
        mv -f -- "$tmp" "$pin_file" 2>/dev/null || {
          err "Failed to write pin file."
          rm -f -- "$tmp" 2>/dev/null || true
          prompt_enter_to_continue
          continue
        }

        log "Removed pin: $target"
        prompt_enter_to_continue
        ;;

      4)
        maybe_temp_remount_rw_for_path "$ENTRIES_DIR" "entries dir (pin file)"
        mkdir -p -- "$ENTRIES_DIR" 2>/dev/null || true
        touch -- "$pin_file" 2>/dev/null || true

        local editor
        editor="${EDITOR:-}"

        if [[ -n "$editor" ]]; then
          # Support multi-word EDITOR (e.g. "vim -u NONE").
          bash -c "$editor \"\$1\"" _ "$pin_file" </dev/tty >/dev/tty 2>&1 || true
        elif command -v nano >/dev/null 2>&1; then
          nano "$pin_file" </dev/tty >/dev/tty 2>&1 || true
        elif command -v vim >/dev/null 2>&1; then
          vim "$pin_file" </dev/tty >/dev/tty 2>&1 || true
        else
          vi "$pin_file" </dev/tty >/dev/tty 2>&1 || true
        fi
        ;;

      5)
        return 0
        ;;

      *)
        log "Invalid option."
        prompt_enter_to_continue
        ;;
    esac
  done
}

menu_settings() {
  while true; do
    menu_header
    log "Settings (these affect menu-run commands by passing flags)"
    log "1) Toggle verbose (currently: $VERBOSE)"
    log "2) Toggle debug  (currently: $DEBUG)"
    log "3) Toggle color  (currently: $COLOR)"
    log "4) Toggle verify snapshots (currently: $VERIFY_SNAPSHOTS)"
    log "5) Toggle verify modules   (currently: $VERIFY_KERNEL_MODULES)"
    log "6) Toggle auto backup      (currently: $AUTO_BACKUP)"
    log "7) Toggle auto snapper     (currently: $AUTO_SNAPPER_BACKUP)"
    log "8) Toggle prune duplicates (currently: $PRUNE_DUPLICATES)"
    log "9) Toggle JSON output      (currently: $JSON_OUTPUT)"
    log "10) Set keep backups (currently: $KEEP_BACKUPS)"
    log "11) Manage pinned entries (pin file)"
    log "12) Back"

    local choice
    read -r -p "> " choice </dev/tty || return 0

    case "$choice" in
      1) VERBOSE=$([[ "$VERBOSE" == true ]] && echo false || echo true) ;;
      2) DEBUG=$([[ "$DEBUG" == true ]] && echo false || echo true) ;;
      3) COLOR=$([[ "$COLOR" == true ]] && echo false || echo true); init_colors ;;
      4) VERIFY_SNAPSHOTS=$([[ "$VERIFY_SNAPSHOTS" == true ]] && echo false || echo true) ;;
      5) VERIFY_KERNEL_MODULES=$([[ "$VERIFY_KERNEL_MODULES" == true ]] && echo false || echo true) ;;
      6) AUTO_BACKUP=$([[ "$AUTO_BACKUP" == true ]] && echo false || echo true) ;;
      7) AUTO_SNAPPER_BACKUP=$([[ "$AUTO_SNAPPER_BACKUP" == true ]] && echo false || echo true) ;;
      8) PRUNE_DUPLICATES=$([[ "$PRUNE_DUPLICATES" == true ]] && echo false || echo true) ;;
      9)
        JSON_OUTPUT=$([[ "$JSON_OUTPUT" == true ]] && echo false || echo true)
        if [[ "$JSON_OUTPUT" == true ]]; then
          COLOR=false
          init_colors
        fi
        ;;
      10)
        local n
        read -r -p "Keep how many backups? (0 disables rotation): " n </dev/tty || true
        if [[ "$n" =~ ^[0-9]+$ ]]; then
          KEEP_BACKUPS="$n"
        else
          log "Invalid number."
        fi
        ;;
      11)
        menu_pins
        ;;
      12) return 0 ;;
      *) log "Invalid option." ;;
    esac

    prompt_enter_to_continue
  done
}

post_apply_updates() {
  if [[ "$REBUILD_GRUB" == true ]]; then
    log ""
    if command -v grub2-mkconfig >/dev/null 2>&1; then
      log "Rebuilding GRUB menu: $GRUB_CFG"
      grub2-mkconfig -o "$GRUB_CFG"
      log "Done."
    else
      warn "--rebuild-grub requested, but grub2-mkconfig not found"
    fi
  fi

  if [[ "$UPDATE_SDBOOT" == true ]]; then
    log ""
    if command -v sdbootutil >/dev/null 2>&1; then
      log "Updating sd-boot entries: sdbootutil update-kernels"
      if ! sdbootutil update-kernels; then
        warn "sdbootutil update-kernels failed"
      fi
    else
      warn "--update-sdboot requested, but sdbootutil not found"
    fi
  fi
}

# Interactive menu: if requested OR no args and running on a TTY.
# Uses ORIG_ARGC because we've shifted args during parsing.
if [[ "$NO_MENU" == false && -z "${SCRUB_GHOST_NO_MENU:-}" ]]; then
  if [[ "$MENU_REQUESTED" == true || ( "$ORIG_ARGC" -eq 0 && -t 0 && -t 1 ) ]]; then
    menu_main
    exit 0
  fi
fi

# Handle non-scan actions after BOOT_DIR and snapper set are ready.
if [[ "$ACTION" == "list-backups" ]]; then
  list_backups
  exit 0
fi

if [[ "$ACTION" == "validate" ]]; then
  mkdir -p -- "$BACKUP_ROOT" 2>/dev/null || true

  if [[ -n "$RESTORE_PICK" ]]; then
    RESTORE_FROM="$(pick_nth_backup_dir "$RESTORE_PICK" || true)"
  elif [[ "$RESTORE_FROM" == "__LATEST__" ]]; then
    RESTORE_FROM="$(latest_backup_dir)"
  fi

  if [[ -z "$RESTORE_FROM" ]]; then
    err "validate: no backup found (use --list-backups)"
    exit 1
  fi

  if validate_backup_bootability "$RESTORE_FROM"; then
    log "Backup validation OK: $RESTORE_FROM"
    exit 0
  else
    err "Backup validation FAILED: $RESTORE_FROM"
    exit 1
  fi
fi

if [[ "$ACTION" == "restore" ]]; then
  mkdir -p -- "$BACKUP_ROOT" 2>/dev/null || true

  if [[ -n "$RESTORE_PICK" ]]; then
    RESTORE_FROM="$(pick_nth_backup_dir "$RESTORE_PICK" || true)"
  elif [[ "$RESTORE_BEST" == true ]]; then
    RESTORE_FROM="$(pick_best_backup_dir || true)"
  elif [[ "$RESTORE_FROM" == "__LATEST__" ]]; then
    RESTORE_FROM="$(latest_backup_dir)"
  fi

  if [[ -z "$RESTORE_FROM" ]]; then
    err "restore: no suitable backup found (use --list-backups)"
    exit 1
  fi

  maybe_temp_remount_rw_for_path "$BACKUP_ROOT" "backup root (restore-pre backup)"
  maybe_temp_remount_rw_for_path "$ENTRIES_DIR" "entries dir (restore target)"

  restore_entries_from_backup "$RESTORE_FROM"
  post_apply_updates
  exit 0
fi

log "========================================"
log " Checking for Ghost BLS Entries"
log " Entries: $ENTRIES_DIR"
log " Boot dir: $BOOT_DIR"
log " Mode: $( [[ "$DRY_RUN" == true ]] && echo DRY-RUN || echo APPLY ) (${DELETE_MODE})"
log " Auto backup:      $AUTO_BACKUP"
log " Auto snapper:     $AUTO_SNAPPER_BACKUP"
log " Auto remount rw:  $AUTO_REMOUNT_RW"
log " Update sdboot:    $UPDATE_SDBOOT"
log " Verify snapshots: $VERIFY_SNAPSHOTS (snapper: $SNAPPER_AVAILABLE)"
log " Verify modules:   $VERIFY_KERNEL_MODULES"
log " Prune stale snaps: $PRUNE_STALE_SNAPSHOTS"
log " Prune uninstalled: $PRUNE_UNINSTALLED_KERNELS (confirm: $CONFIRM_PRUNE_UNINSTALLED)"
log " Prune duplicates:  $PRUNE_DUPLICATES"
log " JSON output:       $JSON_OUTPUT"
log "========================================"

ok_count=0
ghost_count=0
zombie_initrd_count=0
pinned_count=0
protected_count=0
protected_kernel_count=0
critical_kernel_count=0
stale_snapshot_count=0
uninstalled_kernel_count=0
unknown_kver_count=0

duplicate_found_count=0
duplicate_pruned_count=0
moved_or_deleted_count=0
skipped_count=0

declare -A SEEN_PAYLOADS

# Duplicate resolution index (2-pass): keep the best candidate per payload.
# "Best" is chosen by:
#  1) protection score (snapshot-present > protected kernel > normal)
#  2) newest mtime
# This avoids "first file wins" behavior.

declare -A DUP_BEST_FILE
declare -A DUP_BEST_SCORE
declare -A DUP_BEST_MTIME
declare -A DUP_COUNT

declare -a JSON_RESULTS
JSON_RESULTS=()

compute_duplicate_protection_score() {
  # Prints a numeric score (higher = prefer keeping this entry).
  # 4 = pinned (listed in .scrub-ghost-pinned)
  # 3 = GRUB default (saved_entry matches BLS id)
  # 2 = protected snapshot
  # 1 = protected kernel (running/latest)
  # 0 = normal
  local entry_file="$1"
  local kernel_path="$2"

  local kver
  kver="$(kernel_version_from_linux_path "$kernel_path" 2>/dev/null || true)"
  if is_pinned "$entry_file" "$kver"; then
    printf '4\n'
    return 0
  fi

  if entry_is_grub_default "$entry_file"; then
    printf '3\n'
    return 0
  fi

  local snap_num snap_present
  snap_num="$(snapshot_num_from_entry "$entry_file")"
  snap_present=false
  if [[ -n "$snap_num" ]]; then
    if [[ "$VERIFY_SNAPSHOTS" == true ]]; then
      snapshot_exists "$snap_num" && snap_present=true || snap_present=false
    else
      [[ -d "/.snapshots/$snap_num/snapshot" ]] && snap_present=true
    fi
  fi

  if [[ "$snap_present" == true ]]; then
    printf '2\n'
    return 0
  fi

  # Protected kernel check

  if [[ -n "$RUNNING_KERNEL_VER" ]]; then
    if [[ -n "$kver" && "$kver" == "$RUNNING_KERNEL_VER" ]] || path_mentions_kver "$kernel_path" "$RUNNING_KERNEL_VER"; then
      printf '1\n'
      return 0
    fi
  fi
  if [[ -n "$LATEST_INSTALLED_VER" ]]; then
    if [[ -n "$kver" && "$kver" == "$LATEST_INSTALLED_VER" ]] || path_mentions_kver "$kernel_path" "$LATEST_INSTALLED_VER"; then
      printf '1\n'
      return 0
    fi
  fi

  printf '0\n'
}

build_duplicate_index() {
  # Pre-scan entries to decide which duplicate to keep.
  # This is intentionally best-effort; failures just reduce duplicate accuracy.
  local f
  for f in "$ENTRIES_DIR"/*.conf; do
    [[ -e "$f" ]] || continue

    local kp
    kp="$(bls_linux_path "$f")"
    [[ -n "$kp" ]] || continue

    # Collect initrds (multi-initrd aware)
    local initrd_join
    initrd_join=""
    declare -a ips
    ips=()
    mapfile -t ips < <(bls_initrd_paths "$f")
    if (( ${#ips[@]} > 0 )); then
      initrd_join="$(printf '%s ' "${ips[@]}" | sed 's/[[:space:]]*$//')"
    fi

    local opts
    opts="$(bls_options_line "$f")"

    local raw sig
    raw="${kp}|${initrd_join}|${opts}"
    sig="$(payload_signature "$raw")"
    [[ -n "$sig" ]] || continue

    DUP_COUNT["$sig"]=$(( ${DUP_COUNT[$sig]:-0} + 1 ))

    local mtime
    mtime="$(stat -c %Y -- "$f" 2>/dev/null || echo 0)"

    local score
    score="$(compute_duplicate_protection_score "$f" "$kp" 2>/dev/null || echo 0)"
    [[ "$score" =~ ^[0-9]+$ ]] || score=0

    if [[ -z "${DUP_BEST_FILE[$sig]+x}" ]]; then
      DUP_BEST_FILE["$sig"]="$f"
      DUP_BEST_SCORE["$sig"]="$score"
      DUP_BEST_MTIME["$sig"]="$mtime"
      continue
    fi

    local best_score best_mtime
    best_score="${DUP_BEST_SCORE[$sig]:-0}"
    best_mtime="${DUP_BEST_MTIME[$sig]:-0}"

    # Prefer higher score; if tie, prefer newer mtime.
    if [[ "$score" -gt "$best_score" ]]; then
      DUP_BEST_FILE["$sig"]="$f"
      DUP_BEST_SCORE["$sig"]="$score"
      DUP_BEST_MTIME["$sig"]="$mtime"
    elif [[ "$score" -eq "$best_score" ]]; then
      if [[ "$mtime" =~ ^[0-9]+$ && "$best_mtime" =~ ^[0-9]+$ && "$mtime" -gt "$best_mtime" ]]; then
        DUP_BEST_FILE["$sig"]="$f"
        DUP_BEST_SCORE["$sig"]="$score"
        DUP_BEST_MTIME["$sig"]="$mtime"
      fi
    fi
  done
}

ensure_backup_dir() {
  if [[ -z "$BACKUP_DIR" ]]; then
    local ts
    ts="$(ts_now)"

    # Prefer a backup path OUTSIDE the entries dir so we never touch it by accident.
    # Fall back to inside ENTRIES_DIR if /var/backups isn't writable for some reason.
    maybe_temp_remount_rw_for_path "$BACKUP_ROOT" "backup root"
    if mkdir -p -- "$BACKUP_ROOT" 2>/dev/null; then
      BACKUP_DIR="$BACKUP_ROOT/bls-entries-$ts"
    else
      maybe_temp_remount_rw_for_path "$ENTRIES_DIR" "entries dir (fallback backup location)"
      BACKUP_DIR="$ENTRIES_DIR/.scrub-ghost-backup-$ts"
    fi
  fi

  maybe_temp_remount_rw_for_path "$BACKUP_DIR" "backup dir"
  mkdir -p -- "$BACKUP_DIR"

  # Ensure we have space for a full copy of entries (and moved files).
  preflight_backup_space_or_die "$BACKUP_DIR"

  # Point latest -> this backup dir (best effort)
  if [[ "$BACKUP_DIR" == "$BACKUP_ROOT"/* ]]; then
    ln -sfn -- "$BACKUP_DIR" "$BACKUP_ROOT/latest" 2>/dev/null || true
  fi
}

backup_entries_tree() {
  # Makes a full copy of the current BLS entry files before any modifications.
  # This is independent from the "move ghosts into backup" behavior.
  ensure_backup_dir

  local full_dir="$BACKUP_DIR/full"
  mkdir -p -- "$full_dir"

  # Copy only top-level .conf entries (we never recurse), preserving metadata where possible.
  # cp -a on vfat won't preserve everything but it's still a good safety net.
  if compgen -G "$ENTRIES_DIR/*.conf" >/dev/null; then
    cp -a -- "$ENTRIES_DIR"/*.conf "$full_dir/" 2>/dev/null || cp -p -- "$ENTRIES_DIR"/*.conf "$full_dir/"
  fi

  {
    echo "timestamp=$(date -Is)"
    echo "entries_dir=$ENTRIES_DIR"
    echo "boot_dir=$BOOT_DIR"
    echo "delete_mode=$DELETE_MODE"
    if [[ -f /etc/machine-id ]]; then
      echo "machine_id=$(tr -d '\n' </etc/machine-id 2>/dev/null || true)"
    fi
    if [[ -n "$SNAPPER_BACKUP_ID" ]]; then
      echo "snapper_backup_id=$SNAPPER_BACKUP_ID"
    fi
  } >"$BACKUP_DIR/manifest.txt" || true

  # Rotate old backups after creating a new one
  rotate_backups
}

snapper_backup_snapshot() {
  # Best-effort snapper snapshot: may not include ESP contents, but provides system rollback.
  # We do not fail the script if snapper isn't configured.
  if command -v snapper >/dev/null 2>&1; then
    local desc
    desc="scrub-ghost: pre-clean $(date -Is)"
    SNAPPER_BACKUP_ID="$(snapper --no-dbus create --type single --cleanup-algorithm number --description "$desc" 2>/dev/null | tr -dc '0-9' || true)"
    if [[ -n "$SNAPPER_BACKUP_ID" ]]; then
      log "Snapper backup created: #$SNAPPER_BACKUP_ID"
    else
      warn "Snapper backup requested but could not create snapshot (snapper may be unconfigured)"
    fi
  else
    warn "Snapper backup requested but snapper not installed"
  fi
}

move_entry_to_backup_dir() {
  # Moves $1 into $2, safely handling cross-filesystem moves.
  # On EXDEV (e.g. ESP -> /var), "mv" becomes copy+delete; we do it explicitly with a temp file
  # and a size check to reduce the chance of partial backups.
  local src="$1"
  local dest_dir="$2"

  [[ -n "$src" && -n "$dest_dir" ]] || return 1

  local base dest
  base="$(basename -- "$src")"
  dest="$dest_dir/$base"

  # Avoid overwriting an existing file in the backup dir.
  if [[ -e "$dest" ]]; then
    dest="$dest_dir/$base.dup.$$"
  fi

  local src_dev dst_dev
  src_dev="$(stat -c %d -- "$src" 2>/dev/null || true)"
  dst_dev="$(stat -c %d -- "$dest_dir" 2>/dev/null || true)"

  # Same filesystem => real rename is atomic.
  if [[ -n "$src_dev" && -n "$dst_dev" && "$src_dev" == "$dst_dev" ]]; then
    mv -- "$src" "$dest"
    return 0
  fi

  # Cross-filesystem: copy to temp, fsync/sync best-effort, then rename into place, then delete original.
  local tmp
  tmp="$dest_dir/.scrub-ghost.tmp.$$.$base"

  cp -p -- "$src" "$tmp" 2>/dev/null || cp -- "$src" "$tmp"
  sync -f "$tmp" 2>/dev/null || sync 2>/dev/null || true

  local a b
  a="$(stat -c %s -- "$src" 2>/dev/null || true)"
  b="$(stat -c %s -- "$tmp" 2>/dev/null || true)"
  if [[ -n "$a" && -n "$b" && "$a" != "$b" ]]; then
    err "Backup copy size mismatch for $src (src=$a tmp=$b); refusing to delete original"
    rm -f -- "$tmp" 2>/dev/null || true
    return 1
  fi

  mv -f -- "$tmp" "$dest"
  rm -f -- "$src"
}

# Build duplicate index (2-pass) so duplicate pruning keeps the best candidate.
# Done after guardrails/snapper-set are available.
build_duplicate_index

# If applying changes, ensure writable mounts and create backups BEFORE touching entries.
if [[ "$DRY_RUN" == false ]]; then
  maybe_temp_remount_rw_for_path "$ENTRIES_DIR" "entries dir"

  if [[ "$AUTO_SNAPPER_BACKUP" == true ]]; then
    snapper_backup_snapshot
  fi
  if [[ "$AUTO_BACKUP" == true ]]; then
    backup_entries_tree
    if validate_backup_structure "$BACKUP_DIR"; then
      log "Entry backup saved to: $BACKUP_DIR"
    else
      err "Backup integrity check failed; refusing to proceed with cleanup"
      err "(pass --no-backup if you really want to run without backups)"
      exit 1
    fi
  fi
fi

for entry in "$ENTRIES_DIR"/*.conf; do
  [[ -e "$entry" ]] || continue

  # Reset per-entry state to avoid leakage across iterations.
  kernel_path=""
  kernel_full=""
  initrd_path=""
  initrd_full=""
  devicetree_path=""
  devicetree_full=""
  entry_kver=""
  snap_num=""
  snap_present=false
  kver=""
  modules_present=true
  modules_kver_unknown=false
  is_running_kernel=false
  is_latest_kernel=false
  is_grub_default=false

  # Pull first linux/linuxefi path.
  kernel_path="$(bls_linux_path "$entry")"

  if [[ -z "$kernel_path" ]]; then
    warn "Skipping (no linux/linuxefi line): $(basename -- "$entry")"
    skipped_count=$((skipped_count + 1))
    json_add_result "$(basename -- "$entry")" "SKIPPED" "" "" "" "" "" "SKIP" "no linux/linuxefi line"
    continue
  fi

  # Determine kernel version early so skip paths can still report it safely.
  entry_kver="$(kernel_version_from_linux_path "$kernel_path" 2>/dev/null || true)"
  kver="$entry_kver"

  # Snapshot number early as well (avoid stale values in SKIPPED reports).
  snap_num="$(snapshot_num_from_entry "$entry")"

  # Guardrails: protect running/latest kernel even if we can't parse kver (string-match fallback).
  if [[ -n "$RUNNING_KERNEL_VER" ]]; then
    if [[ -n "$entry_kver" && "$entry_kver" == "$RUNNING_KERNEL_VER" ]]; then
      is_running_kernel=true
    elif path_mentions_kver "$kernel_path" "$RUNNING_KERNEL_VER"; then
      is_running_kernel=true
    fi
  fi
  if [[ -n "$LATEST_INSTALLED_VER" ]]; then
    if [[ -n "$entry_kver" && "$entry_kver" == "$LATEST_INSTALLED_VER" ]]; then
      is_latest_kernel=true
    elif path_mentions_kver "$kernel_path" "$LATEST_INSTALLED_VER"; then
      is_latest_kernel=true
    fi
  fi

  # Bootloader awareness: protect the saved GRUB default entry when it matches a BLS id.
  if entry_is_grub_default "$entry"; then
    is_grub_default=true
  fi

  kernel_full="$(resolve_boot_path "$kernel_path" || true)"
  if [[ -z "$kernel_full" ]]; then
    warn "Skipping (could not resolve kernel path): $(basename -- "$entry")"
    skipped_count=$((skipped_count + 1))
    json_add_result "$(basename -- "$entry")" "SKIPPED" "$kernel_path" "" "" "${snap_num:-}" "${entry_kver:-}" "SKIP" "could not resolve kernel path"
    continue
  fi

  # Snapshot verification/protection.
  if [[ "$VERIFY_SNAPSHOTS" == true && -n "$snap_num" ]]; then
    if snapshot_exists "$snap_num"; then
      snap_present=true
    else
      snap_present=false
    fi
  elif [[ -n "$snap_num" ]]; then
    # Without snapper verification, fall back to simple on-disk check.
    if [[ -d "/.snapshots/$snap_num/snapshot" ]]; then
      snap_present=true
    fi
  fi

  # Kernel modules verification (helps detect entries for kernels not installed anymore)
  modules_present=true
  modules_kver_unknown=false
  if [[ "$VERIFY_KERNEL_MODULES" == true ]]; then
    if [[ -n "$kver" ]]; then
      if ! modules_dir_exists_for_kver "$kver"; then
        modules_present=false
      fi
    else
      # Unknown kver: do not classify as "uninstalled kernel" (too risky).
      # Count it so the summary can report that module verification was skipped.
      modules_present=true
      modules_kver_unknown=true
      unknown_kver_count=$((unknown_kver_count + 1))
    fi
  fi

  # initrd/devicetree checks (if referenced)
  # BLS allows multiple initrd lines; ALL must exist for the entry to be bootable.
  initrd_path=""
  initrd_full=""
  missing_initrd=false
  declare -a initrds
  initrds=()
  mapfile -t initrds < <(bls_initrd_paths "$entry")

  if (( ${#initrds[@]} > 0 )); then
    # Keep a joined representation for logging/JSON/duplicate detection.
    initrd_path="$(printf '%s ' "${initrds[@]}" | sed 's/[[:space:]]*$//')"

    local ip
    for ip in "${initrds[@]}"; do
      [[ -n "$ip" ]] || continue
      initrd_full="$(resolve_boot_path "$ip" || true)"
      if [[ -z "$initrd_full" || ! -s "$initrd_full" ]]; then
        missing_initrd=true
        if [[ "$VERBOSE" == true ]]; then
          log "        missing initrd: $ip"
        fi
      else
        # Smart format validation: if initrd exists but doesn't look like an archive,
        # treat it as corrupt/missing.
        if ! initrd_looks_valid "$initrd_full"; then
          local file_type
          file_type="$(initrd_mime_type "$initrd_full" 2>/dev/null || true)"
          [[ -z "$file_type" ]] && file_type="unknown"
          log "${C_RED}[CORRUPT-INITRD]${C_RESET} $(basename -- "$entry") ${C_DIM}(invalid type: $file_type)${C_RESET}"
          missing_initrd=true
        fi
      fi
    done
  fi

  devicetree_path="$(bls_devicetree_path "$entry")"
  devicetree_full=""
  missing_devicetree=false
  if [[ -n "$devicetree_path" ]]; then
    devicetree_full="$(resolve_boot_path "$devicetree_path" || true)"
    if [[ -z "$devicetree_full" || ! -s "$devicetree_full" ]]; then
      missing_devicetree=true
    fi
  fi

  missing_kernel=false
  corrupt_kernel=false
  corrupt_reason=""
  if [[ ! -e "$kernel_full" ]]; then
    missing_kernel=true
  elif [[ ! -s "$kernel_full" ]]; then
    corrupt_kernel=true
    missing_kernel=true
    corrupt_reason="EMPTY"
  else
    # Deep integrity check (RPM): checksum mismatch means the kernel image on disk is not what
    # the owning package shipped.
    if command -v rpm >/dev/null 2>&1; then
      local owners ver_out
      owners="$(rpm -qf -- "$kernel_full" 2>/dev/null || true)"
      if [[ -n "$owners" && "$owners" != *"not owned"* ]]; then
        ver_out="$(rpm -Vf -- "$kernel_full" 2>/dev/null || true)"
        if [[ -n "$ver_out" ]]; then
          # rpm -V output uses '5' to indicate digest (checksum) mismatch.
          while IFS= read -r _line; do
            [[ -n "$_line" ]] || continue
            local _flags _path
            _flags="${_line%%[[:space:]]*}"
            _path="$(awk '{print $NF}' <<<"$_line")"
            if [[ "$_path" == "$kernel_full" && "$_flags" == *5* ]]; then
              corrupt_kernel=true
              missing_kernel=true
              corrupt_reason="CSUM"
              break
            fi
          done <<<"$ver_out"
        fi
      fi
    fi
  fi

  # Manual override: pinned entries are never modified/pruned.
  if is_pinned "$entry" "$entry_kver"; then
    pinned_count=$((pinned_count + 1))

    local pin_status pin_details
    pin_status="PINNED"
    pin_details="pinned"

    if [[ "$missing_kernel" == true || "$missing_initrd" == true || "$missing_devicetree" == true ]]; then
      pin_status="PINNED-BROKEN"
      pin_details="pinned but references missing/corrupt files"
      warn "${C_YELLOW}[PINNED]${C_RESET} $(basename -- "$entry") is pinned but appears broken (will not prune)."
    elif [[ "$VERBOSE" == true ]]; then
      log "${C_BLUE}[PINNED]${C_RESET} $(basename -- "$entry")"
    fi

    json_add_result "$(basename -- "$entry")" "$pin_status" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "SKIP" "$pin_details"
    continue
  fi

  # If nothing is missing, entry is potentially OK (then check duplicates / stale snapshot / uninstalled-kernel).
  if [[ "$missing_kernel" == false && "$missing_initrd" == false && "$missing_devicetree" == false ]]; then

  # Duplicate detection/pruning: hash the functional payload (linux+initrd(s)+options).
  # Snapshot entries are treated as protected when the snapshot exists.
  local entry_options payload_raw payload_sig
  entry_options="$(bls_options_line "$entry")"
  payload_raw="${kernel_path}|${initrd_path}|${entry_options}"
  payload_sig="$(payload_signature "$payload_raw")"

    local best_file best_mtime best_score current_mtime
    best_file="${DUP_BEST_FILE[$payload_sig]:-}"

    # If this payload appears more than once, treat non-best entries as duplicates.
    if [[ "${DUP_COUNT[$payload_sig]:-0}" -gt 1 && -n "$best_file" && "$best_file" != "$entry" ]]; then
      duplicate_found_count=$((duplicate_found_count + 1))

      best_mtime="${DUP_BEST_MTIME[$payload_sig]:-0}"
      best_score="${DUP_BEST_SCORE[$payload_sig]:-0}"
      current_mtime="$(stat -c %Y -- "$entry" 2>/dev/null || echo 0)"

      log "${C_YELLOW}[DUPLICATE]${C_RESET} $(basename -- "$entry")"
      log "        keep:    $(basename -- "$best_file")"
      if [[ "$current_mtime" =~ ^[0-9]+$ && "$best_mtime" =~ ^[0-9]+$ && "$current_mtime" -gt "$best_mtime" ]]; then
        log "        ${C_YELLOW}NOTE:${C_RESET} current is newer but losing due to protection/heuristics (best_score=$best_score)"
      fi

      if [[ "$PRUNE_DUPLICATES" == true ]]; then
        if [[ "$snap_present" == true ]]; then
          log "        action:  ${C_BLUE}SKIP${C_RESET} (protected snapshot entry)"
          json_add_result "$(basename -- "$entry")" "DUPLICATE" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "SKIP" "protected snapshot entry"
          continue
        fi
        if [[ "$is_running_kernel" == true || "$is_latest_kernel" == true || "$is_grub_default" == true ]]; then
          log "        action:  ${C_BLUE}SKIP${C_RESET} (protected kernel/default)"
          json_add_result "$(basename -- "$entry")" "DUPLICATE" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "SKIP" "protected kernel/default"
          continue
        fi

        if [[ "$DRY_RUN" == true ]]; then
          log "        action:  (dry-run) would prune duplicate"
          json_add_result "$(basename -- "$entry")" "DUPLICATE" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "DRYRUN" "would prune duplicate"
          continue
        fi

        log "        action:  pruning duplicate"
        if [[ "$DELETE_MODE" == "delete" ]]; then
          log_audit "ACTION=DELETE file=$entry reason=duplicate keep=$(basename -- "$best_file")"
          rm -f -- "$entry"
          moved_or_deleted_count=$((moved_or_deleted_count + 1))
          duplicate_pruned_count=$((duplicate_pruned_count + 1))
          json_add_result "$(basename -- "$entry")" "DUPLICATE" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "DELETE" "duplicate"
        else
          ensure_backup_dir
          log_audit "ACTION=MOVE file=$entry dest=$BACKUP_DIR reason=duplicate keep=$(basename -- "$best_file")"
          move_entry_to_backup_dir "$entry" "$BACKUP_DIR"
          moved_or_deleted_count=$((moved_or_deleted_count + 1))
          duplicate_pruned_count=$((duplicate_pruned_count + 1))
          json_add_result "$(basename -- "$entry")" "DUPLICATE" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "MOVE" "duplicate"
        fi
        continue
      fi

      log "        note:    enable --prune-duplicates to remove duplicates"
      json_add_result "$(basename -- "$entry")" "DUPLICATE" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "NONE" "duplicate"
      continue
    else
      # Primary / chosen duplicate candidate.
      :
    fi

    # Kernel image exists, but we may still want to flag stale snapper/uninstalled kernels.
    if [[ -n "$snap_num" && "$VERIFY_SNAPSHOTS" == true && "$snap_present" == false ]]; then
      stale_snapshot_count=$((stale_snapshot_count + 1))
      log "${C_RED}[STALE-SNAPSHOT]${C_RESET} $(basename -- "$entry") ${C_DIM}(snapshot #$snap_num not present)${C_RESET}"

      if [[ "$DRY_RUN" == true || "$PRUNE_STALE_SNAPSHOTS" == false ]]; then
        json_add_result "$(basename -- "$entry")" "STALE-SNAPSHOT" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "SKIP" "snapshot missing"
        continue
      fi

      if [[ "$is_running_kernel" == true || "$is_latest_kernel" == true || "$is_grub_default" == true ]]; then
        log "        action:  ${C_BLUE}SKIP${C_RESET} (protected kernel/default: ${entry_kver:-unknown})"
        protected_kernel_count=$((protected_kernel_count + 1))
        json_add_result "$(basename -- "$entry")" "STALE-SNAPSHOT" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "SKIP" "protected kernel/default"
        continue
      fi

      # Apply pruning (move/delete) for stale snapshot entries
      log "        action:  pruning stale snapshot entry"
      if [[ "$DELETE_MODE" == "delete" ]]; then
        log_audit "ACTION=DELETE file=$entry reason=stale-snapshot snapshot=${snap_num:-}"
        rm -f -- "$entry"
        json_add_result "$(basename -- "$entry")" "STALE-SNAPSHOT" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "DELETE" "stale snapshot"
      else
        ensure_backup_dir
        log_audit "ACTION=MOVE file=$entry dest=$BACKUP_DIR reason=stale-snapshot snapshot=${snap_num:-}"
        move_entry_to_backup_dir "$entry" "$BACKUP_DIR"
        json_add_result "$(basename -- "$entry")" "STALE-SNAPSHOT" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "MOVE" "stale snapshot"
      fi
      moved_or_deleted_count=$((moved_or_deleted_count + 1))
      continue
    fi

    if [[ "$modules_present" == false ]]; then
      uninstalled_kernel_count=$((uninstalled_kernel_count + 1))
      log "${C_YELLOW}[UNINSTALLED-KERNEL]${C_RESET} $(basename -- "$entry") ${C_DIM}(modules missing for ${kver:-unknown})${C_RESET}"

      # RPM awareness: if rpm says this kernel is installed, do NOT prune based on missing modules alone.
      local rpm_says_installed=false
      if [[ -n "$kver" ]] && command -v rpm >/dev/null 2>&1; then
        if is_kernel_rpm_installed "$kver"; then
          rpm_says_installed=true
          log "        note:    ${C_BLUE}SKIP${C_RESET} (rpm reports kernel installed: kernel-uname-r=$kver)"
        fi
      fi

      if [[ "$PRUNE_UNINSTALLED_KERNELS" == true && "$CONFIRM_PRUNE_UNINSTALLED" == false ]]; then
        log "        note:    pruning requires --confirm-uninstalled (extra safety flag)"
      fi

      if [[ "$rpm_says_installed" == true ]]; then
        protected_kernel_count=$((protected_kernel_count + 1))
        json_add_result "$(basename -- "$entry")" "UNINSTALLED-KERNEL" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${kver:-}" "SKIP" "rpm reports installed"
        continue
      fi

      if [[ "$DRY_RUN" == true || "$PRUNE_UNINSTALLED_KERNELS" == false || "$CONFIRM_PRUNE_UNINSTALLED" == false ]]; then
        json_add_result "$(basename -- "$entry")" "UNINSTALLED-KERNEL" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${kver:-}" "SKIP" "modules missing"
        continue
      fi

      if [[ "$is_running_kernel" == true || "$is_latest_kernel" == true || "$is_grub_default" == true ]]; then
        log "        action:  ${C_BLUE}SKIP${C_RESET} (protected kernel/default: ${entry_kver:-unknown})"
        protected_kernel_count=$((protected_kernel_count + 1))
        json_add_result "$(basename -- "$entry")" "UNINSTALLED-KERNEL" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${kver:-}" "SKIP" "protected kernel/default"
        continue
      fi

      log "        action:  pruning uninstalled-kernel entry"
      if [[ "$DELETE_MODE" == "delete" ]]; then
        log_audit "ACTION=DELETE file=$entry reason=uninstalled-kernel kver=${kver:-}"
        rm -f -- "$entry"
        json_add_result "$(basename -- "$entry")" "UNINSTALLED-KERNEL" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${kver:-}" "DELETE" "uninstalled kernel"
      else
        ensure_backup_dir
        log_audit "ACTION=MOVE file=$entry dest=$BACKUP_DIR reason=uninstalled-kernel kver=${kver:-}"
        move_entry_to_backup_dir "$entry" "$BACKUP_DIR"
        json_add_result "$(basename -- "$entry")" "UNINSTALLED-KERNEL" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${kver:-}" "MOVE" "uninstalled kernel"
      fi
      moved_or_deleted_count=$((moved_or_deleted_count + 1))
      continue
    fi

    if [[ "$VERBOSE" == true && ( "$is_running_kernel" == true || "$is_latest_kernel" == true ) ]]; then
      prot_reason=""
      [[ "$is_running_kernel" == true ]] && prot_reason+="running "
      [[ "$is_latest_kernel" == true ]] && prot_reason+="latest "
      log "${C_BLUE}[PROTECTED]${C_RESET} $(basename -- "$entry") ${C_DIM}(${prot_reason}kernel: ${entry_kver:-unknown})${C_RESET}"
      protected_kernel_count=$((protected_kernel_count + 1))
      local details
      details="${prot_reason}kernel"
      if [[ "$modules_kver_unknown" == true ]]; then
        details+="; kver unknown (modules check skipped)"
      fi
      json_add_result "$(basename -- "$entry")" "PROTECTED-KERNEL" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "NONE" "$details"
    else
      log "${C_GREEN}[OK]${C_RESET}   $(basename -- "$entry")"
      if [[ "$is_running_kernel" == true || "$is_latest_kernel" == true ]]; then
        local details
        details="kernel protected"
        if [[ "$modules_kver_unknown" == true ]]; then
          details+="; kver unknown (modules check skipped)"
        fi
        json_add_result "$(basename -- "$entry")" "PROTECTED-KERNEL" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "NONE" "$details"
      else
        local details
        details=""
        if [[ "$modules_kver_unknown" == true ]]; then
          details="kver unknown (modules check skipped)"
        fi
        json_add_result "$(basename -- "$entry")" "OK" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "NONE" "$details"
      fi
    fi
    ok_count=$((ok_count + 1))
    continue
  fi

  # Something missing -> likely a ghost/broken entry.
  # Special case: kernel exists but initrd is missing/corrupt => "zombie" (repairable).
  if [[ "${missing_kernel:-false}" == false && "${missing_initrd:-false}" == true ]]; then
    zombie_initrd_count=$((zombie_initrd_count + 1))

    log ""
    log "${C_YELLOW}[ZOMBIE-INITRD]${C_RESET} $(basename -- "$entry") ${C_DIM}(kernel exists, initrd missing/corrupt)${C_RESET}"
    log "        linux:   $kernel_path"
    log "        lookup:  $kernel_full"
    if [[ -n "${initrd_path:-}" ]]; then
      log "        initrd:  $initrd_path"
      log "        lookup:  ${initrd_full:-<unresolved>}"
    fi

    # Snapshot entries remain protected.
    if [[ "$snap_present" == true ]]; then
      log "        action:  ${C_BLUE}SKIP${C_RESET} (protected snapshot entry)"
      protected_count=$((protected_count + 1))
      json_add_result "$(basename -- "$entry")" "PROTECTED-SNAPSHOT" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "SKIP" "snapshot exists"
      continue
    fi

    # By default we do NOT prune these: suggest repair.
    if [[ "$PRUNE_ZOMBIES" != true ]]; then
      local sug
      sug=""
      if [[ -n "${entry_kver:-}" ]]; then
        sug="sudo dracut --force --kver ${entry_kver}"
      fi

      if [[ "$DRY_RUN" == true ]]; then
        log "        action:  ${C_BLUE}SKIP${C_RESET} (repair suggested)"
        json_add_result "$(basename -- "$entry")" "ZOMBIE-INITRD" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "SKIP" "repair suggested"
      else
        log "        action:  ${C_BLUE}SKIP${C_RESET} (repair suggested; enable --prune-zombies to remove)"
        [[ -n "$sug" ]] && log "        suggestion: ${C_DIM}$sug${C_RESET}"
        json_add_result "$(basename -- "$entry")" "ZOMBIE-INITRD" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "SKIP" "repair suggested"
      fi
      continue
    fi

    # Prune zombies only when explicitly requested.
    if [[ "$is_running_kernel" == true || "$is_latest_kernel" == true || "$is_grub_default" == true ]]; then
      log "        action:  ${C_BLUE}SKIP${C_RESET} (protected kernel/default)"
      protected_kernel_count=$((protected_kernel_count + 1))
      json_add_result "$(basename -- "$entry")" "PROTECTED-KERNEL" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "SKIP" "zombie initrd but protected kernel/default"
      continue
    fi

    if [[ "$DRY_RUN" == true ]]; then
      if [[ "$DELETE_MODE" == "delete" ]]; then
        log "        action:  (dry-run) would DELETE zombie entry"
        json_add_result "$(basename -- "$entry")" "ZOMBIE-INITRD" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "DRYRUN" "would delete zombie"
      else
        log "        action:  (dry-run) would MOVE zombie entry to backup"
        json_add_result "$(basename -- "$entry")" "ZOMBIE-INITRD" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "DRYRUN" "would move zombie"
      fi
      continue
    fi

    if [[ "$DELETE_MODE" == "delete" ]]; then
      log "        action:  deleting zombie entry file"
      log_audit "ACTION=DELETE file=$entry reason=ZOMBIE-INITRD"
      rm -f -- "$entry"
      moved_or_deleted_count=$((moved_or_deleted_count + 1))
      json_add_result "$(basename -- "$entry")" "ZOMBIE-INITRD" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "DELETE" "zombie initrd"
    else
      ensure_backup_dir
      log "        action:  moving zombie entry file -> $BACKUP_DIR"
      log_audit "ACTION=MOVE file=$entry dest=$BACKUP_DIR reason=ZOMBIE-INITRD"
      move_entry_to_backup_dir "$entry" "$BACKUP_DIR"
      moved_or_deleted_count=$((moved_or_deleted_count + 1))
      json_add_result "$(basename -- "$entry")" "ZOMBIE-INITRD" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "MOVE" "zombie initrd"
    fi

    continue
  fi

  ghost_count=$((ghost_count + 1))

  log ""
  if [[ "${corrupt_kernel:-false}" == true ]]; then
    local corrupt_desc
    corrupt_desc="kernel file is corrupt"
    if [[ "${corrupt_reason:-}" == "EMPTY" ]]; then
      corrupt_desc="kernel file is 0 bytes"
    elif [[ "${corrupt_reason:-}" == "CSUM" ]]; then
      corrupt_desc="kernel file failed rpm checksum verification"
    fi

    if [[ "$is_running_kernel" == true ]]; then
      log "${C_RED}[CORRUPT-RUNNING]${C_RESET} $(basename -- "$entry") ${C_DIM}(${corrupt_desc}; running kernel: ${entry_kver:-unknown})${C_RESET}"
      critical_kernel_count=$((critical_kernel_count + 1))
    elif [[ "$is_latest_kernel" == true ]]; then
      log "${C_RED}[CORRUPT-LATEST]${C_RESET} $(basename -- "$entry") ${C_DIM}(${corrupt_desc}; latest installed kernel: ${entry_kver:-unknown})${C_RESET}"
      protected_kernel_count=$((protected_kernel_count + 1))
    else
      log "${C_RED}[CORRUPT]${C_RESET} $(basename -- "$entry") ${C_DIM}(${corrupt_desc})${C_RESET}"
    fi

    # Smart consistency check: if rpm owns this file, suggest a repair.
    if command -v rpm >/dev/null 2>&1; then
      local owners
      owners="$(rpm -qf -- "$kernel_full" 2>/dev/null || true)"
      if [[ -n "$owners" && "$owners" != *"not owned"* ]]; then
        if [[ "${corrupt_reason:-}" == "EMPTY" ]]; then
          log "        ${C_RED}CRITICAL:${C_RESET} owned by RPM package(s) but file is empty: $owners"
        else
          log "        ${C_RED}CRITICAL:${C_RESET} owned by RPM package(s) but file is corrupt: $owners"
        fi
        log "        recommendation: sudo zypper in -f $owners"
      fi
    fi
  elif [[ "$is_running_kernel" == true ]]; then
    log "${C_RED}[CRITICAL-GHOST]${C_RESET} $(basename -- "$entry") ${C_DIM}(running kernel: ${entry_kver:-unknown})${C_RESET}"
    critical_kernel_count=$((critical_kernel_count + 1))
  elif [[ "$is_latest_kernel" == true ]]; then
    log "${C_YELLOW}[WARN-GHOST]${C_RESET} $(basename -- "$entry") ${C_DIM}(latest installed kernel: ${entry_kver:-unknown})${C_RESET}"
    protected_kernel_count=$((protected_kernel_count + 1))
  else
    log "${C_RED}[GHOST]${C_RESET} $(basename -- "$entry")"
  fi
  log "        linux:   $kernel_path"
  log "        lookup:  $kernel_full"
  if [[ -n "${initrd_path:-}" ]]; then
    log "        initrd:  $initrd_path"
    log "        lookup:  ${initrd_full:-<unresolved>}"
  fi
  if [[ -n "${devicetree_path:-}" ]]; then
    log "        dtb:     $devicetree_path"
    log "        lookup:  ${devicetree_full:-<unresolved>}"
  fi
  miss_list=""
  [[ "${missing_kernel:-false}" == true ]] && miss_list+=" kernel"
  [[ "${corrupt_kernel:-false}" == true ]] && miss_list+=" corrupt-kernel"
  [[ "${missing_initrd:-false}" == true ]] && miss_list+=" initrd"
  [[ "${missing_devicetree:-false}" == true ]] && miss_list+=" devicetree"
  [[ -n "$miss_list" ]] && log "        missing:${miss_list}"

  if [[ "$snap_present" == true ]]; then
    if [[ -n "$snap_num" ]]; then
      log "        note:    references existing snapshot (#$snap_num)"
    else
      log "        note:    references existing snapshot"
    fi
    log "        action:  ${C_BLUE}SKIP${C_RESET} (protected snapshot entry)"
    protected_count=$((protected_count + 1))
    json_add_result "$(basename -- "$entry")" "PROTECTED-SNAPSHOT" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "SKIP" "snapshot exists"
    continue
  fi

  if [[ "$DRY_RUN" == true ]]; then
    local status
    if [[ "${corrupt_kernel:-false}" == true ]]; then
      if [[ "${corrupt_reason:-}" == "CSUM" ]]; then
        status="CORRUPT-CSUM"
      else
        status="CORRUPT"
      fi
    else
      status="GHOST"
    fi

    if [[ "$is_running_kernel" == true || "$is_latest_kernel" == true || "$is_grub_default" == true ]]; then
      log "        action:  ${C_BLUE}SKIP${C_RESET} (protected kernel/default: ${entry_kver:-unknown})"
      json_add_result "$(basename -- "$entry")" "PROTECTED-KERNEL" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "SKIP" "$status (protected kernel/default)"
    else
      if [[ "$DELETE_MODE" == "delete" ]]; then
        log "        action:  (dry-run) would DELETE"
        json_add_result "$(basename -- "$entry")" "$status" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "DRYRUN" "would delete"
      else
        log "        action:  (dry-run) would MOVE to backup"
        json_add_result "$(basename -- "$entry")" "$status" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "DRYRUN" "would move"
      fi
    fi
    continue
  fi

  if [[ "$is_running_kernel" == true || "$is_latest_kernel" == true || "$is_grub_default" == true ]]; then
    log "        action:  ${C_BLUE}SKIP${C_RESET} (protected kernel/default: ${entry_kver:-unknown})"
    protected_kernel_count=$((protected_kernel_count + 1))
    json_add_result "$(basename -- "$entry")" "PROTECTED-KERNEL" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "SKIP" "ghost/corrupt but protected kernel/default"
    continue
  fi

  local status
  if [[ "${corrupt_kernel:-false}" == true ]]; then
    if [[ "${corrupt_reason:-}" == "CSUM" ]]; then
      status="CORRUPT-CSUM"
    else
      status="CORRUPT"
    fi
  else
    status="GHOST"
  fi

  if [[ "$DELETE_MODE" == "delete" ]]; then
    log "        action:  deleting entry file"
    log_audit "ACTION=DELETE file=$entry reason=$status missing=${miss_list# }"
    rm -f -- "$entry"
    moved_or_deleted_count=$((moved_or_deleted_count + 1))
    json_add_result "$(basename -- "$entry")" "$status" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "DELETE" "missing:${miss_list}"
  else
    ensure_backup_dir
    log "        action:  moving entry file -> $BACKUP_DIR"
    log_audit "ACTION=MOVE file=$entry dest=$BACKUP_DIR reason=$status missing=${miss_list# }"
    move_entry_to_backup_dir "$entry" "$BACKUP_DIR"
    moved_or_deleted_count=$((moved_or_deleted_count + 1))
    json_add_result "$(basename -- "$entry")" "$status" "$kernel_path" "$initrd_path" "$devicetree_path" "${snap_num:-}" "${entry_kver:-}" "MOVE" "missing:${miss_list}"
  fi

done

log ""
log "========================================"
log " Summary"
log "   OK entries:           $ok_count"
log "   Ghost entries:        $ghost_count"
log "   Zombie initrd:        $zombie_initrd_count"
log "   Pinned entries:       $pinned_count"
log "   Protected snapshots:  $protected_count"
log "   Protected kernels:    $protected_kernel_count"
log "   Critical kernels:     $critical_kernel_count"
log "   Stale snapshots:      $stale_snapshot_count"
log "   Uninstalled kernels:  $uninstalled_kernel_count"
if [[ "$unknown_kver_count" -gt 0 ]]; then
  log "   Unknown kver:         $unknown_kver_count (modules check skipped)"
fi
log "   Duplicates found:     $duplicate_found_count"
log "   Duplicates pruned:    $duplicate_pruned_count"
log "   Skipped (malformed):  $skipped_count"
if [[ "$DRY_RUN" == false ]]; then
  log "   Changed:              $moved_or_deleted_count"
  if [[ -n "$SNAPPER_BACKUP_ID" ]]; then
    log "   Snapper backup:       #$SNAPPER_BACKUP_ID"
  fi
  if [[ -n "$BACKUP_DIR" ]]; then
    log "   Backup dir:           $BACKUP_DIR"
  fi
else
  log "   Changed:              0 (dry-run)"
  log ""
  log "To apply safely (move ghosts to backup):"
  log "  sudo bash $0 --force"
  log "To prune stale snapper entries too:"
  log "  sudo bash $0 --force --prune-stale-snapshots"
  log "To prune uninstalled-kernel entries too (extra safety confirm required):"
  log "  sudo bash $0 --force --prune-uninstalled --confirm-uninstalled"
  log "To permanently delete ghosts (and optionally pruned entries):"
  log "  sudo bash $0 --delete [--prune-stale-snapshots] [--prune-uninstalled --confirm-uninstalled]"
fi
log "========================================"

if [[ "$DRY_RUN" == false ]]; then
  post_apply_updates
fi

if [[ "$JSON_OUTPUT" == true ]]; then
  json_emit
fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
  exit $?
fi
