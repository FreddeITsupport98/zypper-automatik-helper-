#!/bin/bash
#
#       VERSION 64 - Dashboard Command Center, diagnostics, and hardened update automation
# This installer deploys the zypper auto-helper stack (downloader + notifier +
# verification/auto-repair tooling), with:
# - a live HTML "Command Center" dashboard (optional)
# - improved diagnostics and support tools
# - safer power/metered-network detection
# - optional enterprise hooks + webhook notifications
#
# MUST be run with sudo or as root.

# --- 1. Strict Mode & Config ---
set -euo pipefail
# Default to a restrictive umask so newly created logs and helper files
# are not world-readable unless we explicitly relax permissions.
umask 077

# Distro guard: only allow running on openSUSE Tumbleweed or Slowroll
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
else
    echo "Cannot detect Linux distribution (missing /etc/os-release). Aborting." >&2
    exit 1
fi

case "${NAME:-}" in
    "openSUSE Tumbleweed"|"openSUSE Slowroll")
        # Supported distributions; continue
        ;;
    *)
        echo "This installer only supports openSUSE Tumbleweed or Slowroll (detected: ${NAME:-unknown}). Aborting." >&2
        exit 1
        ;;
esac

# Fast-path: if invoked as the installed helper (zypper-auto-helper) with an
# unknown option-like first argument (starts with '-'), reject it immediately
# before doing any logging, sanity checks, or installation work. This avoids
# accidental full installs when the user mistypes a flag like '--bre' or
# '-reset'.
if [[ $# -gt 0 ]]; then
    case "${1:-}" in
        install|debug|--help|-h|help|--verify|--repair|--diagnose|--check|--self-check|\
        --soar|--brew|--pip-package|--pipx|--setup-SF|--uninstall-zypper-helper|--uninstall-zypper|\
        --reset-config|--reset-downloads|--reset-state|--rm-conflict|\
        --send-webhook|--webhook|--generate-dashboard|--dashboard|--dash-install|--dash-open|--dash-stop|--dash-api-on|--dash-api-off|--dash-api-status|\
        --logs|--log|--live-logs|--diag-logs-on|--diag-logs-off|\
        --show-logs|--show-loggs|--snapshot-state|--diag-bundle|--diag-logs-runner|--test-notify|--status|\
        --analyze|--health|--debug)
            # Known commands/options; continue into main logic
            :
            ;;
        -*)
            echo "Unknown option: $1"
            echo "Run 'zypper-auto-helper --help' for usage."
            echo ""
            echo "Tip: if you recently updated zypper-auto.sh, your installed command may be outdated."
            echo "Update it by running one of:"
            echo "  - sudo ./zypper-auto.sh install"
            echo "  - sudo zypper-auto-helper install"
            exit 1
            ;;
    esac
fi

# Allow opening the dashboard WITHOUT sudo.
# This improves UX because browser launching is tied to the user's desktop
# session, and running via sudo often loses the GUI environment.
#
# Optional browser override (best-effort):
#   zypper-auto-helper --dash-open firefox
#   ZYPPER_AUTO_DASHBOARD_BROWSER=firefox zypper-auto-helper --dash-open

__znh_port_listen_in_use() {
    # best-effort: return 0 if TCP port appears to have a LISTEN socket
    # Works even when 'ss' is missing.
    local port="$1"

    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":${port}$"
        return $?
    fi

    # Fallback: attempt a fast TCP connect to localhost.
    # - If connect succeeds -> something is listening.
    # - If connection refused / timeout -> assume free.
    if command -v timeout >/dev/null 2>&1; then
        timeout 0.25 bash -lc "</dev/tcp/127.0.0.1/${port}" >/dev/null 2>&1
        return $?
    fi

    # Last resort: try /dev/tcp without timeout (may hang in pathological cases); keep it best-effort.
    # Use ':' as a no-op command so the redirection is attached to something (ShellCheck SC2188).
    : </dev/tcp/127.0.0.1/"${port}" >/dev/null 2>&1
    return $?
}

__znh_pid_is_dashboard_http_server() {
    local pid="$1" dash_dir="$2" port="$3"
    [[ "${pid:-}" =~ ^[0-9]+$ ]] || return 1
    kill -0 "${pid}" 2>/dev/null || return 1
    if command -v ps >/dev/null 2>&1; then
        local args
        args=$(ps -p "${pid}" -o args= 2>/dev/null || true)
        # Verify it's our http.server and pointing at the right directory/port.
        printf '%s' "${args}" | grep -q "python3 -m http.server" || return 1
        # Pattern begins with "--" so terminate grep options explicitly.
        printf '%s' "${args}" | grep -qF -- "--directory ${dash_dir}" || return 1
        printf '%s' "${args}" | grep -q " ${port}\b" || return 1
        return 0
    fi

    # If we cannot inspect the process args (no ps), fail closed.
    # This prevents PID reuse / zombie masquerade causing a false "server running" state.
    return 1
}

__znh_pid_is_dashboard_sync_worker() {
    local pid="$1" dash_dir="$2"
    [[ "${pid:-}" =~ ^[0-9]+$ ]] || return 1
    kill -0 "${pid}" 2>/dev/null || return 1
    if command -v ps >/dev/null 2>&1; then
        local args
        args=$(ps -p "${pid}" -o args= 2>/dev/null || true)
        # We mark the process name via: exec -a znh-dashboard-sync ...
        printf '%s' "${args}" | grep -q "znh-dashboard-sync" || return 1
        printf '%s' "${args}" | grep -q "${dash_dir}" || return 1
        return 0
    fi
    return 1
}

__znh_start_dashboard_sync_worker() {
    # Keep user dashboard files in sync with root-generated artifacts so an open
    # dashboard tab doesn't go stale when root timers run in the background.
    # This runs as the desktop user, reading world-readable files under /var/log.
    local dash_dir="$1" user_name="${2:-}" user_home="${3:-}"
    local pid_file
    pid_file="${dash_dir}/dashboard-sync.pid"

    # If an existing worker is already running, keep it.
    if [ -f "${pid_file}" ]; then
        local old_pid
        old_pid=$(cat "${pid_file}" 2>/dev/null || echo "")
        if __znh_pid_is_dashboard_sync_worker "${old_pid}" "${dash_dir}"; then
            return 0
        fi
        rm -f "${pid_file}" 2>/dev/null || true
    fi

    local run_cmd
    run_cmd=$(cat <<'SYNC'
exec -a znh-dashboard-sync bash -lc '
  dash_dir="$1";
  src_root="/var/log/zypper-auto";

  # Best-effort background priority: idle IO + nice(19).
  # Use -p $$ so we keep the custom argv0 (znh-dashboard-sync) intact.
  if command -v ionice >/dev/null 2>&1; then
    ionice -c3 -p $$ >/dev/null 2>&1 || true
  fi
  if command -v renice >/dev/null 2>&1; then
    renice -n 19 -p $$ >/dev/null 2>&1 || true
  fi

  while true; do
    # Copy updated files if present (best-effort). cp -u is "update if newer".
    cp -u "${src_root}/status-data.json" "${dash_dir}/status-data.json" 2>/dev/null || true
    cp -u "${src_root}/dashboard-install-tail.log" "${dash_dir}/dashboard-install-tail.log" 2>/dev/null || true
    cp -u "${src_root}/dashboard-diag-tail.log" "${dash_dir}/dashboard-diag-tail.log" 2>/dev/null || true
    cp -u "${src_root}/dashboard-journal-tail.log" "${dash_dir}/dashboard-journal-tail.log" 2>/dev/null || true
    cp -u "${src_root}/dashboard-api.log" "${dash_dir}/dashboard-api.log" 2>/dev/null || true
    cp -u "${src_root}/dashboard-verify-tail.log" "${dash_dir}/dashboard-verify-tail.log" 2>/dev/null || true
    # Live mode polls download-status.txt; keep it synced too.
    cp -u "${src_root}/download-status.txt" "${dash_dir}/download-status.txt" 2>/dev/null || true
    # status.html is larger; only update if it changed.
    cp -u "${src_root}/status.html" "${dash_dir}/status.html" 2>/dev/null || true
    sleep 10
  done
' _ "${dash_dir}"
SYNC
)

    # Launch worker detached as the desktop user if known.
    if [ -n "${user_name}" ] && command -v sudo >/dev/null 2>&1; then
        sudo -u "${user_name}" bash -lc "nohup ${run_cmd} >/dev/null 2>&1 & echo \$! >\"${pid_file}\"" || true
    else
        # Fallback: run as current user (non-sudo fast path already runs as desktop user).
        bash -lc "nohup ${run_cmd} >/dev/null 2>&1 & echo \$! >\"${pid_file}\"" || true
    fi

    chmod 600 "${pid_file}" 2>/dev/null || true
    if [ -n "${user_name}" ] && [ -n "${user_home}" ]; then
        chown "${user_name}:${user_name}" "${pid_file}" 2>/dev/null || true
    fi
}

__znh_stop_dashboard_sync_worker() {
    local dash_dir="$1"
    local pid_file
    pid_file="${dash_dir}/dashboard-sync.pid"
    if [ ! -f "${pid_file}" ]; then
        return 0
    fi
    local pid
    pid=$(cat "${pid_file}" 2>/dev/null || echo "")
    if __znh_pid_is_dashboard_sync_worker "${pid}" "${dash_dir}"; then
        kill "${pid}" 2>/dev/null || true
        sleep 0.1
        kill -9 "${pid}" 2>/dev/null || true
    fi
    rm -f "${pid_file}" 2>/dev/null || true
}

__znh_pid_is_dashboard_perf_worker() {
    local pid="$1" dash_dir="$2"
    [[ "${pid:-}" =~ ^[0-9]+$ ]] || return 1
    kill -0 "${pid}" 2>/dev/null || return 1
    if command -v ps >/dev/null 2>&1; then
        local args
        args=$(ps -p "${pid}" -o args= 2>/dev/null || true)
        # We mark the process name via: exec -a znh-dashboard-perf ...
        printf '%s' "${args}" | grep -q "znh-dashboard-perf" || return 1
        # Ensure it's writing into the correct dashboard directory.
        # Pattern begins with "--" so terminate grep options explicitly.
        printf '%s' "${args}" | grep -qF -- "--out-dir ${dash_dir}" || return 1
        return 0
    fi
    return 1
}

__znh_start_dashboard_perf_worker() {
    # Writes perf-data.json into the served dashboard directory so the HTML can
    # plot live CPU/memory/IO usage for helper-related services.
    # Runs as the desktop user.
    local dash_dir="$1" user_name="${2:-}" user_home="${3:-}"
    local pid_file
    pid_file="${dash_dir}/dashboard-perf.pid"

    local worker_bin
    worker_bin="/usr/local/bin/zypper-auto-dashboard-perf-worker"

    # If binary missing, skip silently.
    if [ ! -x "${worker_bin}" ]; then
        return 0
    fi

    # If python3 missing, skip silently (dash-open already requires python3 for http.server).
    if ! command -v python3 >/dev/null 2>&1; then
        return 0
    fi

    # If an existing worker is already running, keep it.
    if [ -f "${pid_file}" ]; then
        local old_pid
        old_pid=$(cat "${pid_file}" 2>/dev/null || echo "")
        if __znh_pid_is_dashboard_perf_worker "${old_pid}" "${dash_dir}"; then
            return 0
        fi
        rm -f "${pid_file}" 2>/dev/null || true
    fi

    local units
    units="zypper-autodownload.service,zypper-auto-verify.service,zypper-auto-dashboard-api.service"

    # Launch worker detached as the desktop user if known.
    if [ -n "${user_name}" ] && command -v sudo >/dev/null 2>&1; then
        sudo -u "${user_name}" bash -lc "nohup bash -lc 'if command -v ionice >/dev/null 2>&1; then ionice -c3 -p \$\$ >/dev/null 2>&1 || true; fi; if command -v renice >/dev/null 2>&1; then renice -n 19 -p \$\$ >/dev/null 2>&1 || true; fi; exec -a znh-dashboard-perf \"\$@\"' _ ${worker_bin} --out-dir \"${dash_dir}\" --interval 2 --max-samples 180 --units \"${units}\" >/dev/null 2>&1 & echo \$! >\"${pid_file}\"" || true
    else
        # Fallback: run as current user.
        nohup bash -lc 'if command -v ionice >/dev/null 2>&1; then ionice -c3 -p $$ >/dev/null 2>&1 || true; fi; if command -v renice >/dev/null 2>&1; then renice -n 19 -p $$ >/dev/null 2>&1 || true; fi; exec -a znh-dashboard-perf "$@"' _ "${worker_bin}" --out-dir "${dash_dir}" --interval 2 --max-samples 180 --units "${units}" >/dev/null 2>&1 &
        echo $! >"${pid_file}" 2>/dev/null || true
    fi

    chmod 600 "${pid_file}" 2>/dev/null || true
    if [ -n "${user_name}" ] && [ -n "${user_home}" ]; then
        chown "${user_name}:${user_name}" "${pid_file}" 2>/dev/null || true
    fi
}

__znh_stop_dashboard_perf_worker() {
    local dash_dir="$1"
    local pid_file
    pid_file="${dash_dir}/dashboard-perf.pid"
    if [ ! -f "${pid_file}" ]; then
        return 0
    fi
    local pid
    pid=$(cat "${pid_file}" 2>/dev/null || echo "")
    if __znh_pid_is_dashboard_perf_worker "${pid}" "${dash_dir}"; then
        kill "${pid}" 2>/dev/null || true
        sleep 0.1
        kill -9 "${pid}" 2>/dev/null || true
    fi
    rm -f "${pid_file}" 2>/dev/null || true
}

__znh_install_polkit_policy() {
    # Installs a Polkit policy so 'pkexec' shows a trusted, human-friendly UI
    # instead of a generic "run /usr/local/bin/..." prompt.
    #
    # This is best-effort and non-fatal: older systems may not run polkit as a
    # systemd unit, and some environments cache actions.
    local policy_file
    policy_file="/usr/share/polkit-1/actions/org.opensuse.zypper-auto.policy"

    log_debug "Installing Polkit policy to ${policy_file}..."

    mkdir -p "$(dirname "${policy_file}")" 2>/dev/null || true

    if ! write_atomic "${policy_file}" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
 "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>Zypper Auto Helper</vendor>
  <vendor_url>https://github.com</vendor_url>
  <icon_name>yast-restore</icon_name>

  <action id="org.opensuse.zypper-auto.verify">
    <description>Run System Verification and Repair</description>
    <description xml:lang="de">Systemprüfung und Reparatur ausführen</description>
    <description xml:lang="fr">Exécuter la vérification et la réparation du système</description>
    <description xml:lang="es">Ejecutar verificación y reparación del sistema</description>

    <message>Authentication is required to run the Zypper Auto system repair tool</message>
    <message xml:lang="de">Authentifizierung ist erforderlich, um das Systemreparatur-Tool auszuführen</message>
    <message xml:lang="fr">Une authentification est requise pour lancer l'outil de réparation</message>
    <message xml:lang="es">Se requiere autenticación para ejecutar la herramienta de reparación</message>

    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin</allow_active>
    </defaults>

    <annotate key="org.freedesktop.policykit.exec.path">/usr/local/bin/zypper-auto-helper</annotate>
  </action>
</policyconfig>
EOF
    then
        log_warn "Failed to write Polkit policy file: ${policy_file}"
        return 1
    fi

    chmod 644 "${policy_file}" 2>/dev/null || true

    # Best-effort reload so the new action shows up immediately.
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet polkit.service 2>/dev/null; then
            systemctl reload polkit.service 2>/dev/null || true
        elif systemctl is-active --quiet polkit 2>/dev/null; then
            systemctl reload polkit 2>/dev/null || true
        fi
    fi

    return 0
}

__znh_pick_free_port() {
    # Pick the first free port in a range. Echo the port, or empty on failure.
    local start="$1" end="$2" p
    for p in $(seq "${start}" "${end}"); do
        if ! __znh_port_listen_in_use "${p}"; then
            echo "${p}"
            return 0
        fi
    done
    return 1
}

__znh_detach_cmd() {
    # Run a command fully detached (best-effort) so closing the terminal doesn't kill it.
    # Usage: __znh_detach_cmd cmd arg1 arg2 ...
    if command -v setsid >/dev/null 2>&1; then
        # setsid detaches from controlling terminal; nohup guards against SIGHUP.
        nohup setsid "$@" >/dev/null 2>&1 &
    else
        nohup "$@" >/dev/null 2>&1 &
    fi
}

__znh_browser_extra_args() {
    # Print extra args for known browsers to avoid profile-lock oddities and
    # make launches more deterministic.
    # Usage: __znh_browser_extra_args <browser>
    local b
    b="$(basename "${1:-}")"
    case "${b}" in
        firefox|firefox-esr)
            printf '%s\n' "--new-window"
            ;;
        google-chrome|google-chrome-stable|chromium|chromium-browser|brave|brave-browser|vivaldi|microsoft-edge)
            printf '%s\n' "--new-window"
            ;;
        *)
            return 0
            ;;
    esac
}

__znh_detach_open_url() {
    # Usage: __znh_detach_open_url <url> [browser]
    local url="$1" browser="${2:-}"
    if [ -n "${browser}" ] && command -v "${browser}" >/dev/null 2>&1; then
        # shellcheck disable=SC2207
        local extra=( $(__znh_browser_extra_args "${browser}" 2>/dev/null || true) )
        __znh_detach_cmd "${browser}" "${extra[@]}" "${url}"
        return 0
    fi
    if command -v xdg-open >/dev/null 2>&1; then
        __znh_detach_cmd xdg-open "${url}"
        return 0
    fi
    return 1
}

__znh_ensure_dash_desktop_shortcut() {
    # UX Polish Version: Adds visual feedback (Notifications) and "Press Enter" delays.
    # Usage: __znh_ensure_dash_desktop_shortcut <user> <home>
    local u="$1" h="$2"
    [ -n "${u:-}" ] || return 0
    [ -n "${h:-}" ] || return 0

    local apps_dir desktop_file
    apps_dir="${h}/.local/share/applications"
    desktop_file="${apps_dir}/zypper-auto-dashboard.desktop"

    # Helpers
    local helper_bin
    helper_bin="/usr/local/bin/zypper-auto-helper"

    # Icon logic (same as before)
    local icon_name
    icon_name="system-software-update"
    if [ -e /usr/share/icons/hicolor/scalable/apps/yast-update.svg ] || \
       [ -e /usr/share/icons/hicolor/48x48/apps/yast-update.png ]; then
        icon_name="yast-update"
    elif [ -e /usr/share/icons/hicolor/scalable/apps/yast-software.svg ]; then
        icon_name="yast-software"
    fi

    # --- UX COMMAND STRINGS ---
    # 1) Install: run, then wait for user input so the window doesn't vanish.
    local cmd_install
    cmd_install="sh -lc \"\\\"\\\${HOME}/.local/bin/zypper-run-install\\\"; echo; echo 'Press Enter to close...'; read line\""

    # 2) CheckNow: show a notification (if available), then wake the notifier.
    local cmd_check
    cmd_check="sh -lc \"command -v notify-send >/dev/null 2>&1 && notify-send 'Zypper Auto' 'Checking for updates...' -i view-refresh; systemctl --user start zypper-notify-user.service >/dev/null 2>&1 || true\""

    # 3) Health report: run via the install helper (nice terminal UX) and wait.
    local cmd_health
    cmd_health="sh -lc \"\\\"\\\${HOME}/.local/bin/zypper-run-install\\\" --inner --health; echo; echo 'Press Enter to close...'; read line\""

    # Define the Desktop Entry with Translations and Maintenance Actions.
    local expected
    expected=$(cat <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=Zypper Auto Dashboard
Name[de]=Zypper Auto Dashboard
Name[fr]=Tableau de bord Zypper
Name[es]=Panel de Zypper Auto
GenericName=System Update Center
GenericName[de]=Systemaktualisierung
GenericName[fr]=Centre de mise à jour
GenericName[es]=Centro de actualizaciones
Comment=View update status, logs, and manage system maintenance
Comment[de]=Update-Status anzeigen und Systemwartung verwalten
Comment[fr]=Voir l'état des mises à jour et gérer la maintenance
Comment[es]=Ver estado de actualizaciones y mantenimiento
Exec=${helper_bin} --dash-open
Terminal=false
Icon=${icon_name}
Categories=System;Utility;Monitor;GTK;Qt;
Keywords=Update;Upgrade;Check;Maintenance;Suse;Snapshot;Repair;Health;
StartupNotify=true
X-GNOME-UsesNotifications=true
Actions=Install;CheckNow;Verify;Health;StopServer;UserLogs;

[Desktop Action Install]
Name=Install Updates (Interactive)
Name[de]=Updates installieren (Interaktiv)
Name[fr]=Installer les mises à jour
Name[es]=Instalar actualizaciones
Exec=${cmd_install}
Icon=system-software-install

[Desktop Action CheckNow]
Name=Check for Updates Now
Name[de]=Jetzt nach Updates suchen
Name[fr]=Vérifier les mises à jour
Name[es]=Buscar actualizaciones ahora
Exec=${cmd_check}
Icon=view-refresh

[Desktop Action Verify]
Name=Run Auto-Repair (Root)
Name[de]=Auto-Reparatur starten (Root)
Name[fr]=Lancer l'auto-réparation (Root)
Name[es]=Ejecutar auto-reparación (Root)
Exec=pkexec ${helper_bin} --verify
Icon=yast-restore

[Desktop Action Health]
Name=Generate Health Report
Name[de]=Gesundheitsbericht erstellen
Name[fr]=Rapport de santé
Name[es]=Informe de salud
Exec=${cmd_health}
Icon=yast-hardware-group

[Desktop Action StopServer]
Name=Stop Dashboard Server
Name[de]=Dashboard-Server stoppen
Name[fr]=Arrêter le serveur
Name[es]=Detener servidor
Exec=${helper_bin} --dash-stop
Icon=process-stop

[Desktop Action UserLogs]
Name=Open Log Folder
Name[de]=Log-Ordner öffnen
Name[fr]=Ouvrir les journaux
Name[es]=Abrir registros
Exec=sh -lc "xdg-open \"\${HOME}/.local/share/zypper-notify\""
Icon=folder-open
EOF
)

    # Smart Update: upgrade if missing OR if it lacks our new wait/feedback logic.
    local need=0
    if [ ! -f "${desktop_file}" ]; then
        need=1
    else
        if ! grep -qF "read line" "${desktop_file}" 2>/dev/null; then
            need=1
        fi
        # Or if the icon is generic but a better one exists
        if [ "${icon_name}" != "system-software-update" ] && grep -qF "Icon=system-software-update" "${desktop_file}" 2>/dev/null; then
            need=1
        fi
    fi

    if [ "${need}" -eq 1 ] 2>/dev/null; then
        mkdir -p "${apps_dir}" 2>/dev/null || true
        printf '%s\n' "${expected}" >"${desktop_file}" 2>/dev/null || true
        chmod 644 "${desktop_file}" 2>/dev/null || true
        chown "${u}:${u}" "${desktop_file}" 2>/dev/null || true

        # Validate to ensure it appears in strict menus (GNOME/KDE)
        if command -v desktop-file-validate >/dev/null 2>&1; then
            desktop-file-validate "${desktop_file}" >/dev/null 2>&1 || true
        fi

        # Refresh desktop database so it appears in search immediately
        if command -v update-desktop-database >/dev/null 2>&1; then
            update-desktop-database "${apps_dir}" >/dev/null 2>&1 || true
        fi
    fi

    # Handle the Desktop Surface shortcut (Copy if changed)
    local desk_dir
    desk_dir=""
    if command -v xdg-user-dir >/dev/null 2>&1; then
        desk_dir=$(sudo -u "${u}" XDG_CONFIG_HOME="${h}/.config" XDG_DATA_HOME="${h}/.local/share" xdg-user-dir DESKTOP 2>/dev/null || true)
    fi
    if [ -z "${desk_dir:-}" ]; then
        desk_dir="${h}/Desktop"
    fi

    if [ -n "${desk_dir:-}" ] && [ -d "${desk_dir}" ]; then
        local desktop_copy
        desktop_copy="${desk_dir}/Zypper Auto Dashboard.desktop"

        # Copy if missing OR if we just updated the master copy
        if [ ! -f "${desktop_copy}" ] || [ "${need}" -eq 1 ] 2>/dev/null; then
            cp -f "${desktop_file}" "${desktop_copy}" 2>/dev/null || true
            chmod 755 "${desktop_copy}" 2>/dev/null || true
            chown "${u}:${u}" "${desktop_copy}" 2>/dev/null || true
        fi
    fi
}

if [[ "${1:-}" == "--dash-stop" ]] && [ "${EUID}" -ne 0 ] 2>/dev/null; then
    dash_dir="$HOME/.local/share/zypper-notify"

    # Stop sync worker first (best-effort)
    __znh_stop_dashboard_sync_worker "${dash_dir}" || true
    # Stop perf worker (best-effort)
    __znh_stop_dashboard_perf_worker "${dash_dir}" || true

    pid_file="${dash_dir}/dashboard-http.pid"
    port_file="${dash_dir}/dashboard-http.port"

    if [ -f "${pid_file}" ] && [ -f "${port_file}" ]; then
        old_pid=$(cat "${pid_file}" 2>/dev/null || echo "")
        old_port=$(cat "${port_file}" 2>/dev/null || echo "")
        if [[ "${old_port:-}" =~ ^[0-9]+$ ]] && __znh_pid_is_dashboard_http_server "${old_pid}" "${dash_dir}" "${old_port}"; then
            kill "${old_pid}" 2>/dev/null || true
            sleep 0.1
            if kill -0 "${old_pid}" 2>/dev/null; then
                kill -9 "${old_pid}" 2>/dev/null || true
            fi
            echo "Stopped dashboard server (pid=${old_pid})."
        else
            echo "Dashboard server not running or PID could not be validated (stale pid file: ${pid_file})."
        fi
        rm -f "${pid_file}" "${port_file}" 2>/dev/null || true
    else
        echo "No dashboard server pid/port files found under ${dash_dir}."
    fi

    exit 0
fi

if [[ "${1:-}" == "--dash-open" ]] && [ "${EUID}" -ne 0 ] 2>/dev/null; then
    dash_dir="$HOME/.local/share/zypper-notify"
    dash_path="${dash_dir}/status.html"
    dash_browser="${2:-${ZYPPER_AUTO_DASHBOARD_BROWSER:-${DASHBOARD_BROWSER:-}}}"

    if [ ! -f "${dash_path}" ]; then
        echo "Dashboard file not found yet: ${dash_path}" >&2
        if command -v sudo >/dev/null 2>&1 && [ -x /usr/local/bin/zypper-auto-helper ]; then
            echo "Generating dashboard now (sudo zypper-auto-helper --dashboard)..." >&2
            sudo /usr/local/bin/zypper-auto-helper --dashboard >/dev/null 2>&1 || true
        fi
    fi

    if [ -f "${dash_path}" ]; then
        echo "Dashboard path: ${dash_path}"

        if [ -n "${dash_browser:-}" ]; then
            echo "Browser override: ${dash_browser}"
        fi

        # Live dashboard: serve the user dashboard dir over a local HTTP server.
        # This avoids browser restrictions around fetch() on file:// URLs and
        # enables realtime polling (status-data.json, download-status.txt, dashboard-live.log).
        #
        # Safeguards:
        # - detect port conflicts (pid file is not enough)
        # - capture server startup errors into a log file
        # - verify the server is actually responding before opening browser
        port=8765
        pid_file="${dash_dir}/dashboard-http.pid"
        port_file="${dash_dir}/dashboard-http.port"
        err_file="${dash_dir}/dashboard-http.err"

        reuse_existing_server=0

        # If a previous server is already running, reuse its port.
        if [ -f "${pid_file}" ] && [ -f "${port_file}" ]; then
            old_pid=$(cat "${pid_file}" 2>/dev/null || echo "")
            old_port=$(cat "${port_file}" 2>/dev/null || echo "")
            if [[ "${old_port:-}" =~ ^[0-9]+$ ]] && __znh_pid_is_dashboard_http_server "${old_pid}" "${dash_dir}" "${old_port}"; then
                port="${old_port}"
                reuse_existing_server=1
            fi
        fi

        # If requested/default port is busy, pick a nearby free port.
        # IMPORTANT: if the port is in use by *our own validated* server, keep it.
        if __znh_port_listen_in_use "${port}" && [ "${reuse_existing_server}" -ne 1 ] 2>/dev/null; then
            port_pick="$(__znh_pick_free_port 8765 8790 2>/dev/null || true)"
            if [[ "${port_pick:-}" =~ ^[0-9]+$ ]]; then
                port="${port_pick}"
            fi
        fi

        url="http://127.0.0.1:${port}/status.html?live=1"

        mkdir -p "${dash_dir}" 2>/dev/null || true

        # Best-effort: auto-refresh the dashboard if the helper command changed.
        # This is how we "apply new changes" for users who just updated the helper
        # but haven't re-generated status.html yet.
        #
        # Controls:
        #   ZNH_DASH_OPEN_NO_REFRESH=1      -> disable auto-refresh
        #   ZNH_DASH_OPEN_FORCE_REFRESH=1   -> always refresh (even if timestamps match)
        if [ "${ZNH_DASH_OPEN_NO_REFRESH:-0}" -ne 1 ] 2>/dev/null \
            && command -v sudo >/dev/null 2>&1 \
            && [ -x /usr/local/bin/zypper-auto-helper ]; then

            helper_mtime=$(stat -c %Y /usr/local/bin/zypper-auto-helper 2>/dev/null || echo 0)
            dash_mtime=$(stat -c %Y "${dash_path}" 2>/dev/null || echo 0)

            if [ "${ZNH_DASH_OPEN_FORCE_REFRESH:-0}" -eq 1 ] 2>/dev/null \
                || [ "${helper_mtime:-0}" -gt "${dash_mtime:-0}" ] 2>/dev/null; then
                echo "Dashboard appears outdated; refreshing first (sudo zypper-auto-helper --dashboard)..." >&2
                sudo /usr/local/bin/zypper-auto-helper --dashboard >/dev/null 2>&1 || true
            fi
        fi

        # Dashboard Settings API (localhost)
        # The Settings drawer in the dashboard talks to a root-only API on:
        #   http://127.0.0.1:8766
        # Auth is done via a random token stored in the dashboard directory.
        #
        # Token safety: only update dashboard-token.txt after the root API has
        # successfully restarted with that token (prevents token desync).
        token_file="${dash_dir}/dashboard-token.txt"
        old_token=""
        if [ -f "${token_file}" ]; then
            old_token=$(cat "${token_file}" 2>/dev/null || echo "")
        fi

        new_token=""
        if command -v python3 >/dev/null 2>&1; then
            new_token=$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(24))
PY
)
        else
            new_token="$(date +%s%N)"
        fi

        api_ok=0
        if command -v sudo >/dev/null 2>&1 && [ -x /usr/local/bin/zypper-auto-helper ]; then
            if sudo /usr/local/bin/zypper-auto-helper --dash-api-on "${new_token}" >/dev/null 2>&1; then
                api_ok=1
            fi
        fi

        if [ "${api_ok}" -eq 1 ] 2>/dev/null; then
            printf '%s' "${new_token}" >"${token_file}" 2>/dev/null || true
            chmod 600 "${token_file}" 2>/dev/null || true
        else
            # Keep the existing token file untouched on failure.
            # (If there wasn't one, Settings will remain unavailable until API starts.)
            if [ -n "${old_token}" ]; then
                chmod 600 "${token_file}" 2>/dev/null || true
            fi
        fi

        server_running=0
        if [ -f "${pid_file}" ] && [ -f "${port_file}" ]; then
            old_pid=$(cat "${pid_file}" 2>/dev/null || echo "")
            old_port=$(cat "${port_file}" 2>/dev/null || echo "")
            if [[ "${old_port:-}" =~ ^[0-9]+$ ]] && __znh_pid_is_dashboard_http_server "${old_pid}" "${dash_dir}" "${old_port}"; then
                server_running=1
            fi
        fi

        if [ "${server_running}" -ne 1 ] 2>/dev/null; then
            # Start server in the background; capture stderr so startup failures aren't silent.
            if command -v python3 >/dev/null 2>&1; then
                rm -f "${err_file}" 2>/dev/null || true
                # Bind explicitly to localhost (privacy/safety) and detach so the server survives terminal close.
                # Run the server at background priority (nice + idle IO) so it never contends with foreground apps.
                # shellcheck disable=SC2016  # $$ is expanded by the nested bash -lc, not by this outer script
                ( nohup bash -lc 'if command -v ionice >/dev/null 2>&1; then ionice -c3 -p $$ >/dev/null 2>&1 || true; fi; if command -v renice >/dev/null 2>&1; then renice -n 19 -p $$ >/dev/null 2>&1 || true; fi; exec python3 -m http.server --bind 127.0.0.1 --directory "$1" "$2"' _ "${dash_dir}" "${port}" >>"${err_file}" 2>&1 & echo $! >"${pid_file}"; echo "${port}" >"${port_file}" ) || true
                sleep 0.25
            else
                echo "python3 not found; cannot start live dashboard server." >&2
                echo "Install it with: sudo zypper install python3" >&2
            fi
        fi

        # Verify server is listening before opening browser (best-effort)
        # Use a short retry loop so we don't emit a scary warning when the server
        # is still starting up.
        ok=0
        for _i in $(seq 1 50); do
            if __znh_port_listen_in_use "${port}"; then
                ok=1
                break
            fi
            sleep 0.1
        done

        if [ "${ok}" -ne 1 ] 2>/dev/null; then
            echo "WARNING: dashboard server did not respond on port ${port}." >&2
            if [ -s "${err_file}" ]; then
                echo "--- dashboard server error (last 20 lines):" >&2
                tail -n 20 "${err_file}" >&2 || true
            else
                echo "(no server error output captured)" >&2
            fi
        fi

        # Start sync worker so status-data.json/log views keep updating even if
        # this dashboard tab stays open for days.
        __znh_start_dashboard_sync_worker "${dash_dir}" "${USER:-}" "${HOME:-}" || true
        # Start perf worker for live service performance charts (best-effort)
        __znh_start_dashboard_perf_worker "${dash_dir}" "${USER:-}" "${HOME:-}" || true

        # Ensure Desktop/app launcher exists (best-effort)
        __znh_ensure_dash_desktop_shortcut "${USER:-}" "${HOME:-}" || true

        echo "Open live dashboard: ${url}"

        # Best-effort open.
        # Prefer explicit browser when requested; fall back to xdg-open.
        # Detach so closing the terminal does not kill the browser/tab.
        __znh_detach_open_url "${url}" "${dash_browser:-}" || true

        echo ""
        echo "To refresh/regenerate first (requires sudo):"
        echo "  sudo zypper-auto-helper --dashboard"
        exit 0
    else
        echo "Dashboard file not found yet: ${dash_path}" >&2
        echo "Generate it with: sudo zypper-auto-helper --dashboard" >&2
        exit 1
    fi
fi

# --- Logging / Configuration Defaults ---
LOG_DIR="/var/log/zypper-auto"
LOG_FILE="${LOG_DIR}/install-$(date +%Y%m%d-%H%M%S).log"
STATUS_FILE="${LOG_DIR}/last-status.txt"
MAX_LOG_FILES=10  # Keep only the last 10 log files (overridable via /etc/zypper-auto.conf)
MAX_LOG_SIZE_MB=50  # Maximum size for a single log file in MB (overridable)

# Safety/observability state (used by EXIT trap + verification wrappers)
ZNH_LOG_CLEANUP_DONE=0
FLIGHT_REPORT_ENABLED=0
FLIGHT_REPORT_PRINTED=0
REPAIR_SAFETY_PRE_SNAP_ID=""
REPAIR_SAFETY_POST_SNAP_ID=""
REPAIR_SAFETY_SNAPSHOT_FINALIZED=0

# Accumulator for any configuration warnings so we can surface them
# once at the end of installation.
CONFIG_WARNINGS=()

# Timer intervals (in minutes) for downloader and notifier (1,5,10,15,30,60)
DL_TIMER_INTERVAL_MINUTES=1
NT_TIMER_INTERVAL_MINUTES=1

# Global config file (optional but recommended for advanced users)
CONFIG_FILE="/etc/zypper-auto.conf"

# Feature toggles (may be overridden by CONFIG_FILE)
ENABLE_FLATPAK_UPDATES="true"
ENABLE_SNAP_UPDATES="true"
ENABLE_SOAR_UPDATES="true"
ENABLE_BREW_UPDATES="true"
ENABLE_PIPX_UPDATES="true"  # new: pipx-based Python CLI updates

# Extensibility / remote monitoring (may be overridden by CONFIG_FILE)
WEBHOOK_URL=""            # Remote monitoring endpoint (Discord/Slack/ntfy/etc.)
HOOKS_ENABLED="true"      # Enable /etc/zypper-auto/hooks/{pre,post}.d
DASHBOARD_ENABLED="true"  # Generate an HTML status page after key operations
DASHBOARD_BROWSER=""      # Optional browser override for --dash-open (e.g. firefox)
HOOKS_BASE_DIR="/etc/zypper-auto/hooks"

# Notifier cache / snooze defaults (also overridable via CONFIG_FILE)
CACHE_EXPIRY_MINUTES="10"
SNOOZE_SHORT_HOURS="1"   # used by the "1h" snooze button
SNOOZE_MEDIUM_HOURS="4"  # used by the "4h" snooze button
SNOOZE_LONG_HOURS="24"   # used by the "1d" snooze button
# Suppress duplicate "Updates Ready" popups while an interactive install is running.
# Config key: INSTALL_CLICK_SUPPRESS_MINUTES (default 120; 0 disables)

# Create log directory
mkdir -p "${LOG_DIR}"
# Root log directory is readable by root and group only; individual
# files may have their own tighter permissions (e.g. 600).
chmod 750 "${LOG_DIR}"

# Dedicated trace log used for high-volume shell tracing and very
# fine-grained events. This is appended to across runs so the
# diagnostics follower and bundles can reconstruct longer histories.
TRACE_LOG="${LOG_DIR}/trace.log"
# Best-effort creation with safe permissions; failures are non-fatal
# and will only disable trace-specific features.
if [ ! -e "${TRACE_LOG}" ]; then
    touch "${TRACE_LOG}" 2>/dev/null || true
    chmod 640 "${TRACE_LOG}" 2>/dev/null || true
fi

# Cleanup old log files with compression and rotation
cleanup_old_logs() {
    # Allow calling cleanup multiple times (e.g., early in main flow and
    # again later during install) without doing duplicate work.
    if [ "${ZNH_LOG_CLEANUP_DONE:-0}" -eq 1 ] 2>/dev/null; then
        return 0
    fi
    ZNH_LOG_CLEANUP_DONE=1

    log_debug "Cleaning up old log files in ${LOG_DIR}..."

    # 1. Compress installer logs older than 1 day (keep very recent logs raw
    # for easy tailing). Skip files already compressed.
    find "${LOG_DIR}" -name "install-*.log" -type f -mtime +1 ! -name "*.gz" \
        -exec gzip {} \; 2>/dev/null || true

    # 2. Delete compressed installer logs older than 30 days to bound disk use
    # while still keeping extended history.
    find "${LOG_DIR}" -name "install-*.log.gz" -type f -mtime +30 -delete 2>/dev/null || true

    # 3. Keep only the last MAX_LOG_FILES *uncompressed* install logs so that
    # the most recent sessions remain easy to browse without decompressing.
    local log_paths=() log_count trim_n i old_log
    # Gather the list once (oldest -> newest) so we don't scan the directory twice.
    mapfile -t log_paths < <(
        find "${LOG_DIR}" -maxdepth 1 -name "install-*.log" -type f -printf '%T@ %p\n' 2>/dev/null | \
            sort -n | awk '{sub(/^[^ ]+ /, "", $0); print $0}' 2>/dev/null || true
    )
    log_count=${#log_paths[@]}
    if [ "${log_count}" -gt "${MAX_LOG_FILES}" ] 2>/dev/null; then
        trim_n=$((log_count - MAX_LOG_FILES))
        log_info "Found ${log_count} uncompressed install logs; trimming to last ${MAX_LOG_FILES}"
        for ((i = 0; i < trim_n; i++)); do
            old_log="${log_paths[$i]}"
            [ -n "${old_log}" ] || continue
            log_debug "Removing old uncompressed log: ${old_log}"
            rm -f "${old_log}" 2>/dev/null || true
        done
    else
        log_debug "Uncompressed install log count (${log_count}) is within limit (${MAX_LOG_FILES})"
    fi

    # 4. Rotate large service logs: rename with timestamp, gzip immediately,
    # and create a fresh empty log file.
    if [ -d "${LOG_DIR}/service-logs" ]; then
        find "${LOG_DIR}/service-logs" -name "*.log" -type f -size +"${MAX_LOG_SIZE_MB}M" | \
            while read -r large_log; do
                log_info "Rotating large log file: ${large_log}"
                local rotated
                rotated="${large_log}.$(date +%Y%m%d-%H%M%S)"
                mv "${large_log}" "${rotated}" 2>/dev/null || continue
                gzip "${rotated}" 2>/dev/null || true
                touch "${large_log}" 2>/dev/null || true
            done

        # Delete rotated/compressed service logs older than 30 days to avoid
        # unbounded growth on long-lived systems.
        find "${LOG_DIR}/service-logs" -name "*.gz" -type f -mtime +30 -delete 2>/dev/null || true
    fi

    # 5. TRACE_LOG can grow indefinitely across runs (by design). Apply the
    # same size-based rotation as service logs, and clean up old rotations.
    local trace_limit_mb trace_limit_bytes trace_size_bytes
    trace_limit_mb="${MAX_LOG_SIZE_MB:-50}"
    if ! [[ "${trace_limit_mb}" =~ ^[0-9]+$ ]]; then
        trace_limit_mb=50
    fi
    trace_limit_bytes=$((trace_limit_mb * 1024 * 1024))

    if [ -n "${TRACE_LOG:-}" ] && [ -f "${TRACE_LOG}" ]; then
        trace_size_bytes=$(stat -c %s "${TRACE_LOG}" 2>/dev/null || echo 0)
        if [[ "${trace_size_bytes:-0}" =~ ^[0-9]+$ ]] && [ "${trace_size_bytes}" -gt "${trace_limit_bytes}" ] 2>/dev/null; then
            local rotated
            rotated="${TRACE_LOG}.$(date +%Y%m%d-%H%M%S)"
            log_info "Rotating large trace log: ${TRACE_LOG} (${trace_size_bytes} bytes)"
            mv "${TRACE_LOG}" "${rotated}" 2>/dev/null || true
            gzip "${rotated}" 2>/dev/null || true
            touch "${TRACE_LOG}" 2>/dev/null || true
            chmod 640 "${TRACE_LOG}" 2>/dev/null || true
        fi

        # Cleanup old trace rotations (>30 days)
        find "${LOG_DIR}" -maxdepth 1 -name "trace.log.*.gz" -type f -mtime +30 -delete 2>/dev/null || true
    fi

    # 6. Optional history file maintenance (if present).
    # Keep last 50 lines to prevent infinite growth.
    local history_file
    history_file="${LOG_DIR}/history.txt"
    if [ -f "${history_file}" ]; then
        local tmp
        tmp="$(mktemp)"
        tail -n 50 "${history_file}" >"${tmp}" 2>/dev/null || true
        if [ -s "${tmp}" ] 2>/dev/null; then
            mv -f "${tmp}" "${history_file}" 2>/dev/null || rm -f "${tmp}" 2>/dev/null || true
        else
            rm -f "${tmp}" 2>/dev/null || true
        fi
    fi

    log_success "Log rotation and compression completed"
}

# Initialize log file
echo "==============================================" | tee "${LOG_FILE}"
echo "Zypper Auto-Helper Installation Log" | tee -a "${LOG_FILE}"
echo "Started: $(date)" | tee -a "${LOG_FILE}"
echo "Log file: ${LOG_FILE}" | tee -a "${LOG_FILE}"
echo "==============================================" | tee -a "${LOG_FILE}"
echo "" | tee -a "${LOG_FILE}"

# Logging / debug configuration
# Global debug flag, can be enabled via --debug on the CLI or via
# the ZYPPER_AUTO_DEBUG_LEVEL environment variable.
DEBUG_MODE=${DEBUG_MODE:-0}

# Optional structured debug level via environment. When ZYPPER_AUTO_DEBUG_LEVEL is
# set to "debug" or "trace", we automatically enable DEBUG_MODE so that
# log_debug output is recorded even without the --debug CLI flag.
DEBUG_LEVEL="${ZYPPER_AUTO_DEBUG_LEVEL:-info}"
case "${DEBUG_LEVEL}" in
    debug|trace)
        DEBUG_MODE=1
        ;;
    *)
        :
        ;;
esac

# Per-invocation run identifier used to correlate all log lines from this
# helper invocation in diagnostics logs.
RUN_ID="R$(date +%Y%m%dT%H%M%S)-$$"

# --- Console formatting & journal integration (plain log files) ---
# We keep LOG_FILE / TRACE_LOG free of ANSI escape codes, but optionally print
# colored output to the console when running interactively.
LOG_TO_CONSOLE=0
if [ -t 1 ] || [ -t 2 ]; then
    LOG_TO_CONSOLE=1
fi
# Allow forcing console logs even when not attached to a TTY
if [ -n "${ZYPPER_AUTO_CONSOLE_LOG:-}" ]; then
    LOG_TO_CONSOLE="${ZYPPER_AUTO_CONSOLE_LOG}"
fi

# ANSI Colors (console only)
C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'
C_CYAN='\033[0;36m'

USE_COLOR=0
if [ "${LOG_TO_CONSOLE}" -eq 1 ] 2>/dev/null && [ -z "${NO_COLOR:-}" ]; then
    USE_COLOR=1
fi

# Enable best-effort journald/syslog logging via `logger`.
# Set ZYPPER_AUTO_JOURNAL_LOGGING=0 to disable.
JOURNAL_LOGGING_ENABLED=1
if [ "${ZYPPER_AUTO_JOURNAL_LOGGING:-1}" = "0" ]; then
    JOURNAL_LOGGING_ENABLED=0
fi

# Millisecond timestamp helper for structured log lines.
_log_ts() {
    date '+%Y-%m-%d %H:%M:%S.%3N'
}

# Core formatter: write a single structured log line to LOG_FILE.
# Optionally mirror to TRACE_LOG, the system journal (logger), and the console.
_log_write() {
    local level="$1"; shift
    local ts msg
    ts="$(_log_ts)"
    msg="$*"

    local trace_tag=""
    # If ZYPPER_TRACE_ID is set (for example by the GUI notifier when the
    # user clicks "Install"), include it so we can correlate frontend
    # actions to backend work across all logs.
    if [ -n "${ZYPPER_TRACE_ID:-}" ]; then
        trace_tag=" [TID=${ZYPPER_TRACE_ID}]"
    fi

    local line
    line="[${level}] ${ts} [RUN=${RUN_ID}]${trace_tag} ${msg}"

    # 1) Always write clean text to LOG_FILE
    echo "${line}" >> "${LOG_FILE}"

    # 2) Mirror structured lines into TRACE_LOG (best-effort)
    if [ -n "${TRACE_LOG:-}" ]; then
        echo "${line}" >> "${TRACE_LOG}" 2>/dev/null || true
    fi

    # 2b) Dashboard live log: a stable file name that the HTML dashboard can
    # poll in realtime (when served via http://). This is intentionally kept
    # as plain text (same structured line format) so it can be tailed/grepped.
    local dash_live_root
    dash_live_root="${LOG_DIR}/dashboard-live.log"
    echo "${line}" >> "${dash_live_root}" 2>/dev/null || true
    chmod 644 "${dash_live_root}" 2>/dev/null || true

    # Also mirror to the user's dashboard directory (best-effort) so the user
    # can run a local web server without needing access to /var/log.
    if [ -n "${SUDO_USER_HOME:-}" ] && [ -n "${SUDO_USER:-}" ]; then
        local dash_live_user_dir dash_live_user
        dash_live_user_dir="${SUDO_USER_HOME}/.local/share/zypper-notify"
        dash_live_user="${dash_live_user_dir}/dashboard-live.log"
        mkdir -p "${dash_live_user_dir}" 2>/dev/null || true
        echo "${line}" >> "${dash_live_user}" 2>/dev/null || true
        chown "${SUDO_USER}:${SUDO_USER}" "${dash_live_user}" 2>/dev/null || true
        chmod 644 "${dash_live_user}" 2>/dev/null || true
    fi

    # 3) Also emit to the system journal (best-effort).
    # This provides: journalctl -t zypper-auto-helper
    if [ "${JOURNAL_LOGGING_ENABLED:-0}" -eq 1 ] 2>/dev/null && command -v logger >/dev/null 2>&1; then
        case "${level}" in
            ERROR)
                logger -t "zypper-auto-helper" -p user.err -- "${line}" 2>/dev/null || true
                ;;
            DEBUG)
                if [ "${DEBUG_MODE:-0}" -eq 1 ] 2>/dev/null; then
                    logger -t "zypper-auto-helper" -p user.debug -- "${line}" 2>/dev/null || true
                fi
                ;;
            *)
                logger -t "zypper-auto-helper" -p user.info -- "${line}" 2>/dev/null || true
                ;;
        esac
    fi

    # 4) Console output (interactive only by default)
    if [ "${LOG_TO_CONSOLE:-0}" -eq 1 ] 2>/dev/null; then
        if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
            case "${level}" in
                INFO)    printf "%b %s\n" "${C_BLUE}[INFO]${C_RESET}" "${msg}" ;;
                SUCCESS) printf "%b %s\n" "${C_GREEN}[OK]${C_RESET}  " "${msg}" ;;
                WARN)    printf "%b %s\n" "${C_YELLOW}[WARN]${C_RESET}" "${msg}" ;;
                ERROR)   printf "%b %s\n" "${C_RED}[ERR]${C_RESET} " "${msg}" >&2 ;;
                DEBUG)
                    if [ "${DEBUG_MODE:-0}" -eq 1 ] 2>/dev/null; then
                        printf "%b %s\n" "${C_CYAN}[DBG]${C_RESET} " "${msg}" >&2
                    fi
                    ;;
            esac
        else
            case "${level}" in
                ERROR) printf "[ERR] %s\n" "${msg}" >&2 ;;
                DEBUG)
                    if [ "${DEBUG_MODE:-0}" -eq 1 ] 2>/dev/null; then
                        printf "[DBG] %s\n" "${msg}" >&2
                    fi
                    ;;
                *) printf "[%s] %s\n" "${level}" "${msg}" ;;
            esac
        fi
    else
        # Non-interactive: keep prior behaviour of surfacing ERRORs on stderr
        if [ "${level}" = "ERROR" ]; then
            echo "${line}" >&2
        fi
    fi
}

log_info() {
    _log_write "INFO" "$@"
}

log_success() {
    _log_write "SUCCESS" "$@"
}

log_error() {
    _log_write "ERROR" "$@"
}

log_warn() {
    _log_write "WARN" "$@"
}

log_debug() {
    _log_write "DEBUG" "$@"
}

# Extremely verbose trace channel for high-frequency events. This writes
# into TRACE_LOG and is separate from shell xtrace (which also targets
# TRACE_LOG when --debug is enabled).
log_trace() {
    local ts
    ts="$(_log_ts)"
    local trace_tag=""
    if [ -n "${ZYPPER_TRACE_ID:-}" ]; then
        trace_tag=" [TID=${ZYPPER_TRACE_ID}]"
    fi
    echo "[TRACE] ${ts} [RUN=${RUN_ID}]${trace_tag} $*" >> "${TRACE_LOG}" 2>/dev/null || true
}

# Record the full CLI invocation once at startup so diagnostics follower and
# bundles can see exactly how the helper was called. We log this after
# RUN_ID/LOG_FILE are initialised but before any mode-specific branching.
if [ "${_ZYP_AUT_HELPER_CLI_LOGGED:-0}" -eq 0 ] 2>/dev/null; then
    _ZYP_AUT_HELPER_CLI_LOGGED=1
    log_info "[cli] Invoked as: $0 ${*:-<no-args>} (EUID=${EUID}, SUDO_USER=${SUDO_USER:-<unset>}, PWD=$(pwd))"
fi

# Atomic file writer for here-doc content.
# Usage:
#   write_atomic "/path/to/file" <<'EOF'
#   ...
#   EOF
write_atomic() {
    local target="$1" tmp
    tmp="${target}.tmp.$$"
    if ! cat >"$tmp"; then
        rm -f "$tmp" 2>/dev/null || true
        return 1
    fi
    if ! mv -f "$tmp" "$target"; then
        rm -f "$tmp" 2>/dev/null || true
        return 1
    fi
}

# If the user passed --debug anywhere on the command line, enable shell
# tracing and more verbose console logging while leaving the main
# behaviour unchanged.
if [ $# -gt 0 ]; then
    for __arg in "$@"; do
        if [ "${__arg}" = "--debug" ]; then
            DEBUG_MODE=1
            break
        fi
    done
    if [ "${DEBUG_MODE}" -eq 1 ] 2>/dev/null; then
        log_info "Debug mode enabled: activating shell trace"
        # Strip --debug from the positional parameters so it does not
        # confuse later option parsing.
        __new_args=()
        for __arg in "$@"; do
            if [ "${__arg}" = "--debug" ]; then
                continue
            fi
            __new_args+=("${__arg}")
        done
        set -- "${__new_args[@]}"
        # Route xtrace output into TRACE_LOG with a rich prefix when
        # available. Failures here are non-fatal; tracing will simply go
        # to stderr instead.
        if exec 9>>"${TRACE_LOG}" 2>/dev/null; then
            BASH_XTRACEFD=9
            PS4='+ [XTRACE] $(date "+%Y-%m-%d %H:%M:%S.%3N") [RUN=${RUN_ID}] ${BASH_SOURCE##*/}:${LINENO}: '
        else
            log_error "Failed to open ${TRACE_LOG} for shell tracing; xtrace will go to stderr"
        fi
        # Enable xtrace after we've initialised logging so traces are also
        # captured in TRACE_LOG via PS4 when possible.
        set -x
    fi
fi

# Format a command (argv) into a shell-escaped string for logs.
# This is best-effort: it's meant for humans and diagnostics.
_format_cmd() {
    local out="" arg
    for arg in "$@"; do
        out+="$(printf '%q ' "$arg")"
    done
    # Trim trailing space
    printf '%s' "${out% }"
}

# Execute a command with full capturing.
# Usage: execute_guarded "Description of task" command arg1 arg2 ...
#
# Behaviour:
# - Always captures stdout/stderr.
# - On success: logs a SUCCESS line. Command output is only persisted when
#   DEBUG_MODE=1 or ZYPPER_AUTO_GUARDED_LOG_SUCCESS_OUTPUT=1.
# - On failure: dumps full captured output to stderr and the install log.
execute_guarded() {
    local desc="$1"
    shift

    local tmp_out cmd_str
    tmp_out="$(mktemp)"
    cmd_str="$(_format_cmd "$@")"

    log_debug "EXEC: [${desc}] -> ${cmd_str}"

    if "$@" >"$tmp_out" 2>&1; then
        log_success "${desc}"

        # Persist successful command output only when explicitly requested.
        if [ "${DEBUG_MODE:-0}" -eq 1 ] 2>/dev/null || [ "${ZYPPER_AUTO_GUARDED_LOG_SUCCESS_OUTPUT:-0}" -eq 1 ] 2>/dev/null; then
            if [ -s "$tmp_out" ] 2>/dev/null; then
                sed 's/^/  [CMD_OUT] /' "$tmp_out" >>"${LOG_FILE}" 2>/dev/null || true
                if [ -n "${TRACE_LOG:-}" ]; then
                    sed 's/^/[CMD_OUT] /' "$tmp_out" >>"${TRACE_LOG}" 2>/dev/null || true
                fi
            fi
        fi

        rm -f "$tmp_out" 2>/dev/null || true
        return 0
    else
        local rc=$?
        log_error "FAILED: ${desc} (Exit Code: ${rc})"
        log_error "Command was: ${cmd_str}"
        log_error "⬇⬇⬇ COMMAND OUTPUT ⬇⬇⬇"

        # Prefix output lines so they're easy to grep in large install logs.
        sed 's/^/  [CMD_OUT] /' "$tmp_out" | tee -a "${LOG_FILE}" >&2
        if [ -n "${TRACE_LOG:-}" ]; then
            sed 's/^/[CMD_OUT] /' "$tmp_out" >>"${TRACE_LOG}" 2>/dev/null || true
        fi

        log_error "⬆⬆⬆ END COMMAND OUTPUT ⬆⬆⬆"
        rm -f "$tmp_out" 2>/dev/null || true
        return $rc
    fi
}

# Execute a command best-effort (non-fatal), capturing output like execute_guarded
# but logging failures at WARN level so missing legacy units/processes do not
# spam diagnostics logs as [ERROR].
#
# Always returns 0.
execute_optional() {
    local desc="$1"
    shift

    local tmp_out cmd_str
    tmp_out="$(mktemp)"
    cmd_str="$(_format_cmd "$@")"

    log_debug "EXEC (optional): [${desc}] -> ${cmd_str}"

    if "$@" >"$tmp_out" 2>&1; then
        # Optional operations should not clutter logs on success.
        log_debug "OPTIONAL OK: ${desc}"

        if [ "${DEBUG_MODE:-0}" -eq 1 ] 2>/dev/null || [ "${ZYPPER_AUTO_GUARDED_LOG_SUCCESS_OUTPUT:-0}" -eq 1 ] 2>/dev/null; then
            if [ -s "$tmp_out" ] 2>/dev/null; then
                sed 's/^/  [CMD_OUT] /' "$tmp_out" >>"${LOG_FILE}" 2>/dev/null || true
                if [ -n "${TRACE_LOG:-}" ]; then
                    sed 's/^/[CMD_OUT] /' "$tmp_out" >>"${TRACE_LOG}" 2>/dev/null || true
                fi
            fi
        fi

        rm -f "$tmp_out" 2>/dev/null || true
        return 0
    else
        local rc=$?
        log_warn "OPTIONAL FAILED: ${desc} (Exit Code: ${rc})"
        log_warn "Command was: ${cmd_str}"

        if [ -s "$tmp_out" ] 2>/dev/null; then
            sed 's/^/  [CMD_OUT] /' "$tmp_out" >>"${LOG_FILE}" 2>/dev/null || true
            if [ -n "${TRACE_LOG:-}" ]; then
                sed 's/^/[CMD_OUT] /' "$tmp_out" >>"${TRACE_LOG}" 2>/dev/null || true
            fi
        fi

        rm -f "$tmp_out" 2>/dev/null || true
        return 0
    fi
}

# Helper: best-effort check whether a system unit file exists.
__znh_unit_file_exists_system() {
    local unit="$1"
    local out first
    out=$(systemctl list-unit-files --no-legend "${unit}" 2>/dev/null || true)
    first=$(printf '%s\n' "$out" | awk 'NR==1 {print $1}')
    [ "${first}" = "${unit}" ]
}

# Helper: best-effort check whether a user unit file exists.
__znh_unit_file_exists_user() {
    local user="$1" unit="$2"
    [ -z "${user}" ] && return 1

    local bus out first
    bus="$(get_user_bus "${user}" 2>/dev/null || true)"
    [ -z "${bus}" ] && return 1

    out=$(sudo -u "${user}" DBUS_SESSION_BUS_ADDRESS="${bus}" \
        systemctl --user list-unit-files --no-legend "${unit}" 2>/dev/null || true)
    first=$(printf '%s\n' "$out" | awk 'NR==1 {print $1}')
    [ "${first}" = "${unit}" ]
}

# Backward-compatible wrapper for older call sites.
# NOTE: Prefer execute_guarded with real argv whenever possible.
log_command() {
    local cmd="$*"
    execute_guarded "$cmd" bash -lc "$cmd"
}

# --- Dashboard Settings Schema (single source of truth) ---
# This schema drives:
#  - the HTML dashboard Settings drawer predefined choices
#  - the localhost Settings API validation
#
# IMPORTANT: Do NOT parse /etc/zypper-auto.conf comments for machine rules.
# Comments are for humans; this JSON is the actual source of truth for the UI/API.
__znh_write_dashboard_schema_json() {
    # Writes a JSON schema file used by the Settings API (/api/schema) so the
    # dashboard UI can render predefined choices (allowed/min/max/step/presets).
    local out_path="$1"
    [ -z "${out_path:-}" ] && return 1

    mkdir -p "$(dirname "${out_path}")" 2>/dev/null || true

    cat >"${out_path}" <<'EOF'
{
  "schema": {
    "ENABLE_FLATPAK_UPDATES": {"type": "bool", "default": "true"},
    "ENABLE_SNAP_UPDATES": {"type": "bool", "default": "true"},
    "ENABLE_SOAR_UPDATES": {"type": "bool", "default": "true"},
    "ENABLE_BREW_UPDATES": {"type": "bool", "default": "true"},
    "ENABLE_PIPX_UPDATES": {"type": "bool", "default": "true"},
    "HOOKS_ENABLED": {"type": "bool", "default": "true"},
    "DASHBOARD_ENABLED": {"type": "bool", "default": "true"},
    "VERIFY_NOTIFY_USER_ENABLED": {"type": "bool", "default": "true"},

    "DL_TIMER_INTERVAL_MINUTES": {"type": "interval", "allowed": ["1","5","10","15","30","60"], "default": "1"},
    "NT_TIMER_INTERVAL_MINUTES": {"type": "interval", "allowed": ["1","5","10","15","30","60"], "default": "1"},
    "VERIFY_TIMER_INTERVAL_MINUTES": {"type": "interval", "allowed": ["1","5","10","15","30","60"], "default": "60"},

    "DOWNLOADER_DOWNLOAD_MODE": {"type": "enum", "allowed": ["full","detect-only"], "default": "full"},
    "AUTO_DUPLICATE_RPM_MODE": {"type": "enum", "allowed": ["whitelist","thirdparty","both"], "default": "whitelist"},
    "CLEANUP_REPORT_FORMAT": {"type": "enum", "allowed": ["text","json","both"], "default": "both"},
    "BOOT_ENTRY_CLEANUP_MODE": {"type": "enum", "allowed": ["backup","delete"], "default": "backup"},

    "SNAP_RETENTION_OPTIMIZER_ENABLED": {"type": "bool", "default": "true"},
    "SNAP_RETENTION_MAX_NUMBER_LIMIT": {"type": "int", "min": 0, "max": 200, "step": 1, "default": "15"},
    "SNAP_RETENTION_MAX_NUMBER_LIMIT_IMPORTANT": {"type": "int", "min": 0, "max": 100, "step": 1, "default": "5"},
    "SNAP_RETENTION_MAX_TIMELINE_LIMIT_HOURLY": {"type": "int", "min": 0, "max": 200, "step": 1, "default": "10"},
    "SNAP_RETENTION_MAX_TIMELINE_LIMIT_DAILY": {"type": "int", "min": 0, "max": 120, "step": 1, "default": "7"},
    "SNAP_RETENTION_MAX_TIMELINE_LIMIT_WEEKLY": {"type": "int", "min": 0, "max": 104, "step": 1, "default": "2"},
    "SNAP_RETENTION_MAX_TIMELINE_LIMIT_MONTHLY": {"type": "int", "min": 0, "max": 60, "step": 1, "default": "2"},
    "SNAP_RETENTION_MAX_TIMELINE_LIMIT_YEARLY": {"type": "int", "min": 0, "max": 20, "step": 1, "default": "0"},

    "SNAP_CLEANUP_CONCURRENCY_GUARD_ENABLED": {"type": "bool", "default": "true"},
    "SNAP_CLEANUP_CRITICAL_FREE_MB": {"type": "int", "min": 0, "max": 5000, "step": 50, "default": "300"},

    "SNAP_BROKEN_SNAPSHOT_HUNTER_ENABLED": {"type": "bool", "default": "false"},
    "SNAP_BROKEN_SNAPSHOT_HUNTER_REGEX": {"type": "string", "max_len": 200, "default": "aborted|failed", "presets": ["aborted|failed", "aborted", "failed", "error", "aborted|failed|error"]},
    "SNAP_BROKEN_SNAPSHOT_HUNTER_CONFIRM": {"type": "bool", "default": "true"}
  }
}
EOF

    chmod 600 "${out_path}" 2>/dev/null || true
    chown root:root "${out_path}" 2>/dev/null || true
    return 0
}

# Load external configuration if present, otherwise create a default template.
load_config() {
    if [ -f "${CONFIG_FILE}" ]; then
        log_info "Loading configuration from ${CONFIG_FILE}"
        # shellcheck source=/etc/zypper-auto.conf
        # shellcheck disable=SC1091
        . "${CONFIG_FILE}"
    else
        log_info "No configuration found at ${CONFIG_FILE}; generating default config"
        cat > "${CONFIG_FILE}" << 'EOF'
# zypper-auto-helper configuration
#
# All values in this file are read by the installer at runtime. You can
# safely edit them and re-run:
#   sudo ./zypper-auto.sh install
# to apply changes. Invalid values fall back to safe defaults and are
# reported in the install log and last-status.txt.
#
# Boolean flags must be "true" or "false" (case-insensitive).

# ---------------------------------------------------------------------
# Post-update helpers (run AFTER "pkexec zypper dup")
# ---------------------------------------------------------------------

# ENABLE_FLATPAK_UPDATES
# If true, run "pkexec flatpak update -y" after a successful zypper dup
# so Flatpak apps/runtimes are upgraded together with system packages.
ENABLE_FLATPAK_UPDATES=true

# ENABLE_SNAP_UPDATES
# If true, run "pkexec snap refresh" after zypper dup so Snap packages
# are refreshed along with the system. Requires snapd to be installed.
ENABLE_SNAP_UPDATES=true

# ENABLE_SOAR_UPDATES
# If true and "soar" is installed, check GitHub for the latest *stable*
# Soar release, update if a newer version exists, then run "soar sync"
# and "soar update" to refresh Soar-managed applications.
ENABLE_SOAR_UPDATES=true

# ENABLE_BREW_UPDATES
# If true and Homebrew is installed, run "brew update" followed by
# "brew outdated --quiet" and "brew upgrade" when there are outdated
# formulae. When false, Homebrew is left entirely to the user.
ENABLE_BREW_UPDATES=true

# ENABLE_PIPX_UPDATES
# If true and pipx is installed for the user, run "pipx upgrade-all"
# after zypper dup so that Python command-line tools (yt-dlp, black,
# ansible, httpie, etc.) are upgraded in their isolated environments.
# When false, pipx-based tools are left entirely to the user.
ENABLE_PIPX_UPDATES=true

# ---------------------------------------------------------------------
# Remote monitoring (webhooks)
# ---------------------------------------------------------------------

# WEBHOOK_URL
# Optional: when set, the helper can send a short status message to a webhook
# endpoint so you can monitor your machine remotely (Discord/Slack/ntfy, etc.).
#
# Security note: treat this URL like a secret token.
#
# Examples:
#   Discord: https://discord.com/api/webhooks/....
#   Slack  : https://hooks.slack.com/services/....
#   ntfy   : https://ntfy.sh/<topic>
WEBHOOK_URL=""

# ---------------------------------------------------------------------
# Extensibility (hooks)
# ---------------------------------------------------------------------

# HOOKS_ENABLED
# When true, pre/post hook scripts under /etc/zypper-auto/hooks will be run
# around interactive updates.
HOOKS_ENABLED=true

# HOOKS_BASE_DIR
# Base directory for hook stages. Two directories are used:
#   - /etc/zypper-auto/hooks/pre.d
#   - /etc/zypper-auto/hooks/post.d
HOOKS_BASE_DIR="/etc/zypper-auto/hooks"

# ---------------------------------------------------------------------
# Visual status dashboard (static HTML)
# ---------------------------------------------------------------------

# DASHBOARD_ENABLED
# When true, the helper writes a simple HTML status page you can open in a
# browser:
#   - /var/log/zypper-auto/status.html (root-owned)
#   - ~/.local/share/zypper-notify/status.html (user copy when available)
DASHBOARD_ENABLED=true

# DASHBOARD_BROWSER
# Optional: override the browser used by --dash-open / --dash-install.
# Leave empty to use the system default (xdg-open).
# Examples: "firefox", "google-chrome", "chromium"
DASHBOARD_BROWSER=""

# ---------------------------------------------------------------------
# Timer intervals for downloader / notifier / verification
# ---------------------------------------------------------------------

# DL_TIMER_INTERVAL_MINUTES
# How often (in minutes) the *root* downloader (zypper-autodownload.timer)
# should run. Allowed values (MUST be one of these exact integers):
#   1,5,10,15,30,60
#   1  = every minute (minutely)
#   5  = every 5 minutes
#   10 = every 10 minutes
#   15 = every 15 minutes
#   30 = every 30 minutes
#   60 = every hour (hourly)
# Any other value is treated as invalid and will be reset to a safe default.
DL_TIMER_INTERVAL_MINUTES=1

# NT_TIMER_INTERVAL_MINUTES
# How often (in minutes) the *user* notifier (zypper-notify-user.timer)
# should run to check for updates and send notifications.
# Uses the same allowed values and rules as above (MUST be exactly one of
# 1,5,10,15,30,60; anything else falls back to a safe default).
NT_TIMER_INTERVAL_MINUTES=1

# VERIFY_TIMER_INTERVAL_MINUTES
# How often (in minutes) the verification/auto-repair timer
# (zypper-auto-verify.timer) should run. Allowed values (MUST be one of
# these exact integers): 1,5,10,15,30,60.
#   1  = every minute (minutely)
#   5  = every 5 minutes
#   10 = every 10 minutes
#   15 = every 15 minutes
#   30 = every 30 minutes
#   60 = every hour (hourly)
# Any other value is treated as invalid and will be reset to a safe default.
# Default: 5 (High Priority Mode default)
VERIFY_TIMER_INTERVAL_MINUTES=5

# ---------------------------------------------------------------------
# Snapper safety: retention optimizer caps (prevent disk filling)
# ---------------------------------------------------------------------

# SNAP_RETENTION_OPTIMIZER_ENABLED
# When true, enabling Snapper timers via:
#   zypper-auto-helper snapper auto
# (or the Snapper menu "AUTO enable" option) will also apply a best-effort
# preventative safety tune to /etc/snapper/configs/*:
#   - It will ONLY LOWER overly-high retention limits (never increases).
#   - It will NOT touch values that are already below the caps.
#   - It supports both formats: KEY="50" and KEY="2-50" (range upper bound).
#
# This helps avoid the classic failure mode where Snapper creates too many
# snapshots and fills / before cleanup has a chance to catch up.
#
# Valid values: true / false. Default: true.
SNAP_RETENTION_OPTIMIZER_ENABLED=true

# The following values are MAXIMUM caps ("desktop safe maxima").
# If your snapper config has a higher value, the helper will lower it to the cap.
#
# Notes:
# - Set a cap to a high number if you do NOT want the helper to lower it.
# - TIMELINE_LIMIT_YEARLY can be 0 to disable yearly retention.

# Numeric cleanup caps
SNAP_RETENTION_MAX_NUMBER_LIMIT=15
SNAP_RETENTION_MAX_NUMBER_LIMIT_IMPORTANT=5

# Timeline cleanup caps
SNAP_RETENTION_MAX_TIMELINE_LIMIT_HOURLY=10
SNAP_RETENTION_MAX_TIMELINE_LIMIT_DAILY=7
SNAP_RETENTION_MAX_TIMELINE_LIMIT_WEEKLY=2
SNAP_RETENTION_MAX_TIMELINE_LIMIT_MONTHLY=2
SNAP_RETENTION_MAX_TIMELINE_LIMIT_YEARLY=0

# ---------------------------------------------------------------------
# Snapper cleanup safety
# ---------------------------------------------------------------------

# SNAP_CLEANUP_CONCURRENCY_GUARD_ENABLED
# When true (default), the Snapper cleanup command checks whether a background
# snapper cleanup process appears to be running (timer/service) and warns before
# starting another cleanup.
SNAP_CLEANUP_CONCURRENCY_GUARD_ENABLED=true

# SNAP_CLEANUP_CRITICAL_FREE_MB
# If free space on / is below this threshold, Snapper cleanup may be risky on
# btrfs because deleting snapshots requires metadata updates.
# Default: 300 (MB)
SNAP_CLEANUP_CRITICAL_FREE_MB=300

# ---------------------------------------------------------------------
# Snapper cleanup: Deep Clean (emergency space recovery)
# ---------------------------------------------------------------------

# SNAP_BROKEN_SNAPSHOT_HUNTER_ENABLED
# When true, Snapper "Full Cleanup" (menu option 4) can also run an extra
# emergency step to hunt for and delete obviously broken/aborted snapshots.
#
# Safety notes:
# - This step is interactive-only (requires a TTY) unless you disable confirmation.
# - It uses a keyword regex match against snapshot descriptions.
# - Default: false (disabled).
SNAP_BROKEN_SNAPSHOT_HUNTER_ENABLED=false

# SNAP_BROKEN_SNAPSHOT_HUNTER_REGEX
# Case-insensitive ERE regex used to detect junk snapshots by description.
# Default: aborted|failed
SNAP_BROKEN_SNAPSHOT_HUNTER_REGEX="aborted|failed"

# SNAP_BROKEN_SNAPSHOT_HUNTER_CONFIRM
# When true (default), ask once before deleting any snapshots found by the hunter.
SNAP_BROKEN_SNAPSHOT_HUNTER_CONFIRM=true

# ---------------------------------------------------------------------
# System Deep Scrub (Option 4): caches, logs, applications
# ---------------------------------------------------------------------

# ZYPPER_CACHE_CLEAN_ENABLED
# When true, Snapper Full Cleanup will also run:
#   zypper clean --all
# This removes cached metadata and downloaded RPMs (safe; they can be re-downloaded).
ZYPPER_CACHE_CLEAN_ENABLED=false

# ZYPPER_CACHE_CLEAN_CONFIRM
# When true (default), ask once before cleaning zypper caches.
ZYPPER_CACHE_CLEAN_CONFIRM=true

# JOURNAL_VACUUM_ENABLED
# When true, Snapper Full Cleanup will also vacuum systemd journals.
JOURNAL_VACUUM_ENABLED=false

# JOURNAL_VACUUM_DAYS
# How many days of journals to keep (journalctl --vacuum-time=<Nd>).
# Default: 7
JOURNAL_VACUUM_DAYS=7

# JOURNAL_VACUUM_SIZE_MB
# Optional: when set to a positive number, uses journalctl --vacuum-size=<Nm>
# instead of vacuum-time. Leave empty/0 to use JOURNAL_VACUUM_DAYS.
# Default: 0 (disabled)
JOURNAL_VACUUM_SIZE_MB=0

# JOURNAL_VACUUM_CONFIRM
# When true (default), ask once before vacuuming journals.
JOURNAL_VACUUM_CONFIRM=true

# COREDUMP_VACUUM_ENABLED
# When true, Snapper Full Cleanup can also vacuum systemd coredumps
# (crash dumps) via coredumpctl.
COREDUMP_VACUUM_ENABLED=false

# COREDUMP_VACUUM_MAX_SIZE_MB
# Keep coredumps under this total size (coredumpctl --vacuum-size=<Nm>).
# Default: 200
COREDUMP_VACUUM_MAX_SIZE_MB=200

# COREDUMP_VACUUM_CONFIRM
# When true (default), ask once before vacuuming coredumps.
COREDUMP_VACUUM_CONFIRM=true

# FLATPAK_UNUSED_CLEAN_ENABLED
# When true, Snapper Full Cleanup can also prune unused Flatpak runtimes:
#   flatpak uninstall --unused
# This is often a large space saver.
FLATPAK_UNUSED_CLEAN_ENABLED=false

# FLATPAK_UNUSED_CLEAN_CONFIRM
# When true (default), ask once before pruning unused flatpaks.
FLATPAK_UNUSED_CLEAN_CONFIRM=true

# SNAP_REFRESH_RETAIN_TUNE_ENABLED
# When true, Snapper Full Cleanup can also tune snapd to keep fewer old
# revisions (space saver):
#   snap set system refresh.retain=<N>
SNAP_REFRESH_RETAIN_TUNE_ENABLED=false

# SNAP_REFRESH_RETAIN_VALUE
# Desired refresh.retain value (recommended: 2 = active + 1 rollback).
# Minimum: 2. Default: 2
SNAP_REFRESH_RETAIN_VALUE=2

# SNAP_REFRESH_RETAIN_TUNE_CONFIRM
# When true (default), ask once before tuning snap refresh retention.
SNAP_REFRESH_RETAIN_TUNE_CONFIRM=true

# USER_THUMBNAILS_CLEAN_ENABLED
# When true, Snapper Full Cleanup will also remove cached thumbnails for the
# desktop user (best-effort) to reclaim space:
#   ~/.cache/thumbnails/* and ~/.thumbnails/*
USER_THUMBNAILS_CLEAN_ENABLED=false

# USER_THUMBNAILS_CLEAN_DAYS
# Optional: when set to a positive number, only delete thumbnail files not
# accessed in N days (find -atime +N). When 0, delete all cached thumbnails.
# Default: 0
USER_THUMBNAILS_CLEAN_DAYS=0

# USER_THUMBNAILS_CLEAN_CONFIRM
# When true (default), ask once before deleting thumbnails.
USER_THUMBNAILS_CLEAN_CONFIRM=true

# ---------------------------------------------------------------------
# Option 4: Cleanup audit reports
# ---------------------------------------------------------------------

# CLEANUP_REPORT_ENABLED
# When true (default), Snapper "Full Cleanup" writes an additional audit report
# under CLEANUP_REPORT_DIR so you can review what happened later.
CLEANUP_REPORT_ENABLED=true

# CLEANUP_REPORT_DIR
# Directory for cleanup reports (text and/or JSON).
CLEANUP_REPORT_DIR="/var/log/zypper-auto/cleanup-reports"

# CLEANUP_REPORT_FORMAT
# Allowed: text | json | both
CLEANUP_REPORT_FORMAT="both"

# CLEANUP_REPORT_MAX_FILES
# Keep only the newest N cleanup reports in CLEANUP_REPORT_DIR (best-effort).
CLEANUP_REPORT_MAX_FILES=30

# ---------------------------------------------------------------------
# System Health Automator (Option 5): btrfs maintenance timers
# ---------------------------------------------------------------------

# BTRFS_MAINTENANCE_TIMERS_ENABLED
# When true (default), Snapper AUTO enable will also attempt to enable btrfs
# maintenance timers if they exist (from btrfsmaintenance package), e.g.:
#   btrfs-scrub.timer, btrfs-balance.timer, btrfs-trim.timer
BTRFS_MAINTENANCE_TIMERS_ENABLED=true

# BTRFS_MAINTENANCE_TIMERS_CONFIRM
# When true (default), ask once before enabling btrfs maintenance timers.
BTRFS_MAINTENANCE_TIMERS_CONFIRM=true

# FSTRIM_TIMER_ENABLED
# When true (default), Snapper AUTO enable will also attempt to enable fstrim.timer
# (SSD health; safe no-op on unsupported filesystems).
FSTRIM_TIMER_ENABLED=true

# FSTRIM_TIMER_CONFIRM
# When true (default), ask once before enabling fstrim.timer.
FSTRIM_TIMER_CONFIRM=true

# BTRFS_MAINTENANCE_TUNE_ENABLED
# When true, Snapper AUTO enable can also tune /etc/sysconfig/btrfsmaintenance
# to reduce performance slowdowns from overly-frequent balances/scrubs.
# Default: false (disabled)
BTRFS_MAINTENANCE_TUNE_ENABLED=false

# BTRFS_MAINTENANCE_TUNE_CONFIRM
# When true (default), ask once before editing /etc/sysconfig/btrfsmaintenance.
BTRFS_MAINTENANCE_TUNE_CONFIRM=true

# ---------------------------------------------------------------------
# Boot menu hygiene: auto-clean old kernel entries (systemd-boot / BLS)
# ---------------------------------------------------------------------

# BOOT_ENTRY_CLEANUP_ENABLED
# When true (default), Snapper cleanup will also try to prune *boot menu entries*
# for old kernels by moving old BLS entry files out of the active entries dir.
# This does NOT delete kernel images; it only reduces clutter in the boot menu.
BOOT_ENTRY_CLEANUP_ENABLED=true

# BOOT_ENTRY_CLEANUP_KEEP_LATEST
# How many latest installed kernels to keep in the boot menu (in addition to the
# currently running kernel, which is always kept). Minimum: 1. Default: 2.
BOOT_ENTRY_CLEANUP_KEEP_LATEST=2

# BOOT_ENTRY_CLEANUP_MODE
#   backup - (default) move old entry files into a timestamped backup folder
#   delete - permanently delete old entry files (not recommended)
BOOT_ENTRY_CLEANUP_MODE="backup"

# BOOT_ENTRY_CLEANUP_ENTRIES_DIR
# Optional override for the BLS entries directory. Leave empty for auto-detect.
# Common locations:
#   - /boot/loader/entries
#   - /boot/efi/loader/entries
#   - /efi/loader/entries
BOOT_ENTRY_CLEANUP_ENTRIES_DIR=""

# BOOT_ENTRY_CLEANUP_CONFIRM
# When true (default), boot-entry cleanup asks once for confirmation.
# When false, it runs automatically after you confirm Snapper cleanup.
BOOT_ENTRY_CLEANUP_CONFIRM=true

# ---------------------------------------------------------------------
# Kernel package cleanup: purge old kernels (zypper purge-kernels)
# ---------------------------------------------------------------------

# KERNEL_PURGE_ENABLED
# When true, Snapper cleanup will also run `zypper purge-kernels` to remove old
# kernel *packages*.
#
# IMPORTANT:
# - This can change what kernels are available in the bootloader.
# - It respects /etc/zypp/zypp.conf:multiversion.kernels.
# - Disabled by default for safety.
KERNEL_PURGE_ENABLED=false

# KERNEL_PURGE_MODE
# How to run purge-kernels:
#   auto    - prefer direct `zypper purge-kernels`, fallback to systemd unit
#   zypper  - run `zypper purge-kernels` directly
#   systemd - `touch /boot/do_purge_kernels` then `systemctl start purge-kernels.service`
KERNEL_PURGE_MODE="auto"

# KERNEL_PURGE_CONFIRM
# When true (default), ask once for confirmation before purging kernels.
KERNEL_PURGE_CONFIRM=true

# KERNEL_PURGE_DRY_RUN
# When true, run `zypper purge-kernels --dry-run` (no changes; prints plan).
KERNEL_PURGE_DRY_RUN=false

# KERNEL_PURGE_DETAILS
# When true, add `--details` to show a more detailed summary.
KERNEL_PURGE_DETAILS=false

# KERNEL_PURGE_TIMEOUT_SECONDS
# Best-effort timeout for the purge-kernels run. Default: 900 seconds.
KERNEL_PURGE_TIMEOUT_SECONDS=900

# ---------------------------------------------------------------------
# Installer log retention
# ---------------------------------------------------------------------

# MAX_LOG_FILES
# Maximum number of install-*.log files to keep under /var/log/zypper-auto.
# Older logs beyond this count are deleted automatically on each install.
MAX_LOG_FILES=10

# MAX_LOG_SIZE_MB
# Maximum size (in megabytes) for individual service logs under
# /var/log/zypper-auto/service-logs. Very large logs are rotated to
# *.old when they exceed this size.
MAX_LOG_SIZE_MB=50

# ---------------------------------------------------------------------
# Notifier cache and snooze behaviour
# ---------------------------------------------------------------------

# CACHE_EXPIRY_MINUTES
# The notifier caches the result of "zypper dup --dry-run" to avoid
# hitting zypper too often. This value controls how long (in minutes)
# a cached result is considered valid before forcing a fresh check.
# Higher values = fewer zypper runs but potentially more stale info.
CACHE_EXPIRY_MINUTES=10

# SNOOZE_SHORT_HOURS / SNOOZE_MEDIUM_HOURS / SNOOZE_LONG_HOURS
# Durations (in hours) used by the Snooze buttons in the desktop
# notification. The labels remain "1h", "4h" and "1d", but you can
# change how long each actually snoozes notifications.
SNOOZE_SHORT_HOURS=1
SNOOZE_MEDIUM_HOURS=4
SNOOZE_LONG_HOURS=24

# INSTALL_CLICK_SUPPRESS_MINUTES
# After you click "Install Now" (Ready to install), the notifier writes a small
# marker file under ~/.cache/zypper-notify and suppresses any further popups
# while the interactive update window is open.
#
# This avoids the common annoyance where the "Updates Ready" notification can
# re-appear while you are already installing updates.
#
# Set to 0 to disable this suppression behavior.
INSTALL_CLICK_SUPPRESS_MINUTES=120

# ---------------------------------------------------------------------
# Zypper lock handling and downloader behaviour
# ---------------------------------------------------------------------

# LOCK_RETRY_MAX_ATTEMPTS
# How many times the "Ready to install" helper should retry when
# another zypper/YaST instance holds the system management lock
# before giving up and showing a message. Each attempt waits a
# little longer than the previous one.
LOCK_RETRY_MAX_ATTEMPTS=10

# LOCK_RETRY_INITIAL_DELAY_SECONDS
# Base delay (in seconds) used for the first lock retry. Subsequent
# retries add this delay again (1,2,3,... style). Set to 0 to disable
# waiting and fail fast when the lock is held.
LOCK_RETRY_INITIAL_DELAY_SECONDS=1

# LOCK_REMINDER_ENABLED
# When "true", the user-space notifier shows a small desktop notification
# whenever zypper/libzypp is locked by another process (YaST, another
# zypper, systemd-zypp-refresh, etc.), and will repeat this reminder on
# each notifier run while the lock is present.
#
# When "false", lock situations are still logged to
# ~/.local/share/zypper-notify/notifier-detailed.log and reflected in
# last-run-status.txt, but no desktop popup is shown.
#
# Valid values: true / false (case-sensitive). Default: true.
LOCK_REMINDER_ENABLED=true

# NO_UPDATES_REMINDER_REPEAT_ENABLED
# When "true", the notifier may re-show identical "No updates found" messages
# on subsequent checks while the system remains fully up to date.
# When "false", the "No updates" notification is shown once per state and
# then suppressed until the update state changes.
#
# Valid values: true / false (case-sensitive). Default: true.
NO_UPDATES_REMINDER_REPEAT_ENABLED=true

# UPDATES_READY_REMINDER_REPEAT_ENABLED
# When "true", the notifier may re-show identical "Updates ready" messages
# on subsequent checks while the same snapshot / update set is still pending.
# When "false", the "Updates ready" notification is shown once per state and
# then suppressed until a new snapshot or different set of updates is detected.
#
# Valid values: true / false (case-sensitive). Default: true.
UPDATES_READY_REMINDER_REPEAT_ENABLED=true

# VERIFY_NOTIFY_USER_ENABLED
# When "true", the periodic verification/auto-repair service sends a
# desktop notification to the primary user when it detects and fixes
# at least one problem. When "false", verification still runs and logs
# repairs to /var/log/zypper-auto but does not notify on the desktop.
#
# Valid values: true / false (case-sensitive). Default: true.
VERIFY_NOTIFY_USER_ENABLED=true

# DOWNLOADER_DOWNLOAD_MODE
# Controls how the background downloader behaves (value is case-sensitive):
#   full        - (default) run "zypper dup --download-only" to
#                 prefetch all packages into the cache.
#   detect-only - only run "zypper dup --dry-run" to detect whether
#                 updates are available; no pre-download is done.
# Any other value is treated as invalid and will be reported in the
# installer log, then reset to the safe default "full".
DOWNLOADER_DOWNLOAD_MODE=full

# DUP_EXTRA_FLAGS
# Extra arguments appended to every "zypper dup" invocation run by this
# helper, both for the background downloader ("dup --download-only") and
# the notifier ("dup --dry-run"). This is useful for flags like
# "--allow-vendor-change" or "--from <repo>".
#
# IMPORTANT:
#   - Do NOT include "--non-interactive", "--download-only" or "--dry-run"
#     here; those are added automatically by the helper where needed.
#   - If you set multiple flags, write them exactly as you would on the
#     command line, for example:
#         DUP_EXTRA_FLAGS="--allow-vendor-change --no-allow-vendor-change"
DUP_EXTRA_FLAGS=""

# AUTO_DUPLICATE_RPM_CLEANUP_PACKAGES
# Space-separated list of package names that zypper-auto-helper is allowed
# to clean up when multiple RPM versions are installed and they block
# updates (for example, due to broken %preun/%postun scriptlets).
#
# For each package name in this list, the zypper wrapper will:
#   - detect when more than one version is installed
#   - keep the newest version
#   - attempt to remove older versions with:
#         rpm -e --noscripts <older-version>
#
# WARNING:
#   - This should only be used for third-party / leaf packages you know
#     are safe to remove this way (e.g. "insync").
#   - Do NOT add core system packages (kernel, glibc, systemd, etc.).
#
# Default: only "insync" is enabled, because it is known to ship
# problematic uninstall scripts on some systems. You can extend this list
# with additional package names if you fully understand the risks, e.g.:
#   AUTO_DUPLICATE_RPM_CLEANUP_PACKAGES="insync some-other-app"
AUTO_DUPLICATE_RPM_CLEANUP_PACKAGES="insync"

# AUTO_DUPLICATE_RPM_MODE
# Controls how duplicate RPM cleanup behaves:
#   whitelist  - only clean packages listed in AUTO_DUPLICATE_RPM_CLEANUP_PACKAGES (default, safest)
#   thirdparty - automatically clean duplicate packages whose Vendor is not SUSE/openSUSE
#   both       - run whitelist cleanup first, then scan third-party duplicates
#
# NOTE: thirdparty/both modes are more aggressive and should only be
# used if you understand the risks. They will never touch packages whose
# Vendor contains "SUSE" or "openSUSE", but may still affect important
# third-party drivers or libraries.
AUTO_DUPLICATE_RPM_MODE="whitelist"

# LOG_FOLDER_OPENER
# Optional command used by the debug menu (option 5) to open the
# diagnostics folder. When set and found in the desktop user's PATH,
# it is tried before xdg-open. Example values: "dolphin", "nautilus".
# Leave empty to let the helper auto-detect.
LOG_FOLDER_OPENER=""

# Example:
#   FORCE_FORM_FACTOR=laptop
#
#FORCE_FORM_FACTOR=
EOF
        # Ensure config file has safe permissions.
        # This file may contain secrets (e.g. WEBHOOK_URL), so keep it root-only.
        chmod 600 "${CONFIG_FILE}" || true

        # The dashboard Settings API runs sandboxed (ProtectSystem=strict) and writes directly to ${CONFIG_FILE}.
        # No extra temp file is required.
# NOTE: The downloader, notifier, and verification timer schedules are
# derived from DL_TIMER_INTERVAL_MINUTES, NT_TIMER_INTERVAL_MINUTES, and
# VERIFY_TIMER_INTERVAL_MINUTES in this file. After changing these values,
# re-run:
#   sudo ./zypper-auto.sh install
# so the systemd units are regenerated with the new schedule.
    fi

    # Basic numeric validation with safe fallbacks so a broken config
    # never crashes the installer. Uses indirect expansion + printf -v
    # instead of eval for safety and clarity.
    validate_int() {
        local name="$1" default="$2" value
        # Use indirect expansion to read the current value (may be empty).
        value="${!name-}"
        if ! [[ "$value" =~ ^[0-9]+$ ]] || [ "$value" -le 0 ]; then
            local msg="Invalid or missing $name='$value' in ${CONFIG_FILE}, using default $default"
            log_info "$msg"
            CONFIG_WARNINGS+=("$msg")
            printf -v "$name" '%s' "$default"
        fi
    }

    # Basic boolean validation for true/false style flags. When the key is
    # completely unset we quietly use the default without logging a warning,
    # so older configs without newer flags do not spam the logs.
    validate_bool_flag() {
        local name="$1" default="$2" value lower
        value="${!name-}"
        if [ -z "$value" ]; then
            printf -v "$name" '%s' "$default"
            return
        fi
        lower="${value,,}"
        case "$lower" in
            true|false)
                printf -v "$name" '%s' "$lower"
                ;;
            *)
                local msg="Invalid $name='$value' in ${CONFIG_FILE}, using default $default"
                log_info "$msg"
                CONFIG_WARNINGS+=("$msg")
                printf -v "$name" '%s' "$default"
                ;;
        esac
    }

    # Optional integer validation that allows 0 (non-negative).
    # If the key is missing entirely, we silently set a default (like validate_bool_flag).
    validate_nonneg_int_optional() {
        local name="$1" default="$2" value
        value="${!name-}"
        if [ -z "${value}" ]; then
            printf -v "$name" '%s' "$default"
            return
        fi
        if ! [[ "$value" =~ ^[0-9]+$ ]] || [ "$value" -lt 0 ] 2>/dev/null; then
            local msg="Invalid $name='$value' in ${CONFIG_FILE}, using default $default"
            log_info "$msg"
            CONFIG_WARNINGS+=("$msg")
            printf -v "$name" '%s' "$default"
        fi
    }

    # Optional integer validation that requires a positive integer (>=1).
    # If the key is missing entirely, we silently set a default.
    validate_pos_int_optional() {
        local name="$1" default="$2" value
        value="${!name-}"
        if [ -z "${value}" ]; then
            printf -v "$name" '%s' "$default"
            return
        fi
        if ! [[ "$value" =~ ^[0-9]+$ ]] || [ "$value" -le 0 ] 2>/dev/null; then
            local msg="Invalid $name='$value' in ${CONFIG_FILE}, using default $default"
            log_info "$msg"
            CONFIG_WARNINGS+=("$msg")
            printf -v "$name" '%s' "$default"
        fi
    }

    # Validate that a key is one of an allowed set of literal values.
    validate_allowed_set() {
        local name="$1" default="$2" allowed_csv="$3" value
        value="${!name-}"
        if [ -z "${value}" ]; then
            printf -v "$name" '%s' "$default"
            return
        fi
        if ! printf '%s' ",${allowed_csv}," | grep -q ",${value},"; then
            local msg="Invalid $name='$value' in ${CONFIG_FILE}, allowed values are: ${allowed_csv}. Using default ${default}"
            log_info "$msg"
            CONFIG_WARNINGS+=("$msg")
            printf -v "$name" '%s' "$default"
        fi
    }

    # Optional non-negative int with upper bound.
    validate_nonneg_int_bounded_optional() {
        local name="$1" default="$2" min="$3" max="$4" value
        value="${!name-}"
        if [ -z "${value}" ]; then
            printf -v "$name" '%s' "$default"
            return
        fi
        if ! [[ "$value" =~ ^[0-9]+$ ]]; then
            local msg="Invalid $name='$value' in ${CONFIG_FILE}, using default $default"
            log_info "$msg"
            CONFIG_WARNINGS+=("$msg")
            printf -v "$name" '%s' "$default"
            return
        fi
        if [ "$value" -lt "$min" ] 2>/dev/null || [ "$value" -gt "$max" ] 2>/dev/null; then
            local msg="Invalid $name='$value' in ${CONFIG_FILE}, allowed range is ${min}-${max}. Using default ${default}"
            log_info "$msg"
            CONFIG_WARNINGS+=("$msg")
            printf -v "$name" '%s' "$default"
        fi
    }

    validate_string_max_len_optional() {
        local name="$1" default="$2" max_len="$3" value
        value="${!name-}"
        if [ -z "${value}" ]; then
            printf -v "$name" '%s' "$default"
            return
        fi
        # Strip CR to prevent odd rendering, keep other characters.
        value="${value//$'\r'/}"
        if [ "${#value}" -gt "$max_len" ] 2>/dev/null; then
            local msg="Invalid $name (length ${#value}) in ${CONFIG_FILE}, max length is ${max_len}. Using default ${default}"
            log_info "$msg"
            CONFIG_WARNINGS+=("$msg")
            printf -v "$name" '%s' "$default"
        else
            printf -v "$name" '%s' "$value"
        fi
    }

    # --- Dashboard mirrored settings validation (must match /var/lib/zypper-auto/dashboard-schema.json) ---
    validate_bool_flag ENABLE_FLATPAK_UPDATES true
    validate_bool_flag ENABLE_SNAP_UPDATES true
    validate_bool_flag ENABLE_SOAR_UPDATES true
    validate_bool_flag ENABLE_BREW_UPDATES true
    validate_bool_flag ENABLE_PIPX_UPDATES true
    validate_bool_flag HOOKS_ENABLED true
    validate_bool_flag DASHBOARD_ENABLED true
    validate_bool_flag VERIFY_NOTIFY_USER_ENABLED true

    # Timers: exact allowed list
    validate_allowed_set DL_TIMER_INTERVAL_MINUTES 1 "1,5,10,15,30,60"
    validate_allowed_set NT_TIMER_INTERVAL_MINUTES 1 "1,5,10,15,30,60"
    validate_allowed_set VERIFY_TIMER_INTERVAL_MINUTES 60 "1,5,10,15,30,60"

    # Enums
    validate_allowed_set DOWNLOADER_DOWNLOAD_MODE full "full,detect-only"
    validate_allowed_set AUTO_DUPLICATE_RPM_MODE whitelist "whitelist,thirdparty,both"
    validate_allowed_set CLEANUP_REPORT_FORMAT both "text,json,both"
    validate_allowed_set BOOT_ENTRY_CLEANUP_MODE backup "backup,delete"

    # Snapper knobs (bounded ints + bools)
    validate_bool_flag SNAP_RETENTION_OPTIMIZER_ENABLED true
    validate_nonneg_int_bounded_optional SNAP_RETENTION_MAX_NUMBER_LIMIT 15 0 200
    validate_nonneg_int_bounded_optional SNAP_RETENTION_MAX_NUMBER_LIMIT_IMPORTANT 5 0 100
    validate_nonneg_int_bounded_optional SNAP_RETENTION_MAX_TIMELINE_LIMIT_HOURLY 10 0 200
    validate_nonneg_int_bounded_optional SNAP_RETENTION_MAX_TIMELINE_LIMIT_DAILY 7 0 120
    validate_nonneg_int_bounded_optional SNAP_RETENTION_MAX_TIMELINE_LIMIT_WEEKLY 2 0 104
    validate_nonneg_int_bounded_optional SNAP_RETENTION_MAX_TIMELINE_LIMIT_MONTHLY 2 0 60
    validate_nonneg_int_bounded_optional SNAP_RETENTION_MAX_TIMELINE_LIMIT_YEARLY 0 0 20

    validate_bool_flag SNAP_CLEANUP_CONCURRENCY_GUARD_ENABLED true
    validate_nonneg_int_bounded_optional SNAP_CLEANUP_CRITICAL_FREE_MB 300 0 5000

    validate_bool_flag SNAP_BROKEN_SNAPSHOT_HUNTER_ENABLED false
    validate_string_max_len_optional SNAP_BROKEN_SNAPSHOT_HUNTER_REGEX "aborted|failed" 200
    validate_bool_flag SNAP_BROKEN_SNAPSHOT_HUNTER_CONFIRM true

    validate_int MAX_LOG_FILES 10
    validate_int MAX_LOG_SIZE_MB 50
    validate_int CACHE_EXPIRY_MINUTES 10
    validate_int SNOOZE_SHORT_HOURS 1
    validate_int SNOOZE_MEDIUM_HOURS 4
    validate_int SNOOZE_LONG_HOURS 24
    validate_nonneg_int_optional INSTALL_CLICK_SUPPRESS_MINUTES 120
    validate_int LOCK_RETRY_MAX_ATTEMPTS 10
    validate_int LOCK_RETRY_INITIAL_DELAY_SECONDS 1

    # Validate enumerated string options with safe fallbacks so typos
    # in the config are reported clearly in the log and do not break
    # the installer. Uses indirect expansion instead of eval.
    validate_mode() {
        local name="$1" default="$2" allowed_pattern="$3" value raw_value
        value="${!name-}"
        raw_value="$value"
        # Normalise by stripping CR, surrounding whitespace, and simple outer quotes
        value="$(printf '%s' "$value" | tr -d '\r' | sed -e 's/^\s*//' -e 's/\s*$//' -e 's/^"//' -e 's/"$//')"

        # If empty after normalisation -> use default
        if [ -z "$value" ]; then
            local msg="Missing $name in ${CONFIG_FILE}, using default '$default'"
            log_info "$msg"
            CONFIG_WARNINGS+=("$msg")
            printf -v "$name" '%s' "$default"
            return
        fi

        # Split allowed_pattern on '|' and compare literally (no globbing)
        local IFS='|'
        local allowed ok=0
        for allowed in $allowed_pattern; do
            if [ "$value" = "$allowed" ]; then
                ok=1
                break
            fi
        done

        if [ "$ok" -eq 1 ]; then
            # Valid value, store normalised form
            printf -v "$name" '%s' "$value"
        else
            local msg="Invalid $name='$raw_value' in ${CONFIG_FILE} (allowed: $allowed_pattern); using default '$default'"
            log_info "$msg"
            CONFIG_WARNINGS+=("$msg")
            printf -v "$name" '%s' "$default"
        fi
    }

    # Validate timer intervals (minutes) for downloader/notifier/verification:
    # allow only 1,5,10,15,30,60 minutes to keep systemd OnCalendar
    # expressions simple and predictable.
    validate_interval() {
        local name="$1" default="$2" value
        value="${!name-}"
        if ! [[ "$value" =~ ^[0-9]+$ ]]; then
            local msg="Invalid $name='$value' in ${CONFIG_FILE}, using default $default"
            log_info "$msg"
            CONFIG_WARNINGS+=("$msg")
            printf -v "$name" '%s' "$default"
            return
        fi
        case "$value" in
            1|5|10|15|30|60) ;;
            *)
                local msg="Unsupported $name='$value' in ${CONFIG_FILE} (allowed: 1,5,10,15,30,60); using default $default"
                log_info "$msg"
                CONFIG_WARNINGS+=("$msg")
                printf -v "$name" '%s' "$default"
                ;;
        esac
    }

    validate_interval DL_TIMER_INTERVAL_MINUTES 1
    validate_interval NT_TIMER_INTERVAL_MINUTES 1
    validate_interval VERIFY_TIMER_INTERVAL_MINUTES 60
    validate_bool_flag VERIFY_NOTIFY_USER_ENABLED true
    validate_bool_flag HOOKS_ENABLED true
    validate_bool_flag DASHBOARD_ENABLED true

    # Snapper retention optimizer (optional, used by snapper auto-timers)
    validate_bool_flag SNAP_RETENTION_OPTIMIZER_ENABLED true
    validate_nonneg_int_optional SNAP_RETENTION_MAX_NUMBER_LIMIT 15
    validate_nonneg_int_optional SNAP_RETENTION_MAX_NUMBER_LIMIT_IMPORTANT 5
    validate_nonneg_int_optional SNAP_RETENTION_MAX_TIMELINE_LIMIT_HOURLY 10
    validate_nonneg_int_optional SNAP_RETENTION_MAX_TIMELINE_LIMIT_DAILY 7
    validate_nonneg_int_optional SNAP_RETENTION_MAX_TIMELINE_LIMIT_WEEKLY 2
    validate_nonneg_int_optional SNAP_RETENTION_MAX_TIMELINE_LIMIT_MONTHLY 2
    validate_nonneg_int_optional SNAP_RETENTION_MAX_TIMELINE_LIMIT_YEARLY 0

    # Snapper cleanup safety
    validate_bool_flag SNAP_CLEANUP_CONCURRENCY_GUARD_ENABLED true
    validate_nonneg_int_optional SNAP_CLEANUP_CRITICAL_FREE_MB 300

    # Snapper cleanup Deep Clean (broken snapshot hunter)
    validate_bool_flag SNAP_BROKEN_SNAPSHOT_HUNTER_ENABLED false
    SNAP_BROKEN_SNAPSHOT_HUNTER_REGEX="${SNAP_BROKEN_SNAPSHOT_HUNTER_REGEX:-aborted|failed}"
    validate_bool_flag SNAP_BROKEN_SNAPSHOT_HUNTER_CONFIRM true

    # System Deep Scrub (Option 4)
    validate_bool_flag ZYPPER_CACHE_CLEAN_ENABLED false
    validate_bool_flag ZYPPER_CACHE_CLEAN_CONFIRM true
    validate_bool_flag JOURNAL_VACUUM_ENABLED false
    validate_pos_int_optional JOURNAL_VACUUM_DAYS 7
    validate_nonneg_int_optional JOURNAL_VACUUM_SIZE_MB 0
    validate_bool_flag JOURNAL_VACUUM_CONFIRM true

    validate_bool_flag COREDUMP_VACUUM_ENABLED false
    validate_nonneg_int_optional COREDUMP_VACUUM_MAX_SIZE_MB 200
    validate_bool_flag COREDUMP_VACUUM_CONFIRM true

    validate_bool_flag FLATPAK_UNUSED_CLEAN_ENABLED false
    validate_bool_flag FLATPAK_UNUSED_CLEAN_CONFIRM true

    validate_bool_flag SNAP_REFRESH_RETAIN_TUNE_ENABLED false
    validate_pos_int_optional SNAP_REFRESH_RETAIN_VALUE 2
    if [ "${SNAP_REFRESH_RETAIN_VALUE:-2}" -lt 2 ] 2>/dev/null; then
        SNAP_REFRESH_RETAIN_VALUE=2
    fi
    validate_bool_flag SNAP_REFRESH_RETAIN_TUNE_CONFIRM true

    validate_bool_flag USER_THUMBNAILS_CLEAN_ENABLED false
    validate_nonneg_int_optional USER_THUMBNAILS_CLEAN_DAYS 0
    validate_bool_flag USER_THUMBNAILS_CLEAN_CONFIRM true

    # Cleanup audit reports (Option 4)
    validate_bool_flag CLEANUP_REPORT_ENABLED true
    CLEANUP_REPORT_DIR="${CLEANUP_REPORT_DIR:-/var/log/zypper-auto/cleanup-reports}"
    validate_mode CLEANUP_REPORT_FORMAT both "text|json|both"
    validate_pos_int_optional CLEANUP_REPORT_MAX_FILES 30

    # System Health Automator (Option 5)
    validate_bool_flag BTRFS_MAINTENANCE_TIMERS_ENABLED true
    validate_bool_flag BTRFS_MAINTENANCE_TIMERS_CONFIRM true
    validate_bool_flag FSTRIM_TIMER_ENABLED true
    validate_bool_flag FSTRIM_TIMER_CONFIRM true
    validate_bool_flag BTRFS_MAINTENANCE_TUNE_ENABLED false
    validate_bool_flag BTRFS_MAINTENANCE_TUNE_CONFIRM true

    # Boot entry cleanup (boot menu hygiene)
    validate_bool_flag BOOT_ENTRY_CLEANUP_ENABLED true
    validate_nonneg_int_optional BOOT_ENTRY_CLEANUP_KEEP_LATEST 2
    if [ "${BOOT_ENTRY_CLEANUP_KEEP_LATEST:-2}" -lt 1 ] 2>/dev/null; then
        BOOT_ENTRY_CLEANUP_KEEP_LATEST=1
    fi
    validate_mode BOOT_ENTRY_CLEANUP_MODE backup "backup|delete"
    BOOT_ENTRY_CLEANUP_ENTRIES_DIR="${BOOT_ENTRY_CLEANUP_ENTRIES_DIR:-}"
    validate_bool_flag BOOT_ENTRY_CLEANUP_CONFIRM true

    # Kernel package cleanup (purge-kernels)
    validate_bool_flag KERNEL_PURGE_ENABLED false
    validate_mode KERNEL_PURGE_MODE auto "auto|zypper|systemd"
    validate_bool_flag KERNEL_PURGE_CONFIRM true
    validate_bool_flag KERNEL_PURGE_DRY_RUN false
    validate_bool_flag KERNEL_PURGE_DETAILS false
    validate_pos_int_optional KERNEL_PURGE_TIMEOUT_SECONDS 900

    # DASHBOARD_BROWSER is an optional command name; keep empty by default.
    DASHBOARD_BROWSER="${DASHBOARD_BROWSER:-}"

    # Log effective configuration summary for easier diagnostics
    log_debug "Effective configuration after validation:"
    log_debug "  DL_TIMER_INTERVAL_MINUTES=${DL_TIMER_INTERVAL_MINUTES}"
    log_debug "  NT_TIMER_INTERVAL_MINUTES=${NT_TIMER_INTERVAL_MINUTES}"
    log_debug "  VERIFY_TIMER_INTERVAL_MINUTES=${VERIFY_TIMER_INTERVAL_MINUTES}"
    log_debug "  CACHE_EXPIRY_MINUTES=${CACHE_EXPIRY_MINUTES}"
    log_debug "  SNOOZE_SHORT_HOURS=${SNOOZE_SHORT_HOURS}"
    log_debug "  SNOOZE_MEDIUM_HOURS=${SNOOZE_MEDIUM_HOURS}"
    log_debug "  SNOOZE_LONG_HOURS=${SNOOZE_LONG_HOURS}"
    log_debug "  LOCK_RETRY_MAX_ATTEMPTS=${LOCK_RETRY_MAX_ATTEMPTS}"
    log_debug "  LOCK_RETRY_INITIAL_DELAY_SECONDS=${LOCK_RETRY_INITIAL_DELAY_SECONDS}"
    log_debug "  VERIFY_NOTIFY_USER_ENABLED=${VERIFY_NOTIFY_USER_ENABLED}"
    # Use parameter expansion defaults here so set -u does not trip on
    # configs that do not yet define these keys; validation and
    # missing-key handling below will still normalise them.
    log_debug "  DOWNLOADER_DOWNLOAD_MODE=${DOWNLOADER_DOWNLOAD_MODE:-full}"
    log_debug "  DUP_EXTRA_FLAGS=${DUP_EXTRA_FLAGS:-}"
    log_debug "  AUTO_DUPLICATE_RPM_CLEANUP_PACKAGES=${AUTO_DUPLICATE_RPM_CLEANUP_PACKAGES:-insync}"
    log_debug "  AUTO_DUPLICATE_RPM_MODE=${AUTO_DUPLICATE_RPM_MODE:-whitelist}"
    log_debug "  HOOKS_ENABLED=${HOOKS_ENABLED:-true}"
    log_debug "  DASHBOARD_ENABLED=${DASHBOARD_ENABLED:-true}"
    log_debug "  DASHBOARD_BROWSER=${DASHBOARD_BROWSER:-<default>}"
    log_debug "  HOOKS_BASE_DIR=${HOOKS_BASE_DIR:-/etc/zypper-auto/hooks}"
    log_debug "  SNAP_RETENTION_OPTIMIZER_ENABLED=${SNAP_RETENTION_OPTIMIZER_ENABLED:-true}"
    log_debug "  SNAP_RETENTION_MAX_NUMBER_LIMIT=${SNAP_RETENTION_MAX_NUMBER_LIMIT:-15}"
    log_debug "  SNAP_RETENTION_MAX_NUMBER_LIMIT_IMPORTANT=${SNAP_RETENTION_MAX_NUMBER_LIMIT_IMPORTANT:-5}"
    log_debug "  SNAP_RETENTION_MAX_TIMELINE_LIMIT_HOURLY=${SNAP_RETENTION_MAX_TIMELINE_LIMIT_HOURLY:-10}"
    log_debug "  SNAP_RETENTION_MAX_TIMELINE_LIMIT_DAILY=${SNAP_RETENTION_MAX_TIMELINE_LIMIT_DAILY:-7}"
    log_debug "  SNAP_RETENTION_MAX_TIMELINE_LIMIT_WEEKLY=${SNAP_RETENTION_MAX_TIMELINE_LIMIT_WEEKLY:-2}"
    log_debug "  SNAP_RETENTION_MAX_TIMELINE_LIMIT_MONTHLY=${SNAP_RETENTION_MAX_TIMELINE_LIMIT_MONTHLY:-2}"
    log_debug "  SNAP_RETENTION_MAX_TIMELINE_LIMIT_YEARLY=${SNAP_RETENTION_MAX_TIMELINE_LIMIT_YEARLY:-0}"
    log_debug "  SNAP_CLEANUP_CONCURRENCY_GUARD_ENABLED=${SNAP_CLEANUP_CONCURRENCY_GUARD_ENABLED:-true}"
    log_debug "  SNAP_CLEANUP_CRITICAL_FREE_MB=${SNAP_CLEANUP_CRITICAL_FREE_MB:-300}"
    log_debug "  SNAP_BROKEN_SNAPSHOT_HUNTER_ENABLED=${SNAP_BROKEN_SNAPSHOT_HUNTER_ENABLED:-false}"
    log_debug "  SNAP_BROKEN_SNAPSHOT_HUNTER_REGEX=${SNAP_BROKEN_SNAPSHOT_HUNTER_REGEX:-aborted|failed}"
    log_debug "  SNAP_BROKEN_SNAPSHOT_HUNTER_CONFIRM=${SNAP_BROKEN_SNAPSHOT_HUNTER_CONFIRM:-true}"
    log_debug "  ZYPPER_CACHE_CLEAN_ENABLED=${ZYPPER_CACHE_CLEAN_ENABLED:-false}"
    log_debug "  ZYPPER_CACHE_CLEAN_CONFIRM=${ZYPPER_CACHE_CLEAN_CONFIRM:-true}"
    log_debug "  JOURNAL_VACUUM_ENABLED=${JOURNAL_VACUUM_ENABLED:-false}"
    log_debug "  JOURNAL_VACUUM_DAYS=${JOURNAL_VACUUM_DAYS:-7}"
    log_debug "  JOURNAL_VACUUM_SIZE_MB=${JOURNAL_VACUUM_SIZE_MB:-0}"
    log_debug "  JOURNAL_VACUUM_CONFIRM=${JOURNAL_VACUUM_CONFIRM:-true}"
    log_debug "  COREDUMP_VACUUM_ENABLED=${COREDUMP_VACUUM_ENABLED:-false}"
    log_debug "  COREDUMP_VACUUM_MAX_SIZE_MB=${COREDUMP_VACUUM_MAX_SIZE_MB:-200}"
    log_debug "  COREDUMP_VACUUM_CONFIRM=${COREDUMP_VACUUM_CONFIRM:-true}"
    log_debug "  FLATPAK_UNUSED_CLEAN_ENABLED=${FLATPAK_UNUSED_CLEAN_ENABLED:-false}"
    log_debug "  FLATPAK_UNUSED_CLEAN_CONFIRM=${FLATPAK_UNUSED_CLEAN_CONFIRM:-true}"
    log_debug "  SNAP_REFRESH_RETAIN_TUNE_ENABLED=${SNAP_REFRESH_RETAIN_TUNE_ENABLED:-false}"
    log_debug "  SNAP_REFRESH_RETAIN_VALUE=${SNAP_REFRESH_RETAIN_VALUE:-2}"
    log_debug "  SNAP_REFRESH_RETAIN_TUNE_CONFIRM=${SNAP_REFRESH_RETAIN_TUNE_CONFIRM:-true}"
    log_debug "  USER_THUMBNAILS_CLEAN_ENABLED=${USER_THUMBNAILS_CLEAN_ENABLED:-false}"
    log_debug "  USER_THUMBNAILS_CLEAN_DAYS=${USER_THUMBNAILS_CLEAN_DAYS:-0}"
    log_debug "  USER_THUMBNAILS_CLEAN_CONFIRM=${USER_THUMBNAILS_CLEAN_CONFIRM:-true}"
    log_debug "  CLEANUP_REPORT_ENABLED=${CLEANUP_REPORT_ENABLED:-true}"
    log_debug "  CLEANUP_REPORT_DIR=${CLEANUP_REPORT_DIR:-/var/log/zypper-auto/cleanup-reports}"
    log_debug "  CLEANUP_REPORT_FORMAT=${CLEANUP_REPORT_FORMAT:-both}"
    log_debug "  CLEANUP_REPORT_MAX_FILES=${CLEANUP_REPORT_MAX_FILES:-30}"
    log_debug "  BTRFS_MAINTENANCE_TIMERS_ENABLED=${BTRFS_MAINTENANCE_TIMERS_ENABLED:-true}"
    log_debug "  BTRFS_MAINTENANCE_TIMERS_CONFIRM=${BTRFS_MAINTENANCE_TIMERS_CONFIRM:-true}"
    log_debug "  FSTRIM_TIMER_ENABLED=${FSTRIM_TIMER_ENABLED:-true}"
    log_debug "  FSTRIM_TIMER_CONFIRM=${FSTRIM_TIMER_CONFIRM:-true}"
    log_debug "  BTRFS_MAINTENANCE_TUNE_ENABLED=${BTRFS_MAINTENANCE_TUNE_ENABLED:-false}"
    log_debug "  BTRFS_MAINTENANCE_TUNE_CONFIRM=${BTRFS_MAINTENANCE_TUNE_CONFIRM:-true}"
    log_debug "  BOOT_ENTRY_CLEANUP_ENABLED=${BOOT_ENTRY_CLEANUP_ENABLED:-true}"
    log_debug "  BOOT_ENTRY_CLEANUP_KEEP_LATEST=${BOOT_ENTRY_CLEANUP_KEEP_LATEST:-2}"
    log_debug "  BOOT_ENTRY_CLEANUP_MODE=${BOOT_ENTRY_CLEANUP_MODE:-backup}"
    log_debug "  BOOT_ENTRY_CLEANUP_ENTRIES_DIR=${BOOT_ENTRY_CLEANUP_ENTRIES_DIR:-<auto>}"
    log_debug "  BOOT_ENTRY_CLEANUP_CONFIRM=${BOOT_ENTRY_CLEANUP_CONFIRM:-true}"
    log_debug "  KERNEL_PURGE_ENABLED=${KERNEL_PURGE_ENABLED:-false}"
    log_debug "  KERNEL_PURGE_MODE=${KERNEL_PURGE_MODE:-auto}"
    log_debug "  KERNEL_PURGE_CONFIRM=${KERNEL_PURGE_CONFIRM:-true}"
    log_debug "  KERNEL_PURGE_DRY_RUN=${KERNEL_PURGE_DRY_RUN:-false}"
    log_debug "  KERNEL_PURGE_DETAILS=${KERNEL_PURGE_DETAILS:-false}"
    log_debug "  KERNEL_PURGE_TIMEOUT_SECONDS=${KERNEL_PURGE_TIMEOUT_SECONDS:-900}"
    if [ -n "${WEBHOOK_URL:-}" ]; then
        log_debug "  WEBHOOK_URL=<configured>"
    else
        log_debug "  WEBHOOK_URL=<empty>"
    fi

    # DOWNLOADER_DOWNLOAD_MODE must be spelled exactly "full" or
    # "detect-only" (case-sensitive). Anything else is reported as
    # invalid and reset to the safe default "full".
    validate_mode DOWNLOADER_DOWNLOAD_MODE full "full|detect-only"

    # AUTO_DUPLICATE_RPM_MODE controls how duplicate RPM cleanup behaves
    # in the zypper wrapper. Valid values:
    #   whitelist  - only clean packages listed in AUTO_DUPLICATE_RPM_CLEANUP_PACKAGES
    #   thirdparty - clean duplicate packages whose Vendor is not SUSE/openSUSE
    #   both       - run whitelist cleanup, then thirdparty scan
    validate_mode AUTO_DUPLICATE_RPM_MODE whitelist "whitelist|thirdparty|both"

    # Detect older/stale config files that are missing newer keys.
    # We do NOT overwrite the config automatically; instead we collect
    # warnings and suggest using the reset helper so the user can
    # consciously regenerate `/etc/zypper-auto.conf`.
    local missing_keys=()

    # Helper: record a key as missing if it is not defined at all.
    _mark_missing_key() {
        local key="$1"
        if [ -z "${!key+x}" ]; then
            missing_keys+=("$key")
        fi
    }

    # Keys introduced in newer versions that we depend on for full
    # functionality. Add new ones here as the project evolves.
    _mark_missing_key "DUP_EXTRA_FLAGS"
    _mark_missing_key "LOCK_RETRY_MAX_ATTEMPTS"
    _mark_missing_key "LOCK_RETRY_INITIAL_DELAY_SECONDS"
    _mark_missing_key "DOWNLOADER_DOWNLOAD_MODE"
    _mark_missing_key "LOCK_REMINDER_ENABLED"
    _mark_missing_key "NO_UPDATES_REMINDER_REPEAT_ENABLED"
    _mark_missing_key "UPDATES_READY_REMINDER_REPEAT_ENABLED"
    _mark_missing_key "AUTO_DUPLICATE_RPM_CLEANUP_PACKAGES"
    _mark_missing_key "AUTO_DUPLICATE_RPM_MODE"
    _mark_missing_key "LOG_FOLDER_OPENER"
    _mark_missing_key "WEBHOOK_URL"
    _mark_missing_key "HOOKS_ENABLED"
    _mark_missing_key "HOOKS_BASE_DIR"
    _mark_missing_key "DASHBOARD_ENABLED"
    _mark_missing_key "DASHBOARD_BROWSER"

    # Snapper retention optimizer knobs
    _mark_missing_key "SNAP_RETENTION_OPTIMIZER_ENABLED"
    _mark_missing_key "SNAP_RETENTION_MAX_NUMBER_LIMIT"
    _mark_missing_key "SNAP_RETENTION_MAX_NUMBER_LIMIT_IMPORTANT"
    _mark_missing_key "SNAP_RETENTION_MAX_TIMELINE_LIMIT_HOURLY"
    _mark_missing_key "SNAP_RETENTION_MAX_TIMELINE_LIMIT_DAILY"
    _mark_missing_key "SNAP_RETENTION_MAX_TIMELINE_LIMIT_WEEKLY"
    _mark_missing_key "SNAP_RETENTION_MAX_TIMELINE_LIMIT_MONTHLY"
    _mark_missing_key "SNAP_RETENTION_MAX_TIMELINE_LIMIT_YEARLY"

    # Snapper cleanup safety knobs
    _mark_missing_key "SNAP_CLEANUP_CONCURRENCY_GUARD_ENABLED"
    _mark_missing_key "SNAP_CLEANUP_CRITICAL_FREE_MB"

    # Snapper cleanup Deep Clean (broken snapshot hunter)
    _mark_missing_key "SNAP_BROKEN_SNAPSHOT_HUNTER_ENABLED"
    _mark_missing_key "SNAP_BROKEN_SNAPSHOT_HUNTER_REGEX"
    _mark_missing_key "SNAP_BROKEN_SNAPSHOT_HUNTER_CONFIRM"

    # System Deep Scrub (Option 4)
    _mark_missing_key "ZYPPER_CACHE_CLEAN_ENABLED"
    _mark_missing_key "ZYPPER_CACHE_CLEAN_CONFIRM"
    _mark_missing_key "JOURNAL_VACUUM_ENABLED"
    _mark_missing_key "JOURNAL_VACUUM_DAYS"
    _mark_missing_key "JOURNAL_VACUUM_SIZE_MB"
    _mark_missing_key "JOURNAL_VACUUM_CONFIRM"
    _mark_missing_key "COREDUMP_VACUUM_ENABLED"
    _mark_missing_key "COREDUMP_VACUUM_MAX_SIZE_MB"
    _mark_missing_key "COREDUMP_VACUUM_CONFIRM"
    _mark_missing_key "FLATPAK_UNUSED_CLEAN_ENABLED"
    _mark_missing_key "FLATPAK_UNUSED_CLEAN_CONFIRM"
    _mark_missing_key "SNAP_REFRESH_RETAIN_TUNE_ENABLED"
    _mark_missing_key "SNAP_REFRESH_RETAIN_VALUE"
    _mark_missing_key "SNAP_REFRESH_RETAIN_TUNE_CONFIRM"
    _mark_missing_key "USER_THUMBNAILS_CLEAN_ENABLED"
    _mark_missing_key "USER_THUMBNAILS_CLEAN_DAYS"
    _mark_missing_key "USER_THUMBNAILS_CLEAN_CONFIRM"

    # Cleanup audit reports (Option 4)
    _mark_missing_key "CLEANUP_REPORT_ENABLED"
    _mark_missing_key "CLEANUP_REPORT_DIR"
    _mark_missing_key "CLEANUP_REPORT_FORMAT"
    _mark_missing_key "CLEANUP_REPORT_MAX_FILES"

    # System Health Automator (Option 5)
    _mark_missing_key "BTRFS_MAINTENANCE_TIMERS_ENABLED"
    _mark_missing_key "BTRFS_MAINTENANCE_TIMERS_CONFIRM"
    _mark_missing_key "FSTRIM_TIMER_ENABLED"
    _mark_missing_key "FSTRIM_TIMER_CONFIRM"
    _mark_missing_key "BTRFS_MAINTENANCE_TUNE_ENABLED"
    _mark_missing_key "BTRFS_MAINTENANCE_TUNE_CONFIRM"

    # Boot entry cleanup (boot menu hygiene)
    _mark_missing_key "BOOT_ENTRY_CLEANUP_ENABLED"
    _mark_missing_key "BOOT_ENTRY_CLEANUP_KEEP_LATEST"
    _mark_missing_key "BOOT_ENTRY_CLEANUP_MODE"
    _mark_missing_key "BOOT_ENTRY_CLEANUP_ENTRIES_DIR"
    _mark_missing_key "BOOT_ENTRY_CLEANUP_CONFIRM"

    # Kernel package cleanup (purge-kernels)
    _mark_missing_key "KERNEL_PURGE_ENABLED"
    _mark_missing_key "KERNEL_PURGE_MODE"
    _mark_missing_key "KERNEL_PURGE_CONFIRM"
    _mark_missing_key "KERNEL_PURGE_DRY_RUN"
    _mark_missing_key "KERNEL_PURGE_DETAILS"
    _mark_missing_key "KERNEL_PURGE_TIMEOUT_SECONDS"

    if [ "${#missing_keys[@]}" -gt 0 ]; then
        local keys_joined
        keys_joined="${missing_keys[*]}"
        local msg
        msg="${CONFIG_FILE} appears to be from an older version (missing keys: ${keys_joined}). Run 'sudo zypper-auto-helper --reset-config' to regenerate it with the latest options."
        log_info "$msg"
        CONFIG_WARNINGS+=("$msg")

        # Log a short, per-key feature description so the user knows
        # what functionality is affected.
        log_info "Missing configuration keys and related features:"
        for key in "${missing_keys[@]}"; do
            case "$key" in
                DUP_EXTRA_FLAGS)
                    log_info "  - DUP_EXTRA_FLAGS: controls extra flags added to every 'zypper dup' run (background downloader and notifier), e.g. --allow-vendor-change."
                    ;;
                AUTO_DUPLICATE_RPM_CLEANUP_PACKAGES)
                    log_info "  - AUTO_DUPLICATE_RPM_CLEANUP_PACKAGES: optional list of package names whose older duplicate RPMs may be auto-removed with 'rpm -e --noscripts' when they block updates."
                    ;;
                AUTO_DUPLICATE_RPM_MODE)
                    log_info "  - AUTO_DUPLICATE_RPM_MODE: chooses between whitelist-only cleanup, third-party vendor-based cleanup, or both."
                    ;;
                LOCK_RETRY_MAX_ATTEMPTS)
                    log_info "  - LOCK_RETRY_MAX_ATTEMPTS: how many times the Ready-to-Install helper retries when zypper is locked before giving up."
                    ;;
                LOCK_RETRY_INITIAL_DELAY_SECONDS)
                    log_info "  - LOCK_RETRY_INITIAL_DELAY_SECONDS: base delay (in seconds) between lock retries for the Ready-to-Install helper."
                    ;;
                DOWNLOADER_DOWNLOAD_MODE)
                    log_info "  - DOWNLOADER_DOWNLOAD_MODE: controls whether the background helper only detects updates (detect-only) or also pre-downloads them (full)."
                    ;;
                WEBHOOK_URL)
                    log_info "  - WEBHOOK_URL: optional remote webhook endpoint for success/failure notifications (Discord/Slack/ntfy/etc.)."
                    ;;
                HOOKS_ENABLED)
                    log_info "  - HOOKS_ENABLED: enables /etc/zypper-auto/hooks/{pre,post}.d scripts around interactive updates."
                    ;;
                HOOKS_BASE_DIR)
                    log_info "  - HOOKS_BASE_DIR: base directory for hook stages (default: /etc/zypper-auto/hooks)."
                    ;;
                DASHBOARD_ENABLED)
                    log_info "  - DASHBOARD_ENABLED: enables generation of a static HTML status page."
                    ;;
                DASHBOARD_BROWSER)
                    log_info "  - DASHBOARD_BROWSER: optional browser override for dashboard opening (e.g. firefox)."
                    ;;
                SNAP_RETENTION_OPTIMIZER_ENABLED)
                    log_info "  - SNAP_RETENTION_OPTIMIZER_ENABLED: when true, enabling snapper timers also caps overly aggressive retention limits in /etc/snapper/configs/* to safer maxima."
                    ;;
                SNAP_RETENTION_MAX_NUMBER_LIMIT)
                    log_info "  - SNAP_RETENTION_MAX_NUMBER_LIMIT: maximum allowed NUMBER_LIMIT upper bound (only lowers values when enabling snapper timers)."
                    ;;
                SNAP_RETENTION_MAX_NUMBER_LIMIT_IMPORTANT)
                    log_info "  - SNAP_RETENTION_MAX_NUMBER_LIMIT_IMPORTANT: maximum allowed NUMBER_LIMIT_IMPORTANT upper bound (only lowers values when enabling snapper timers)."
                    ;;
                SNAP_RETENTION_MAX_TIMELINE_LIMIT_HOURLY)
                    log_info "  - SNAP_RETENTION_MAX_TIMELINE_LIMIT_HOURLY: maximum TIMELINE_LIMIT_HOURLY (only lowers values when enabling snapper timers)."
                    ;;
                SNAP_RETENTION_MAX_TIMELINE_LIMIT_DAILY)
                    log_info "  - SNAP_RETENTION_MAX_TIMELINE_LIMIT_DAILY: maximum TIMELINE_LIMIT_DAILY (only lowers values when enabling snapper timers)."
                    ;;
                SNAP_RETENTION_MAX_TIMELINE_LIMIT_WEEKLY)
                    log_info "  - SNAP_RETENTION_MAX_TIMELINE_LIMIT_WEEKLY: maximum TIMELINE_LIMIT_WEEKLY (only lowers values when enabling snapper timers)."
                    ;;
                SNAP_RETENTION_MAX_TIMELINE_LIMIT_MONTHLY)
                    log_info "  - SNAP_RETENTION_MAX_TIMELINE_LIMIT_MONTHLY: maximum TIMELINE_LIMIT_MONTHLY (only lowers values when enabling snapper timers)."
                    ;;
                SNAP_RETENTION_MAX_TIMELINE_LIMIT_YEARLY)
                    log_info "  - SNAP_RETENTION_MAX_TIMELINE_LIMIT_YEARLY: maximum TIMELINE_LIMIT_YEARLY (0 disables yearly retention; only lowers values when enabling snapper timers)."
                    ;;
                SNAP_CLEANUP_CONCURRENCY_GUARD_ENABLED)
                    log_info "  - SNAP_CLEANUP_CONCURRENCY_GUARD_ENABLED: when true, snapper cleanup warns if background cleanup appears to already be running (timer/service/process)."
                    ;;
                SNAP_CLEANUP_CRITICAL_FREE_MB)
                    log_info "  - SNAP_CLEANUP_CRITICAL_FREE_MB: minimum recommended free space on / before running snapper cleanup (btrfs metadata safety)."
                    ;;
                SNAP_BROKEN_SNAPSHOT_HUNTER_ENABLED)
                    log_info "  - SNAP_BROKEN_SNAPSHOT_HUNTER_ENABLED: enables an optional Deep Clean step in Snapper menu cleanup to hunt for and delete obviously aborted/failed snapshots by description."
                    ;;
                SNAP_BROKEN_SNAPSHOT_HUNTER_REGEX)
                    log_info "  - SNAP_BROKEN_SNAPSHOT_HUNTER_REGEX: regex used to detect junk snapshots in the Deep Clean step (default: aborted|failed)."
                    ;;
                SNAP_BROKEN_SNAPSHOT_HUNTER_CONFIRM)
                    log_info "  - SNAP_BROKEN_SNAPSHOT_HUNTER_CONFIRM: when true, asks once before deleting snapshots found by the Deep Clean hunter."
                    ;;
                ZYPPER_CACHE_CLEAN_ENABLED)
                    log_info "  - ZYPPER_CACHE_CLEAN_ENABLED: when true, Snapper menu cleanup also runs 'zypper clean --all' to clear cached metadata and downloaded RPMs."
                    ;;
                ZYPPER_CACHE_CLEAN_CONFIRM)
                    log_info "  - ZYPPER_CACHE_CLEAN_CONFIRM: when true, asks once before running zypper cache cleaning."
                    ;;
                JOURNAL_VACUUM_ENABLED)
                    log_info "  - JOURNAL_VACUUM_ENABLED: when true, Snapper menu cleanup also vacuums systemd journals (journalctl vacuum)."
                    ;;
                JOURNAL_VACUUM_DAYS)
                    log_info "  - JOURNAL_VACUUM_DAYS: number of days of journals to keep when vacuuming by time (default: 7)."
                    ;;
                JOURNAL_VACUUM_SIZE_MB)
                    log_info "  - JOURNAL_VACUUM_SIZE_MB: when set >0, vacuum journals by size (MB) instead of time."
                    ;;
                JOURNAL_VACUUM_CONFIRM)
                    log_info "  - JOURNAL_VACUUM_CONFIRM: when true, asks once before vacuuming journals."
                    ;;
                COREDUMP_VACUUM_ENABLED)
                    log_info "  - COREDUMP_VACUUM_ENABLED: when true, Snapper menu cleanup also vacuums systemd coredumps (crash dumps) via coredumpctl."
                    ;;
                COREDUMP_VACUUM_MAX_SIZE_MB)
                    log_info "  - COREDUMP_VACUUM_MAX_SIZE_MB: maximum total coredump size (MB) to keep after vacuum."
                    ;;
                COREDUMP_VACUUM_CONFIRM)
                    log_info "  - COREDUMP_VACUUM_CONFIRM: when true, asks once before vacuuming coredumps."
                    ;;
                FLATPAK_UNUSED_CLEAN_ENABLED)
                    log_info "  - FLATPAK_UNUSED_CLEAN_ENABLED: when true, Snapper menu cleanup also prunes unused Flatpak runtimes (flatpak uninstall --unused)."
                    ;;
                FLATPAK_UNUSED_CLEAN_CONFIRM)
                    log_info "  - FLATPAK_UNUSED_CLEAN_CONFIRM: when true, asks once before pruning unused Flatpaks."
                    ;;
                SNAP_REFRESH_RETAIN_TUNE_ENABLED)
                    log_info "  - SNAP_REFRESH_RETAIN_TUNE_ENABLED: when true, Snapper menu cleanup can tune snapd refresh.retain to keep fewer old revisions (space saver)."
                    ;;
                SNAP_REFRESH_RETAIN_VALUE)
                    log_info "  - SNAP_REFRESH_RETAIN_VALUE: desired snapd refresh.retain value (min 2)."
                    ;;
                SNAP_REFRESH_RETAIN_TUNE_CONFIRM)
                    log_info "  - SNAP_REFRESH_RETAIN_TUNE_CONFIRM: when true, asks once before tuning snap refresh retention."
                    ;;
                USER_THUMBNAILS_CLEAN_ENABLED)
                    log_info "  - USER_THUMBNAILS_CLEAN_ENABLED: when true, Snapper menu cleanup also deletes cached thumbnails for the desktop user (best-effort)."
                    ;;
                USER_THUMBNAILS_CLEAN_DAYS)
                    log_info "  - USER_THUMBNAILS_CLEAN_DAYS: when set >0, only deletes thumbnail files not accessed in N days; when 0, clears the whole thumbnail cache."
                    ;;
                USER_THUMBNAILS_CLEAN_CONFIRM)
                    log_info "  - USER_THUMBNAILS_CLEAN_CONFIRM: when true, asks once before deleting thumbnails."
                    ;;
                CLEANUP_REPORT_ENABLED)
                    log_info "  - CLEANUP_REPORT_ENABLED: when true, Snapper Full Cleanup writes an extra audit report under CLEANUP_REPORT_DIR (text/JSON)."
                    ;;
                CLEANUP_REPORT_DIR)
                    log_info "  - CLEANUP_REPORT_DIR: directory where cleanup audit reports are written."
                    ;;
                CLEANUP_REPORT_FORMAT)
                    log_info "  - CLEANUP_REPORT_FORMAT: choose report format (text, json, or both)."
                    ;;
                CLEANUP_REPORT_MAX_FILES)
                    log_info "  - CLEANUP_REPORT_MAX_FILES: keep only the newest N cleanup reports (best-effort)."
                    ;;
                BTRFS_MAINTENANCE_TIMERS_ENABLED)
                    log_info "  - BTRFS_MAINTENANCE_TIMERS_ENABLED: when true, Snapper AUTO enable also enables btrfs maintenance timers (scrub/balance/trim/defrag) when available."
                    ;;
                BTRFS_MAINTENANCE_TIMERS_CONFIRM)
                    log_info "  - BTRFS_MAINTENANCE_TIMERS_CONFIRM: when true, asks once before enabling btrfs maintenance timers."
                    ;;
                FSTRIM_TIMER_ENABLED)
                    log_info "  - FSTRIM_TIMER_ENABLED: when true, Snapper AUTO enable also enables fstrim.timer for SSD health (safe)."
                    ;;
                FSTRIM_TIMER_CONFIRM)
                    log_info "  - FSTRIM_TIMER_CONFIRM: when true, asks once before enabling fstrim.timer."
                    ;;
                BTRFS_MAINTENANCE_TUNE_ENABLED)
                    log_info "  - BTRFS_MAINTENANCE_TUNE_ENABLED: when true, Snapper AUTO enable can tune /etc/sysconfig/btrfsmaintenance to reduce slowdowns (best-effort)."
                    ;;
                BTRFS_MAINTENANCE_TUNE_CONFIRM)
                    log_info "  - BTRFS_MAINTENANCE_TUNE_CONFIRM: when true, asks once before editing /etc/sysconfig/btrfsmaintenance."
                    ;;
                BOOT_ENTRY_CLEANUP_ENABLED)
                    log_info "  - BOOT_ENTRY_CLEANUP_ENABLED: when true, snapper cleanup also prunes old kernel boot-menu entry files (BLS) to reduce clutter." 
                    ;;
                BOOT_ENTRY_CLEANUP_KEEP_LATEST)
                    log_info "  - BOOT_ENTRY_CLEANUP_KEEP_LATEST: number of latest installed kernels to keep in the boot menu (running kernel is always kept)."
                    ;;
                BOOT_ENTRY_CLEANUP_MODE)
                    log_info "  - BOOT_ENTRY_CLEANUP_MODE: backup (move old entries to a backup folder) or delete (permanent; not recommended)."
                    ;;
                BOOT_ENTRY_CLEANUP_ENTRIES_DIR)
                    log_info "  - BOOT_ENTRY_CLEANUP_ENTRIES_DIR: optional override for the BLS entries directory (leave empty for auto-detect)."
                    ;;
                BOOT_ENTRY_CLEANUP_CONFIRM)
                    log_info "  - BOOT_ENTRY_CLEANUP_CONFIRM: when true, asks once for confirmation before pruning boot entries."
                    ;;
                KERNEL_PURGE_ENABLED)
                    log_info "  - KERNEL_PURGE_ENABLED: when true, snapper cleanup also runs 'zypper purge-kernels' to auto-remove old kernel packages (respects /etc/zypp/zypp.conf:multiversion.kernels)."
                    ;;
                KERNEL_PURGE_MODE)
                    log_info "  - KERNEL_PURGE_MODE: selects how to run purge-kernels (direct zypper vs systemd service)."
                    ;;
                KERNEL_PURGE_CONFIRM)
                    log_info "  - KERNEL_PURGE_CONFIRM: when true, asks once for confirmation before purging kernel packages."
                    ;;
                KERNEL_PURGE_DRY_RUN)
                    log_info "  - KERNEL_PURGE_DRY_RUN: when true, runs purge-kernels in --dry-run mode (no changes; prints plan)."
                    ;;
                KERNEL_PURGE_DETAILS)
                    log_info "  - KERNEL_PURGE_DETAILS: when true, adds --details for a more detailed purge-kernels summary."
                    ;;
                KERNEL_PURGE_TIMEOUT_SECONDS)
                    log_info "  - KERNEL_PURGE_TIMEOUT_SECONDS: best-effort timeout for purge-kernels (seconds)."
                    ;;
                *)
                    log_info "  - ${key}: (no description available)"
                    ;;
            esac
        done

        # Provide safe defaults for keys we rely on at runtime so the
        # installer and services do not break even with a stale config.
        for key in "${missing_keys[@]}"; do
            case "$key" in
                DUP_EXTRA_FLAGS)
                    DUP_EXTRA_FLAGS=""
                    ;;
                AUTO_DUPLICATE_RPM_CLEANUP_PACKAGES)
                    AUTO_DUPLICATE_RPM_CLEANUP_PACKAGES="insync"
                    ;;
                AUTO_DUPLICATE_RPM_MODE)
                    AUTO_DUPLICATE_RPM_MODE="whitelist"
                    ;;
                LOCK_RETRY_MAX_ATTEMPTS)
                    LOCK_RETRY_MAX_ATTEMPTS=10
                    ;;
                LOCK_RETRY_INITIAL_DELAY_SECONDS)
                    LOCK_RETRY_INITIAL_DELAY_SECONDS=1
                    ;;
                DOWNLOADER_DOWNLOAD_MODE)
                    DOWNLOADER_DOWNLOAD_MODE="full"
                    ;;
                LOG_FOLDER_OPENER)
                    LOG_FOLDER_OPENER=""
                    ;;
                WEBHOOK_URL)
                    WEBHOOK_URL=""
                    ;;
                HOOKS_ENABLED)
                    HOOKS_ENABLED="true"
                    ;;
                HOOKS_BASE_DIR)
                    HOOKS_BASE_DIR="/etc/zypper-auto/hooks"
                    ;;
                DASHBOARD_ENABLED)
                    DASHBOARD_ENABLED="true"
                    ;;
                DASHBOARD_BROWSER)
                    DASHBOARD_BROWSER=""
                    ;;
                SNAP_RETENTION_OPTIMIZER_ENABLED)
                    SNAP_RETENTION_OPTIMIZER_ENABLED="true"
                    ;;
                SNAP_RETENTION_MAX_NUMBER_LIMIT)
                    SNAP_RETENTION_MAX_NUMBER_LIMIT=15
                    ;;
                SNAP_RETENTION_MAX_NUMBER_LIMIT_IMPORTANT)
                    SNAP_RETENTION_MAX_NUMBER_LIMIT_IMPORTANT=5
                    ;;
                SNAP_RETENTION_MAX_TIMELINE_LIMIT_HOURLY)
                    SNAP_RETENTION_MAX_TIMELINE_LIMIT_HOURLY=10
                    ;;
                SNAP_RETENTION_MAX_TIMELINE_LIMIT_DAILY)
                    SNAP_RETENTION_MAX_TIMELINE_LIMIT_DAILY=7
                    ;;
                SNAP_RETENTION_MAX_TIMELINE_LIMIT_WEEKLY)
                    SNAP_RETENTION_MAX_TIMELINE_LIMIT_WEEKLY=2
                    ;;
                SNAP_RETENTION_MAX_TIMELINE_LIMIT_MONTHLY)
                    SNAP_RETENTION_MAX_TIMELINE_LIMIT_MONTHLY=2
                    ;;
                SNAP_RETENTION_MAX_TIMELINE_LIMIT_YEARLY)
                    SNAP_RETENTION_MAX_TIMELINE_LIMIT_YEARLY=0
                    ;;
                SNAP_CLEANUP_CONCURRENCY_GUARD_ENABLED)
                    SNAP_CLEANUP_CONCURRENCY_GUARD_ENABLED="true"
                    ;;
                SNAP_CLEANUP_CRITICAL_FREE_MB)
                    SNAP_CLEANUP_CRITICAL_FREE_MB=300
                    ;;
                SNAP_BROKEN_SNAPSHOT_HUNTER_ENABLED)
                    SNAP_BROKEN_SNAPSHOT_HUNTER_ENABLED="false"
                    ;;
                SNAP_BROKEN_SNAPSHOT_HUNTER_REGEX)
                    SNAP_BROKEN_SNAPSHOT_HUNTER_REGEX="aborted|failed"
                    ;;
                SNAP_BROKEN_SNAPSHOT_HUNTER_CONFIRM)
                    SNAP_BROKEN_SNAPSHOT_HUNTER_CONFIRM="true"
                    ;;
                ZYPPER_CACHE_CLEAN_ENABLED)
                    ZYPPER_CACHE_CLEAN_ENABLED="false"
                    ;;
                ZYPPER_CACHE_CLEAN_CONFIRM)
                    ZYPPER_CACHE_CLEAN_CONFIRM="true"
                    ;;
                JOURNAL_VACUUM_ENABLED)
                    JOURNAL_VACUUM_ENABLED="false"
                    ;;
                JOURNAL_VACUUM_DAYS)
                    JOURNAL_VACUUM_DAYS=7
                    ;;
                JOURNAL_VACUUM_SIZE_MB)
                    JOURNAL_VACUUM_SIZE_MB=0
                    ;;
                JOURNAL_VACUUM_CONFIRM)
                    JOURNAL_VACUUM_CONFIRM="true"
                    ;;
                COREDUMP_VACUUM_ENABLED)
                    COREDUMP_VACUUM_ENABLED="false"
                    ;;
                COREDUMP_VACUUM_MAX_SIZE_MB)
                    COREDUMP_VACUUM_MAX_SIZE_MB=200
                    ;;
                COREDUMP_VACUUM_CONFIRM)
                    COREDUMP_VACUUM_CONFIRM="true"
                    ;;
                FLATPAK_UNUSED_CLEAN_ENABLED)
                    FLATPAK_UNUSED_CLEAN_ENABLED="false"
                    ;;
                FLATPAK_UNUSED_CLEAN_CONFIRM)
                    FLATPAK_UNUSED_CLEAN_CONFIRM="true"
                    ;;
                SNAP_REFRESH_RETAIN_TUNE_ENABLED)
                    SNAP_REFRESH_RETAIN_TUNE_ENABLED="false"
                    ;;
                SNAP_REFRESH_RETAIN_VALUE)
                    SNAP_REFRESH_RETAIN_VALUE=2
                    ;;
                SNAP_REFRESH_RETAIN_TUNE_CONFIRM)
                    SNAP_REFRESH_RETAIN_TUNE_CONFIRM="true"
                    ;;
                USER_THUMBNAILS_CLEAN_ENABLED)
                    USER_THUMBNAILS_CLEAN_ENABLED="false"
                    ;;
                USER_THUMBNAILS_CLEAN_DAYS)
                    USER_THUMBNAILS_CLEAN_DAYS=0
                    ;;
                USER_THUMBNAILS_CLEAN_CONFIRM)
                    USER_THUMBNAILS_CLEAN_CONFIRM="true"
                    ;;
                CLEANUP_REPORT_ENABLED)
                    CLEANUP_REPORT_ENABLED="true"
                    ;;
                CLEANUP_REPORT_DIR)
                    CLEANUP_REPORT_DIR="/var/log/zypper-auto/cleanup-reports"
                    ;;
                CLEANUP_REPORT_FORMAT)
                    CLEANUP_REPORT_FORMAT="both"
                    ;;
                CLEANUP_REPORT_MAX_FILES)
                    CLEANUP_REPORT_MAX_FILES=30
                    ;;
                BTRFS_MAINTENANCE_TIMERS_ENABLED)
                    BTRFS_MAINTENANCE_TIMERS_ENABLED="true"
                    ;;
                BTRFS_MAINTENANCE_TIMERS_CONFIRM)
                    BTRFS_MAINTENANCE_TIMERS_CONFIRM="true"
                    ;;
                FSTRIM_TIMER_ENABLED)
                    FSTRIM_TIMER_ENABLED="true"
                    ;;
                FSTRIM_TIMER_CONFIRM)
                    FSTRIM_TIMER_CONFIRM="true"
                    ;;
                BTRFS_MAINTENANCE_TUNE_ENABLED)
                    BTRFS_MAINTENANCE_TUNE_ENABLED="false"
                    ;;
                BTRFS_MAINTENANCE_TUNE_CONFIRM)
                    BTRFS_MAINTENANCE_TUNE_CONFIRM="true"
                    ;;
                BOOT_ENTRY_CLEANUP_ENABLED)
                    BOOT_ENTRY_CLEANUP_ENABLED="true"
                    ;;
                BOOT_ENTRY_CLEANUP_KEEP_LATEST)
                    BOOT_ENTRY_CLEANUP_KEEP_LATEST=2
                    ;;
                BOOT_ENTRY_CLEANUP_MODE)
                    BOOT_ENTRY_CLEANUP_MODE="backup"
                    ;;
                BOOT_ENTRY_CLEANUP_ENTRIES_DIR)
                    BOOT_ENTRY_CLEANUP_ENTRIES_DIR=""
                    ;;
                BOOT_ENTRY_CLEANUP_CONFIRM)
                    BOOT_ENTRY_CLEANUP_CONFIRM="true"
                    ;;
                KERNEL_PURGE_ENABLED)
                    KERNEL_PURGE_ENABLED="false"
                    ;;
                KERNEL_PURGE_MODE)
                    KERNEL_PURGE_MODE="auto"
                    ;;
                KERNEL_PURGE_CONFIRM)
                    KERNEL_PURGE_CONFIRM="true"
                    ;;
                KERNEL_PURGE_DRY_RUN)
                    KERNEL_PURGE_DRY_RUN="false"
                    ;;
                KERNEL_PURGE_DETAILS)
                    KERNEL_PURGE_DETAILS="false"
                    ;;
                KERNEL_PURGE_TIMEOUT_SECONDS)
                    KERNEL_PURGE_TIMEOUT_SECONDS=900
                    ;;
            esac
        done
    fi
}

# Status update function
update_status() {
    local status="$1"
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"

    # Status file is a single-line indicator consumed by the dashboard.
    # Keep it plain and stable so it can be parsed by humans and tools.
    printf '[%s] %s\n' "${ts}" "${status}" >"${STATUS_FILE}" 2>/dev/null || true
    chmod 644 "${STATUS_FILE}" 2>/dev/null || true

    # Also emit a structured line so the dashboard Recent Activity timeline
    # shows verification/auto-repair progress with the same log format.
    # (This replaces the previous tee-to-LOG_FILE behaviour to avoid duplicates.)
    log_info "[status] ${status}"
}

# Helper: determine whether a system reboot is required.
# Used to surface a "Reboot Required" status in the dashboard, since rolling
# releases frequently update the kernel and core libraries.
check_reboot_required() {
    # Returns 0 if a reboot is required, 1 otherwise.

    local had_errexit rc_nr
    had_errexit=0
    [[ "$-" == *e* ]] && had_errexit=1

    # 1) Prefer zypper's own hint when available.
    if command -v zypper >/dev/null 2>&1; then
        set +e
        zypper needs-reboot >/dev/null 2>&1
        rc_nr=$?
        [ "$had_errexit" -eq 1 ] 2>/dev/null && set -e

        # On openSUSE, rc=1 means reboot needed.
        if [ "$rc_nr" -eq 1 ] 2>/dev/null; then
            return 0
        fi
    fi

    # 2) Marker files used by various tools.
    if [ -f /run/reboot-needed ] || [ -f /var/run/reboot-needed ] || [ -f /run/reboot-required ] || [ -f /var/run/reboot-required ]; then
        return 0
    fi

    # 3) Kernel package version heuristic (best-effort).
    local running_kernel installed_pkg installed_ver
    running_kernel=$(uname -r 2>/dev/null || echo "")

    if command -v rpm >/dev/null 2>&1; then
        installed_pkg=$(rpm -q --last kernel-default kernel-preempt kernel-rt 2>/dev/null | head -n 1 | awk '{print $1}' || true)
        if [ -n "${installed_pkg:-}" ] && [[ "${installed_pkg}" == kernel-*-* ]]; then
            installed_ver=${installed_pkg#kernel-default-}
            installed_ver=${installed_ver#kernel-preempt-}
            installed_ver=${installed_ver#kernel-rt-}

            if [ -n "${installed_ver:-}" ] && [ -n "${running_kernel:-}" ] && [[ "${running_kernel}" != *"${installed_ver}"* ]]; then
                return 0
            fi
        fi
    fi

    return 1
}

# --- Remote monitoring: Webhooks (best-effort) ---
_json_escape() {
    # Minimal JSON escaping for safe webhook payloads and dashboard JSON blobs.
    # Escapes: backslash, double quote, newlines, CR, tabs.
    # Also strips other ASCII control chars which can break JSON parsers.
    local s="$*"
    if command -v tr >/dev/null 2>&1; then
        # delete: NUL..BS, VT, FF, SO..US
        s=$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037')
    fi
    s=${s//\\/\\\\}
    s=${s//"/\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

_redact_url() {
    # Redact secret paths/tokens while keeping enough info for diagnostics.
    # Example: https://example.com/secret -> https://example.com/...
    local url="$1"
    printf '%s' "$url" | sed -E 's#^(https?://[^/]+).*$#\1/...#'
}

send_webhook() {
    # Usage: send_webhook "Title" "Message" "ColorInt(optional)"
    # Color is a Discord-style integer (e.g., 65280 green, 16711680 red).
    local title="$1"
    local message="$2"
    local color="${3:-}"

    # Only run if URL is configured
    [ -z "${WEBHOOK_URL:-}" ] && return 0

    # Never fail the main script because remote monitoring is unavailable.
    if ! command -v curl >/dev/null 2>&1; then
        log_debug "Webhook configured but curl not found; skipping webhook send"
        return 0
    fi

    local url
    url="${WEBHOOK_URL}"

    # Append correlation IDs for traceability
    local trace_tag=""
    [ -n "${ZYPPER_TRACE_ID:-}" ] && trace_tag=" TID=${ZYPPER_TRACE_ID}"
    message="${message}\n\nRUN=${RUN_ID}${trace_tag}"

    local title_esc msg_esc
    title_esc="$(_json_escape "$title")"
    msg_esc="$(_json_escape "$message")"

    # Keep URL out of logs; only show a redacted host.
    log_debug "Sending webhook: title='${title}' url=$(_redact_url "$url")"

    # Provider auto-detection based on URL patterns.
    if [[ "$url" == *"discord.com/api/webhooks"* ]] || [[ "$url" == *"discordapp.com/api/webhooks"* ]]; then
        # Discord embed
        local c
        c="${color:-65280}"
        curl -fsS --connect-timeout 5 --max-time 10 \
            -H "Content-Type: application/json" \
            -d "{\"embeds\":[{\"title\":\"${title_esc}\",\"description\":\"${msg_esc}\",\"color\":${c}}]}" \
            "$url" >/dev/null 2>&1 || true
        return 0
    fi

    if [[ "$url" == *"hooks.slack.com/services"* ]]; then
        # Slack incoming webhook (simple text)
        curl -fsS --connect-timeout 5 --max-time 10 \
            -H "Content-Type: application/json" \
            -d "{\"text\":\"${title_esc}: ${msg_esc}\"}" \
            "$url" >/dev/null 2>&1 || true
        return 0
    fi

    if [[ "$url" == *"ntfy.sh/"* ]]; then
        # ntfy.sh: post text with headers
        curl -fsS --connect-timeout 5 --max-time 10 \
            -H "Title: ${title}" \
            -H "Tags: zypper-auto" \
            -d "${message}" \
            "$url" >/dev/null 2>&1 || true
        return 0
    fi

    # Generic fallback: POST as plain text
    curl -fsS --connect-timeout 5 --max-time 10 \
        -H "Content-Type: text/plain" \
        -d "${title}: ${message}" \
        "$url" >/dev/null 2>&1 || true
    return 0
}

# --- Extensibility: Hook system ---
ensure_hook_dirs() {
    local base
    base="${HOOKS_BASE_DIR:-/etc/zypper-auto/hooks}"
    execute_guarded "Ensure hook base directory exists (${base})" mkdir -p "${base}" || true
    execute_guarded "Ensure pre-hook directory exists" mkdir -p "${base}/pre.d" || true
    execute_guarded "Ensure post-hook directory exists" mkdir -p "${base}/post.d" || true
    execute_guarded "Set hook directory permissions" chmod 755 "${base}" "${base}/pre.d" "${base}/post.d" || true
}

install_hook_templates() {
    # Best-effort: install example templates so users can quickly enable hooks
    # by copying them to a new filename and making them executable.
    local base
    base="${HOOKS_BASE_DIR:-/etc/zypper-auto/hooks}"

    local pre_tpl post_tpl
    pre_tpl="${base}/pre.d/00-example-pre.sh.example"
    post_tpl="${base}/post.d/00-example-post.sh.example"

    if [ ! -f "${pre_tpl}" ]; then
        if write_atomic "${pre_tpl}" <<'EOF'
#!/usr/bin/env bash
# Example pre-update hook for zypper-auto-helper
#
# To enable:
#   sudo cp /etc/zypper-auto/hooks/pre.d/00-example-pre.sh.example /etc/zypper-auto/hooks/pre.d/10-my-pre-hook.sh
#   sudo chmod +x /etc/zypper-auto/hooks/pre.d/10-my-pre-hook.sh
set -euo pipefail

stage="${HOOK_STAGE:-pre}"
run_id="${ZNH_RUN_ID:-}"
tid="${ZYPPER_TRACE_ID:-}"

msg="[HOOK] stage=${stage} RUN=${run_id}${tid:+ TID=${tid}} (example hook)"

if command -v logger >/dev/null 2>&1; then
  logger -t zypper-auto-hook -- "$msg" || true
fi

# Optional file log (best-effort)
echo "$(date '+%Y-%m-%d %H:%M:%S') $msg" >>/var/log/zypper-auto/hooks.log 2>/dev/null || true
EOF
        then
            chmod 644 "${pre_tpl}" 2>/dev/null || true
            log_success "Hook template installed: ${pre_tpl}"
        else
            log_warn "Failed to write hook template: ${pre_tpl} (non-fatal)"
        fi
    fi

    if [ ! -f "${post_tpl}" ]; then
        if write_atomic "${post_tpl}" <<'EOF'
#!/usr/bin/env bash
# Example post-update hook for zypper-auto-helper
#
# To enable:
#   sudo cp /etc/zypper-auto/hooks/post.d/00-example-post.sh.example /etc/zypper-auto/hooks/post.d/90-my-post-hook.sh
#   sudo chmod +x /etc/zypper-auto/hooks/post.d/90-my-post-hook.sh
set -euo pipefail

stage="${HOOK_STAGE:-post}"
run_id="${ZNH_RUN_ID:-}"
tid="${ZYPPER_TRACE_ID:-}"

msg="[HOOK] stage=${stage} RUN=${run_id}${tid:+ TID=${tid}} (example hook)"

if command -v logger >/dev/null 2>&1; then
  logger -t zypper-auto-hook -- "$msg" || true
fi

# Optional file log (best-effort)
echo "$(date '+%Y-%m-%d %H:%M:%S') $msg" >>/var/log/zypper-auto/hooks.log 2>/dev/null || true
EOF
        then
            chmod 644 "${post_tpl}" 2>/dev/null || true
            log_success "Hook template installed: ${post_tpl}"
        else
            log_warn "Failed to write hook template: ${post_tpl} (non-fatal)"
        fi
    fi
}

run_hooks() {
    local stage="$1"

    if [[ "${HOOKS_ENABLED,,}" != "true" ]]; then
        log_debug "Hooks disabled (HOOKS_ENABLED=${HOOKS_ENABLED}); skipping ${stage} hooks"
        return 0
    fi

    local base hook_dir
    base="${HOOKS_BASE_DIR:-/etc/zypper-auto/hooks}"
    hook_dir="${base}/${stage}.d"

    if [ ! -d "${hook_dir}" ]; then
        log_debug "Hook directory not present: ${hook_dir} (skipping)"
        return 0
    fi

    log_info "Running ${stage}-update hooks from ${hook_dir}..."

    local hook ran_any=0
    for hook in "${hook_dir}"/*; do
        [ -e "${hook}" ] || continue
        if [ -f "${hook}" ] && [ -x "${hook}" ]; then
            ran_any=1
            log_info "  -> Executing hook: $(basename "${hook}")"
            if ! execute_guarded "Hook (${stage}): $(basename "${hook}")" "${hook}"; then
                log_warn "Hook $(basename "${hook}") failed (non-fatal)"
            fi
        fi
    done

    if [ "${ran_any}" -eq 0 ] 2>/dev/null; then
        log_debug "No executable hooks found in ${hook_dir}"
    fi

    return 0
}

# --- Visual reporting: Static HTML dashboard ---
_html_escape() {
    local s="$*"
    s=${s//&/\&amp;}
    s=${s//</\&lt;}
    s=${s//>/\&gt;}
    printf '%s' "$s"
}

generate_dashboard() {
    if [[ "${DASHBOARD_ENABLED,,}" != "true" ]]; then
        log_debug "Dashboard disabled (DASHBOARD_ENABLED=${DASHBOARD_ENABLED}); skipping dashboard generation"
        return 0
    fi

    local out_root out_user
    out_root="${LOG_DIR}/status.html"

    out_user=""
    if [ -n "${SUDO_USER_HOME:-}" ]; then
        out_user="${SUDO_USER_HOME}/.local/share/zypper-notify/status.html"
    fi

    local last_status last_install_log last_install_tail now now_iso
    now="$(date '+%Y-%m-%d %H:%M:%S')"
    now_iso="$(date -Iseconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')"
    last_status=$(cat "${STATUS_FILE}" 2>/dev/null || echo "Unknown")

    # Pending updates count (from cached dry-run output)
    local pending_count dry_file
    pending_count="0"
    dry_file="${LOG_DIR}/dry-run-last.txt"
    if [ -f "${dry_file}" ]; then
        pending_count=$(grep -oP "\d+(?= packages to upgrade)" "${dry_file}" 2>/dev/null | head -1 || true)
        if [ -z "${pending_count:-}" ]; then
            pending_count=$(grep -Eo "[0-9]+ packages to upgrade" "${dry_file}" 2>/dev/null | head -1 | awk '{print $1}' || true)
        fi
        if ! [[ "${pending_count:-}" =~ ^[0-9]+$ ]]; then
            pending_count="0"
        fi
    fi

    # Feature toggles (visual state)
    local feat_flatpak feat_snap feat_soar feat_brew feat_pipx
    local feat_flatpak_class feat_snap_class feat_soar_class feat_brew_class feat_pipx_class

    feat_flatpak=$([[ "${ENABLE_FLATPAK_UPDATES,,}" == "true" ]] && echo "ON" || echo "OFF")
    feat_snap=$([[ "${ENABLE_SNAP_UPDATES,,}" == "true" ]] && echo "ON" || echo "OFF")
    feat_soar=$([[ "${ENABLE_SOAR_UPDATES,,}" == "true" ]] && echo "ON" || echo "OFF")
    feat_brew=$([[ "${ENABLE_BREW_UPDATES,,}" == "true" ]] && echo "ON" || echo "OFF")
    feat_pipx=$([[ "${ENABLE_PIPX_UPDATES,,}" == "true" ]] && echo "ON" || echo "OFF")

    feat_flatpak_class=$([[ "${feat_flatpak}" == "ON" ]] && echo "feat-on" || echo "feat-off")
    feat_snap_class=$([[ "${feat_snap}" == "ON" ]] && echo "feat-on" || echo "feat-off")
    feat_soar_class=$([[ "${feat_soar}" == "ON" ]] && echo "feat-on" || echo "feat-off")
    feat_brew_class=$([[ "${feat_brew}" == "ON" ]] && echo "feat-on" || echo "feat-off")
    feat_pipx_class=$([[ "${feat_pipx}" == "ON" ]] && echo "feat-on" || echo "feat-off")

    # Determine status color for a quick-glance badge.
    local status_color last_status_lc
    status_color="#7f8c8d" # Default gray
    last_status_lc="${last_status,,}"
    if [[ "${last_status_lc}" == *"error"* ]] || [[ "${last_status_lc}" == *"failed"* ]] || [[ "${last_status_lc}" == *"crash"* ]]; then
        status_color="#e74c3c" # Red
    elif [[ "${last_status_lc}" == *"complete"* ]] || [[ "${last_status_lc}" == *"success"* ]]; then
        status_color="#2ecc71" # Green
    elif [[ "${last_status_lc}" == *"downloading"* ]] || [[ "${last_status_lc}" == *"refreshing"* ]]; then
        status_color="#3498db" # Blue
    fi

    last_install_log=""
    last_install_log=$(find "${LOG_DIR}" -maxdepth 1 -type f -name 'install-*.log' -printf '%T@\t%p\n' 2>/dev/null \
        | sort -nr | head -1 | cut -f2- || true)

    last_install_tail=""
    if [ -n "${last_install_log}" ] && [ -f "${last_install_log}" ]; then
        # Use a slightly larger tail for the dashboard so it feels like a UI,
        # without embedding the entire log.
        last_install_tail=$(tail -n 100 "${last_install_log}" 2>/dev/null || true)
    fi

    # Extract the last appended Flight Report (executive summary) from the most recent
    # log that actually contains it. The newest log may be a "--dashboard" run, which
    # won't include a Flight Report.
    local flight_report_log flight_report_raw
    flight_report_log=""
    flight_report_raw=""

    while IFS= read -r f; do
        [ -n "${f:-}" ] || continue
        if grep -q "ZYPPER-AUTO FLIGHT REPORT:" "$f" 2>/dev/null; then
            flight_report_log="$f"
            break
        fi
    done < <(
        find "${LOG_DIR}" -maxdepth 1 -type f -name 'install-*.log' -printf '%T@\t%p\n' 2>/dev/null \
            | sort -nr | cut -f2- || true
    )

    if [ -n "${flight_report_log}" ] && [ -f "${flight_report_log}" ]; then
        flight_report_raw=$(awk '
            BEGIN {cap=0; buf=""; last=""; pending_sep=""; }
            /^===================================================$/ {
                if (cap==1) {
                    buf = buf $0 "\n";
                    last = buf;
                    buf="";
                    cap=0;
                } else {
                    pending_sep=$0;
                }
                next;
            }
            /^ZYPPER-AUTO FLIGHT REPORT:/ {
                cap=1;
                buf="";
                if (pending_sep!="") { buf = pending_sep "\n"; pending_sep=""; }
                buf = buf $0 "\n";
                next;
            }
            cap==1 { buf = buf $0 "\n"; }
            END {
                if (last!="") printf "%s", last;
                else if (buf!="") printf "%s", buf;
            }
        ' "${flight_report_log}" 2>/dev/null || true)
    fi

    local dl_timer nt_timer verify_timer
    dl_timer=$(systemctl is-active "${DL_SERVICE_NAME}.timer" 2>/dev/null || echo "unknown")
    verify_timer=$(systemctl is-active "${VERIFY_SERVICE_NAME}.timer" 2>/dev/null || echo "unknown")
    nt_timer="unknown"
    if [ -n "${SUDO_USER:-}" ]; then
        local bus
        bus="unix:path=/run/user/$(id -u "${SUDO_USER}" 2>/dev/null || echo "")/bus"
        nt_timer=$(sudo -u "${SUDO_USER}" DBUS_SESSION_BUS_ADDRESS="$bus" systemctl --user is-active "${NT_SERVICE_NAME}.timer" 2>/dev/null || echo "unknown")
    fi

    # Timer status classes for badges.
    local dl_timer_class verify_timer_class nt_timer_class
    dl_timer_class="timer-inactive"
    verify_timer_class="timer-inactive"
    nt_timer_class="timer-inactive"
    if [ "${dl_timer}" = "active" ]; then dl_timer_class="timer-active"; fi
    if [ "${verify_timer}" = "active" ]; then verify_timer_class="timer-active"; fi
    if [ "${nt_timer}" = "active" ]; then nt_timer_class="timer-active"; fi

    # Last verification summary (auto-fix counters)
    local verify_last_fixed verify_last_detected verify_last_remaining verify_last_ts verify_last_ts_esc
    verify_last_fixed="0"
    verify_last_detected="0"
    verify_last_remaining="0"
    verify_last_ts="unknown"
    local verify_summary_file
    verify_summary_file="${LOG_DIR}/last-verify-summary.txt"
    if [ -f "${verify_summary_file}" ]; then
        verify_last_fixed=$(grep -E '^fixed=' "${verify_summary_file}" 2>/dev/null | head -n 1 | cut -d= -f2- || echo 0)
        verify_last_detected=$(grep -E '^detected=' "${verify_summary_file}" 2>/dev/null | head -n 1 | cut -d= -f2- || echo 0)
        verify_last_remaining=$(grep -E '^remaining=' "${verify_summary_file}" 2>/dev/null | head -n 1 | cut -d= -f2- || echo 0)
        verify_last_ts=$(grep -E '^ts_human=' "${verify_summary_file}" 2>/dev/null | head -n 1 | cut -d= -f2- || echo "unknown")
    fi
    if ! [[ "${verify_last_fixed:-}" =~ ^[0-9]+$ ]]; then verify_last_fixed="0"; fi
    if ! [[ "${verify_last_detected:-}" =~ ^[0-9]+$ ]]; then verify_last_detected="0"; fi
    if ! [[ "${verify_last_remaining:-}" =~ ^[0-9]+$ ]]; then verify_last_remaining="0"; fi
    verify_last_ts_esc="$(_html_escape "${verify_last_ts}")"

    # Snapper timers (for dashboard snapper panel): enabled/partial/disabled/missing.
    local snapper_timeline_timer snapper_cleanup_timer snapper_boot_timer
    local snapper_timeline_class snapper_cleanup_class snapper_boot_class

    __znh_dash_timer_state() {
        local unit="$1"
        if ! __znh_unit_file_exists_system "${unit}"; then
            printf '%s' "missing"
            return 0
        fi

        local en=0 act=0
        if systemctl is-enabled --quiet "${unit}" 2>/dev/null; then
            en=1
        fi
        if systemctl is-active --quiet "${unit}" 2>/dev/null; then
            act=1
        fi

        if [ "${en}" -eq 1 ] 2>/dev/null && [ "${act}" -eq 1 ] 2>/dev/null; then
            printf '%s' "enabled"
        elif [ "${en}" -eq 1 ] 2>/dev/null || [ "${act}" -eq 1 ] 2>/dev/null; then
            printf '%s' "partial"
        else
            printf '%s' "disabled"
        fi
        return 0
    }

    __znh_dash_timer_class() {
        local state="$1"
        case "${state}" in
            enabled) printf '%s' "timer-active" ;;
            partial) printf '%s' "timer-partial" ;;
            *) printf '%s' "timer-inactive" ;;
        esac
        return 0
    }

    snapper_timeline_timer="$(__znh_dash_timer_state snapper-timeline.timer 2>/dev/null || echo disabled)"
    snapper_cleanup_timer="$(__znh_dash_timer_state snapper-cleanup.timer 2>/dev/null || echo disabled)"
    snapper_boot_timer="$(__znh_dash_timer_state snapper-boot.timer 2>/dev/null || echo disabled)"

    snapper_timeline_class="$(__znh_dash_timer_class "${snapper_timeline_timer}" 2>/dev/null || echo timer-inactive)"
    snapper_cleanup_class="$(__znh_dash_timer_class "${snapper_cleanup_timer}" 2>/dev/null || echo timer-inactive)"
    snapper_boot_class="$(__znh_dash_timer_class "${snapper_boot_timer}" 2>/dev/null || echo timer-inactive)"

    # System metrics for quick scanning.
    local kernel_ver uptime_info disk_used disk_total disk_percent disk_usage_display mem_usage
    kernel_ver=$(uname -r 2>/dev/null || echo "Unknown")
    # Uptime: prefer `uptime -p` but don't depend on PATH (systemd units can have a minimal PATH).
    # Fallback to /proc/uptime parsing so the dashboard never shows Unknown on normal systems.
    uptime_info=""
    if [ -x /usr/bin/uptime ]; then
        uptime_info=$(/usr/bin/uptime -p 2>/dev/null | sed 's/^up //' || true)
    elif command -v uptime >/dev/null 2>&1; then
        uptime_info=$(uptime -p 2>/dev/null | sed 's/^up //' || true)
    fi
    if [ -z "${uptime_info}" ] && [ -r /proc/uptime ]; then
        # /proc/uptime: "<seconds> <idle_seconds>"
        up_s=$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo "")
        if [[ "${up_s:-}" =~ ^[0-9]+$ ]]; then
            d=$((up_s/86400))
            h=$(((up_s%86400)/3600))
            m=$(((up_s%3600)/60))
            if [ "$d" -gt 0 ]; then
                uptime_info="${d} days, ${h} hours, ${m} minutes"
            elif [ "$h" -gt 0 ]; then
                uptime_info="${h} hours, ${m} minutes"
            else
                uptime_info="${m} minutes"
            fi
        fi
    fi
    if [ -z "${uptime_info}" ]; then
        uptime_info="Unknown"
    fi

    # Disk: used/total + percent integer.
    disk_used=$(df -h / 2>/dev/null | awk 'NR==2 {print $3}' || echo "?")
    disk_total=$(df -h / 2>/dev/null | awk 'NR==2 {print $2}' || echo "?")
    disk_percent=$(df -P / 2>/dev/null | awk 'NR==2 {print $5}' | tr -d '%' || echo "0")
    if ! [[ "${disk_percent:-}" =~ ^[0-9]+$ ]]; then
        disk_percent=0
    fi
    disk_usage_display="${disk_used}/${disk_total} (${disk_percent}%)"

    # Memory: used/total (best-effort)
    mem_usage="Unknown"
    if command -v free >/dev/null 2>&1; then
        mem_usage=$(free -h 2>/dev/null | awk '/^Mem:/ {print $3 "/" $2}' || echo "Unknown")
    fi

    local last_status_esc last_tail_esc last_install_log_esc flight_report_esc flight_report_log_esc
    last_status_esc="$(_html_escape "$last_status")"
    last_tail_esc="$(_html_escape "$last_install_tail")"
    last_install_log_esc="$(_html_escape "$last_install_log")"
    flight_report_esc="$(_html_escape "$flight_report_raw")"
    flight_report_log_esc="$(_html_escape "$flight_report_log")"

    mkdir -p "$(dirname "${out_root}")" 2>/dev/null || true

    cat >"${out_root}" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Zypper Auto Command Center</title>
  <style>
    html { color-scheme: light dark; }
    /* Ensure native form controls (especially <select>/<option>) follow our theme */
    html[data-theme="dark"] { color-scheme: dark; }
    html[data-theme="light"] { color-scheme: light; }

    select, input[type="number"], input[type="text"], textarea {
        color: var(--text);
        background: rgba(255,255,255,0.04);
        border: 1px solid var(--border);
    }
    select option {
        background: var(--bg);
        color: var(--text);
    }

    :root {
        --bg: #f6f7fb;
        --card-bg: rgba(255,255,255,0.78);
        --text: #0f172a;
        --muted: rgba(15,23,42,0.68);
        --accent: #2563eb;
        --accent-2: #7c3aed;
        --border: rgba(15,23,42,0.10);
        --shadow: 0 10px 30px rgba(15,23,42,0.10);
        --subtle: rgba(15,23,42,0.04);
        --code-bg: #0b1220;
        --code-text: #e5e7eb;
        --focus: rgba(37, 99, 235, 0.35);
        --success: #16a34a;
        --danger: #ef4444;
        --warning: #f59e0b;

        --radius: 16px;
        --radius-sm: 12px;
    }

    /* Explicit theme overrides (JS toggles html[data-theme]) */
    html[data-theme="dark"] {
        --bg: #0b1220;
        --card-bg: rgba(17, 24, 39, 0.72);
        --text: #e5e7eb;
        --muted: rgba(229,231,235,0.70);
        --accent: #60a5fa;
        --accent-2: #a78bfa;
        --border: rgba(255,255,255,0.10);
        --shadow: 0 16px 40px rgba(0,0,0,0.55);
        --subtle: rgba(255,255,255,0.06);
        --code-bg: #060b14;
        --code-text: #d1d5db;
        --focus: rgba(96, 165, 250, 0.40);
    }

    /* Default to dark when system prefers dark, unless user forced a theme */
    @media (prefers-color-scheme: dark) {
        html:not([data-theme]) {
            --bg: #0b1220;
            --card-bg: rgba(17, 24, 39, 0.72);
            --text: #e5e7eb;
            --muted: rgba(229,231,235,0.70);
            --accent: #60a5fa;
            --accent-2: #a78bfa;
            --border: rgba(255,255,255,0.10);
            --shadow: 0 16px 40px rgba(0,0,0,0.55);
            --subtle: rgba(255,255,255,0.06);
            --code-bg: #060b14;
            --code-text: #d1d5db;
            --focus: rgba(96, 165, 250, 0.40);
        }
    }

    * { box-sizing: border-box; }

    body {
        font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, "Apple Color Emoji", "Segoe UI Emoji";
        padding: 24px;
        margin: 0;
        color: var(--text);
        line-height: 1.55;

        /* Layered gradients for a modern "pro" look */
        background:
            radial-gradient(1200px 700px at 15% 5%, rgba(37,99,235,0.16), transparent 60%),
            radial-gradient(900px 600px at 85% 10%, rgba(124,58,237,0.14), transparent 55%),
            radial-gradient(900px 600px at 50% 95%, rgba(16,185,129,0.10), transparent 55%),
            var(--bg);
    }

    .container { max-width: 1040px; margin: 0 auto; }

    .card {
        background: var(--card-bg);
        padding: 24px;
        border-radius: var(--radius);
        box-shadow: var(--shadow);
        margin-bottom: 18px;
        border: 1px solid var(--border);
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        transition: transform 180ms ease, border-color 180ms ease, box-shadow 180ms ease;
    }
    .card:hover { transform: translateY(-2px); border-color: rgba(37,99,235,0.18); }

    h1 {
        margin: 0;
        font-size: 1.35rem;
        letter-spacing: 0.2px;
        color: var(--text);
        display: flex;
        align-items: center;
        gap: 10px;
    }

    h2 {
        font-size: 1.02rem;
        margin: 0 0 14px 0;
        padding-bottom: 10px;
        color: var(--muted);
        border-bottom: 1px solid var(--border);
        letter-spacing: 0.2px;
    }

    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; }

    .stat-box {
        background: linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.00)), var(--subtle);
        padding: 14px;
        border-radius: var(--radius-sm);
        border: 1px solid var(--border);
        box-shadow: 0 1px 0 rgba(255,255,255,0.06) inset;
    }

    .stat-label {
        font-size: 0.78rem;
        color: var(--muted);
        display: block;
        margin-bottom: 6px;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        font-weight: 800;
    }

    .stat-value { font-weight: 800; font-size: 1.02rem; }

    code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }

    /* Small pill controls */
    .pill {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 8px 12px;
        border-radius: 999px;
        border: 1px solid var(--border);
        background: rgba(255,255,255,0.04);
        color: var(--muted);
        font-weight: 800;
        font-size: 0.85rem;
        cursor: pointer;
        transition: transform 150ms ease, border-color 150ms ease, background 150ms ease;
        user-select: none;
    }
    .pill:hover { transform: translateY(-1px); border-color: rgba(37,99,235,0.30); background: rgba(37,99,235,0.07); }
    .pill:focus { outline: none; box-shadow: 0 0 0 4px var(--focus); }
    .pill.active {
        background: linear-gradient(135deg, rgba(37,99,235,0.20), rgba(124,58,237,0.16));
        border-color: rgba(37,99,235,0.38);
        color: var(--text);
    }
    html[data-theme="dark"] .pill.active,
    html:not([data-theme]) .pill.active {
        color: var(--text);
    }

    input[type="checkbox"] { accent-color: var(--accent); }

    /* JS-only motion effects (kept subtle) */
    @media (prefers-reduced-motion: reduce) {
        * { scroll-behavior: auto !important; transition: none !important; animation: none !important; }
    }

    html.js .card {
        opacity: 0;
        transform: translateY(10px);
    }
    html.js .card.enter {
        opacity: 1;
        transform: translateY(0);
        transition: opacity 380ms ease, transform 380ms ease, border-color 180ms ease, box-shadow 180ms ease;
    }

    @keyframes flash {
        0%   { box-shadow: 0 0 0 0 rgba(37,99,235,0.0); }
        30%  { box-shadow: 0 0 0 6px rgba(37,99,235,0.18); }
        100% { box-shadow: 0 0 0 0 rgba(37,99,235,0.0); }
    }
    .flash {
        animation: flash 700ms ease;
        border-radius: 10px;
    }

    @keyframes pulseGlow {
        0%   { transform: translateY(0); filter: saturate(1); }
        50%  { transform: translateY(-1px); filter: saturate(1.2); }
        100% { transform: translateY(0); filter: saturate(1); }
    }
    .pulse {
        animation: pulseGlow 600ms ease;
    }

    /* Ripple effect */
    .ripple {
        position: absolute;
        border-radius: 999px;
        transform: scale(0);
        opacity: 0.7;
        pointer-events: none;
        background: radial-gradient(circle, rgba(255,255,255,0.8) 0%, rgba(255,255,255,0.25) 35%, rgba(255,255,255,0.0) 70%);
        animation: ripple 650ms ease-out;
        mix-blend-mode: overlay;
    }
    @keyframes ripple {
        to { transform: scale(12); opacity: 0; }
    }

    /* Toast */
    #toast-wrap {
        position: fixed;
        right: 18px;
        bottom: 18px;
        display: grid;
        gap: 10px;
        z-index: 9999;
        max-width: min(420px, calc(100vw - 36px));
    }
    .toast {
        background: rgba(17, 24, 39, 0.82);
        color: #fff;
        border: 1px solid rgba(255,255,255,0.12);
        border-radius: 14px;
        padding: 12px 14px;
        box-shadow: 0 18px 40px rgba(0,0,0,0.35);
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        font-weight: 800;
        font-size: 0.92rem;
        transform: translateY(10px);
        opacity: 0;
        animation: toastIn 260ms ease forwards;
    }
    .toast small { display:block; font-weight: 700; opacity: 0.8; margin-top: 4px; }
    .toast.ok { border-color: rgba(34,197,94,0.35); }
    .toast.err { border-color: rgba(239,68,68,0.35); }
    @keyframes toastIn { to { transform: translateY(0); opacity: 1; } }
    @keyframes toastOut { to { transform: translateY(6px); opacity: 0; } }

    /* Feature toggles */
    .feat-grid { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px; }
    .feat-badge { font-size: 0.8rem; padding: 6px 10px; border-radius: 10px; background: var(--subtle); border: 1px solid var(--border); display: inline-flex; align-items: center; gap: 8px; }
    .feat-dot { font-size: 0.9rem; }
    .feat-on { color: #2ecc71; font-weight: 900; }
    .feat-off { color: var(--muted); font-weight: 900; }

    /* Command Center action buttons */
    .action-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-top: 12px; }
    .cmd-btn {
        font-family: inherit;
        background: linear-gradient(180deg, rgba(255,255,255,0.06), rgba(255,255,255,0.00)), var(--subtle);
        border: 1px solid var(--border);
        color: var(--text);
        padding: 14px;
        border-radius: var(--radius-sm);
        cursor: pointer;
        text-align: left;
        transition: transform 150ms ease, border-color 150ms ease, box-shadow 150ms ease;
        position: relative;
        overflow: hidden;
        box-shadow: 0 1px 0 rgba(255,255,255,0.06) inset;
    }
    .cmd-btn:hover {
        transform: translateY(-2px);
        border-color: rgba(37,99,235,0.30);
        box-shadow: 0 18px 40px rgba(15,23,42,0.12);
    }
    .cmd-btn:active { transform: translateY(-1px) scale(0.99); }
    .cmd-btn:focus { outline: none; box-shadow: 0 0 0 4px var(--focus); }
    .cmd-label { display: block; font-weight: 950; font-size: 0.95rem; margin-bottom: 5px; letter-spacing: 0.15px; }
    .cmd-desc { display: block; font-size: 0.80rem; color: var(--muted); line-height: 1.25; }
    .cmd-copy-feedback {
        position: absolute; top: 0; left: 0; right: 0; bottom: 0;
        background: linear-gradient(90deg, var(--success), #22c55e);
        color: white;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: 900;
        opacity: 0;
        pointer-events: none;
        transition: opacity 0.18s;
    }
    .cmd-btn.copied .cmd-copy-feedback { opacity: 1; }

    /* Status badges */
    .status-badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 7px 14px;
        border-radius: 999px;
        color: white;
        font-weight: 900;
        font-size: 0.86rem;
        background:
            linear-gradient(90deg, rgba(255,255,255,0.18), rgba(255,255,255,0.05)),
            var(--status-color, ${status_color});
        box-shadow: 0 10px 22px rgba(0,0,0,0.18);
        border: 1px solid rgba(255,255,255,0.18);
        max-width: 100%;
        overflow-wrap: anywhere;
    }
    .timer-active { color: #2ecc71; font-weight: 800; }
    .timer-partial { color: #f59e0b; font-weight: 800; }
    .timer-inactive { color: #e74c3c; font-weight: 800; }

    /* Disk usage bar */
    .progress-track { height: 10px; background: rgba(0,0,0,0.06); border-radius: 999px; margin-top: 10px; overflow: hidden; border: 1px solid var(--border); }
    .progress-fill { height: 100%; background: linear-gradient(90deg, var(--accent), var(--accent-2)); border-radius: 999px; width: 0%; transition: width 0.45s ease; }

    /* Logs */
    .log-container { position: relative; }

    .copy-btn,
    .jump-btn {
        position: absolute;
        top: 10px;
        font-family: inherit;
        background: rgba(255,255,255,0.06);
        border: 1px solid var(--border);
        color: var(--muted);
        padding: 8px 10px;
        font-size: 0.85rem;
        border-radius: 10px;
        cursor: pointer;
        transition: transform 150ms ease, border-color 150ms ease, background 150ms ease, opacity 150ms ease;
        backdrop-filter: blur(6px);
        -webkit-backdrop-filter: blur(6px);
        user-select: none;
    }

    .copy-btn { right: 10px; }
    .jump-btn { right: 104px; opacity: 0; pointer-events: none; }
    .log-container.show-jump .jump-btn { opacity: 1; pointer-events: auto; }

    .copy-btn:hover,
    .jump-btn:hover {
        transform: translateY(-1px);
        border-color: rgba(37,99,235,0.28);
        background: rgba(37,99,235,0.08);
        color: var(--text);
    }
    .copy-btn:focus,
    .jump-btn:focus { outline: none; box-shadow: 0 0 0 4px var(--focus); }

    pre {
        background: linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0.00)), var(--code-bg);
        color: var(--code-text);
        padding: 16px;
        border-radius: var(--radius-sm);
        overflow-x: auto;
        font-size: 0.86rem;
        white-space: pre-wrap;
        border: 1px solid rgba(255,255,255,0.12);
        max-height: 460px;
        overflow-y: auto;
        box-shadow: 0 1px 0 rgba(255,255,255,0.06) inset;
    }

    /* Keyword highlighting */
    .log-time { color: #888; }
    .log-info { color: #61afef; }
    .log-success { color: #98c379; font-weight: 800; }
    .log-warn { color: #e5c07b; font-weight: 800; }
    .log-error { color: #e06c75; font-weight: 900; }

    .footer { font-size: 0.85rem; color: var(--muted); text-align: center; margin-top: 28px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap: 10px;">
          <h1>🚀 Zypper Auto Command Center</h1>
          <span class="status-badge" id="status-badge">${last_status_esc}</span>
      </div>
      <p style="color:var(--muted); margin-top:8px; margin-bottom:0; font-size:0.9rem;">
        Generated <span id="time-ago">just now</span> (<span style="font-family:monospace" id="generated-at">${now}</span>) • Pending Updates: <strong id="pending-count">${pending_count}</strong>
      </p>
      <div style="margin-top:12px; display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
        <label class="pill" style="gap:10px;">
          <input type="checkbox" id="live-toggle" /> Live mode
        </label>
        <button class="pill" id="theme-toggle" type="button" title="Toggle theme (auto/light/dark)">Theme: Auto</button>
        <span style="font-size:0.85rem; color: var(--muted);">Live polls <code>status-data.json</code>, <code>download-status.txt</code>, and <code>perf-data.json</code> (best via <code>http://</code>).</span>
      </div>

      <div class="grid" style="margin-top: 18px;">
        <div class="stat-box">
            <span class="stat-label">Kernel</span>
            <span class="stat-value" id="kernel-ver">${kernel_ver}</span>
        </div>
        <div class="stat-box">
            <span class="stat-label">Uptime</span>
            <span class="stat-value" id="uptime-info">${uptime_info}</span>
        </div>
        <div class="stat-box">
            <span class="stat-label">Memory (Used/Total)</span>
            <span class="stat-value" id="mem-usage">${mem_usage}</span>
        </div>
        <div class="stat-box">
            <span class="stat-label">Disk Usage (/)</span>
            <span class="stat-value" id="disk-usage">${disk_usage_display}</span>
            <div class="progress-track">
                <div class="progress-fill" id="disk-bar" data-percent="${disk_percent}"></div>
            </div>
        </div>
      </div>
    </div>

    <div class="card">
      <h2>⚙️ Features & Config</h2>
      <div class="stat-label" style="text-transform:none;">Active Modules</div>
      <div class="feat-grid">
        <div class="feat-badge"><span class="feat-dot ${feat_flatpak_class}" id="feat-flatpak-dot">●</span> Flatpak: <strong id="feat-flatpak-val">${feat_flatpak}</strong></div>
        <div class="feat-badge"><span class="feat-dot ${feat_snap_class}" id="feat-snap-dot">●</span> Snap: <strong id="feat-snap-val">${feat_snap}</strong></div>
        <div class="feat-badge"><span class="feat-dot ${feat_soar_class}" id="feat-soar-dot">●</span> Soar: <strong id="feat-soar-val">${feat_soar}</strong></div>
        <div class="feat-badge"><span class="feat-dot ${feat_brew_class}" id="feat-brew-dot">●</span> Brew: <strong id="feat-brew-val">${feat_brew}</strong></div>
        <div class="feat-badge"><span class="feat-dot ${feat_pipx_class}" id="feat-pipx-dot">●</span> Pipx: <strong id="feat-pipx-val">${feat_pipx}</strong></div>
      </div>

      <details id="settings-drawer" style="margin-top: 16px;">
        <summary style="cursor:pointer; font-weight: 900; color: var(--text);">▸ Settings (edit /etc/zypper-auto.conf)</summary>
        <div style="margin-top: 12px; color: var(--muted); font-size: 0.9rem;">
          This panel writes settings via a localhost API (<code>127.0.0.1:8766</code>). If a value is invalid, it will auto-heal back to safe defaults.
        </div>
        <div id="settings-banner" style="margin-top: 10px; display:none; padding: 10px 12px; border-radius: 12px; border: 1px solid rgba(239,68,68,0.35); background: rgba(239,68,68,0.08); color: var(--text); font-weight: 900;"></div>
        <div id="settings-form" style="margin-top: 12px; display:grid; gap: 10px;"></div>
        <div style="margin-top: 12px; display:flex; gap:10px; flex-wrap:wrap;">
          <button class="pill" type="button" id="settings-save">Save</button>
          <button class="pill" type="button" id="settings-reload">Reload</button>
          <button class="pill" type="button" id="settings-reset" title="Backup and regenerate defaults" style="border-color: rgba(239,68,68,0.30);">Factory reset</button>
        </div>
      </details>

      <div style="margin-top: 14px;">
        <span class="stat-label" style="text-transform:none;">Run ID</span>
        <code style="font-size:0.85rem; background:var(--subtle); padding:2px 6px; border-radius:6px; border:1px solid var(--border);" id="run-id">${RUN_ID}</code>
      </div>
    </div>

    <div class="card">
      <h2>⚡ Quick Actions</h2>
      <div style="color:var(--muted); font-size:0.9rem; margin-bottom: 10px;">
        Most buttons copy a command to your clipboard (your browser will not run it automatically). “Run: Refresh Dashboard” triggers a sudo-free refresh via the localhost API.
      </div>
      <div class="action-grid">
        <button class="cmd-btn" id="dash-refresh-run-btn" type="button" title="Regenerate the dashboard via the localhost API (requires Settings API running)">
            <span class="cmd-label">Run: Refresh Dashboard</span>
            <span class="cmd-desc">Via localhost API (127.0.0.1:8766) • reloads after refresh</span>
            <div class="cmd-copy-feedback">Refreshing…</div>
        </button>
        <button class="cmd-btn" onclick="copyCmd('sudo zypper-auto-helper --verify', this)">
            <span class="cmd-label">Verify & Fix</span>
            <span class="cmd-desc">Health checks + auto-repair (includes RPM DB repair)</span>
            <div class="cmd-copy-feedback">Copied!</div>
        </button>
        <button class="cmd-btn" onclick="copyCmd('zypper-auto-helper install', this)">
            <span class="cmd-label">Install Updates</span>
            <span class="cmd-desc">Launch the interactive updater</span>
            <div class="cmd-copy-feedback">Copied!</div>
        </button>
        <button class="cmd-btn" onclick="copyCmd('sudo zypper-auto-helper --health', this)">
            <span class="cmd-label">Health Report</span>
            <span class="cmd-desc">Analyze recent runs (errors, locks, crashes)</span>
            <div class="cmd-copy-feedback">Copied!</div>
        </button>
        <button class="cmd-btn" onclick="copyCmd('sudo zypper-auto-helper --logs', this)">
            <span class="cmd-label">View Logs</span>
            <span class="cmd-desc">Tail recent installer/service/notifier logs</span>
            <div class="cmd-copy-feedback">Copied!</div>
        </button>
        <button class="cmd-btn" onclick="copyCmd('sudo zypper-auto-helper --reset-downloads', this)">
            <span class="cmd-label">Reset Downloads</span>
            <span class="cmd-desc">Clear cached state + restart timers</span>
            <div class="cmd-copy-feedback">Copied!</div>
        </button>
        <button class="cmd-btn" onclick="copyCmd('sudo zypper-auto-helper --reset-config', this)">
            <span class="cmd-label">Reset Config</span>
            <span class="cmd-desc">Recreate defaults (with backup)</span>
            <div class="cmd-copy-feedback">Copied!</div>
        </button>
        <button class="cmd-btn" onclick="copyCmd('sudo zypper-auto-helper --dashboard', this)">
            <span class="cmd-label">Copy: Refresh Dashboard</span>
            <span class="cmd-desc">Regenerate this page (sudo)</span>
            <div class="cmd-copy-feedback">Copied!</div>
        </button>
        <button class="cmd-btn" onclick="copyCmd('zypper-auto-helper --dash-open', this)">
            <span class="cmd-label">Open Dashboard</span>
            <span class="cmd-desc">Generate + open in your browser</span>
            <div class="cmd-copy-feedback">Copied!</div>
        </button>
      </div>

      <details style="margin-top: 14px;">
        <summary style="cursor:pointer; color: var(--muted); font-weight: 800;">More actions…</summary>
        <div class="action-grid" style="margin-top: 12px;">
          <button class="cmd-btn" onclick="copyCmd('python3 -m http.server --directory ~/.local/share/zypper-notify 8765', this)">
              <span class="cmd-label">Serve Live Dashboard</span>
              <span class="cmd-desc">Start local server for realtime polling</span>
              <div class="cmd-copy-feedback">Copied!</div>
          </button>
          <button class="cmd-btn" onclick="copyCmd('xdg-open http://127.0.0.1:8765/status.html?live=1', this)">
              <span class="cmd-label">Open Live URL</span>
              <span class="cmd-desc">Open served dashboard in browser</span>
              <div class="cmd-copy-feedback">Copied!</div>
          </button>
          <button class="cmd-btn" onclick="copyCmd('sudo zypper-auto-helper --live-logs', this)">
              <span class="cmd-label">Live Logs</span>
              <span class="cmd-desc">Follow logs in real time (Ctrl+C)</span>
              <div class="cmd-copy-feedback">Copied!</div>
          </button>
          <button class="cmd-btn" onclick="copyCmd('sudo zypper-auto-helper --rm-conflict', this)">
              <span class="cmd-label">Fix RPM Conflicts</span>
              <span class="cmd-desc">Clean safe duplicate RPM versions</span>
              <div class="cmd-copy-feedback">Copied!</div>
          </button>
          <button class="cmd-btn" onclick="copyCmd('zypper-auto-helper --check', this)">
              <span class="cmd-label">Self Check</span>
              <span class="cmd-desc">Syntax checks only</span>
              <div class="cmd-copy-feedback">Copied!</div>
          </button>
          <button class="cmd-btn" onclick="copyCmd('zypper-auto-helper --test-notify', this)">
              <span class="cmd-label">Test Notification</span>
              <span class="cmd-desc">Verify GUI/DBus wiring</span>
              <div class="cmd-copy-feedback">Copied!</div>
          </button>
          <button class="cmd-btn" onclick="copyCmd('sudo zypper-auto-helper --snapshot-state', this)">
              <span class="cmd-label">Snapshot State</span>
              <span class="cmd-desc">Write diagnostics snapshot</span>
              <div class="cmd-copy-feedback">Copied!</div>
          </button>
          <button class="cmd-btn" onclick="copyCmd('sudo zypper-auto-helper --diag-bundle', this)">
              <span class="cmd-label">Diag Bundle</span>
              <span class="cmd-desc">Collect a support bundle</span>
              <div class="cmd-copy-feedback">Copied!</div>
          </button>
          <button class="cmd-btn" onclick="copyCmd('sudo zypper-auto-helper --diag-logs-on', this)">
              <span class="cmd-label">Diag Logs ON</span>
              <span class="cmd-desc">Enable aggregated log follower</span>
              <div class="cmd-copy-feedback">Copied!</div>
          </button>
          <button class="cmd-btn" onclick="copyCmd('sudo zypper-auto-helper --diag-logs-off', this)">
              <span class="cmd-label">Diag Logs OFF</span>
              <span class="cmd-desc">Disable aggregated log follower</span>
              <div class="cmd-copy-feedback">Copied!</div>
          </button>
          <button class="cmd-btn" onclick="copyCmd('sudo zypper-auto-helper --setup-SF', this)">
              <span class="cmd-label">Setup Snap/Flatpak</span>
              <span class="cmd-desc">Install + configure stores/remotes</span>
              <div class="cmd-copy-feedback">Copied!</div>
          </button>
          <button class="cmd-btn" onclick="copyCmd('sudo zypper-auto-helper debug', this)">
              <span class="cmd-label">Debug Menu</span>
              <span class="cmd-desc">Interactive diagnostics tools</span>
              <div class="cmd-copy-feedback">Copied!</div>
          </button>
        </div>
      </details>
    </div>

    <div class="card">
      <h2>🧰 Snapper Manager (Root)</h2>
      <div style="color:var(--muted); font-size:0.9rem; margin-bottom: 10px;">
        Runs Snapper menu actions (1–6) through the local Dashboard API. Requires confirmation for any change.
      </div>

      <div class="grid" style="margin-bottom: 12px;">
        <div class="stat-box">
          <span class="stat-label">snapper-timeline.timer</span>
          <span class="stat-value ${snapper_timeline_class}" id="snapper-timeline-timer">${snapper_timeline_timer}</span>
        </div>
        <div class="stat-box">
          <span class="stat-label">snapper-cleanup.timer</span>
          <span class="stat-value ${snapper_cleanup_class}" id="snapper-cleanup-timer">${snapper_cleanup_timer}</span>
        </div>
        <div class="stat-box">
          <span class="stat-label">snapper-boot.timer</span>
          <span class="stat-value ${snapper_boot_class}" id="snapper-boot-timer">${snapper_boot_timer}</span>
        </div>
      </div>

      <div class="grid">
        <div class="stat-box">
          <span class="stat-label">Status (Option 1)</span>
          <button class="pill" type="button" id="snapper-status-btn">Run status</button>
        </div>

        <div class="stat-box">
          <span class="stat-label">List snapshots (Option 2)</span>
          <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
            <input id="snapper-list-n" type="number" min="1" max="50" step="1" value="10" style="width:100px; padding:8px 10px; border-radius: 12px;" />
            <button class="pill" type="button" id="snapper-list-btn">List</button>
          </div>
        </div>

        <div class="stat-box">
          <span class="stat-label">Create snapshot (Option 3)</span>
          <input id="snapper-desc" type="text" placeholder="Description (optional)" style="width:100%; padding:8px 10px; border-radius: 12px;" />
          <div style="margin-top:10px;">
            <button class="pill" type="button" id="snapper-create-btn">Create</button>
          </div>
        </div>

        <div class="stat-box">
          <span class="stat-label">Full Cleanup (Option 4)</span>
          <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
            <select id="snapper-cleanup-mode" style="padding:8px 10px; border-radius: 12px;">
              <option value="all">all</option>
              <option value="empty-pre-post">empty-pre-post</option>
              <option value="timeline">timeline</option>
              <option value="number">number</option>
            </select>
            <button class="pill" type="button" id="snapper-cleanup-btn" style="border-color: rgba(239,68,68,0.30);">Run cleanup</button>
          </div>
          <div style="margin-top:8px; font-size:0.85rem; color: var(--muted);">
            Warning: cleanup may delete snapshots.
          </div>
        </div>

        <div class="stat-box">
          <span class="stat-label">AUTO enable timers (Option 5)</span>
          <button class="pill" type="button" id="snapper-auto-enable-btn">Enable</button>
        </div>

        <div class="stat-box">
          <span class="stat-label">AUTO disable timers (Option 6)</span>
          <button class="pill" type="button" id="snapper-auto-disable-btn" style="border-color: rgba(239,68,68,0.30);">Disable</button>
        </div>
      </div>

      <div style="margin-top: 14px;">
        <div class="stat-label" style="text-transform:none;">Output</div>
        <pre id="snapper-output" style="max-height: 420px;">(no snapper action run yet)</pre>
      </div>
    </div>

    <div class="card">
      <h2>Service Health</h2>
      <div class="grid">
        <div class="stat-box">
            <span class="stat-label">Downloader Timer</span>
            <span class="stat-value ${dl_timer_class}" id="dl-timer">${dl_timer}</span>
        </div>
        <div class="stat-box">
            <span class="stat-label">Downloader Status</span>
            <span class="stat-value" id="downloader-status">(live mode off)</span>
            <div class="progress-track" style="margin-top:10px;">
                <div class="progress-fill" id="download-bar" data-percent="0"></div>
            </div>
            <div style="margin-top:8px; font-size:0.85rem; color: var(--muted);" id="downloader-detail"></div>
        </div>
        <div class="stat-box">
            <span class="stat-label">Verify/Repair Timer</span>
            <span class="stat-value ${verify_timer_class}" id="verify-timer">${verify_timer}</span>
        </div>
        <div class="stat-box">
            <span class="stat-label">Auto-Repairs (last verify)</span>
            <span class="stat-value" id="verify-last-fixed">${verify_last_fixed}</span>
            <div style="margin-top:8px; font-size:0.85rem; color: var(--muted);">
              detected: <span id="verify-last-detected">${verify_last_detected}</span> • remaining: <span id="verify-last-remaining">${verify_last_remaining}</span>
            </div>
            <div style="margin-top:6px; font-size:0.82rem; color: var(--muted);">
              at: <span id="verify-last-ts">${verify_last_ts_esc}</span>
            </div>
        </div>
        <div class="stat-box">
            <span class="stat-label">User Notifier Timer</span>
            <span class="stat-value ${nt_timer_class}" id="notifier-timer">${nt_timer}</span>
        </div>
      </div>
    </div>

    <div class="card" id="perf-card">
      <h2>📈 Performance (Helper Services)</h2>
      <div style="color:var(--muted); font-size:0.9rem; margin-bottom: 10px;">
        Live mode reads <code>perf-data.json</code> (written by the dashboard perf worker started by <code>--dash-open</code>).
      </div>
      <div class="grid">
        <div class="stat-box">
            <span class="stat-label">CPU % (approx)</span>
            <canvas id="perf-cpu" style="width:100%; height:150px; display:block;"></canvas>
        </div>
        <div class="stat-box">
            <span class="stat-label">Memory (MiB)</span>
            <canvas id="perf-mem" style="width:100%; height:150px; display:block;"></canvas>
        </div>
      </div>
      <div id="perf-legend" style="margin-top:10px; display:flex; gap:10px; flex-wrap:wrap; align-items:center;"></div>
      <div id="perf-now" style="margin-top:8px; font-size:0.9rem; color: var(--muted);"></div>
    </div>

    <div class="card">
      <h2>Recent Activity Log</h2>
      <div class="stat-label" style="margin-bottom:10px; text-transform:none;">File: <span id="last-install-log">${last_install_log_esc}</span></div>

      <div style="display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin: 10px 0 10px 0;">
        <button class="pill log-tab" type="button" data-view="live">View: Live</button>
        <button class="pill log-tab" type="button" data-view="install">View: Logs (tail)</button>
        <button class="pill log-tab" type="button" data-view="verify">View: Verify/Repair</button>
        <button class="pill log-tab" type="button" data-view="diag">View: Diagnostics</button>
        <button class="pill log-tab" type="button" data-view="api">View: API</button>
        <button class="pill log-tab" type="button" data-view="journal">View: journalctl</button>
        <span style="font-size:0.82rem; color: var(--muted);">Source: <code id="log-source-hint">dashboard-live.log</code></span>
      </div>

      <div style="display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin: 0 0 12px 0;">
        <button class="pill" type="button" onclick="copyCmd('sudo zypper-auto-helper --live-logs', this)">Copy: Live Logs</button>
        <button class="pill" type="button" onclick="copyCmd('sudo zypper-auto-helper debug', this)">Copy: Debug Menu</button>
        <button class="pill" type="button" onclick="copyCmd('sudo zypper-auto-helper --logs', this)">Copy: Logs (tail)</button>
        <button class="pill" type="button" onclick="copyCmd('sudo tail -n 220 /var/log/zypper-auto/service-logs/verify.log', this)">Copy: Verify</button>
        <button class="pill" type="button" onclick="copyCmd('journalctl -t zypper-auto-helper -n 200 --no-pager', this)">Copy: journalctl</button>
      </div>

      <div class="log-container" id="recent-log-wrap">
          <button class="jump-btn" id="jump-log-btn" type="button" title="Jump to latest log lines">Latest</button>
          <button class="copy-btn" onclick="copyBlock('log-content', this)">Copy Log</button>
          <pre id="log-content">${last_tail_esc}</pre>
      </div>
    </div>

    <div class="card">
      <h2>Flight Report (Last Run)</h2>
      <div class="stat-label" style="margin-bottom:10px; text-transform:none;">Source: <span id="flight-report-log">${flight_report_log_esc:-No Flight Report log found yet.}</span></div>
      <div class="log-container" id="flight-log-wrap">
          <button class="jump-btn" id="jump-flight-btn" type="button" title="Jump to latest lines">Latest</button>
          <button class="copy-btn" onclick="copyBlock('flight-content', this)">Copy Flight Report</button>
          <pre id="flight-content">${flight_report_esc:-No flight report found yet. Run: sudo zypper-auto-helper --verify}</pre>
      </div>
    </div>

    <div class="footer">Generated by zypper-auto-helper | RUN: <code>${RUN_ID}</code></div>
  </div>

  <script>
    // Enable JS-only styling hooks
    try { document.documentElement.classList.add('js'); } catch (e) {}

    // Global UI state (used by live polling)
    var genTime = new Date("${now_iso}");

    // Toast notifications (non-intrusive)
    function ensureToastWrap() {
        var w = document.getElementById('toast-wrap');
        if (w) return w;
        w = document.createElement('div');
        w.id = 'toast-wrap';
        document.body.appendChild(w);
        return w;
    }

    function toast(msg, detail, kind) {
        // kind: 'ok' | 'err'
        try {
            var w = ensureToastWrap();
            var t = document.createElement('div');
            t.className = 'toast ' + (kind || 'ok');
            t.textContent = msg;
            if (detail) {
                var s = document.createElement('small');
                s.textContent = detail;
                t.appendChild(s);
            }
            w.appendChild(t);
            setTimeout(function() {
                t.style.animation = 'toastOut 200ms ease forwards';
                setTimeout(function() { if (t && t.parentNode) t.parentNode.removeChild(t); }, 240);
            }, 2200);
        } catch (e) {
            // ignore
        }
    }

    // --- Settings drawer (localhost API) ---
    var SETTINGS_API_BASE = 'http://127.0.0.1:8766';
    var _settingsToken = null;
    var _settingsSchema = null;
    var _settingsConfig = null;
    var _settingsDirty = false;
    var _settingsLastConfig = null;
    var _settingsDirtyToastShown = false;
    var _settingsAutosaveTimer = null;
    var _settingsAutosaveInFlight = false;
    var _settingsAutosavePendingToast = false;
    var SETTINGS_AUTOSAVE_ENABLED = true;
    var SETTINGS_AUTOSAVE_DEBOUNCE_MS = 900;

    function _settingsSetDirty(v) {
        _settingsDirty = !!v;
        var saveBtn = document.getElementById('settings-save');
        if (!saveBtn) return;
        if (_settingsDirty) {
            saveBtn.textContent = 'Save (unsaved)';
            saveBtn.style.borderColor = 'rgba(250,204,21,0.55)';
        } else {
            saveBtn.textContent = 'Save';
            saveBtn.style.borderColor = 'rgba(255,255,255,0.10)';
            _settingsDirtyToastShown = false;
            _settingsAutosavePendingToast = false;
        }
    }

    function _settingsMarkDirty() {
        _settingsSetDirty(true);

        if (SETTINGS_AUTOSAVE_ENABLED) {
            if (_settingsAutosaveTimer) {
                try { clearTimeout(_settingsAutosaveTimer); } catch (e) {}
            }
            _settingsAutosaveTimer = setTimeout(function() {
                settingsAutoSave();
            }, SETTINGS_AUTOSAVE_DEBOUNCE_MS);
            if (!_settingsAutosavePendingToast) {
                _settingsAutosavePendingToast = true;
                toast('Auto-save pending', 'Applying changes…', 'ok');
            }
        } else {
            if (!_settingsDirtyToastShown) {
                _settingsDirtyToastShown = true;
                toast('Unsaved changes', 'Click Save to apply', 'ok');
            }
        }
    }

    var SETTINGS_FIELDS = [
        { key: 'ENABLE_FLATPAK_UPDATES', type: 'bool', label: 'Flatpak updates' },
        { key: 'ENABLE_SNAP_UPDATES', type: 'bool', label: 'Snap updates' },
        { key: 'ENABLE_SOAR_UPDATES', type: 'bool', label: 'Soar updates' },
        { key: 'ENABLE_BREW_UPDATES', type: 'bool', label: 'Homebrew updates' },
        { key: 'ENABLE_PIPX_UPDATES', type: 'bool', label: 'pipx upgrade-all' },
        { key: 'HOOKS_ENABLED', type: 'bool', label: 'Hooks enabled' },
        { key: 'DASHBOARD_ENABLED', type: 'bool', label: 'Dashboard enabled' },
        { key: 'VERIFY_NOTIFY_USER_ENABLED', type: 'bool', label: 'Notify on auto-repair' },

        // Snapper safety (affects /etc/snapper/configs/* only when you run snapper tools)
        { key: 'SNAP_RETENTION_OPTIMIZER_ENABLED', type: 'bool', label: 'Snapper retention optimizer (cap overly high limits)' },
        { key: 'SNAP_RETENTION_MAX_NUMBER_LIMIT', type: 'int', label: 'Snapper cap: NUMBER_LIMIT (max upper bound)' },
        { key: 'SNAP_RETENTION_MAX_NUMBER_LIMIT_IMPORTANT', type: 'int', label: 'Snapper cap: NUMBER_LIMIT_IMPORTANT' },
        { key: 'SNAP_RETENTION_MAX_TIMELINE_LIMIT_HOURLY', type: 'int', label: 'Snapper cap: TIMELINE_LIMIT_HOURLY' },
        { key: 'SNAP_RETENTION_MAX_TIMELINE_LIMIT_DAILY', type: 'int', label: 'Snapper cap: TIMELINE_LIMIT_DAILY' },
        { key: 'SNAP_RETENTION_MAX_TIMELINE_LIMIT_WEEKLY', type: 'int', label: 'Snapper cap: TIMELINE_LIMIT_WEEKLY' },
        { key: 'SNAP_RETENTION_MAX_TIMELINE_LIMIT_MONTHLY', type: 'int', label: 'Snapper cap: TIMELINE_LIMIT_MONTHLY' },
        { key: 'SNAP_RETENTION_MAX_TIMELINE_LIMIT_YEARLY', type: 'int', label: 'Snapper cap: TIMELINE_LIMIT_YEARLY (0 disables yearly)' },
        { key: 'SNAP_CLEANUP_CONCURRENCY_GUARD_ENABLED', type: 'bool', label: 'Snapper cleanup concurrency guard' },
        { key: 'SNAP_CLEANUP_CRITICAL_FREE_MB', type: 'int', label: 'Snapper cleanup critical free space (MB)' },
        { key: 'SNAP_BROKEN_SNAPSHOT_HUNTER_ENABLED', type: 'bool', label: 'Deep clean: broken snapshot hunter' },
        { key: 'SNAP_BROKEN_SNAPSHOT_HUNTER_REGEX', type: 'string', label: 'Deep clean: broken snapshot regex' },
        { key: 'SNAP_BROKEN_SNAPSHOT_HUNTER_CONFIRM', type: 'bool', label: 'Deep clean: confirm before delete' },

        { key: 'DL_TIMER_INTERVAL_MINUTES', type: 'interval', label: 'Downloader interval (min)' },
        { key: 'NT_TIMER_INTERVAL_MINUTES', type: 'interval', label: 'Notifier interval (min)' },
        { key: 'VERIFY_TIMER_INTERVAL_MINUTES', type: 'interval', label: 'Verify interval (min)' },

        { key: 'DOWNLOADER_DOWNLOAD_MODE', type: 'enum', label: 'Downloader mode' },
        { key: 'AUTO_DUPLICATE_RPM_MODE', type: 'enum', label: 'Duplicate RPM cleanup mode' },
        { key: 'CLEANUP_REPORT_FORMAT', type: 'enum', label: 'Cleanup report format' },
        { key: 'BOOT_ENTRY_CLEANUP_MODE', type: 'enum', label: 'Boot entry cleanup mode' }
    ];

    function _settingsBanner(msg, isErr) {
        var b = document.getElementById('settings-banner');
        if (!b) return;
        if (!msg) {
            b.style.display = 'none';
            b.textContent = '';
            return;
        }
        b.style.display = 'block';
        b.style.borderColor = isErr ? 'rgba(239,68,68,0.35)' : 'rgba(34,197,94,0.35)';
        b.style.background = isErr ? 'rgba(239,68,68,0.08)' : 'rgba(34,197,94,0.08)';
        b.textContent = msg;
    }

    function _fetchToken() {
        if (_settingsToken) return Promise.resolve(_settingsToken);
        // Token is served from the dashboard directory itself:
        //   ~/.local/share/zypper-notify/dashboard-token.txt
        return fetch('dashboard-token.txt', { cache: 'no-store' }).then(function(r) {
            if (!r.ok) throw new Error('token file not found');
            return r.text();
        }).then(function(t) {
            _settingsToken = (t || '').trim();
            return _settingsToken;
        });
    }

    function _api(path, opts) {
        opts = opts || {};
        return _fetchToken().then(function(tok) {
            var headers = opts.headers || {};
            headers['X-ZNH-Token'] = tok;
            if (opts.body && !headers['Content-Type']) {
                headers['Content-Type'] = 'application/json';
            }
            opts.headers = headers;
            return fetch(SETTINGS_API_BASE + path, opts);
        }).then(function(r) {
            return r.json().then(function(j) {
                if (!r.ok) {
                    var e = new Error((j && j.error) ? j.error : ('HTTP ' + r.status));
                    e.payload = j;
                    throw e;
                }
                return j;
            });
        });
    }

    function _settingsClientLog(level, msg, ctx) {
        // Best-effort: send UI events to the API log so debug level matches the rest of the project.
        // If API is down, this will fail silently.
        try {
            return _api('/api/client-log', { method: 'POST', body: JSON.stringify({ level: level || 'info', msg: String(msg || ''), ctx: ctx || {} }) });
        } catch (e) {
            return null;
        }
    }

    // --- Dashboard refresh (dashboard -> root API) ---
    function dashboardRefreshRun(btnEl) {
        var btn = btnEl || document.getElementById('dash-refresh-run-btn');
        var fb = null;
        try { fb = btn ? btn.querySelector('.cmd-copy-feedback') : null; } catch (e) { fb = null; }

        if (btn) {
            btn.disabled = true;
            btn.classList.add('copied');
        }
        if (fb) fb.textContent = 'Refreshing…';

        toast('Refreshing dashboard…', 'Running sudo-free refresh via localhost API', 'ok');
        _settingsClientLog('info', 'dashboard refresh requested', {});

        return _api('/api/dashboard/refresh', { method: 'POST', body: JSON.stringify({}) }).then(function(r) {
            toast('Dashboard refreshed', (r && r.rc === 0) ? 'OK (reloading soon)' : ('rc=' + String(r.rc || '?')), (r && r.rc === 0) ? 'ok' : 'err');
            _settingsClientLog((r && r.rc === 0) ? 'info' : 'warn', 'dashboard refresh result', { rc: r.rc });

            if (fb) fb.textContent = (r && r.rc === 0) ? 'OK ✓' : 'Done';

            // The dashboard sync worker copies /var/log/zypper-auto/status.html -> ~/.local/share/zypper-notify/status.html every 10s.
            // Reload after a short delay so most users see the refreshed HTML.
            setTimeout(function() {
                try { window.location.reload(); } catch (e) {}
            }, 12000);

            return r;
        }).catch(function(e) {
            var msg = (e && e.message) ? e.message : 'API not reachable';
            toast('Refresh failed', msg, 'err');
            _settingsClientLog('warn', 'dashboard refresh failed', { error: msg });
            if (fb) fb.textContent = 'Failed';
            return null;
        }).finally(function() {
            if (btn) {
                setTimeout(function() {
                    try { btn.disabled = false; } catch (e) {}
                    try { btn.classList.remove('copied'); } catch (e) {}
                    if (fb) fb.textContent = 'Refreshing…';
                }, 900);
            }
        });
    }

    function _wireDashboardRefreshUI() {
        var btn = document.getElementById('dash-refresh-run-btn');
        if (!btn) return;
        btn.addEventListener('click', function() {
            dashboardRefreshRun(btn);
        });
    }

    // --- Snapper Manager (dashboard -> root API) ---
    function _snapperSetOut(text) {
        var el = document.getElementById('snapper-output');
        if (!el) return;
        el.textContent = String(text || '');
        highlightBlock('snapper-output');
        try { el.scrollTop = el.scrollHeight; } catch (e) {}
    }

    function snapperRun(action, params, confirmAction) {
        params = params || {};

        function doRun(confirm_token, confirm_phrase) {
            var body = { action: action, params: params };
            if (confirm_token) body.confirm_token = confirm_token;
            if (confirm_phrase) body.confirm_phrase = confirm_phrase;

            _snapperSetOut('Running: ' + action + ' ...');
            return _api('/api/snapper/run', { method: 'POST', body: JSON.stringify(body) }).then(function(r) {
                _snapperSetOut(r.output || '(no output)');
                toast('Snapper: ' + action, (r.rc === 0) ? 'OK' : ('rc=' + r.rc), (r.rc === 0) ? 'ok' : 'err');
                _settingsClientLog((r.rc === 0) ? 'info' : 'warn', 'snapperRun result', { action: action, rc: r.rc });
                return r;
            }).catch(function(e) {
                var msg = (e && e.message) ? e.message : 'unknown error';
                var payload = (e && e.payload) ? JSON.stringify(e.payload) : '';
                _snapperSetOut('ERROR: ' + msg + (payload ? ('\n' + payload) : ''));
                toast('Snapper failed', msg, 'err');
                _settingsClientLog('warn', 'snapperRun failed', { action: action, error: msg });
                return null;
            });
        }

        // Read-only actions: no confirm.
        if (!confirmAction) {
            return doRun('', '');
        }

        // Confirm flow: request token + require typed phrase.
        return _api('/api/snapper/confirm', { method: 'POST', body: JSON.stringify({ action: confirmAction, params: params }) }).then(function(r) {
            var phrase = r.phrase || '';
            var hint = r.hint || ('Type ' + phrase + ' to confirm');
            var got = prompt(hint + "\n\nEnter confirmation phrase:", "");
            if (!got) {
                toast('Cancelled', 'No confirmation entered', 'err');
                return null;
            }
            return doRun(r.confirm_token, got);
        }).catch(function(e) {
            var msg = (e && e.message) ? e.message : 'confirm failed';
            toast('Confirm failed', msg, 'err');
            _settingsClientLog('warn', 'snapper confirm failed', { action: action, error: msg });
            return null;
        });
    }

    function _wireSnapperUI() {
        var b1 = document.getElementById('snapper-status-btn');
        var b2 = document.getElementById('snapper-list-btn');
        var b3 = document.getElementById('snapper-create-btn');
        var b4 = document.getElementById('snapper-cleanup-btn');
        var b5 = document.getElementById('snapper-auto-enable-btn');
        var b6 = document.getElementById('snapper-auto-disable-btn');

        if (b1) b1.addEventListener('click', function() {
            _api('/api/snapper/status', { method: 'GET' }).then(function(r) {
                _snapperSetOut(r.output || '(no output)');
                toast('Snapper status', (r.rc === 0) ? 'OK' : ('rc=' + r.rc), (r.rc === 0) ? 'ok' : 'err');
            }).catch(function(e) {
                var msg = (e && e.message) ? e.message : 'failed';
                _snapperSetOut('ERROR: ' + msg);
                toast('Snapper status failed', msg, 'err');
            });
        });

        if (b2) b2.addEventListener('click', function() {
            var n = 10;
            try {
                var el = document.getElementById('snapper-list-n');
                n = parseInt((el && el.value) ? el.value : '10', 10);
                if (isNaN(n)) n = 10;
                if (n < 1) n = 1;
                if (n > 50) n = 50;
            } catch (e) { n = 10; }

            _api('/api/snapper/list?n=' + String(n), { method: 'GET' }).then(function(r) {
                _snapperSetOut(r.output || '(no output)');
                toast('Snapper list', (r.rc === 0) ? 'OK' : ('rc=' + r.rc), (r.rc === 0) ? 'ok' : 'err');
            }).catch(function(e) {
                var msg = (e && e.message) ? e.message : 'failed';
                _snapperSetOut('ERROR: ' + msg);
                toast('Snapper list failed', msg, 'err');
            });
        });

        if (b3) b3.addEventListener('click', function() {
            var desc = '';
            try { desc = String((document.getElementById('snapper-desc') || {}).value || ''); } catch (e) { desc = ''; }
            snapperRun('create', { desc: desc }, 'create');
        });

        if (b4) b4.addEventListener('click', function() {
            var mode = 'all';
            try { mode = String((document.getElementById('snapper-cleanup-mode') || {}).value || 'all'); } catch (e) { mode = 'all'; }
            snapperRun('cleanup', { mode: mode }, 'cleanup');
        });

        if (b5) b5.addEventListener('click', function() {
            snapperRun('auto-enable', {}, 'auto-enable');
        });

        if (b6) b6.addEventListener('click', function() {
            snapperRun('auto-disable', {}, 'auto-disable');
        });
    }

    function _renderSettingsForm(schema, cfg) {
        var form = document.getElementById('settings-form');
        if (!form) return;
        form.innerHTML = '';
        _settingsSetDirty(false);
        // Keep a copy so we can log diffs on save/autosave.
        try { _settingsLastConfig = JSON.parse(JSON.stringify(cfg || {})); } catch (e) { _settingsLastConfig = cfg || {}; }

        SETTINGS_FIELDS.forEach(function(f) {
            if (!schema || !schema[f.key]) return;
            var meta = schema[f.key];
            var row = document.createElement('div');
            row.style.display = 'grid';
            row.style.gridTemplateColumns = 'minmax(180px, 1fr) minmax(180px, 1fr)';
            row.style.gap = '10px';
            row.style.alignItems = 'center';
            row.style.padding = '10px 12px';
            row.style.border = '1px solid var(--border)';
            row.style.borderRadius = '12px';
            row.style.background = 'var(--subtle)';

            var lab = document.createElement('div');
            lab.innerHTML = '<div style="font-weight:950;">' + f.label + '</div>' +
                            '<div style="color:var(--muted); font-size:0.82rem;">' + f.key + '</div>';

            var ctrlWrap = document.createElement('div');

            if (meta.type === 'bool') {
                var c = document.createElement('label');
                c.className = 'pill';
                c.style.gap = '10px';
                var inp = document.createElement('input');
                inp.type = 'checkbox';
                inp.dataset.key = f.key;
                inp.checked = String(cfg[f.key]).toLowerCase() === 'true';
                c.appendChild(inp);
                c.appendChild(document.createTextNode(inp.checked ? 'ON' : 'OFF'));
                inp.addEventListener('change', function() {
                    c.lastChild.nodeValue = inp.checked ? 'ON' : 'OFF';
                    _settingsMarkDirty();
                });
                ctrlWrap.appendChild(c);
            } else if (meta.type === 'enum' || meta.type === 'interval') {
                var sel = document.createElement('select');
                sel.dataset.key = f.key;
                sel.style.width = '100%';
                sel.style.padding = '10px 12px';
                sel.style.borderRadius = '12px';
                sel.style.border = '1px solid var(--border)';
                sel.style.background = 'rgba(255,255,255,0.04)';
                sel.style.color = 'var(--text)';
                (meta.allowed || []).forEach(function(opt) {
                    var o = document.createElement('option');
                    o.value = opt;
                    o.textContent = opt;
                    sel.appendChild(o);
                });
                sel.value = String(cfg[f.key]);
                sel.addEventListener('change', function() { _settingsMarkDirty(); });
                ctrlWrap.appendChild(sel);
            } else if (meta.type === 'int') {
                // Prefer predefined select options when a bounded range is provided
                var mn = (meta.min != null) ? parseInt(meta.min, 10) : 0;
                var mx = (meta.max != null) ? parseInt(meta.max, 10) : null;
                var st = (meta.step != null) ? parseInt(meta.step, 10) : 1;

                if (mx != null && isFinite(mx) && st > 0 && (mx - mn) / st <= 400) {
                    var sel2 = document.createElement('select');
                    sel2.dataset.key = f.key;
                    sel2.style.width = '100%';
                    sel2.style.padding = '10px 12px';
                    sel2.style.borderRadius = '12px';
                    sel2.style.border = '1px solid var(--border)';
                    sel2.style.background = 'rgba(255,255,255,0.04)';
                    sel2.style.color = 'var(--text)';
                    for (var i = mn; i <= mx; i += st) {
                        var o2 = document.createElement('option');
                        o2.value = String(i);
                        o2.textContent = String(i);
                        sel2.appendChild(o2);
                    }
                    sel2.value = String(cfg[f.key]);
                    sel2.addEventListener('change', function() { _settingsMarkDirty(); });
                    ctrlWrap.appendChild(sel2);
                } else {
                    // fallback (should be rare): still allow manual number entry
                    var num = document.createElement('input');
                    num.type = 'number';
                    num.min = String(mn);
                    if (mx != null && isFinite(mx)) num.max = String(mx);
                    num.step = String(st);
                    num.dataset.key = f.key;
                    num.value = String(cfg[f.key]);
                    num.addEventListener('input', function() { _settingsMarkDirty(); });
                    num.style.width = '100%';
                    num.style.padding = '10px 12px';
                    num.style.borderRadius = '12px';
                    num.style.border = '1px solid var(--border)';
                    num.style.background = 'rgba(255,255,255,0.04)';
                    num.style.color = 'var(--text)';
                    ctrlWrap.appendChild(num);
                }
            } else if (meta.type === 'string') {
                var presets = meta.presets || null;
                var cur = String(cfg[f.key] || '');

                if (presets && Array.isArray(presets) && presets.length > 0) {
                    var sel3 = document.createElement('select');
                    sel3.dataset.key = f.key;
                    sel3.style.width = '100%';
                    sel3.style.padding = '10px 12px';
                    sel3.style.borderRadius = '12px';
                    sel3.style.border = '1px solid var(--border)';
                    sel3.style.background = 'rgba(255,255,255,0.04)';
                    sel3.style.color = 'var(--text)';

                    (presets || []).forEach(function(p) {
                        var o3 = document.createElement('option');
                        o3.value = String(p);
                        o3.textContent = String(p);
                        sel3.appendChild(o3);
                    });
                    var oc = document.createElement('option');
                    oc.value = '__custom__';
                    oc.textContent = 'Custom...';
                    sel3.appendChild(oc);

                    var txt = document.createElement('input');
                    txt.type = 'text';
                    txt.dataset.customFor = f.key;
                    txt.value = cur;
                    txt.placeholder = (meta.default != null) ? String(meta.default) : '';
                    txt.style.display = 'none';
                    txt.style.marginTop = '8px';
                    txt.style.width = '100%';
                    txt.style.padding = '10px 12px';
                    txt.style.borderRadius = '12px';
                    txt.style.border = '1px solid var(--border)';
                    txt.style.background = 'rgba(255,255,255,0.04)';
                    txt.style.color = 'var(--text)';

                    if (presets.indexOf(cur) >= 0) {
                        sel3.value = cur;
                        txt.style.display = 'none';
                    } else {
                        sel3.value = '__custom__';
                        txt.style.display = 'block';
                    }

                    sel3.addEventListener('change', function() {
                        if (sel3.value === '__custom__') {
                            txt.style.display = 'block';
                        } else {
                            txt.style.display = 'none';
                            txt.value = sel3.value;
                        }
                        _settingsMarkDirty();
                    });
                    txt.addEventListener('input', function() { _settingsMarkDirty(); });

                    ctrlWrap.appendChild(sel3);
                    ctrlWrap.appendChild(txt);
                } else {
                    var txt2 = document.createElement('input');
                    txt2.type = 'text';
                    txt2.dataset.key = f.key;
                    txt2.value = cur;
                    txt2.placeholder = (meta.default != null) ? String(meta.default) : '';
                    txt2.addEventListener('input', function() { _settingsMarkDirty(); });
                    txt2.style.width = '100%';
                    txt2.style.padding = '10px 12px';
                    txt2.style.borderRadius = '12px';
                    txt2.style.border = '1px solid var(--border)';
                    txt2.style.background = 'rgba(255,255,255,0.04)';
                    txt2.style.color = 'var(--text)';
                    ctrlWrap.appendChild(txt2);
                }
            }

            row.appendChild(lab);
            row.appendChild(ctrlWrap);
            form.appendChild(row);
        });
    }

    function _collectSettingsPatch(schema) {
        var form = document.getElementById('settings-form');
        if (!form) return {};
        var patch = {};
        var inputs = form.querySelectorAll('[data-key]');
        inputs.forEach(function(el) {
            var k = el.dataset.key;
            if (!schema || !schema[k]) return;
            if (el.tagName.toLowerCase() === 'input' && el.type === 'checkbox') {
                patch[k] = el.checked ? 'true' : 'false';
            } else if (el.tagName.toLowerCase() === 'select') {
                if (el.value === '__custom__') {
                    var c = form.querySelector('[data-custom-for="' + k + '"]');
                    patch[k] = c ? String(c.value || '') : '';
                } else {
                    patch[k] = el.value;
                }
            } else if (el.tagName.toLowerCase() === 'input' && el.type === 'number') {
                patch[k] = el.value;
            } else if (el.tagName.toLowerCase() === 'input' && el.type === 'text') {
                // ignore custom companion inputs; read via select '__custom__'
                if (el.dataset.customFor) return;
                patch[k] = el.value;
            }
        });
        return patch;
    }

    function settingsLoad(showToast) {
        _settingsBanner('', false);
        return _api('/api/schema', { method: 'GET' }).then(function(s) {
            _settingsSchema = s.schema;
            return _api('/api/config', { method: 'GET' });
        }).then(function(c) {
            _settingsConfig = c.config;
            _renderSettingsForm(_settingsSchema, _settingsConfig);

            var inv = (c.invalid_keys || []);
            var warn = (c.warnings || []);
            if (inv.length > 0) {
                _settingsBanner('Config had invalid values: ' + inv.join(', ') + ' (defaults applied). You can Factory reset or Save to heal.', true);
            } else if (warn.length > 0) {
                _settingsBanner('Warnings: ' + warn.slice(0, 3).join(' | '), true);
            } else {
                _settingsBanner('Config OK', false);
            }

            if (showToast) {
                toast('Settings loaded', 'Read from /etc/zypper-auto.conf', 'ok');
            }
            _settingsClientLog('info', 'settingsLoad ok', { invalid_keys: inv, warnings: warn });
            return c;
        }).catch(function(e) {
            _settingsBanner('Settings API not reachable. Try re-opening dashboard so it can start the API (sudo may prompt).', true);
            if (showToast) {
                toast('Settings load failed', (e && e.message) ? e.message : 'API not reachable', 'err');
            }
            try { console && console.warn && console.warn('settingsLoad failed', e); } catch (ee) {}
            // Can't log via API if the API is unreachable.
            return null;
        });
    }

    function _diffForKeys(oldCfg, newCfg, keys) {
        var out = {};
        (keys || []).forEach(function(k) {
            var a = (oldCfg && oldCfg[k] != null) ? String(oldCfg[k]) : '';
            var b = (newCfg && newCfg[k] != null) ? String(newCfg[k]) : '';
            if (a !== b) out[k] = { from: a, to: b };
        });
        return out;
    }

    function settingsSave() {
        if (!_settingsSchema) return settingsLoad(true);
        var patch = _collectSettingsPatch(_settingsSchema);
        var keys = Object.keys(patch || {});
        return _api('/api/config', { method: 'POST', body: JSON.stringify({ patch: patch }) }).then(function(r) {
            toast('Settings saved', 'Applied to /etc/zypper-auto.conf', 'ok');

            var changed = _diffForKeys(_settingsLastConfig || _settingsConfig || {}, (r && r.config) ? r.config : {}, keys);
            _settingsClientLog('info', 'settingsSave ok', {
                keys: keys,
                changed: changed,
                invalid_keys: (r && r.invalid_keys) ? r.invalid_keys : [],
                warnings: (r && r.warnings) ? r.warnings.slice(0, 6) : []
            });

            _settingsSetDirty(false);
            return settingsLoad(false);
        }).catch(function(e) {
            try { console && console.warn && console.warn('settingsSave failed', e); } catch (ee) {}
            toast('Save failed', (e && e.message) ? e.message : 'unknown error', 'err');
            _settingsClientLog('warn', 'settingsSave failed', { error: (e && e.message) ? e.message : 'unknown' });
            _settingsBanner('Save failed. You can click Factory reset to restore safe defaults.', true);
            return settingsLoad(false);
        });
    }

    function settingsAutoSave() {
        if (!SETTINGS_AUTOSAVE_ENABLED) return;
        if (_settingsAutosaveInFlight) return;
        if (!_settingsDirty) return;
        if (!_settingsSchema) {
            // Try to load schema/config first, then autosave.
            return settingsLoad(false).then(function() {
                if (_settingsDirty) return settingsAutoSave();
                return null;
            });
        }

        _settingsAutosaveInFlight = true;
        var patch = _collectSettingsPatch(_settingsSchema);
        var keys = Object.keys(patch || {});
        return _api('/api/config', { method: 'POST', body: JSON.stringify({ patch: patch }) }).then(function(r) {
            toast('Settings auto-saved', 'Applied to /etc/zypper-auto.conf', 'ok');

            var changed = _diffForKeys(_settingsLastConfig || _settingsConfig || {}, (r && r.config) ? r.config : {}, keys);
            _settingsClientLog('debug', 'settingsAutoSave ok', {
                keys: keys,
                changed: changed,
                invalid_keys: (r && r.invalid_keys) ? r.invalid_keys : [],
                warnings: (r && r.warnings) ? r.warnings.slice(0, 6) : []
            });

            _settingsSetDirty(false);
            return settingsLoad(false);
        }).catch(function(e) {
            try { console && console.warn && console.warn('settingsAutoSave failed', e); } catch (ee) {}
            toast('Auto-save failed', (e && e.message) ? e.message : 'unknown error', 'err');
            _settingsClientLog('warn', 'settingsAutoSave failed', { error: (e && e.message) ? e.message : 'unknown' });
            _settingsBanner('Auto-save failed (API may be restarting). Try again or click Factory reset to restore safe defaults.', true);
            // Keep dirty so user can retry (or click Save/Reset).
            _settingsSetDirty(true);
            return null;
        }).finally(function() {
            _settingsAutosaveInFlight = false;
            _settingsAutosavePendingToast = false;
        });
    }

    function settingsReset() {
        return _api('/api/reset-config', { method: 'POST', body: JSON.stringify({}) }).then(function(r) {
            toast('Factory reset complete', 'Defaults restored (backup created)', 'ok');
            _settingsSetDirty(false);
            return settingsLoad(false);
        }).catch(function(e) {
            toast('Factory reset failed', (e && e.message) ? e.message : 'unknown error', 'err');
            return settingsLoad(false);
        });
    }

    function _wireSettingsUI() {
        var drawer = document.getElementById('settings-drawer');
        if (!drawer) return;

        var saveBtn = document.getElementById('settings-save');
        var reloadBtn = document.getElementById('settings-reload');
        var resetBtn = document.getElementById('settings-reset');

        if (saveBtn) saveBtn.addEventListener('click', function() { settingsSave(); });
        if (reloadBtn) reloadBtn.addEventListener('click', function() { settingsLoad(true); });

        // Auto-load on page open so users immediately see success/failure.
        // (Drawer toggle handler below still refreshes when opened.)
        try {
            settingsLoad(true);
        } catch (e) {}
        if (resetBtn) resetBtn.addEventListener('click', function() {
            if (confirm('Factory reset /etc/zypper-auto.conf to defaults? (a backup will be created)')) {
                settingsReset();
            }
        });

        drawer.addEventListener('toggle', function() {
            if (drawer.open) {
                settingsLoad(true);
            }
        });
    }

    // Wire dashboard actions.
    _wireDashboardRefreshUI();
    // Wire settings drawer once DOM is ready (we are at end of body).
    _wireSettingsUI();
    // Wire Snapper manager UI.
    _wireSnapperUI();

    // Ripple click effect on buttons
    function addRipple(el, x, y) {
        if (!el) return;
        try {
            // Ensure positioning context
            var cs = window.getComputedStyle(el);
            if (cs.position === 'static') {
                el.style.position = 'relative';
            }

            var r = document.createElement('span');
            r.className = 'ripple';

            var rect = el.getBoundingClientRect();
            var cx = (typeof x === 'number') ? x - rect.left : rect.width / 2;
            var cy = (typeof y === 'number') ? y - rect.top : rect.height / 2;

            r.style.left = cx + 'px';
            r.style.top = cy + 'px';
            r.style.width = '10px';
            r.style.height = '10px';

            el.appendChild(r);
            setTimeout(function() { if (r && r.parentNode) r.parentNode.removeChild(r); }, 700);
        } catch (e) {
            // ignore
        }
    }

    // 0) Command Center clipboard copy (with fallback)
    function copyCmd(cmd, btn) {
        function feedback(ok) {
            if (!btn) return;
            if (ok) {
                btn.classList.add('copied');
                btn.classList.add('pulse');
                setTimeout(function() { btn.classList.remove('copied'); btn.classList.remove('pulse'); }, 1500);
                toast('Copied command', cmd.length > 80 ? (cmd.slice(0, 80) + '…') : cmd, 'ok');
            } else {
                toast('Copy failed', 'Your browser blocked clipboard access.', 'err');
            }
        }

        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(cmd).then(function() {
                feedback(true);
            }, function() {
                try {
                    var ta = document.createElement('textarea');
                    ta.value = cmd;
                    document.body.appendChild(ta);
                    ta.select();
                    document.execCommand('copy');
                    document.body.removeChild(ta);
                    feedback(true);
                } catch (e) {
                    feedback(false);
                }
            });
        } else {
            try {
                var ta2 = document.createElement('textarea');
                ta2.value = cmd;
                document.body.appendChild(ta2);
                ta2.select();
                document.execCommand('copy');
                document.body.removeChild(ta2);
                feedback(true);
            } catch (e2) {
                feedback(false);
            }
        }
    }
    window.copyCmd = copyCmd;

    // Settings drawer wired above.

    // 1) Live "time ago" counter
    function _timeAgoText(diffSeconds) {
        if (diffSeconds < 5) return "just now";
        if (diffSeconds < 60) return diffSeconds + " sec ago";
        var mins = Math.floor(diffSeconds / 60);
        if (mins < 60) return mins + " min" + (mins === 1 ? "" : "s") + " ago";
        var hrs = Math.floor(mins / 60);
        if (hrs < 48) return hrs + " hour" + (hrs === 1 ? "" : "s") + " ago";
        var days = Math.floor(hrs / 24);
        return days + " day" + (days === 1 ? "" : "s") + " ago";
    }
    function updateTimeAgo() {
        var diff = Math.floor((new Date() - genTime) / 1000);
        var el = document.getElementById("time-ago");
        if (el) el.textContent = _timeAgoText(diff);
    }
    updateTimeAgo();
    setInterval(updateTimeAgo, 15000);

    // 2) Disk bar animation + color
    function updateDiskBar(pct) {
        var bar = document.getElementById("disk-bar");
        if (!bar) return;
        var n = parseInt(pct || "0", 10);
        if (isNaN(n)) n = 0;
        bar.setAttribute("data-percent", String(n));
        bar.style.width = n + "%";
        if (n >= 90) bar.style.backgroundColor = "#e74c3c";      // red
        else if (n >= 75) bar.style.backgroundColor = "#f39c12"; // orange
        else bar.style.backgroundColor = "#2ecc71";             // green
    }

    // Initial disk bar draw
    setTimeout(function() {
        var bar0 = document.getElementById("disk-bar");
        if (!bar0) return;
        updateDiskBar(bar0.getAttribute("data-percent") || "0");
    }, 80);

    // 3) Smart keyword highlighting (log readability)
    function highlightBlock(id) {
        var el = document.getElementById(id);
        if (!el) return;

        // Start from the escaped HTML text we generated server-side.
        var html = el.innerHTML;

        // Prefix markers
        html = html.replace(/\[ERR\]/g, '<span class="log-error">[ERR]</span>');
        html = html.replace(/\[WARN\]/g, '<span class="log-warn">[WARN]</span>');
        html = html.replace(/\[OK\]/g, '<span class="log-success">[OK]</span>');
        html = html.replace(/\[INFO\]/g, '<span class="log-info">[INFO]</span>');
        html = html.replace(/\[DBG\]/g, '<span class="log-info">[DBG]</span>');

        // Timestamps like: [2026-02-09 21:20:20]
        html = html.replace(/^\[[0-9]{4}-[0-9]{2}-[0-9]{2}[^\]]*\]/gm, function(m) {
            return '<span class="log-time">' + m + '</span>';
        });

        // Keywords
        html = html.replace(/\b(error|failed|failure|critical)\b/gi, function(m) {
            return '<span class="log-error">' + m + '</span>';
        });
        html = html.replace(/\b(warn|warning)\b/gi, function(m) {
            return '<span class="log-warn">' + m + '</span>';
        });
        html = html.replace(/\b(success|complete|fixed|repaired|enabled|started)\b/gi, function(m) {
            return '<span class="log-success">' + m + '</span>';
        });
        html = html.replace(/\b(installing|installed|install|removing|removed|cleanup|cleaning)\b/gi, function(m) {
            return '<span class="log-warn">' + m + '</span>';
        });

        el.innerHTML = html;
    }
    highlightBlock('log-content');
    highlightBlock('flight-content');

    // Wire "Latest" jump buttons (recent log + flight report).
    wireJumpButton('log-content', 'recent-log-wrap', 'jump-log-btn');
    wireJumpButton('flight-content', 'flight-log-wrap', 'jump-flight-btn');

    // 4) Copy button (Clipboard API + fallback)
    function copyBlock(id, btn) {
        var el = document.getElementById(id);
        if (!el) return;
        var text = el.innerText || el.textContent || '';

        function done(ok) {
            if (!btn) return;
            var old = btn.textContent;
            btn.textContent = ok ? 'Copied!' : 'Copy failed';
            btn.classList.add('pulse');
            setTimeout(function() { btn.textContent = old; btn.classList.remove('pulse'); }, 2000);
            if (ok) toast('Copied text', id, 'ok');
            else toast('Copy failed', 'Clipboard access blocked.', 'err');
        }

        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(function() {
                done(true);
            }, function() {
                // Fallback
                try {
                    var ta = document.createElement('textarea');
                    ta.value = text;
                    document.body.appendChild(ta);
                    ta.select();
                    document.execCommand('copy');
                    document.body.removeChild(ta);
                    done(true);
                } catch (e) {
                    done(false);
                }
            });
        } else {
            try {
                var ta2 = document.createElement('textarea');
                ta2.value = text;
                document.body.appendChild(ta2);
                ta2.select();
                document.execCommand('copy');
                document.body.removeChild(ta2);
                done(true);
            } catch (e2) {
                done(false);
            }
        }
    }
    window.copyBlock = copyBlock;

    // Log UX: show a "Latest" button when the user scrolls away from bottom.
    function _nearBottom(el) {
        if (!el) return true;
        return (el.scrollHeight - el.scrollTop - el.clientHeight) < 120;
    }

    function updateJumpButton(preId, wrapId) {
        var pre = document.getElementById(preId);
        var wrap = document.getElementById(wrapId);
        if (!pre || !wrap) return;
        if (_nearBottom(pre)) wrap.classList.remove('show-jump');
        else wrap.classList.add('show-jump');
    }

    function wireJumpButton(preId, wrapId, btnId) {
        var pre = document.getElementById(preId);
        var wrap = document.getElementById(wrapId);
        var btn = document.getElementById(btnId);
        if (!pre || !wrap || !btn) return;

        btn.addEventListener('click', function() {
            try {
                pre.scrollTop = pre.scrollHeight;
                updateJumpButton(preId, wrapId);
            } catch (e) {
                // ignore
            }
        });

        pre.addEventListener('scroll', function() {
            updateJumpButton(preId, wrapId);
        }, { passive: true });

        // Initial state
        updateJumpButton(preId, wrapId);
    }

    // Theme toggle (Auto/Light/Dark)
    function setTheme(mode) {
        // mode: 'auto' | 'light' | 'dark'
        try { localStorage.setItem('znh_theme', mode); } catch (e) { /* ignore */ }

        // Remove explicit theme for auto, otherwise set data-theme.
        if (mode === 'auto') {
            document.documentElement.removeAttribute('data-theme');
        } else {
            document.documentElement.setAttribute('data-theme', mode);
        }

        var btn = document.getElementById('theme-toggle');
        if (btn) {
            var label = (mode === 'auto') ? 'Auto' : (mode === 'dark' ? 'Dark' : 'Light');
            btn.textContent = 'Theme: ' + label;
        }
    }

    (function() {
        var mode = 'auto';
        try {
            mode = localStorage.getItem('znh_theme') || 'auto';
        } catch (e) {
            mode = 'auto';
        }
        if (mode !== 'auto' && mode !== 'light' && mode !== 'dark') mode = 'auto';
        setTheme(mode);

        var btn = document.getElementById('theme-toggle');
        if (!btn) return;
        btn.addEventListener('click', function() {
            var current = 'auto';
            try { current = localStorage.getItem('znh_theme') || 'auto'; } catch (e) { current = 'auto'; }
            var next = 'auto';
            if (current === 'auto') next = 'light';
            else if (current === 'light') next = 'dark';
            else next = 'auto';
            setTheme(next);
        });
    })();

    // 5) Live polling (realtime-ish dashboard)
    function setText(id, val) {
        var el = document.getElementById(id);
        if (!el) return;
        var next = (val === undefined || val === null) ? "" : String(val);
        if (el.textContent !== next) {
            el.textContent = next;
            // Subtle "updated" highlight
            el.classList.remove('flash');
            // Reflow so animation restarts
            void el.offsetWidth;
            el.classList.add('flash');
        }
    }

    function setClass(id, on) {
        var el = document.getElementById(id);
        if (!el) return;
        el.classList.remove('feat-on');
        el.classList.remove('feat-off');
        el.classList.add(on ? 'feat-on' : 'feat-off');
    }

    function setTimerState(id, state) {
        var el = document.getElementById(id);
        if (!el) return;
        var s = (state === undefined || state === null) ? '' : String(state);
        if (el.textContent !== s) el.textContent = s;
        el.classList.remove('timer-active');
        el.classList.remove('timer-partial');
        el.classList.remove('timer-inactive');
        if (s === 'enabled') el.classList.add('timer-active');
        else if (s === 'partial') el.classList.add('timer-partial');
        else el.classList.add('timer-inactive');
    }

    function applyLiveData(d) {
        if (!d) return;

        if (d.generated_iso) {
            genTime = new Date(d.generated_iso);
        }

        if (d.status_color) {
            document.documentElement.style.setProperty('--status-color', d.status_color);
        }

        setText('status-badge', d.last_status);
        setText('generated-at', d.generated_human);
        setText('pending-count', d.pending_count);

        setText('kernel-ver', d.kernel_ver);
        setText('uptime-info', d.uptime_info);
        setText('mem-usage', d.mem_usage);
        setText('disk-usage', d.disk_usage_display);
        if (d.disk_percent !== undefined && d.disk_percent !== null) {
            updateDiskBar(d.disk_percent);
        }

        setText('dl-timer', d.dl_timer);
        setText('verify-timer', d.verify_timer);
        setText('notifier-timer', d.nt_timer);

        // Last verify summary (auto-repair stats)
        if (d.verify_last_fixed !== undefined) setText('verify-last-fixed', d.verify_last_fixed);
        if (d.verify_last_detected !== undefined) setText('verify-last-detected', d.verify_last_detected);
        if (d.verify_last_remaining !== undefined) setText('verify-last-remaining', d.verify_last_remaining);
        if (d.verify_last_ts !== undefined) setText('verify-last-ts', d.verify_last_ts);

        // Snapper timers (dashboard Snapper panel)
        if (d.snapper_timeline_timer !== undefined) setTimerState('snapper-timeline-timer', d.snapper_timeline_timer);
        if (d.snapper_cleanup_timer !== undefined) setTimerState('snapper-cleanup-timer', d.snapper_cleanup_timer);
        if (d.snapper_boot_timer !== undefined) setTimerState('snapper-boot-timer', d.snapper_boot_timer);

        setText('last-install-log', d.last_install_log);
        setText('flight-report-log', d.flight_report_log);
        setText('run-id', d.run_id);

        // Feature toggles
        setText('feat-flatpak-val', d.feat_flatpak ? 'ON' : 'OFF');
        setText('feat-snap-val', d.feat_snap ? 'ON' : 'OFF');
        setText('feat-soar-val', d.feat_soar ? 'ON' : 'OFF');
        setText('feat-brew-val', d.feat_brew ? 'ON' : 'OFF');
        setText('feat-pipx-val', d.feat_pipx ? 'ON' : 'OFF');

        setClass('feat-flatpak-dot', !!d.feat_flatpak);
        setClass('feat-snap-dot', !!d.feat_snap);
        setClass('feat-soar-dot', !!d.feat_soar);
        setClass('feat-brew-dot', !!d.feat_brew);
        setClass('feat-pipx-dot', !!d.feat_pipx);

        // Logs (re-highlight after replacing)
        // IMPORTANT: do not overwrite the Recent Activity Log content when the user
        // has selected a different log view tab (live/diag/journal). Those views
        // are updated by pollRecentActivityLog() instead.
        var logEl = document.getElementById('log-content');
        if (logEl && d.last_install_tail !== undefined) {
            var view = (typeof logView === 'undefined') ? 'install' : logView;
            if (view === 'install') {
                // Same auto-scroll semantics as the live log poller.
                var nearBottom2 = (logEl.scrollHeight - logEl.scrollTop - logEl.clientHeight) < 80;
                logEl.textContent = d.last_install_tail || '';
                highlightBlock('log-content');
                if (nearBottom2 || _logAutoScrollOnce) {
                    logEl.scrollTop = logEl.scrollHeight;
                    _logAutoScrollOnce = false;
                }
                updateJumpButton('log-content', 'recent-log-wrap');
            }
        }
        var flightEl = document.getElementById('flight-content');
        if (flightEl && d.flight_report_raw !== undefined) {
            flightEl.textContent = d.flight_report_raw || '';
            highlightBlock('flight-content');
        }
    }

    var liveEnabled = false;
    try {
        var params = new URLSearchParams(window.location.search);
        liveEnabled = (params.get('live') === '1') || (localStorage.getItem('znh_live') === '1');
    } catch (e) {
        liveEnabled = false;
    }

    var liveFailures = 0;

    // Live mode toggle
    (function() {
        var t = document.getElementById('live-toggle');
        if (!t) return;
        t.checked = !!liveEnabled;
        t.addEventListener('change', function() {
            liveEnabled = !!t.checked;
            try {
                localStorage.setItem('znh_live', liveEnabled ? '1' : '0');
            } catch (e) {
                // ignore
            }
            if (liveEnabled) {
                pollLive();
                pollDownloaderStatus();
                pollPerf();
                pollRecentActivityLog();
            }
        });
    })();

    function pollLive() {
        if (!liveEnabled) return;
        fetch('status-data.json?ts=' + Date.now(), { cache: 'no-store' })
            .then(function(r) {
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.json();
            })
            .then(function(d) {
                liveFailures = 0;
                applyLiveData(d);
            })
            .catch(function() {
                // When opened as file://, many browsers block fetch().
                liveFailures++;
                if (liveFailures >= 3) {
                    // Fallback: full reload every 15s (still useful if some other process regenerates the file)
                    setTimeout(function() { window.location.reload(); }, 15000);
                }
            });
    }

    function parseDownloadStatus(raw) {
        // Expected formats:
        //  - idle
        //  - refreshing
        //  - downloading:PKGS:SIZE:DOWNLOADED:PCT
        //  - complete:DURATION_SEC:DOWNLOADED_PKGS
        //  - error:network | error:repo | error:solver:RC
        var s = (raw || '').trim();
        if (!s) return { state: 'unknown', pct: 0, detail: '' };

        function fmtDur(sec) {
            var v = parseInt(sec || '0', 10);
            if (isNaN(v) || v < 0) v = 0;
            var m = Math.floor(v / 60);
            var r = v % 60;
            if (m > 0) return String(m) + 'm ' + String(r) + 's';
            return String(r) + 's';
        }

        if (s.indexOf('downloading:') === 0) {
            var parts = s.split(':');
            var pkgs = parseInt(parts[1] || '0', 10);
            if (isNaN(pkgs) || pkgs < 0) pkgs = 0;
            var size = parts[2] || 'unknown';
            var done = parseInt(parts[3] || '0', 10);
            if (isNaN(done) || done < 0) done = 0;
            var pct = parseInt(parts[4] || '0', 10);
            if (isNaN(pct)) pct = 0;
            if (pct < 0) pct = 0;
            if (pct > 100) pct = 100;

            if (pkgs > 0) {
                return { state: 'downloading', pct: pct, detail: String(done) + '/' + String(pkgs) + ' pkgs • ' + size };
            }
            return { state: 'downloading', pct: pct, detail: 'Downloading updates • ' + size };
        }

        if (s.indexOf('complete:') === 0) {
            var parts2 = s.split(':');
            var dur = parts2[1] || '0';
            var downloaded = parts2[2] || '0';

            var dlN = parseInt(downloaded, 10);
            if (isNaN(dlN) || dlN < 0) dlN = 0;

            if (dlN === 0) {
                return { state: 'complete', pct: 100, detail: 'No new downloads (already cached / detect-only)' };
            }
            return { state: 'complete', pct: 100, detail: 'Downloaded ' + String(dlN) + ' pkg(s) in ' + fmtDur(dur) };
        }

        if (s.indexOf('error:') === 0) {
            var parts3 = s.split(':');
            var kind = parts3[1] || 'unknown';
            var rc = parts3[2] || '';
            var detail = kind;
            if (kind === 'network') detail = 'Network error while checking repos';
            else if (kind === 'repo') detail = 'Repository refresh error';
            else if (kind === 'solver') detail = 'Solver/download error' + (rc ? (' (rc=' + rc + ')') : '');
            return { state: 'error', pct: 100, detail: detail };
        }

        if (s === 'idle') return { state: 'idle', pct: 0, detail: '' };
        if (s === 'refreshing') return { state: 'refreshing', pct: 10, detail: 'Refreshing repositories…' };

        return { state: s, pct: 0, detail: '' };
    }

    function updateDownloadUI(obj) {
        var st = document.getElementById('downloader-status');
        var det = document.getElementById('downloader-detail');
        var bar = document.getElementById('download-bar');
        if (st) st.textContent = obj.state;
        if (det) det.textContent = obj.detail || '';
        if (bar) {
            var pct = parseInt(obj.pct || '0', 10);
            if (isNaN(pct)) pct = 0;
            if (pct < 0) pct = 0;
            if (pct > 100) pct = 100;

            bar.style.width = pct + '%';

            if (obj.state === 'error') bar.style.backgroundColor = '#ef4444';
            else if (obj.state === 'complete') bar.style.backgroundColor = '#2ecc71';
            else bar.style.backgroundColor = '#3498db';
        }
    }

    function pollDownloaderStatus() {
        if (!liveEnabled) return;
        fetch('download-status.txt?ts=' + Date.now(), { cache: 'no-store' })
            .then(function(r) { return r.ok ? r.text() : ''; })
            .then(function(txt) {
                var obj = parseDownloadStatus(txt);
                updateDownloadUI(obj);
            })
            .catch(function() {
                // ignore
            });
    }

    // --- Realtime performance charts (helper services) ---
    var _perfLastRaw = '';
    var _perfLegendBuilt = false;

    var PERF_UNITS = [
        { unit: 'zypper-autodownload.service', label: 'Downloader', color: '#3498db' },
        { unit: 'zypper-auto-verify.service', label: 'Verify', color: '#a78bfa' },
        { unit: 'zypper-auto-dashboard-api.service', label: 'Dashboard API', color: '#f59e0b' }
    ];

    function _fmtMiB(bytes) {
        try {
            var b = parseFloat(bytes || '0');
            if (!isFinite(b) || b <= 0) return '0';
            return String(Math.round(b / (1024 * 1024)));
        } catch (e) {
            return '0';
        }
    }

    function _canvasResizeToDisplaySize(canvas) {
        if (!canvas) return;
        var w = canvas.clientWidth || 0;
        var h = canvas.clientHeight || 0;
        if (!w || !h) return;
        var dpr = window.devicePixelRatio || 1;
        var tw = Math.floor(w * dpr);
        var th = Math.floor(h * dpr);
        if (canvas.width !== tw || canvas.height !== th) {
            canvas.width = tw;
            canvas.height = th;
        }
    }

    function _drawChart(canvasId, seriesList, opts) {
        var canvas = document.getElementById(canvasId);
        if (!canvas) return;
        _canvasResizeToDisplaySize(canvas);

        var ctx = canvas.getContext('2d');
        if (!ctx) return;

        var w = canvas.width;
        var h = canvas.height;

        // Background
        ctx.clearRect(0, 0, w, h);
        ctx.fillStyle = 'rgba(0,0,0,0.06)';
        ctx.fillRect(0, 0, w, h);

        var padL = 40;
        var padR = 10;
        var padT = 12;
        var padB = 18;

        // Compute yMax
        var yMax = 1;
        for (var i = 0; i < seriesList.length; i++) {
            var s = seriesList[i];
            for (var j = 0; j < (s.points || []).length; j++) {
                var v = s.points[j].v;
                if (typeof v === 'number' && isFinite(v) && v > yMax) yMax = v;
            }
        }

        if (opts && typeof opts.minYMax === 'number' && yMax < opts.minYMax) yMax = opts.minYMax;
        // Add headroom
        yMax = yMax * 1.15;

        // Axes/grid
        ctx.strokeStyle = 'rgba(255,255,255,0.12)';
        ctx.lineWidth = 1;

        var gridN = 4;
        for (var g = 0; g <= gridN; g++) {
            var y = padT + (h - padT - padB) * (g / gridN);
            ctx.beginPath();
            ctx.moveTo(padL, y);
            ctx.lineTo(w - padR, y);
            ctx.stroke();

            // Labels
            var val = Math.round((yMax * (1 - (g / gridN))) * 10) / 10;
            ctx.fillStyle = 'rgba(255,255,255,0.55)';
            ctx.font = '12px ui-monospace, monospace';
            ctx.fillText(String(val), 6, y + 4);
        }

        // Series lines
        for (var i2 = 0; i2 < seriesList.length; i2++) {
            var ss = seriesList[i2];
            var pts = ss.points || [];
            if (pts.length < 2) continue;

            ctx.strokeStyle = ss.color;
            ctx.lineWidth = 2;
            ctx.beginPath();
            for (var k = 0; k < pts.length; k++) {
                var x = padL + (w - padL - padR) * (k / (pts.length - 1));
                var yv = pts[k].v;
                if (!isFinite(yv)) yv = 0;
                var y2 = padT + (h - padT - padB) * (1 - (yv / yMax));
                if (k === 0) ctx.moveTo(x, y2);
                else ctx.lineTo(x, y2);
            }
            ctx.stroke();
        }

        // Title
        if (opts && opts.title) {
            ctx.fillStyle = 'rgba(255,255,255,0.75)';
            ctx.font = '13px ui-sans-serif, system-ui';
            ctx.fillText(opts.title, padL, 14);
        }
    }

    function _buildPerfLegend() {
        if (_perfLegendBuilt) return;
        var el = document.getElementById('perf-legend');
        if (!el) return;
        try {
            for (var i = 0; i < PERF_UNITS.length; i++) {
                var u = PERF_UNITS[i];
                var b = document.createElement('span');
                b.className = 'feat-badge';
                b.innerHTML = '<span class="feat-dot" style="color:' + u.color + '">●</span> ' + u.label;
                el.appendChild(b);
            }
            _perfLegendBuilt = true;
        } catch (e) {
            // ignore
        }
    }

    function _renderPerf(perf) {
        _buildPerfLegend();

        var cpuSeries = [];
        var memSeries = [];
        var nowLines = [];

        for (var i = 0; i < PERF_UNITS.length; i++) {
            var meta = PERF_UNITS[i];
            var u = (perf && perf.units) ? perf.units[meta.unit] : null;
            var samples = (u && u.samples) ? u.samples : [];
            if (!samples || samples.length === 0) {
                cpuSeries.push({ color: meta.color, points: [] });
                memSeries.push({ color: meta.color, points: [] });
                continue;
            }

            // Take last N points
            var N = 60;
            var slice = samples.slice(Math.max(0, samples.length - N));

            var cpuPts = [];
            var memPts = [];
            for (var j = 0; j < slice.length; j++) {
                var s = slice[j] || {};
                cpuPts.push({ v: parseFloat(s.cpu || 0) });
                memPts.push({ v: parseFloat(_fmtMiB(s.mem || 0)) });
            }
            cpuSeries.push({ color: meta.color, points: cpuPts });
            memSeries.push({ color: meta.color, points: memPts });

            var last = slice[slice.length - 1] || {};
            var cpuNow = (typeof last.cpu === 'number') ? last.cpu : parseFloat(last.cpu || 0);
            if (!isFinite(cpuNow)) cpuNow = 0;
            var memNow = _fmtMiB(last.mem || 0);
            var st = (last.active || '') + (last.sub ? '/' + last.sub : '');
            var err = last.err ? (' • err: ' + String(last.err).slice(0, 90)) : '';
            nowLines.push(meta.label + ': ' + cpuNow.toFixed(2) + '% CPU • ' + memNow + ' MiB' + (st ? ' • ' + st : '') + err);
        }

        _drawChart('perf-cpu', cpuSeries, { title: 'CPU % (systemd units)', minYMax: 5 });
        _drawChart('perf-mem', memSeries, { title: 'Memory (MiB)', minYMax: 50 });

        var nowEl = document.getElementById('perf-now');
        if (nowEl) {
            nowEl.textContent = nowLines.length ? nowLines.join(' | ') : 'No perf data yet.';
        }
    }

    function pollPerf(force) {
        if (!liveEnabled && !force) return;
        fetch('perf-data.json?ts=' + Date.now(), { cache: 'no-store' })
            .then(function(r) {
                if (r.status === 404 || r.status === 416) return null;
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.text();
            })
            .then(function(txt) {
                if (!txt) {
                    var nowEl = document.getElementById('perf-now');
                    if (nowEl) nowEl.textContent = 'perf-data.json not available yet. Open via --dash-open to start the perf worker.';
                    return;
                }
                if (txt === _perfLastRaw) return;
                _perfLastRaw = txt;
                var perf = null;
                try { perf = JSON.parse(txt); } catch (e) { perf = null; }
                if (!perf) return;
                _renderPerf(perf);
            })
            .catch(function() {
                // ignore
            });
    }

    // Realtime Recent Activity Log (multi-source)
    var _lastLiveLog = '';
    // When true, the next successful log render will scroll to the bottom so the
    // user sees the latest events immediately. After that, we only keep the
    // view pinned to bottom when the user is already near the bottom.
    var _logAutoScrollOnce = true;

    var logView = (function() {
        try {
            return localStorage.getItem('znh_log_view') || 'live';
        } catch (e) {
            return 'live';
        }
    })();

    function tailLines(s, n) {
        var lines = (s || '').split('\n');
        if (lines.length <= n) return (s || '');
        return lines.slice(Math.max(0, lines.length - n)).join('\n');
    }

    function _updateLogTabsUI() {
        try {
            var tabs = document.querySelectorAll('.log-tab');
            for (var i = 0; i < tabs.length; i++) {
                var v = tabs[i].getAttribute('data-view') || '';
                if (v === logView) tabs[i].classList.add('active');
                else tabs[i].classList.remove('active');
            }

            var hint = document.getElementById('log-source-hint');
                if (hint) {
                    var txt = 'dashboard-live.log';
                    if (logView === 'install') txt = 'dashboard-install-tail.log';
                    else if (logView === 'verify') txt = 'dashboard-verify-tail.log';
                    else if (logView === 'diag') txt = 'dashboard-diag-tail.log';
                    else if (logView === 'api') txt = 'dashboard-api.log';
                    else if (logView === 'journal') txt = 'dashboard-journal-tail.log';
                    hint.textContent = txt;
                }
        } catch (e) {
            // ignore
        }
    }

    function setLogView(v) {
        if (!v) return;
        logView = v;
        try {
            localStorage.setItem('znh_log_view', v);
        } catch (e) {
            // ignore
        }

        // Reset cache so the next poll definitely updates the DOM.
        _lastLiveLog = '';
        // After switching views, auto-scroll to the latest entries once.
        _logAutoScrollOnce = true;
        updateJumpButton('log-content', 'recent-log-wrap');
        _updateLogTabsUI();

        // Fetch immediately even if live mode is off (useful for click-to-view).
        pollRecentActivityLog(true);
    }

    // Wire log view tabs
    (function() {
        var tabs = document.querySelectorAll('.log-tab');
        for (var i = 0; i < tabs.length; i++) {
            tabs[i].addEventListener('click', function() {
                setLogView(this.getAttribute('data-view') || 'live');
            });
        }
        _updateLogTabsUI();
    })();

    function pollRecentActivityLog(force) {
        if (!liveEnabled && !force) return;

        // Log sources are pre-rendered by the helper into files located next to status.html
        // so the browser never executes commands.
        var base = 'dashboard-live.log';
        var rangeBytes = 60000;
        if (logView === 'install') base = 'dashboard-install-tail.log';
        else if (logView === 'verify') base = 'dashboard-verify-tail.log';
        else if (logView === 'diag') base = 'dashboard-diag-tail.log';
        else if (logView === 'api') base = 'dashboard-api.log';
        else if (logView === 'journal') base = 'dashboard-journal-tail.log';

        var url = base + '?ts=' + Date.now();
        var headers = {};
        if (logView === 'live' || logView === 'verify' || logView === 'diag' || logView === 'api' || logView === 'journal') {
            headers['Range'] = 'bytes=-' + String(rangeBytes);
        }

        fetch(url, {
            cache: 'no-store',
            headers: headers
        })
            .then(function(r) {
                // Accept 206 (partial content) and 200. If the file is empty and Range is used,
                // some servers reply 416; treat that as empty content.
                // If the file is missing (404), also treat as empty so the UI doesn't freeze.
                if (r.status === 416 || r.status === 404) return '';
                if (!r.ok && r.status !== 206) throw new Error('HTTP ' + r.status);
                return r.text();
            })
            .then(function(txt) {
                var tailed = tailLines(txt, 220);
                if (tailed === _lastLiveLog) return;
                _lastLiveLog = tailed;

                var el = document.getElementById('log-content');
                if (!el) return;

                // Keep scroll pinned to bottom if the user is already near bottom.
                var nearBottom = (el.scrollHeight - el.scrollTop - el.clientHeight) < 80;

                el.textContent = tailed;
                highlightBlock('log-content');

                // Default behaviour: always show latest entries the first time
                // (or after view switches). After that, only auto-scroll when
                // the user is already near the bottom.
                if (nearBottom || _logAutoScrollOnce) {
                    el.scrollTop = el.scrollHeight;
                    _logAutoScrollOnce = false;
                }
                updateJumpButton('log-content', 'recent-log-wrap');
            })
            .catch(function() {
                // If files aren't accessible (e.g. opened via file://), do nothing.
            });
    }

    // One-time: entrance animation for cards
    (function() {
        var cards = document.querySelectorAll('.card');
        for (var i = 0; i < cards.length; i++) {
            (function(card, idx) {
                setTimeout(function() { card.classList.add('enter'); }, 60 + (idx * 55));
            })(cards[i], i);
        }
    })();

    // One-time: wire ripple effect to buttons
    (function() {
        var targets = document.querySelectorAll('.cmd-btn, .copy-btn, .pill');
        for (var i = 0; i < targets.length; i++) {
            targets[i].addEventListener('click', function(e) {
                addRipple(this, e.clientX, e.clientY);
            }, { passive: true });
        }
    })();

    // Live poll intervals
    setInterval(pollLive, 5000);
    setInterval(pollDownloaderStatus, 2000);
    setInterval(pollPerf, 2000);
    setInterval(pollRecentActivityLog, 2000);
    pollLive();
    pollDownloaderStatus();
    pollPerf(true);
    pollRecentActivityLog();
  </script>
</body>
</html>
EOF

    # Also generate a machine-readable data file for live polling.
    local out_json_root
    out_json_root="${LOG_DIR}/status-data.json"

    local json_last_status json_last_install_log json_last_install_tail json_flight_report_raw json_flight_report_log
    json_last_status="$(_json_escape "$last_status")"
    json_last_install_log="$(_json_escape "$last_install_log")"
    json_last_install_tail="$(_json_escape "$last_install_tail")"
    json_flight_report_raw="$(_json_escape "$flight_report_raw")"
    json_flight_report_log="$(_json_escape "$flight_report_log")"

    cat >"${out_json_root}" <<JSON_EOF
{
  "generated_iso": "${now_iso}",
  "generated_human": "${now}",
  "run_id": "$(_json_escape "$RUN_ID")",

  "last_status": "${json_last_status}",
  "status_color": "$(_json_escape "$status_color")",

  "pending_count": ${pending_count},

  "feat_flatpak": $([[ "${ENABLE_FLATPAK_UPDATES,,}" == "true" ]] && echo true || echo false),
  "feat_snap": $([[ "${ENABLE_SNAP_UPDATES,,}" == "true" ]] && echo true || echo false),
  "feat_soar": $([[ "${ENABLE_SOAR_UPDATES,,}" == "true" ]] && echo true || echo false),
  "feat_brew": $([[ "${ENABLE_BREW_UPDATES,,}" == "true" ]] && echo true || echo false),
  "feat_pipx": $([[ "${ENABLE_PIPX_UPDATES,,}" == "true" ]] && echo true || echo false),

  "dl_timer": "$(_json_escape "$dl_timer")",
  "verify_timer": "$(_json_escape "$verify_timer")",
  "nt_timer": "$(_json_escape "$nt_timer")",

  "verify_last_fixed": ${verify_last_fixed},
  "verify_last_detected": ${verify_last_detected},
  "verify_last_remaining": ${verify_last_remaining},
  "verify_last_ts": "$(_json_escape "$verify_last_ts")",

  "snapper_timeline_timer": "$(_json_escape "$snapper_timeline_timer")",
  "snapper_cleanup_timer": "$(_json_escape "$snapper_cleanup_timer")",
  "snapper_boot_timer": "$(_json_escape "$snapper_boot_timer")",

  "kernel_ver": "$(_json_escape "$kernel_ver")",
  "uptime_info": "$(_json_escape "$uptime_info")",
  "mem_usage": "$(_json_escape "$mem_usage")",
  "disk_usage_display": "$(_json_escape "$disk_usage_display")",
  "disk_percent": ${disk_percent},

  "last_install_log": "${json_last_install_log}",
  "last_install_tail": "${json_last_install_tail}",

  "flight_report_log": "${json_flight_report_log}",
  "flight_report_raw": "${json_flight_report_raw}"
}
JSON_EOF

    chmod 644 "${out_json_root}" 2>/dev/null || true

    # Extra pre-rendered log views for the dashboard toggles
    local out_install_tail_root out_verify_tail_root out_diag_tail_root out_journal_tail_root out_api_tail_root
    out_install_tail_root="${LOG_DIR}/dashboard-install-tail.log"
    out_verify_tail_root="${LOG_DIR}/dashboard-verify-tail.log"
    out_diag_tail_root="${LOG_DIR}/dashboard-diag-tail.log"
    out_journal_tail_root="${LOG_DIR}/dashboard-journal-tail.log"
    out_api_tail_root="${LOG_DIR}/dashboard-api.log"

    printf '%s\n' "${last_install_tail}" >"${out_install_tail_root}" 2>/dev/null || true
    chmod 644 "${out_install_tail_root}" 2>/dev/null || true

    # Verify/repair log (tail) for the dashboard 'View: Verify/Repair' tab.
    local verify_root_log
    verify_root_log="${LOG_DIR}/service-logs/verify.log"
    if [ -f "${verify_root_log}" ]; then
        tail -n 260 "${verify_root_log}" >"${out_verify_tail_root}" 2>/dev/null || true
    else
        printf '%s\n' "Verify log not found yet at ${verify_root_log}." >"${out_verify_tail_root}" 2>/dev/null || true
    fi
    chmod 644 "${out_verify_tail_root}" 2>/dev/null || true

    local diag_src
    diag_src="${LOG_DIR}/diagnostics/diag-$(date +%Y-%m-%d).log"
    if [ -f "${diag_src}" ]; then
        tail -n 220 "${diag_src}" >"${out_diag_tail_root}" 2>/dev/null || true
    else
        printf '%s\n' "No diagnostics log found at ${diag_src}. Enable via: sudo zypper-auto-helper --diag-logs-on" >"${out_diag_tail_root}" 2>/dev/null || true
    fi
    chmod 644 "${out_diag_tail_root}" 2>/dev/null || true

    if command -v journalctl >/dev/null 2>&1; then
        if command -v timeout >/dev/null 2>&1; then
            timeout 2 journalctl -t zypper-auto-helper -n 200 --no-pager >"${out_journal_tail_root}" 2>/dev/null || true
        else
            journalctl -t zypper-auto-helper -n 200 --no-pager >"${out_journal_tail_root}" 2>/dev/null || true
        fi
    else
        printf '%s\n' "journalctl not available on this system." >"${out_journal_tail_root}" 2>/dev/null || true
    fi
    chmod 644 "${out_journal_tail_root}" 2>/dev/null || true

    # Settings API log (tail) for the dashboard 'View: API' tab.
    # Prefer the root service log so the UI always has data even if mirror logging isn't enabled.
    local api_root_log
    api_root_log="${LOG_DIR}/service-logs/dashboard-api.log"
    if [ -f "${api_root_log}" ]; then
        tail -n 260 "${api_root_log}" >"${out_api_tail_root}" 2>/dev/null || true
    else
        printf '%s\n' "Settings API log not found yet at ${api_root_log}." >"${out_api_tail_root}" 2>/dev/null || true
    fi
    chmod 644 "${out_api_tail_root}" 2>/dev/null || true

    chmod 644 "${out_root}" 2>/dev/null || true

    if [ -n "${out_user}" ]; then
        local out_user_dir out_user_json
        out_user_dir="$(dirname "${out_user}")"
        out_user_json="${out_user_dir}/status-data.json"

        mkdir -p "${out_user_dir}" 2>/dev/null || true
        cp -f "${out_root}" "${out_user}" 2>/dev/null || true
        cp -f "${out_json_root}" "${out_user_json}" 2>/dev/null || true
        cp -f "${out_install_tail_root}" "${out_user_dir}/dashboard-install-tail.log" 2>/dev/null || true
        cp -f "${out_verify_tail_root}" "${out_user_dir}/dashboard-verify-tail.log" 2>/dev/null || true
        cp -f "${out_diag_tail_root}" "${out_user_dir}/dashboard-diag-tail.log" 2>/dev/null || true
        cp -f "${out_journal_tail_root}" "${out_user_dir}/dashboard-journal-tail.log" 2>/dev/null || true
        cp -f "${out_api_tail_root}" "${out_user_dir}/dashboard-api.log" 2>/dev/null || true

        # Live mode polls download-status.txt; ensure it exists in the served user dir.
        if [ -f "${LOG_DIR}/download-status.txt" ]; then
            cp -f "${LOG_DIR}/download-status.txt" "${out_user_dir}/download-status.txt" 2>/dev/null || true
        else
            printf '%s\n' "idle" >"${out_user_dir}/download-status.txt" 2>/dev/null || true
        fi

        chown "${SUDO_USER}:${SUDO_USER}" \
            "${out_user}" "${out_user_json}" \
            "${out_user_dir}/dashboard-install-tail.log" \
            "${out_user_dir}/dashboard-verify-tail.log" \
            "${out_user_dir}/dashboard-diag-tail.log" \
            "${out_user_dir}/dashboard-journal-tail.log" \
            "${out_user_dir}/dashboard-api.log" \
            "${out_user_dir}/download-status.txt" \
            2>/dev/null || true
        chmod 644 "${out_user}" "${out_user_json}" \
            "${out_user_dir}/dashboard-install-tail.log" \
            "${out_user_dir}/dashboard-verify-tail.log" \
            "${out_user_dir}/dashboard-diag-tail.log" \
            "${out_user_dir}/dashboard-journal-tail.log" \
            "${out_user_dir}/dashboard-api.log" \
            "${out_user_dir}/download-status.txt" \
            2>/dev/null || true
    fi

    log_success "Dashboard generated: ${out_root}${out_user:+ (user copy: ${out_user})}"
    return 0
}

# --- Advanced Crash Forensics ---
failure_handler() {
    # Avoid recursion / secondary failures inside the crash handler
    trap - ERR
    set +e

    local exit_code=$?
    local line_no=$1
    local bash_command="${BASH_COMMAND}"

    # Get the actual line of code from the script itself (best-effort)
    local code_snippet
    code_snippet=$(sed -n "${line_no}p" "$0" 2>/dev/null | sed 's/^\s*//' 2>/dev/null)

    echo "" >&2
    log_error "╔══════════════════════════════════════════════════════════════╗"
    log_error "║ CRITICAL FAILURE DETECTED                                    ║"
    log_error "╠══════════════════════════════════════════════════════════════╣"
    log_error "║ Exit Code : ${exit_code}"
    log_error "║ Line No   : ${line_no}"
    log_error "║ Command   : ${bash_command}"
    log_error "║ Code      : ${code_snippet:-<unavailable>}"
    log_error "╚══════════════════════════════════════════════════════════════╝"

    # Print the full function call stack (Backtrace)
    log_error "Call Stack:"
    local i=0
    while caller "$i" >/dev/null 2>&1; do
        local frame_data frame_line frame_func frame_file
        frame_data=$(caller "$i" 2>/dev/null)
        frame_line=$(echo "${frame_data}" | awk '{print $1}')
        frame_func=$(echo "${frame_data}" | awk '{print $2}')
        frame_file=$(echo "${frame_data}" | awk '{print $3}')
        log_error "  [${i}] ${frame_func} at ${frame_file}:${frame_line}"
        i=$((i + 1))
    done

    # Dump the last 10 lines of the log to stderr for immediate visibility
    if [ -f "${LOG_FILE}" ]; then
        echo "Last 10 log entries:" >&2
        tail -n 10 "${LOG_FILE}" 2>/dev/null | sed 's/^/  >> /' >&2
    fi

    # TRACE_LOG often contains xtrace output (when debug mode is enabled) and
    # other mirrored diagnostics. Including a short tail here helps correlate
    # crashes even when LOG_FILE is very large.
    if [ -n "${TRACE_LOG:-}" ] && [ -f "${TRACE_LOG}" ]; then
        echo "Last 20 trace entries:" >&2
        tail -n 20 "${TRACE_LOG}" 2>/dev/null | sed 's/^/  >> /' >&2
    fi

    # Remote monitoring: send a critical webhook if configured.
    send_webhook "zypper-auto-helper: CRITICAL FAILURE" \
        "Crash at line ${line_no} (rc=${exit_code}).\nCommand: ${bash_command}\nCode: ${code_snippet:-<unavailable>}\nLog: ${LOG_FILE}" \
        "16711680" || true

    update_status "FAILED: Crash at line ${line_no} (rc=${exit_code})"
    exit "${exit_code}"
}

# Trap ERR and send to our forensics handler
trap 'failure_handler ${LINENO}' ERR

# --- Root/System Service Config ---
DL_SERVICE_NAME="zypper-autodownload"
DL_SERVICE_FILE="/etc/systemd/system/${DL_SERVICE_NAME}.service"
DL_TIMER_FILE="/etc/systemd/system/${DL_SERVICE_NAME}.timer"

CLEANUP_SERVICE_NAME="zypper-cache-cleanup"
CLEANUP_SERVICE_FILE="/etc/systemd/system/${CLEANUP_SERVICE_NAME}.service"
CLEANUP_TIMER_FILE="/etc/systemd/system/${CLEANUP_SERVICE_NAME}.timer"

# Periodic verification / auto-repair service (root)
VERIFY_SERVICE_NAME="zypper-auto-verify"
VERIFY_SERVICE_FILE="/etc/systemd/system/${VERIFY_SERVICE_NAME}.service"
VERIFY_TIMER_FILE="/etc/systemd/system/${VERIFY_SERVICE_NAME}.timer"

# Diagnostics follower service (root)
DIAG_SERVICE_NAME="zypper-auto-diag-logs"
DIAG_SERVICE_FILE="/etc/systemd/system/${DIAG_SERVICE_NAME}.service"

# --- User Service Config ---
NT_SERVICE_NAME="zypper-notify-user"
NT_SCRIPT_NAME="zypper-notify-updater.py"
INSTALL_SCRIPT_NAME="zypper-run-install"
VIEW_CHANGES_SCRIPT_NAME="zypper-view-changes"

# Helper: compute a DBus user bus address for a given user (defaults to
# SUDO_USER). Prints the address to stdout.
get_user_bus() {
    local user="${1:-${SUDO_USER:-}}"
    if [ -z "$user" ]; then
        return 1
    fi
    local uid
    uid=$(id -u "$user" 2>/dev/null) || return 1
    printf 'unix:path=/run/user/%s/bus' "$uid"
}

# Print a clickable URL (e.g. file:///path) to the console.
# Uses color when supported so the link is easier to spot.
print_clickable_url() {
    local url="$1"
    if [ -z "${url}" ]; then
        return 0
    fi

    if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null && [ -t 1 ]; then
        printf '%b%s%b\n' "${C_CYAN}" "${url}" "${C_RESET}"
    else
        printf '%s\n' "${url}"
    fi
}

# Best-effort: open a folder in the desktop user's session.
# Returns 0 if an opener command succeeded, non-zero otherwise.
open_folder_in_desktop_session() {
    local folder="$1"
    local user="${2:-${SUDO_USER:-}}"

    if [ -z "${folder}" ]; then
        return 2
    fi

    local open_rc=1

    # Prefer user launch when available.
    if [ -n "${user:-}" ] && [ "${user}" != "root" ]; then
        local uid run_dir bus
        uid=$(id -u "${user}" 2>/dev/null || true)
        if ! [[ "${uid:-}" =~ ^[0-9]+$ ]]; then
            return 1
        fi
        run_dir="/run/user/${uid}"
        bus="$(get_user_bus "${user}" 2>/dev/null || true)"

        # Minimal sane PATH for GUI launchers when invoked from sudo/root.
        local base_path
        base_path="/usr/local/bin:/usr/bin:/bin"

        # Try to query the user systemd environment for GUI variables.
        local env_dump
        env_dump=""
        if [ -n "${bus}" ]; then
            env_dump=$(sudo -u "${user}" DBUS_SESSION_BUS_ADDRESS="${bus}" systemctl --user show-environment 2>/dev/null || true)
        fi

        __znh_env_from_dump() {
            local k="$1"
            printf '%s\n' "${env_dump}" | sed -n "s/^${k}=//p" | head -n 1
        }

        local disp wayland session xauth desktop session_name dbus
        disp="$(__znh_env_from_dump DISPLAY)";            disp="${disp:-${DISPLAY:-}}"
        wayland="$(__znh_env_from_dump WAYLAND_DISPLAY)"; wayland="${wayland:-${WAYLAND_DISPLAY:-}}"
        session="$(__znh_env_from_dump XDG_SESSION_TYPE)"; session="${session:-${XDG_SESSION_TYPE:-}}"
        xauth="$(__znh_env_from_dump XAUTHORITY)";         xauth="${xauth:-${XAUTHORITY:-}}"
        desktop="$(__znh_env_from_dump XDG_CURRENT_DESKTOP)"; desktop="${desktop:-${XDG_CURRENT_DESKTOP:-}}"
        session_name="$(__znh_env_from_dump DESKTOP_SESSION)"; session_name="${session_name:-${DESKTOP_SESSION:-}}"
        dbus="$(__znh_env_from_dump DBUS_SESSION_BUS_ADDRESS)"; dbus="${dbus:-${bus:-${DBUS_SESSION_BUS_ADDRESS:-}}}"

        # Heuristics: when invoked from a pure root/sudo context, DISPLAY/WAYLAND_DISPLAY
        # might be missing even though a desktop session is active.
        # Try safe defaults based on common socket locations.
        if [ -z "${disp:-}" ] && [ -z "${wayland:-}" ]; then
            if [ -S "${run_dir}/wayland-0" ]; then
                wayland="wayland-0"
                session="${session:-wayland}"
            elif [ -S "/tmp/.X11-unix/X0" ]; then
                disp=":0"
                session="${session:-x11}"
            fi
        fi

        # 0) KDE-native openers (often more reliable than xdg-open on Plasma)
        local kio
        for kio in kioclient5 kioclient kde-open5 kde-open; do
            local kio_bin
            kio_bin=$(command -v "${kio}" 2>/dev/null || true)
            if [ -n "${kio_bin}" ]; then
                log_debug "[folder-open] attempting ${kio} as ${user}: folder=${folder}"

                local kio_args=()
                case "${kio}" in
                    kioclient5|kioclient)
                        kio_args=(exec "${folder}")
                        ;;
                    kde-open5|kde-open)
                        kio_args=("${folder}")
                        ;;
                esac

                if sudo -u "${user}" env \
                    PATH="${base_path}" \
                    DISPLAY="${disp}" \
                    WAYLAND_DISPLAY="${wayland}" \
                    XDG_SESSION_TYPE="${session}" \
                    XAUTHORITY="${xauth}" \
                    XDG_CURRENT_DESKTOP="${desktop}" \
                    DESKTOP_SESSION="${session_name}" \
                    XDG_RUNTIME_DIR="${run_dir}" \
                    DBUS_SESSION_BUS_ADDRESS="${dbus}" \
                    "${kio_bin}" "${kio_args[@]}" >/dev/null 2>&1; then
                    log_debug "[folder-open] opener=${kio} rc=0 (success)"
                    return 0
                else
                    open_rc=$?
                    log_debug "[folder-open] opener=${kio} rc=${open_rc} (failed)"
                fi
            fi
        done

        # 0b) XFCE openers (common on openSUSE XFCE)
        local exo_bin xfce_open_bin
        exo_bin=$(command -v exo-open 2>/dev/null || true)
        if [ -n "${exo_bin}" ]; then
            log_debug "[folder-open] attempting exo-open as ${user}: folder=${folder}"
            if sudo -u "${user}" env \
                PATH="${base_path}" \
                DISPLAY="${disp}" \
                WAYLAND_DISPLAY="${wayland}" \
                XDG_SESSION_TYPE="${session}" \
                XAUTHORITY="${xauth}" \
                XDG_CURRENT_DESKTOP="${desktop}" \
                DESKTOP_SESSION="${session_name}" \
                XDG_RUNTIME_DIR="${run_dir}" \
                DBUS_SESSION_BUS_ADDRESS="${dbus}" \
                "${exo_bin}" "${folder}" >/dev/null 2>&1; then
                log_debug "[folder-open] opener=exo-open rc=0 (success)"
                return 0
            else
                open_rc=$?
                log_debug "[folder-open] opener=exo-open rc=${open_rc} (failed)"
            fi
        fi

        xfce_open_bin=$(command -v xfce4-open 2>/dev/null || true)
        if [ -n "${xfce_open_bin}" ]; then
            log_debug "[folder-open] attempting xfce4-open as ${user}: folder=${folder}"
            if sudo -u "${user}" env \
                PATH="${base_path}" \
                DISPLAY="${disp}" \
                WAYLAND_DISPLAY="${wayland}" \
                XDG_SESSION_TYPE="${session}" \
                XAUTHORITY="${xauth}" \
                XDG_CURRENT_DESKTOP="${desktop}" \
                DESKTOP_SESSION="${session_name}" \
                XDG_RUNTIME_DIR="${run_dir}" \
                DBUS_SESSION_BUS_ADDRESS="${dbus}" \
                "${xfce_open_bin}" "${folder}" >/dev/null 2>&1; then
                log_debug "[folder-open] opener=xfce4-open rc=0 (success)"
                return 0
            else
                open_rc=$?
                log_debug "[folder-open] opener=xfce4-open rc=${open_rc} (failed)"
            fi
        fi

        # 1) Direct xdg-open as the user (absolute path so sudo PATH quirks don't break)
        local xdg_open_bin
        xdg_open_bin=$(command -v xdg-open 2>/dev/null || true)
        if [ -n "${xdg_open_bin}" ]; then
            log_debug "[folder-open] attempting xdg-open as ${user}: folder=${folder} DISPLAY=${disp:-<empty>} WAYLAND_DISPLAY=${wayland:-<empty>} XDG_RUNTIME_DIR=${run_dir:-<empty>} DBUS_SESSION_BUS_ADDRESS=${dbus:-<empty>}"
            if sudo -u "${user}" env \
                PATH="${base_path}" \
                DISPLAY="${disp}" \
                WAYLAND_DISPLAY="${wayland}" \
                XDG_SESSION_TYPE="${session}" \
                XAUTHORITY="${xauth}" \
                XDG_CURRENT_DESKTOP="${desktop}" \
                DESKTOP_SESSION="${session_name}" \
                XDG_RUNTIME_DIR="${run_dir}" \
                DBUS_SESSION_BUS_ADDRESS="${dbus}" \
                "${xdg_open_bin}" "${folder}" >/dev/null 2>&1; then
                log_debug "[folder-open] opener=xdg-open rc=0 (success)"
                return 0
            else
                open_rc=$?
                log_debug "[folder-open] opener=xdg-open rc=${open_rc} (failed)"
            fi
        fi

        # 2) systemd-run scope (user) + xdg-open
        local systemd_run_bin
        systemd_run_bin=$(command -v systemd-run 2>/dev/null || true)
        if [ -n "${systemd_run_bin}" ] && [ -n "${xdg_open_bin:-}" ]; then
            log_debug "[folder-open] attempting systemd-run --user --scope xdg-open as ${user}: folder=${folder}"
            if sudo -u "${user}" env \
                PATH="${base_path}" \
                XDG_RUNTIME_DIR="${run_dir}" \
                DBUS_SESSION_BUS_ADDRESS="${dbus}" \
                "${systemd_run_bin}" --user --scope \
                --setenv="DISPLAY=${disp}" \
                --setenv="WAYLAND_DISPLAY=${wayland}" \
                --setenv="XDG_SESSION_TYPE=${session}" \
                --setenv="XAUTHORITY=${xauth}" \
                --setenv="XDG_CURRENT_DESKTOP=${desktop}" \
                --setenv="DESKTOP_SESSION=${session_name}" \
                "${xdg_open_bin}" "${folder}" >/dev/null 2>&1; then
                log_debug "[folder-open] opener=systemd-run+xdg-open rc=0 (success)"
                return 0
            else
                open_rc=$?
                log_debug "[folder-open] opener=systemd-run+xdg-open rc=${open_rc} (failed)"
            fi
        fi

        # 2b) GNOME-ish opener
        local gio_bin
        gio_bin=$(command -v gio 2>/dev/null || true)
        if [ -n "${gio_bin}" ]; then
            log_debug "[folder-open] attempting gio open as ${user}: folder=${folder}"
            if sudo -u "${user}" env \
                PATH="${base_path}" \
                DISPLAY="${disp}" \
                WAYLAND_DISPLAY="${wayland}" \
                XDG_SESSION_TYPE="${session}" \
                XAUTHORITY="${xauth}" \
                XDG_CURRENT_DESKTOP="${desktop}" \
                DESKTOP_SESSION="${session_name}" \
                XDG_RUNTIME_DIR="${run_dir}" \
                DBUS_SESSION_BUS_ADDRESS="${dbus}" \
                "${gio_bin}" open "${folder}" >/dev/null 2>&1; then
                log_debug "[folder-open] opener=gio-open rc=0 (success)"
                return 0
            else
                open_rc=$?
                log_debug "[folder-open] opener=gio-open rc=${open_rc} (failed)"
            fi
        fi

        # 3) Fallback to common file managers (use absolute paths from root env)
        local fm
        for fm in dolphin nautilus nemo thunar pcmanfm caja konqueror; do
            local fm_bin
            fm_bin=$(command -v "${fm}" 2>/dev/null || true)
            if [ -n "${fm_bin}" ]; then
                log_debug "[folder-open] attempting ${fm} as ${user}: folder=${folder}"
                if [ -n "${systemd_run_bin:-}" ]; then
                    if sudo -u "${user}" env \
                        PATH="${base_path}" \
                        XDG_RUNTIME_DIR="${run_dir}" \
                        DBUS_SESSION_BUS_ADDRESS="${dbus}" \
                        "${systemd_run_bin}" --user --scope "${fm_bin}" "${folder}" >/dev/null 2>&1; then
                        log_debug "[folder-open] opener=${fm}(systemd-run) rc=0 (success)"
                        return 0
                    else
                        open_rc=$?
                        log_debug "[folder-open] opener=${fm}(systemd-run) rc=${open_rc} (failed)"
                    fi
                else
                    if sudo -u "${user}" env \
                        PATH="${base_path}" \
                        DISPLAY="${disp}" \
                        WAYLAND_DISPLAY="${wayland}" \
                        XDG_SESSION_TYPE="${session}" \
                        XAUTHORITY="${xauth}" \
                        XDG_CURRENT_DESKTOP="${desktop}" \
                        DESKTOP_SESSION="${session_name}" \
                        XDG_RUNTIME_DIR="${run_dir}" \
                        DBUS_SESSION_BUS_ADDRESS="${dbus}" \
                        "${fm_bin}" "${folder}" >/dev/null 2>&1; then
                        log_debug "[folder-open] opener=${fm} rc=0 (success)"
                        return 0
                    else
                        open_rc=$?
                        log_debug "[folder-open] opener=${fm} rc=${open_rc} (failed)"
                    fi
                fi
            fi
        done

        return "${open_rc}"
    fi

    # No SUDO_USER / root-only context: attempt as current user.
    if command -v xdg-open >/dev/null 2>&1; then
        if xdg-open "${folder}" >/dev/null 2>&1; then
            return 0
        fi
        return $?
    fi

    if command -v systemd-run >/dev/null 2>&1 && command -v xdg-open >/dev/null 2>&1; then
        if systemd-run --user --scope xdg-open "${folder}" >/dev/null 2>&1; then
            return 0
        fi
        return $?
    fi

    return 127
}

# --- 2. Sanity Checks & User Detection ---
update_status "Running sanity checks..."
log_info ">>> Running Sanity Checks..."
log_debug "EUID: $EUID"

if [ "$EUID" -ne 0 ]; then
  log_error "This script must be run with sudo or as root."
  update_status "FAILED: Script not run as root"
  exit 1
fi
log_success "Root privileges confirmed"

# Load configuration now that we have root privileges (for /etc writes)
load_config

# --- Early housekeeping (Janitor) ---
# Do log rotation/compression early so long-running systems don't accumulate
# unlimited history under /var/log/zypper-auto.
cleanup_old_logs || true

# Prefer SUDO_USER when present (normal case when run via sudo).
# When invoked by systemd services (e.g. --verify from zypper-auto-verify
# service), SUDO_USER may be empty; in that case, fall back to the
# primary logged-in non-root user so verification can still run.
if [ -z "${SUDO_USER:-}" ]; then
    # Try to detect a non-root user with an active login session.
    PRIMARY_USER=$(loginctl list-users --no-legend 2>/dev/null | awk '$1 != 0 {print $2; exit}') || PRIMARY_USER=""
    if [ -n "$PRIMARY_USER" ]; then
        SUDO_USER="$PRIMARY_USER"
        log_info "SUDO_USER not set; falling back to PRIMARY_USER=$SUDO_USER for verification/maintenance modes"
    else
        log_error "Could not detect the user. Please run with 'sudo', not as pure root."
        update_status "FAILED: SUDO_USER not detected"
        exit 1
    fi
fi
log_success "Detected user: $SUDO_USER"

SUDO_USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
log_debug "User home directory: $SUDO_USER_HOME"

if [ ! -d "$SUDO_USER_HOME" ]; then
    log_error "Could not find home directory for user $SUDO_USER."
    update_status "FAILED: User home directory not found"
    exit 1
fi
log_success "User home directory found: $SUDO_USER_HOME"

# Define user-level paths
USER_CONFIG_DIR="$SUDO_USER_HOME/.config/systemd/user"
USER_BIN_DIR="$SUDO_USER_HOME/.local/bin"
NT_SERVICE_FILE="$USER_CONFIG_DIR/${NT_SERVICE_NAME}.service"
NT_TIMER_FILE="$USER_CONFIG_DIR/${NT_SERVICE_NAME}.timer"
NOTIFY_SCRIPT_PATH="$USER_BIN_DIR/${NT_SCRIPT_NAME}"
INSTALL_SCRIPT_PATH="$USER_BIN_DIR/${INSTALL_SCRIPT_NAME}"
VIEW_CHANGES_SCRIPT_PATH="$USER_BIN_DIR/${VIEW_CHANGES_SCRIPT_NAME}"

# --- Helper: Self-check syntax for this script and the notifier ---
run_self_check() {
    log_info ">>> Running self-check (syntax)..."
    update_status "Running syntax checks..."

    # Check bash syntax of this installer
    log_debug "Checking bash syntax of $0"
    if ! execute_guarded "Bash syntax check for installer" bash -n "$0"; then
        log_error "Self-check FAILED: bash syntax error in $0"
        update_status "FAILED: Bash syntax error in installer script"
        exit 1
    fi

    # Check Python notifier syntax if it already exists
    # NOTE: use -B so this still works under systemd services with ProtectHome=read-only
    # (py_compile normally tries to write __pycache__/*.pyc next to the source file).
    if [ -f "$NOTIFY_SCRIPT_PATH" ]; then
        log_debug "Checking Python syntax of $NOTIFY_SCRIPT_PATH"
        if ! execute_guarded "Python syntax check for notifier" python3 -B -m py_compile "$NOTIFY_SCRIPT_PATH"; then
            log_error "Self-check FAILED: Python syntax error in $NOTIFY_SCRIPT_PATH"
            update_status "FAILED: Python syntax error in notifier script"
            exit 1
        fi
    else
        log_info "Python notifier $NOTIFY_SCRIPT_PATH not found yet (first install?)"
    fi

    log_success "Self-check passed"
    update_status "Syntax checks completed successfully"
}

# --- Function: Run Verification (used by both install and --verify modes) ---
run_verification_only() {
    # This function contains all the verification logic
    # It can be called standalone or as part of installation
    
    VERIFICATION_FAILED=0
    # Allow a wrapper to run verification multiple times while preserving a
    # cumulative repair counter across attempts.
    REPAIR_ATTEMPTS=${REPAIR_ATTEMPTS_BASE:-0}
    local TOTAL_CHECKS=50

    # Flags used to coordinate "later" repair stages so early checks don't
    # permanently fail verification when follow-up auto-repair can recover.
    DISK_SPACE_CRITICAL=0
    DISK_SPACE_CLEANED_ZYPPER=0
    RPMDB_STRUCTURAL_FAILED=0

    # Repo refresh hints so we can decide whether to run deeper GPG repairs.
    REPO_REFRESH_FAILED=0
    REPO_REFRESH_USED_GPG_IMPORT=0

    # Track whether zypper appears to be legitimately running (lock held by a
    # live process). When true, we avoid running zypper-based checks/repairs
    # that would fail or interfere with an in-progress update.
    ZYPPER_LOCK_ACTIVE=0
    ZYPPER_LOCK_PID_ACTIVE=""

    # If we have to perform a critical repair (e.g. restart the dashboard API),
    # schedule a one-off follow-up verification soon so we can confirm the fix held.
    FOLLOWUP_SOON=0

    log_info ">>> Running advanced installation verification and auto-repair..."
    update_status "Verifying installation..."

# Helper function for advanced repair with retry logic
attempt_repair() {
    local check_name="$1"
    local repair_command="$2"
    local verify_command="$3"
    local max_attempts="${4:-2}"

    # Before attempting any repair, clear potential "failed" states on
    # the core units we manage so systemd is willing to restart them.
    # This is safe to run even when we're repairing something else.
    execute_guarded "Reset failed state for core system units" \
        systemctl reset-failed "${DL_SERVICE_NAME}.service" "${DL_SERVICE_NAME}.timer" || true
    if [ -n "${SUDO_USER:-}" ] && [ -n "${USER_BUS_PATH:-}" ]; then
        execute_guarded "Reset failed state for user notifier units" \
            sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" \
            systemctl --user reset-failed "${NT_SERVICE_NAME}.service" "${NT_SERVICE_NAME}.timer" || true
    fi

    REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))  # Track that we're attempting a repair

    for i in $(seq 1 "$max_attempts"); do
        log_info "  → Repair attempt $i/$max_attempts: $check_name"
        if log_command "$repair_command"; then
            sleep 0.5  # Brief pause for system to stabilize
            if bash -lc "$verify_command" &>/dev/null; then
                log_success "  ✓ Repaired successfully on attempt $i"
                return 0
            fi
        fi
    done
    log_error "  ✗ Failed to repair after $max_attempts attempts"
    return 1
}

# Check 1: System service is active and healthy
log_debug "[1/${TOTAL_CHECKS}] Checking system downloader service..."
if systemctl is-active "${DL_SERVICE_NAME}.timer" &>/dev/null; then
    # Additional health check: verify it's enabled
    if systemctl is-enabled "${DL_SERVICE_NAME}.timer" &>/dev/null; then
        log_success "✓ System downloader timer is active and enabled"
    else
        log_error "✗ System downloader timer is active but NOT enabled (won't survive reboot)"
        if attempt_repair "enable timer for persistence" \
            "systemctl unmask ${DL_SERVICE_NAME}.timer >/dev/null 2>&1 || true; systemctl enable ${DL_SERVICE_NAME}.timer" \
            "systemctl is-enabled ${DL_SERVICE_NAME}.timer"; then
            log_success "  ✓ Timer is now enabled for persistence"
        else
            VERIFICATION_FAILED=1
        fi
    fi
else
    log_error "✗ System downloader timer is NOT active"
    # Try comprehensive repair (including unmask in case the unit was masked)
    if attempt_repair "restart system downloader" \
        "systemctl unmask ${DL_SERVICE_NAME}.timer >/dev/null 2>&1 || true; systemctl daemon-reload && systemctl enable --now ${DL_SERVICE_NAME}.timer" \
        "systemctl is-active ${DL_SERVICE_NAME}.timer" 3; then
        log_success "  ✓ System downloader timer repaired"
    else
        log_error "  → Attempting nuclear option: recreating service files..."
        # Service file should exist from earlier in install, but verify
        if [ ! -f "${DL_SERVICE_FILE}" ] || [ ! -f "${DL_TIMER_FILE}" ]; then
            log_error "  ✗ CRITICAL: Service files missing - installation may have failed"
            VERIFICATION_FAILED=1
        else
            execute_guarded "systemd daemon-reload (nuclear repair)" systemctl daemon-reload
            execute_guarded "Enable + start ${DL_SERVICE_NAME}.timer (nuclear repair)" systemctl enable --now "${DL_SERVICE_NAME}.timer"
            sleep 1
            if systemctl is-active "${DL_SERVICE_NAME}.timer" &>/dev/null; then
                log_success "  ✓ Nuclear repair successful"
            else
                log_error "  ✗ CRITICAL: Cannot start system timer - check permissions"
                VERIFICATION_FAILED=1
            fi
        fi
    fi
fi

# Check 2: User service is active and healthy
log_debug "[2/${TOTAL_CHECKS}] Checking user notifier service..."
if sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user is-active "${NT_SERVICE_NAME}.timer" &>/dev/null; then
    # Check if enabled
    if sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user is-enabled "${NT_SERVICE_NAME}.timer" &>/dev/null; then
        log_success "✓ User notifier timer is active and enabled"
        # Deep health check: verify it's actually triggering.
        # Use systemctl show NextElapseUSecRealtime instead of parsing list-timers output.
        local next_elapse
        next_elapse=$(sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" \
            systemctl --user show "${NT_SERVICE_NAME}.timer" -p NextElapseUSecRealtime --value 2>/dev/null || true)
        if [ -n "${next_elapse}" ] && [ "${next_elapse}" != "n/a" ]; then
            log_success "  ✓ Timer has an upcoming trigger scheduled: ${next_elapse}"
        else
            log_info "  ⚠ Timer is active but no next trigger is scheduled; restarting to reset schedule..."
            execute_guarded "Restart user timer ${NT_SERVICE_NAME}.timer (fix missing next trigger)" \
                sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" \
                systemctl --user restart "${NT_SERVICE_NAME}.timer"
        fi
    else
        log_error "✗ User timer is active but NOT enabled"
        if attempt_repair "enable user timer" \
            "sudo -u $SUDO_USER DBUS_SESSION_BUS_ADDRESS=$USER_BUS_PATH systemctl --user unmask ${NT_SERVICE_NAME}.timer >/dev/null 2>&1 || true; sudo -u $SUDO_USER DBUS_SESSION_BUS_ADDRESS=$USER_BUS_PATH systemctl --user enable ${NT_SERVICE_NAME}.timer" \
            "sudo -u $SUDO_USER DBUS_SESSION_BUS_ADDRESS=$USER_BUS_PATH systemctl --user is-enabled ${NT_SERVICE_NAME}.timer"; then
            log_success "  ✓ User timer enabled"
        else
            VERIFICATION_FAILED=1
        fi
    fi
else
    log_error "✗ User notifier timer is NOT active"
    # Multi-stage repair process
    log_info "  → Stage 1: Daemon reload and restart..."
    if attempt_repair "restart user service" \
        "sudo -u $SUDO_USER DBUS_SESSION_BUS_ADDRESS=$USER_BUS_PATH systemctl --user unmask ${NT_SERVICE_NAME}.timer >/dev/null 2>&1 || true; sudo -u $SUDO_USER DBUS_SESSION_BUS_ADDRESS=$USER_BUS_PATH systemctl --user daemon-reload && sudo -u $SUDO_USER DBUS_SESSION_BUS_ADDRESS=$USER_BUS_PATH systemctl --user enable --now ${NT_SERVICE_NAME}.timer" \
        "sudo -u $SUDO_USER DBUS_SESSION_BUS_ADDRESS=$USER_BUS_PATH systemctl --user is-active ${NT_SERVICE_NAME}.timer" 3; then
        log_success "  ✓ User notifier timer repaired"
    else
        log_error "  → Stage 2: Checking for service file corruption..."
        if [ ! -f "${NT_SERVICE_FILE}" ] || [ ! -f "${NT_TIMER_FILE}" ]; then
            log_error "  ✗ CRITICAL: User service files missing"
            VERIFICATION_FAILED=1
        else
            # Check file permissions
            if [ ! -r "${NT_SERVICE_FILE}" ] || [ ! -r "${NT_TIMER_FILE}" ]; then
                log_error "  ⚠ Service files have wrong permissions"
                execute_guarded "Fix ownership for user unit files" \
                    chown "$SUDO_USER:$SUDO_USER" "${NT_SERVICE_FILE}" "${NT_TIMER_FILE}"
                execute_guarded "Fix permissions for user unit files" \
                    chmod 644 "${NT_SERVICE_FILE}" "${NT_TIMER_FILE}"
            fi
            
            # Final attempt
            log_info "  → Stage 3: Nuclear option - full service reset..."
            execute_guarded "Stop user timer ${NT_SERVICE_NAME}.timer (nuclear repair)" \
                sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user stop "${NT_SERVICE_NAME}.timer" || true
            execute_guarded "Disable user timer ${NT_SERVICE_NAME}.timer (nuclear repair)" \
                sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user disable "${NT_SERVICE_NAME}.timer" || true
            execute_guarded "Unmask user timer ${NT_SERVICE_NAME}.timer (nuclear repair)" \
                sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user unmask "${NT_SERVICE_NAME}.timer" || true
            execute_guarded "systemctl --user daemon-reload (nuclear repair)" \
                sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user daemon-reload
            sleep 1
            execute_guarded "Enable + start user timer ${NT_SERVICE_NAME}.timer (nuclear repair)" \
                sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user enable --now "${NT_SERVICE_NAME}.timer"
            sleep 1
            
            if sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user is-active "${NT_SERVICE_NAME}.timer" &>/dev/null; then
                log_success "  ✓ Nuclear repair successful - user timer now active"
            else
                log_error "  ✗ CRITICAL: All repair attempts failed"
                log_error "  → This may indicate a DBUS or systemd user session issue"
                log_info "  → Try: loginctl enable-linger $SUDO_USER"
                VERIFICATION_FAILED=1
            fi
        fi
    fi
fi

# Check 3: Python script exists and is executable
log_debug "Checking Python notifier script..."
if [ -x "${NOTIFY_SCRIPT_PATH}" ]; then
    log_success "✓ Python notifier script is executable"
    # Check Python syntax.
    # IMPORTANT: use -B so this works under systemd hardening (ProtectHome=read-only).
    if python3 -B -m py_compile "${NOTIFY_SCRIPT_PATH}" &>/dev/null; then
        log_success "✓ Python script syntax is valid"
    else
        log_error "✗ Python script failed to compile (syntax error or environment issue)"
        log_error "  → Cannot auto-fix: inspect the file and run: python3 -B -m py_compile ${NOTIFY_SCRIPT_PATH}"
        VERIFICATION_FAILED=1
    fi
else
    log_error "✗ Python notifier script is missing or not executable"
    if [ -f "${NOTIFY_SCRIPT_PATH}" ]; then
        log_info "  → Attempting to fix: making script executable..."
        execute_guarded "Make notifier script executable" chmod +x "${NOTIFY_SCRIPT_PATH}"
        execute_guarded "Fix notifier script ownership" chown "$SUDO_USER:$SUDO_USER" "${NOTIFY_SCRIPT_PATH}"
        if [ -x "${NOTIFY_SCRIPT_PATH}" ]; then
            log_success "  ✓ Fixed: Python script is now executable"
        else
            log_error "  ✗ Failed to make Python script executable"
            VERIFICATION_FAILED=1
        fi
    else
        log_error "  → Cannot auto-fix: file is completely missing"
        VERIFICATION_FAILED=1
    fi
fi

# Check 4: Downloader script exists and is executable
log_debug "Checking downloader script..."
if [ -x "$DOWNLOADER_SCRIPT" ]; then
    log_success "✓ Downloader script is executable"
    # Check bash syntax
    if bash -n "$DOWNLOADER_SCRIPT" &>/dev/null; then
        log_success "✓ Downloader script syntax is valid"
    else
        log_error "✗ Downloader script has syntax errors"
        VERIFICATION_FAILED=1
    fi
else
    log_error "✗ Downloader script is missing or not executable"
    VERIFICATION_FAILED=1
fi

# Check 5: Shell wrapper exists
log_debug "Checking zypper wrapper script..."
if [ -x "$ZYPPER_WRAPPER_PATH" ]; then
    log_success "✓ Zypper wrapper script is executable"
else
    log_error "✗ Zypper wrapper script is missing or not executable"
    VERIFICATION_FAILED=1
fi

# Check 6: Fish shell integration (if Fish is installed)
if [ -d "$SUDO_USER_HOME/.config/fish" ]; then
    log_debug "Checking Fish shell integration..."
    if [ -f "$SUDO_USER_HOME/.config/fish/conf.d/zypper-wrapper.fish" ]; then
        log_success "✓ Fish shell wrapper is installed"
    else
        log_error "✗ Fish shell wrapper is missing"
        VERIFICATION_FAILED=1
    fi
fi

# Check 7: No old Python processes running
log_debug "Checking for stale Python processes..."
if pgrep -f "zypper-notify-updater.py" &>/dev/null; then
    PROCESS_COUNT=$(pgrep -f "zypper-notify-updater.py" | wc -l)
    if [ "$PROCESS_COUNT" -gt 1 ]; then
        log_warn "⚠ Warning: $PROCESS_COUNT Python notifier processes running (expected 0-1)"
        log_info "  → Attempting to fix: killing stale processes..."
        execute_guarded "Kill stale notifier processes" pkill -9 -f "zypper-notify-updater.py" || true
        sleep 1
        if pgrep -f "zypper-notify-updater.py" &>/dev/null; then
            NEW_COUNT=$(pgrep -f "zypper-notify-updater.py" | wc -l)
            log_info "  ✓ Fixed: Reduced to $NEW_COUNT process(es)"
        else
            log_success "  ✓ Fixed: All stale processes killed"
        fi
    else
        log_success "✓ Python notifier process count is normal"
    fi
else
    log_success "✓ No stale Python processes detected"
fi

# Check 8: Python bytecode cache is clear
log_debug "Checking Python bytecode cache..."
if find "$SUDO_USER_HOME/.local/bin" \( -type f -name "*.pyc" -o -type d -name "__pycache__" \) -print 2>/dev/null | grep -q .; then
    log_warn "⚠ Warning: Python bytecode cache exists (may cause issues)"
    log_info "  → Attempting to fix: clearing bytecode cache..."

    # Best-effort: fix ownership first (old runs may have created root-owned cache).
    execute_guarded "Fix ownership for bytecode cache artifacts" \
        find "$SUDO_USER_HOME/.local/bin" \( -type f -name "*.pyc" -o -type d -name "__pycache__" \) \
        -exec chown "$SUDO_USER:$SUDO_USER" {} + 2>/dev/null || true

    execute_guarded "Delete .pyc files" find "$SUDO_USER_HOME/.local/bin" -type f -name "*.pyc" -delete
    execute_guarded "Remove __pycache__ directories" find "$SUDO_USER_HOME/.local/bin" -type d -name "__pycache__" -exec rm -rf {} + || true
    if find "$SUDO_USER_HOME/.local/bin" \( -type f -name "*.pyc" -o -type d -name "__pycache__" \) -print 2>/dev/null | grep -q .; then
        log_warn "  ✗ Failed to clear bytecode cache completely"
    else
        log_success "  ✓ Fixed: Python bytecode cache cleared"
    fi
else
    log_success "✓ Python bytecode cache is clean"
fi

# Check 9: Log directories exist
log_debug "Checking log directories..."
if [ -d "${LOG_DIR}" ] && [ -d "${USER_LOG_DIR}" ]; then
    log_success "✓ Log directories exist"
else
    log_error "✗ Log directories are missing"
    VERIFICATION_FAILED=1
fi

# Check 10: Dashboard API unit sandbox paths (prevents silent log loss + HTTP 500)
log_debug "[10/${TOTAL_CHECKS}] Checking dashboard API unit sandbox paths..."
local DASH_API_UNIT_FILE expected_rw dash_api_changed
DASH_API_UNIT_FILE="/etc/systemd/system/zypper-auto-dashboard-api.service"
if [ -f "${DASH_API_UNIT_FILE}" ]; then
    expected_rw="ReadWritePaths=${CONFIG_FILE} /var/lib/zypper-auto /var/log/zypper-auto /var/log/zypper-auto/service-logs"
    dash_api_changed=0

    # Ensure ProtectHome is compatible with reading user home paths (needed for snapper helper UX)
    if grep -q '^ProtectHome=true$' "${DASH_API_UNIT_FILE}" 2>/dev/null; then
        execute_guarded "Patch dashboard API unit (ProtectHome=read-only)" \
            sed -i 's/^ProtectHome=true$/ProtectHome=read-only/' "${DASH_API_UNIT_FILE}" || true
        dash_api_changed=1
    elif grep -q '^ProtectHome=' "${DASH_API_UNIT_FILE}" 2>/dev/null; then
        if ! grep -q '^ProtectHome=read-only$' "${DASH_API_UNIT_FILE}" 2>/dev/null; then
            execute_guarded "Normalize dashboard API unit (ProtectHome=read-only)" \
                sed -i 's/^ProtectHome=.*/ProtectHome=read-only/' "${DASH_API_UNIT_FILE}" || true
            dash_api_changed=1
        fi
    else
        # Missing line; append (best-effort)
        printf '%s\n' 'ProtectHome=read-only' >>"${DASH_API_UNIT_FILE}" 2>/dev/null || true
        dash_api_changed=1
    fi

    # Ensure ReadWritePaths includes /var/log/zypper-auto so the service can create its log dirs/files.
    if grep -q '^ReadWritePaths=' "${DASH_API_UNIT_FILE}" 2>/dev/null; then
        if ! grep -qF '/var/log/zypper-auto' "${DASH_API_UNIT_FILE}" 2>/dev/null \
            || ! grep -qF '/var/log/zypper-auto/service-logs' "${DASH_API_UNIT_FILE}" 2>/dev/null \
            || ! grep -qF '/var/lib/zypper-auto' "${DASH_API_UNIT_FILE}" 2>/dev/null; then
            execute_guarded "Patch dashboard API unit (ReadWritePaths)" \
                sed -i "s|^ReadWritePaths=.*$|${expected_rw}|" "${DASH_API_UNIT_FILE}" || true
            dash_api_changed=1
        fi
    else
        printf '%s\n' "${expected_rw}" >>"${DASH_API_UNIT_FILE}" 2>/dev/null || true
        dash_api_changed=1
    fi

    # If we changed anything, reload systemd and restart the service if it's running.
    if [ "${dash_api_changed}" -eq 1 ]; then
        execute_guarded "systemd daemon-reload (dashboard api auto-fix)" systemctl daemon-reload || true
        if systemctl is-active zypper-auto-dashboard-api.service &>/dev/null; then
            execute_guarded "Restart dashboard API (apply sandbox fix)" systemctl restart zypper-auto-dashboard-api.service || true
        fi
        REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))
        log_success "  ✓ Auto-fixed dashboard API unit sandbox paths"
    else
        log_success "✓ Dashboard API unit sandbox paths look OK"
    fi
else
    log_info "Dashboard API unit not installed (skipping)"
fi

# Check 11: Dashboard artifacts freshness (apply new changes automatically)
# If the installed helper is newer than the generated dashboard, regenerate it.
log_debug "[11/${TOTAL_CHECKS}] Checking dashboard artifacts freshness..."
if [[ "${DASHBOARD_ENABLED,,}" == "true" ]]; then
    local helper_bin dash_root helper_mtime dash_mtime
    helper_bin="/usr/local/bin/zypper-auto-helper"
    dash_root="${LOG_DIR}/status.html"

    helper_mtime=$(stat -c %Y "${helper_bin}" 2>/dev/null || echo 0)
    dash_mtime=$(stat -c %Y "${dash_root}" 2>/dev/null || echo 0)

    if [ ! -f "${dash_root}" ] || [ "${helper_mtime:-0}" -gt "${dash_mtime:-0}" ] 2>/dev/null; then
        log_info "Dashboard appears stale/missing; regenerating (apply new changes)..."
        generate_dashboard || true
        REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))
        log_success "  ✓ Dashboard regenerated"
    else
        log_success "✓ Dashboard artifacts look fresh"
    fi
else
    log_debug "Dashboard generation disabled (DASHBOARD_ENABLED=false); skipping freshness check"
fi

# Check 12: Dashboard API runtime reload
# The API is a long-running service; after upgrades it may need a restart to
# pick up new endpoints (e.g. /api/dashboard/refresh). We probe /api/ping.
log_debug "[12/${TOTAL_CHECKS}] Checking dashboard API runtime (/api/ping)..."
if systemctl is-active --quiet zypper-auto-dashboard-api.service 2>/dev/null; then
    if command -v curl >/dev/null 2>&1; then
        if ! curl -fsS --max-time 1 http://127.0.0.1:8766/api/ping >/dev/null 2>&1; then
            log_warn "Dashboard API is running but /api/ping is not responding; restarting service to apply upgrades..."
            execute_guarded "Restart dashboard API (apply upgrades)" systemctl restart zypper-auto-dashboard-api.service || true
            sleep 0.4
            if curl -fsS --max-time 1 http://127.0.0.1:8766/api/ping >/dev/null 2>&1; then
                REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))
                FOLLOWUP_SOON=1
                log_success "  ✓ Dashboard API restarted and responding"
            else
                log_warn "  ⚠ Dashboard API still not responding to /api/ping (non-fatal)"
            fi
        else
            log_success "✓ Dashboard API ping OK"
        fi
    else
        log_debug "curl not available; skipping dashboard API ping check"
    fi
fi

# Check 13: Status file integrity (auto-fix enabled)
log_debug "[13/${TOTAL_CHECKS}] Checking status file integrity..."
local DL_STATUS_FILE
DL_STATUS_FILE="/var/log/zypper-auto/download-status.txt"
CURRENT_STATUS=""

# Helper status format: idle | refreshing | downloading:... | complete | complete:... | error:...
__znh_validate_download_status_ok() {
    local s="$1"
    printf '%s\n' "$s" | grep -qE '^(idle|refreshing|downloading:|complete($|:)|error:)'
}

if [ -s "${DL_STATUS_FILE}" ]; then
    CURRENT_STATUS=$(cat "${DL_STATUS_FILE}" 2>/dev/null || echo "")
    if __znh_validate_download_status_ok "${CURRENT_STATUS:-}"; then
        log_success "✓ Status file exists and is valid (current: ${CURRENT_STATUS:-unknown})"
    else
        log_warn "⚠ Status file content looks invalid. Auto-repairing to 'idle'..."
        mkdir -p /var/log/zypper-auto
        echo "idle" > "${DL_STATUS_FILE}"
        chmod 644 "${DL_STATUS_FILE}" 2>/dev/null || true
        REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))
        CURRENT_STATUS="idle"
        log_success "  ✓ Reset status file content (idle)"
    fi
elif [ -f "${DL_STATUS_FILE}" ]; then
    log_warn "⚠ Status file exists but is empty. Auto-repairing..."
    mkdir -p /var/log/zypper-auto
    echo "idle" > "${DL_STATUS_FILE}"
    chmod 644 "${DL_STATUS_FILE}" 2>/dev/null || true
    REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))
    CURRENT_STATUS="idle"
    log_success "  ✓ Created default status file content (idle)"
else
    log_warn "⚠ Status file is missing. Auto-repairing..."
    mkdir -p /var/log/zypper-auto
    echo "idle" > "${DL_STATUS_FILE}"
    chmod 644 "${DL_STATUS_FILE}" 2>/dev/null || true
    REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))
    CURRENT_STATUS="idle"
    log_success "  ✓ Created default status file (idle)"
fi

# Auto-fix: detect and reset stale download status so the helper does not
# appear to be "stuck" in a downloading state forever (for example after a
# crash or abrupt reboot).
if [ -f "/var/log/zypper-auto/download-status.txt" ]; then
    NOW_TS=$(date +%s)
    STATUS_MTIME=$(stat -c %Y "/var/log/zypper-auto/download-status.txt" 2>/dev/null || echo "$NOW_TS")
    STATUS_AGE=$((NOW_TS - STATUS_MTIME))
    # Treat anything older than 1 hour in an in-progress state as stale.
    if printf '%s\n' "$CURRENT_STATUS" | grep -qE '^(refreshing|downloading:)' && [ "$STATUS_AGE" -gt 3600 ]; then
        log_warn "⚠ Warning: Stale download status '$CURRENT_STATUS' detected (age ${STATUS_AGE}s)"
        log_info "  → Auto-fixer: resetting download status and timing files so background downloads can resume cleanly"
        execute_guarded "Reset stale download-status.txt to idle" bash -lc "echo idle > /var/log/zypper-auto/download-status.txt" || true
        execute_guarded "Remove stale downloader timing files" rm -f \
              "/var/log/zypper-auto/download-last-check.txt" \
              "/var/log/zypper-auto/download-start-time.txt" || true
        REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))
        log_success "  ✓ Stale download status reset; helper will perform a fresh check on next run"
    fi
fi

# Check 14: zypp lock state (stale vs active)
log_debug "[14/${TOTAL_CHECKS}] Checking for zypp lock file (stale vs active)..."
if [ -f "/run/zypp.pid" ] || [ -f "/var/run/zypp.pid" ]; then
    ZYPP_LOCK_FILE="/run/zypp.pid"
    [ -f "/var/run/zypp.pid" ] && ZYPP_LOCK_FILE="/var/run/zypp.pid"
    ZYPP_LOCK_PID=$(cat "$ZYPP_LOCK_FILE" 2>/dev/null || echo "")

    # If PID is numeric and alive: treat as an active/legitimate lock.
    if [[ "${ZYPP_LOCK_PID:-}" =~ ^[0-9]+$ ]] && kill -0 "$ZYPP_LOCK_PID" 2>/dev/null; then
        ZYPPER_LOCK_ACTIVE=1
        ZYPPER_LOCK_PID_ACTIVE="$ZYPP_LOCK_PID"
        log_warn "⚠ zypper appears to be running (lock held by PID ${ZYPP_LOCK_PID}); skipping zypper-based repairs"
    else
        # PID is missing/non-numeric OR process is dead.
        # Never remove the lock if any zypper process is currently running.
        if pgrep -x zypper >/dev/null 2>&1; then
            ZYPPER_LOCK_ACTIVE=1
            ZYPPER_LOCK_PID_ACTIVE="${ZYPP_LOCK_PID:-unknown}"
            log_warn "⚠ zypp lock file looks stale but a zypper process is running; NOT removing lock (${ZYPP_LOCK_FILE})"
        else
            log_warn "⚠ Found stale zypp lock at ${ZYPP_LOCK_FILE} (PID ${ZYPP_LOCK_PID:-unknown} not running)"
            log_info "  → Attempting to remove stale lock file..."
            if execute_guarded "Remove stale zypp lock file" rm -f "$ZYPP_LOCK_FILE"; then
                REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))
                log_success "  ✓ Removed stale zypp lock file"
            else
                log_error "  ✗ Failed to remove stale zypp lock file"
                VERIFICATION_FAILED=1
            fi
        fi
    fi
else
    log_debug "No zypp lock file present"
fi

# Check 15: Root filesystem free space and cleanup
log_debug "[15/${TOTAL_CHECKS}] Checking root filesystem free space..."
ROOT_FREE_MB=$(df -Pm / 2>/dev/null | awk 'NR==2 {print $4}')
if [ -n "$ROOT_FREE_MB" ] && [ "$ROOT_FREE_MB" -lt 1024 ]; then
    log_warn "⚠ Low free space on / (only ${ROOT_FREE_MB}MB available; minimum 1024MB recommended)"
    log_info "  → Attempting best-effort cleanup with 'zypper clean --all'..."

    if [ "${ZYPPER_LOCK_ACTIVE:-0}" -eq 1 ] 2>/dev/null; then
        log_warn "  ⚠ Skipping 'zypper clean --all' because zypper appears to be running (lock PID: ${ZYPPER_LOCK_PID_ACTIVE:-unknown})"
        DISK_SPACE_CRITICAL=1
    else
        DISK_SPACE_CLEANED_ZYPPER=1
        REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))

        if execute_guarded "Run zypper clean --all" zypper --non-interactive clean --all; then
            sleep 1
            ROOT_FREE_MB_AFTER=$(df -Pm / 2>/dev/null | awk 'NR==2 {print $4}')
            if [ -n "$ROOT_FREE_MB_AFTER" ] && [ "$ROOT_FREE_MB_AFTER" -ge 1024 ]; then
                log_success "  ✓ Free space after cleanup: ${ROOT_FREE_MB_AFTER}MB (>= 1024MB)"
            else
                log_warn "  ⚠ Still low on space after cleanup (currently ${ROOT_FREE_MB_AFTER:-unknown}MB)"
                log_info "  → Advanced reclamation will run later (see Check 36)"
                DISK_SPACE_CRITICAL=1
            fi
        else
            log_warn "  ⚠ 'zypper clean --all' failed; advanced reclamation will run later (see Check 36)"
            DISK_SPACE_CRITICAL=1
        fi
    fi
else
    log_success "✓ Root filesystem has sufficient free space (${ROOT_FREE_MB:-unknown}MB)"
fi

# Check 16: RPM database integrity (best-effort)
log_debug "[16/${TOTAL_CHECKS}] Checking RPM database integrity..."
RPM_DB_PATH=$(rpm --eval '%{_dbpath}' 2>/dev/null || true)
if [ -z "${RPM_DB_PATH:-}" ]; then
    RPM_DB_PATH="/usr/lib/sysimage/rpm"
fi

RPM_DB_FILE=""
if [ -f "${RPM_DB_PATH}/Packages" ]; then
    RPM_DB_FILE="${RPM_DB_PATH}/Packages"
elif [ -f "${RPM_DB_PATH}/rpmdb.sqlite" ]; then
    RPM_DB_FILE="${RPM_DB_PATH}/rpmdb.sqlite"
fi

RPMDB_VERIFY_BIN=""
if command -v rpmdb_verify >/dev/null 2>&1; then
    RPMDB_VERIFY_BIN="$(command -v rpmdb_verify)"
elif [ -x /usr/lib/rpm/rpmdb_verify ]; then
    RPMDB_VERIFY_BIN="/usr/lib/rpm/rpmdb_verify"
fi

if [ -n "${RPMDB_VERIFY_BIN}" ] && [ -n "${RPM_DB_FILE}" ]; then
    if command -v timeout >/dev/null 2>&1; then
        if execute_guarded "RPM DB structural verify (${RPM_DB_FILE})" timeout 15 "${RPMDB_VERIFY_BIN}" "${RPM_DB_FILE}"; then
            log_success "✓ RPM database structural check passed"
        else
            log_error "✗ RPM database structural check FAILED (dbpath=${RPM_DB_PATH})"
            log_error "  → Auto-repair will attempt an rpmdb rebuild later (see Check 38)"
            RPMDB_STRUCTURAL_FAILED=1
        fi
    else
        if execute_guarded "RPM DB structural verify (${RPM_DB_FILE})" "${RPMDB_VERIFY_BIN}" "${RPM_DB_FILE}"; then
            log_success "✓ RPM database structural check passed"
        else
            log_error "✗ RPM database structural check FAILED (dbpath=${RPM_DB_PATH})"
            log_error "  → Auto-repair will attempt an rpmdb rebuild later (see Check 38)"
            RPMDB_STRUCTURAL_FAILED=1
        fi
    fi
else
    log_info "ℹ RPM DB structural check skipped (rpmdb_verify not found or db file not detected at ${RPM_DB_PATH})"
fi

# Check 17: Targeted RPM package verification (critical packages)
log_debug "[17/${TOTAL_CHECKS}] Verifying critical system packages (rpm -V)..."
(
    set +e
    critical_pkgs=(glibc systemd zypper libzypp rpm)
    rpm_verify_out=$(rpm -V --nomtime --nosize "${critical_pkgs[@]}" 2>&1)
    rpm_verify_rc=$?
    set -e

    if [ "$rpm_verify_rc" -eq 0 ] && [ -z "${rpm_verify_out:-}" ]; then
        log_success "✓ rpm -V reports no verification differences for critical packages"
    elif [ "$rpm_verify_rc" -eq 1 ]; then
        log_warn "⚠ rpm -V reported verification differences (this may be expected on some systems)"
        echo "rpm -V output (first 50 lines):" | tee -a "${LOG_FILE}"
        printf '%s\n' "${rpm_verify_out}" | head -n 50 | tee -a "${LOG_FILE}"
    else
        log_error "✗ rpm -V failed unexpectedly (rc=${rpm_verify_rc})"
        echo "rpm -V output (first 50 lines):" | tee -a "${LOG_FILE}"
        printf '%s\n' "${rpm_verify_out}" | head -n 50 | tee -a "${LOG_FILE}"
        VERIFICATION_FAILED=1
    fi
)

# Check 18: Global systemd failed units (auto-fix enabled)
log_debug "[18/${TOTAL_CHECKS}] Checking for failed systemd units (global)..."
FAILED_UNITS=$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | sed '/^$/d' || true)
if [ -z "${FAILED_UNITS:-}" ]; then
    log_success "✓ No failed systemd units detected"
else
    log_warn "⚠ Failed systemd units detected: $(echo "$FAILED_UNITS" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
    log_info "  → Attempting auto-repair: resetting failed unit states..."

    if execute_guarded "Reset failed systemd units" systemctl reset-failed; then
        REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))
        FAILED_UNITS_AFTER=$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | sed '/^$/d' || true)
        if [ -z "${FAILED_UNITS_AFTER:-}" ]; then
            log_success "  ✓ Auto-repair successful: All failed states cleared"
        else
            log_error "  ✗ Some units remain failed: $(echo "$FAILED_UNITS_AFTER" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
            # Only fail verification for units likely to impact updates/networking.
            if echo "$FAILED_UNITS_AFTER" | grep -qE '(zypper|zypp|NetworkManager|wicked|systemd-networkd|wpa_supplicant)'; then
                VERIFICATION_FAILED=1
            fi
        fi
    else
        log_error "  ✗ Failed to reset systemd failed states"
    fi
fi

# Check 19: Systemd flapping/stale service hint (restart counters)
log_debug "[19/${TOTAL_CHECKS}] Checking systemd restart counters (flapping hint)..."
flap_warned=0
for unit in "${DL_SERVICE_NAME}.service" "${DL_SERVICE_NAME}.timer" "${VERIFY_SERVICE_NAME}.service" "${CLEANUP_SERVICE_NAME}.service"; do
    nr=$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || echo "")
    if [[ "${nr:-}" =~ ^[0-9]+$ ]] && [ "$nr" -gt 3 ] 2>/dev/null; then
        log_warn "⚠ Unit $unit has NRestarts=$nr (possible flapping)"
        flap_warned=1
    fi
done
if [ -n "${SUDO_USER:-}" ] && [ -n "${USER_BUS_PATH:-}" ]; then
    nr_u=$(sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user show "${NT_SERVICE_NAME}.service" -p NRestarts --value 2>/dev/null || echo "")
    if [[ "${nr_u:-}" =~ ^[0-9]+$ ]] && [ "$nr_u" -gt 3 ] 2>/dev/null; then
        log_warn "⚠ User unit ${NT_SERVICE_NAME}.service has NRestarts=$nr_u (possible flapping)"
        flap_warned=1
    fi
fi
if [ "${flap_warned}" -eq 0 ] 2>/dev/null; then
    log_success "✓ No high restart counters detected on core units"
fi

# Check 20: DNS resolution for primary repo domain (auto-fix enabled)
log_debug "[20/${TOTAL_CHECKS}] Checking DNS resolution for download.opensuse.org..."
if getent hosts download.opensuse.org >/dev/null 2>&1; then
    log_success "✓ DNS resolution OK for download.opensuse.org"
else
    log_warn "⚠ DNS resolution FAILED. Attempting auto-repair..."

    REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))

    # Best-effort: flush resolver caches first (less disruptive than a network restart).
    if command -v resolvectl >/dev/null 2>&1; then
        execute_guarded "Flush systemd-resolved DNS caches" resolvectl flush-caches >/dev/null 2>&1 || true
    fi

    # Avoid restarting the whole network stack during an active SSH session.
    if [ -n "${SSH_CONNECTION:-}" ] || [ -n "${SSH_TTY:-}" ]; then
        log_warn "  ⚠ Skipping NetworkManager/wicked restart (SSH session detected)"
    else
        if systemctl is-active NetworkManager.service >/dev/null 2>&1 || systemctl is-active NetworkManager >/dev/null 2>&1; then
            execute_guarded "Restart NetworkManager" systemctl restart NetworkManager
            sleep 5
        elif systemctl is-active wicked.service >/dev/null 2>&1 || systemctl is-active wicked >/dev/null 2>&1; then
            execute_guarded "Restart wicked" systemctl restart wicked
            sleep 5
        fi
    fi

    if getent hosts download.opensuse.org >/dev/null 2>&1; then
        log_success "  ✓ Auto-repair successful: DNS resolution restored"
    else
        log_error "  ✗ DNS resolution still failing after repair attempts"
        VERIFICATION_FAILED=1
    fi
fi

# Check 21: Repository accessibility (best-effort; network may be offline)
log_debug "[21/${TOTAL_CHECKS}] Checking zypper repository configuration/readability..."
if zypper --non-interactive --quiet lr >/dev/null 2>&1; then
    log_success "✓ zypper repositories are readable (lr)"
else
    log_error "✗ Unable to list repositories (zypper lr failed)"
    VERIFICATION_FAILED=1
fi

log_debug "[21/${TOTAL_CHECKS}] Checking repository reachability (zypper refresh; auto-fix)..."

if [ "${ZYPPER_LOCK_ACTIVE:-0}" -eq 1 ] 2>/dev/null; then
    log_warn "⚠ Skipping repo refresh check because zypper appears to be running (lock PID: ${ZYPPER_LOCK_PID_ACTIVE:-unknown})"
else
    refresh_ok=0
    if command -v timeout >/dev/null 2>&1; then
        if timeout 25 zypper --non-interactive --quiet refresh >/dev/null 2>&1; then
            refresh_ok=1
        fi
    else
        if zypper --non-interactive --quiet refresh >/dev/null 2>&1; then
            refresh_ok=1
        fi
    fi

    if [ "${refresh_ok}" -eq 1 ] 2>/dev/null; then
        log_success "✓ zypper refresh succeeded (repos reachable)"
    else
        log_warn "⚠ zypper refresh failed. Attempting auto-repair (force refresh)..."
        REPO_REFRESH_FAILED=1

    # Attempt a force refresh first (no key auto-import).
    REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))
    if command -v timeout >/dev/null 2>&1; then
        if execute_guarded "Force zypper refresh" timeout 60 zypper --non-interactive refresh --force; then
            log_success "  ✓ Auto-repair successful: Repository metadata refreshed"
            REPO_REFRESH_FAILED=0
        else
            log_warn "  ⚠ Force refresh failed; attempting with --gpg-auto-import-keys as a last resort..."
            if execute_guarded "Force zypper refresh (auto-import keys)" timeout 60 zypper --non-interactive --gpg-auto-import-keys refresh --force; then
                log_success "  ✓ Auto-repair successful: Repository metadata refreshed (keys auto-imported)"
                REPO_REFRESH_FAILED=0
                REPO_REFRESH_USED_GPG_IMPORT=1
            else
                log_error "  ✗ Repository refresh failed even after force attempts"
                VERIFICATION_FAILED=1
            fi
        fi
    else
        if execute_guarded "Force zypper refresh" zypper --non-interactive refresh --force; then
            log_success "  ✓ Auto-repair successful: Repository metadata refreshed"
            REPO_REFRESH_FAILED=0
        else
            log_warn "  ⚠ Force refresh failed; attempting with --gpg-auto-import-keys as a last resort..."
            if execute_guarded "Force zypper refresh (auto-import keys)" zypper --non-interactive --gpg-auto-import-keys refresh --force; then
                log_success "  ✓ Auto-repair successful: Repository metadata refreshed (keys auto-imported)"
                REPO_REFRESH_FAILED=0
                REPO_REFRESH_USED_GPG_IMPORT=1
            else
                log_error "  ✗ Repository refresh failed even after force attempts"
                VERIFICATION_FAILED=1
            fi
        fi
    fi
    fi
fi

# Check 22: Sudoers permissions hardening (auto-fix enabled)
log_debug "[22/${TOTAL_CHECKS}] Checking sudoers permissions..."
bad_sudoers=0

sudoers_mode=""
if [ -f /etc/sudoers ]; then
    sudoers_mode=$(stat -c %a /etc/sudoers 2>/dev/null || echo "")
    if [ -n "${sudoers_mode:-}" ] && [ "${sudoers_mode}" != "440" ]; then
        bad_sudoers=1
    fi
fi

# Quick scan for any bad perms in included files
if [ -d /etc/sudoers.d ]; then
    if find /etc/sudoers.d -maxdepth 1 -type f ! -perm 440 -print -quit 2>/dev/null | grep -q .; then
        bad_sudoers=1
    fi
fi

if [ "${bad_sudoers}" -eq 0 ] 2>/dev/null; then
    log_success "✓ sudoers permissions look correct (0440)"
else
    log_warn "⚠ Sudoers permissions are incorrect (security risk)"

    if [ -n "${sudoers_mode:-}" ] && [ "${sudoers_mode}" != "440" ]; then
        log_warn "  - /etc/sudoers mode is ${sudoers_mode} (expected 440)"
    fi
    if [ -d /etc/sudoers.d ]; then
        bad_files=$(find /etc/sudoers.d -maxdepth 1 -type f ! -perm 440 2>/dev/null | head -n 20 || true)
        if [ -n "${bad_files:-}" ]; then
            log_warn "  - sudoers.d files with incorrect perms (first 20):"
            printf '%s\n' "$bad_files" | sed 's/^/    - /' | tee -a "${LOG_FILE}"
        fi
    fi

    log_info "  → Attempting auto-repair: enforcing 0440 permissions..."
    execute_guarded "Fix /etc/sudoers permissions" chmod 440 /etc/sudoers >/dev/null 2>&1 || true
    execute_guarded "Fix /etc/sudoers.d/* permissions" find /etc/sudoers.d -maxdepth 1 -type f -exec chmod 440 {} + >/dev/null 2>&1 || true
    REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))

    new_mode=$(stat -c %a /etc/sudoers 2>/dev/null || echo "")
    if [ "$new_mode" = "440" ] 2>/dev/null; then
        log_success "  ✓ Sudoers permissions fixed successfully"
    else
        log_error "  ✗ Failed to fix /etc/sudoers permissions (current: ${new_mode:-unknown})"
    fi
fi

# Check 23: Btrfs filesystem health (device error stats)
log_debug "[23/${TOTAL_CHECKS}] Checking Btrfs device stats for / (if applicable)..."
root_fstype=""
if command -v findmnt >/dev/null 2>&1; then
    root_fstype=$(findmnt -n -o FSTYPE / 2>/dev/null || true)
fi
if [ "${root_fstype:-}" = "btrfs" ] && command -v btrfs >/dev/null 2>&1; then
    btrfs_out=$(btrfs device stats / 2>/dev/null || true)
    btrfs_bad=$(printf '%s\n' "$btrfs_out" | awk '$NF != 0 {print}' | sed '/^$/d' || true)
    if [ -z "${btrfs_bad:-}" ]; then
        log_success "✓ Btrfs device stats report no errors"
    else
        log_error "✗ Btrfs device stats report errors (non-zero counters):"
        printf '%s\n' "$btrfs_bad" | head -n 50 | sed 's/^/  /' | tee -a "${LOG_FILE}"
        VERIFICATION_FAILED=1
    fi
else
    log_info "ℹ Btrfs device stats check skipped (fstype=${root_fstype:-unknown})"
fi

# Check 24: Snapper root config validation (best-effort)
log_debug "[24/${TOTAL_CHECKS}] Checking Snapper root config (if available)..."
if command -v snapper >/dev/null 2>&1; then
    set +e
    # Newer snapper versions support '--last N'. Some older versions do not.
    snapper_out=$(snapper -c root list --last 1 2>&1)
    snapper_rc=$?
    if [ "$snapper_rc" -ne 0 ] && printf '%s\n' "$snapper_out" | grep -q "Unknown option '--last'"; then
        snapper_out=$(snapper -c root list 2>&1)
        snapper_rc=$?
    fi
    set -e

    if [ "$snapper_rc" -eq 0 ]; then
        # snapper output can be ASCII pipes '|' or unicode table separators '│'
        snapper_count=$(printf '%s\n' "$snapper_out" | awk '/^[[:space:]]*[0-9]+\*?[[:space:]]*[|│]/ {c++} END {print c+0}')
        if [ "${snapper_count:-0}" -gt 0 ] 2>/dev/null; then
            log_success "✓ Snapper root config appears functional (${snapper_count} snapshot(s) detected)"
        elif printf '%s\n' "$snapper_out" | grep -qiE 'no snapshots'; then
            log_warn "⚠ Snapper root config exists but no snapshots were listed"
        else
            log_warn "⚠ Snapper root config check could not detect snapshots (output format unexpected)"
        fi
    else
        log_warn "⚠ Snapper root config check failed (rc=${snapper_rc}); Snapper may be missing/unconfigured"
        printf '%s\n' "$snapper_out" | head -n 30 | tee -a "${LOG_FILE}"
    fi
else
    log_info "ℹ Snapper not installed; skipping root snapshot validation"
fi

# Check 25: Cron conflicts (best-effort)
log_debug "[25/${TOTAL_CHECKS}] Checking for cron jobs that run zypper (conflicts)..."
# Ignore comment-only mentions to avoid false positives from documentation lines.
# (With -n, grep prefixes results with 'file:line:', so the comment check must happen after that prefix.)
cron_hits=$(grep -R -n -E ':[0-9]+:[[:space:]]*[^#].*\<zypper\>' /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /etc/crontab /var/spool/cron 2>/dev/null | head -n 20 || true)
if [ -z "${cron_hits:-}" ]; then
    log_success "✓ No zypper cron jobs detected"
else
    log_warn "⚠ Found cron entries that appear to run zypper (may conflict with systemd timers):"
    printf '%s\n' "$cron_hits" | tee -a "${LOG_FILE}"
fi

# Check 26: World-writable files in critical locations (best-effort)
log_debug "[26/${TOTAL_CHECKS}] Scanning for world-writable files in /etc and /usr/local/bin..."
ww_hits=$(find /etc /usr/local/bin -xdev -type f -perm -0002 -print 2>/dev/null | head -n 10 || true)
if [ -z "${ww_hits:-}" ]; then
    log_success "✓ No world-writable critical files found"
else
    log_warn "⚠ Found world-writable files in /etc or /usr/local/bin (security risk)"
    printf '%s\n' "$ww_hits" | sed 's/^/  /' | tee -a "${LOG_FILE}"
fi

# Check 27: SSH configuration hardening (best-effort; only if sshd is active)
log_debug "[27/${TOTAL_CHECKS}] Checking SSH hardening (PermitRootLogin / PermitEmptyPasswords)..."
if systemctl is-active sshd.service >/dev/null 2>&1 || systemctl is-active sshd >/dev/null 2>&1; then
    ssh_warned=0

    # Prefer effective config via 'sshd -T' when available.
    if command -v sshd >/dev/null 2>&1; then
        sshd_eff=$(sshd -T 2>/dev/null || true)
        if printf '%s\n' "$sshd_eff" | grep -qiE '^permitrootlogin[[:space:]]+yes$'; then
            log_warn "⚠ SSH allows root login (PermitRootLogin yes)"
            ssh_warned=1
        fi
        if printf '%s\n' "$sshd_eff" | grep -qiE '^permitemptypasswords[[:space:]]+yes$'; then
            log_warn "⚠ SSH allows empty passwords (PermitEmptyPasswords yes)"
            ssh_warned=1
        fi
    fi

    # Fallback: scan common config locations (may miss Match blocks; best-effort only).
    if [ "$ssh_warned" -eq 0 ] 2>/dev/null; then
        ssh_cfg_hits=$(grep -R -n -E '^[[:space:]]*(PermitRootLogin[[:space:]]+yes|PermitEmptyPasswords[[:space:]]+yes)\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null | head -n 10 || true)
        if [ -n "${ssh_cfg_hits:-}" ]; then
            log_warn "⚠ SSH hardening findings in sshd config (review recommended):"
            printf '%s\n' "$ssh_cfg_hits" | sed 's/^/  /' | tee -a "${LOG_FILE}"
            ssh_warned=1
        fi
    fi

    if [ "$ssh_warned" -eq 0 ] 2>/dev/null; then
        log_success "✓ SSH hardening looks OK (no obvious root-login/empty-password settings found)"
    fi
else
    log_info "ℹ SSH daemon not active; skipping SSH hardening check"
fi

# Check 28: Time synchronization (NTP)
log_debug "[28/${TOTAL_CHECKS}] Verifying system clock synchronization (NTP)..."
if command -v timedatectl >/dev/null 2>&1; then
    ntp_sync=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo "")
    if printf '%s' "$ntp_sync" | grep -qi '^yes$'; then
        log_success "✓ System clock is synchronized"
    else
        log_warn "⚠ System clock is NOT synchronized (may cause GPG/signature errors)"
        log_info "  → Attempting to fix: restarting time sync services (chronyd/chrony/systemd-timesyncd)..."
        REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))
        execute_guarded "Restart chronyd" systemctl restart chronyd.service >/dev/null 2>&1 || true
        execute_guarded "Restart chrony" systemctl restart chrony.service >/dev/null 2>&1 || true
        execute_guarded "Restart systemd-timesyncd" systemctl restart systemd-timesyncd.service >/dev/null 2>&1 || true

        ntp_sync2=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo "")
        if printf '%s' "$ntp_sync2" | grep -qi '^yes$'; then
            log_success "  ✓ NTP synchronization recovered"
        else
            log_warn "  ⚠ NTP still not synchronized after restart (check chrony/timesyncd configuration)"
        fi
    fi
else
    log_info "ℹ timedatectl not available; skipping NTP synchronization check"
fi

# Check 29: Orphaned packages (best-effort)
log_debug "[29/${TOTAL_CHECKS}] Checking for orphaned packages (no repository)..."
if [ "${ZYPPER_LOCK_ACTIVE:-0}" -eq 1 ] 2>/dev/null; then
    log_warn "⚠ Skipping orphaned package check because zypper appears to be running (lock PID: ${ZYPPER_LOCK_PID_ACTIVE:-unknown})"
elif command -v zypper >/dev/null 2>&1; then
    set +e
    if command -v timeout >/dev/null 2>&1; then
        orphans_out=$(timeout 20 zypper --no-refresh --non-interactive packages --orphaned 2>&1)
        orphans_rc=$?
    else
        orphans_out=$(zypper --no-refresh --non-interactive packages --orphaned 2>&1)
        orphans_rc=$?
    fi
    set -e

    if [ "$orphans_rc" -eq 0 ]; then
        orphans_count=$(printf '%s\n' "$orphans_out" | awk -F'|' '$1 ~ /i/ {c++} END {print c+0}')
        if [ "${orphans_count:-0}" -gt 0 ] 2>/dev/null; then
            log_info "ℹ Found ${orphans_count} orphaned package(s) (installed but not provided by any configured repo)"
            log_info "  → Review with: sudo zypper packages --orphaned"
        else
            log_success "✓ No orphaned packages detected"
        fi
    else
        log_warn "⚠ Orphaned package check failed (rc=${orphans_rc}); skipping"
        printf '%s\n' "$orphans_out" | head -n 20 | tee -a "${LOG_FILE}"
    fi
else
    log_info "ℹ zypper not available; skipping orphaned package check"
fi

# Check 30: Physical disk health (SMART) (best-effort)
log_debug "[30/${TOTAL_CHECKS}] Checking SMART health (if smartctl is available)..."
if command -v smartctl >/dev/null 2>&1; then
    smart_failed=0
    smart_devices=$(smartctl --scan-open 2>/dev/null | awk '{print $1}' | sed '/^$/d' || true)

    if [ -z "${smart_devices:-}" ]; then
        log_info "ℹ smartctl found but no devices detected via --scan-open; skipping SMART health check"
    else
        while IFS= read -r dev; do
            [ -z "${dev:-}" ] && continue
            set +e
            if command -v timeout >/dev/null 2>&1; then
                smart_out=$(timeout 15 smartctl -H "$dev" 2>&1)
                smart_rc=$?
            else
                smart_out=$(smartctl -H "$dev" 2>&1)
                smart_rc=$?
            fi
            set -e

            # smartctl uses a bitmask rc; parse output for explicit FAIL.
            if printf '%s\n' "$smart_out" | grep -qE 'SMART overall-health self-assessment test result:.*FAIL|SMART Health Status:.*FAIL|FAILED!|\bFAILED\b'; then
                log_error "✗ CRITICAL: SMART health check reports failure for ${dev}"
                printf '%s\n' "$smart_out" | head -n 25 | sed 's/^/  /' | tee -a "${LOG_FILE}"
                smart_failed=1
            elif [ "$smart_rc" -ne 0 ] 2>/dev/null && printf '%s\n' "$smart_out" | grep -qi 'Unavailable\|Unknown USB bridge\|Permission denied'; then
                log_warn "⚠ SMART health check could not assess ${dev} (unsupported/permission/bridge issue)"
            fi
        done <<< "$smart_devices"

        if [ "$smart_failed" -eq 0 ] 2>/dev/null; then
            log_success "✓ SMART health check passed on detected drives"
        else
            VERIFICATION_FAILED=1
        fi
    fi
else
    log_info "ℹ smartctl not installed; skipping SMART health check"
fi

# Check 31: Kernel taint state (best-effort)
log_debug "[31/${TOTAL_CHECKS}] Checking kernel taint state..."
if [ -r /proc/sys/kernel/tainted ]; then
    taint=$(cat /proc/sys/kernel/tainted 2>/dev/null || echo "")
    if [[ "${taint:-}" =~ ^[0-9]+$ ]] && [ "$taint" -ne 0 ] 2>/dev/null; then
        log_warn "⚠ Kernel is tainted (value: $taint). Check 'dmesg' or 'journalctl -k'."
    else
        log_success "✓ Kernel is not tainted"
    fi
else
    log_info "ℹ /proc/sys/kernel/tainted not available; skipping kernel taint check"
fi

# Check 32: Pending system reboot (runtime consistency)
log_debug "[32/${TOTAL_CHECKS}] Checking if system reboot is required (zypper needs-reboot)..."
if command -v zypper >/dev/null 2>&1; then
    set +e
    zypper needs-reboot >/dev/null 2>&1
    needs_reboot_rc=$?
    set -e

    # On openSUSE, zypper returns 1 when a reboot is needed.
    if [ "$needs_reboot_rc" -eq 1 ]; then
        log_warn "⚠ System reboot is pending (core libraries/kernel updated)"
        log_info "  → Recommended: reboot before applying further updates"
    elif [ "$needs_reboot_rc" -eq 0 ]; then
        log_success "✓ No pending reboot detected"
    else
        # Some zypper versions may not support needs-reboot.
        set +e
        zypper needs-rebooting >/dev/null 2>&1
        needs_rebooting_rc=$?
        set -e
        if [ "$needs_rebooting_rc" -eq 1 ]; then
            log_warn "⚠ System reboot is pending (core libraries/kernel updated)"
            log_info "  → Recommended: reboot before applying further updates"
        elif [ "$needs_rebooting_rc" -eq 0 ]; then
            log_success "✓ No pending reboot detected"
        else
            log_info "ℹ Reboot check not available (zypper needs-reboot returned rc=${needs_reboot_rc})"
        fi
    fi
else
    log_info "ℹ zypper not available; skipping reboot requirement check"
fi

# Check 33: Dashboard Shortcut Health (Start Menu & Desktop)
log_debug "[33/${TOTAL_CHECKS}] Checking Shortcuts (Start Menu + Desktop)..."

# 1) Define paths
local app_shortcut desktop_dir desk_shortcut shortcuts_ok
app_shortcut="${SUDO_USER_HOME}/.local/share/applications/zypper-auto-dashboard.desktop"

# Smart detection of the Desktop folder (handles different languages)
desktop_dir="${SUDO_USER_HOME}/Desktop"
if [ -n "${SUDO_USER:-}" ]; then
    desktop_dir=$(sudo -u "${SUDO_USER}" sh -c 'command -v xdg-user-dir >/dev/null && xdg-user-dir DESKTOP || echo "$HOME/Desktop"' 2>/dev/null || echo "${SUDO_USER_HOME}/Desktop")
fi

desk_shortcut="${desktop_dir}/Zypper Auto Dashboard.desktop"

log_debug "[shortcuts] app_shortcut=${app_shortcut}"
log_debug "[shortcuts] desktop_dir=${desktop_dir}"
log_debug "[shortcuts] desk_shortcut=${desk_shortcut}"

shortcuts_ok=1

# 2) Verify Start Menu Icon
if [ ! -f "${app_shortcut}" ]; then
    shortcuts_ok=0
    log_warn "[shortcuts] Missing Start Menu launcher: ${app_shortcut}"
elif ! grep -qE '^[[:space:]]*Actions=.*Verify' "${app_shortcut}" 2>/dev/null; then
    shortcuts_ok=0
    log_warn "[shortcuts] Start Menu launcher is outdated (missing Verify action): ${app_shortcut}"
elif ! grep -qF "read line" "${app_shortcut}" 2>/dev/null; then
    # Keep the check strict so older shortcut generations get upgraded.
    shortcuts_ok=0
    log_warn "[shortcuts] Start Menu launcher is outdated (missing UX marker 'read line'): ${app_shortcut}"
fi

# 3) Verify Desktop Surface Icon
# Only check if the Desktop folder actually exists (some users disable it)
if [ -d "${desktop_dir}" ]; then
    if [ ! -f "${desk_shortcut}" ]; then
        shortcuts_ok=0
        log_warn "[shortcuts] Missing Desktop shortcut: ${desk_shortcut}"
    fi
else
    log_info "[shortcuts] Desktop directory does not exist; skipping Desktop shortcut check: ${desktop_dir}"
fi

# 4) Act
if [ "${shortcuts_ok}" -eq 1 ] 2>/dev/null; then
    log_success "✓ Shortcuts present in Start Menu & Desktop"
else
    log_error "✗ Shortcuts are missing or outdated"
    log_info "  → Triggering immediate restore via __znh_ensure_dash_desktop_shortcut..."

    REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))

    if execute_guarded "Regenerate shortcuts" \
        __znh_ensure_dash_desktop_shortcut "${SUDO_USER}" "${SUDO_USER_HOME}"; then

        # Polish: Touch the desktop file to force the DE to redraw it immediately
        if [ -f "${desk_shortcut}" ] && [ -n "${SUDO_USER:-}" ]; then
            execute_optional "Touch Desktop shortcut (icon refresh hint)" \
                sudo -u "${SUDO_USER}" touch "${desk_shortcut}" >/dev/null 2>&1 || true
        fi

        log_success "  ✓ Auto-repair successful: All shortcuts restored"
    else
        log_error "  ✗ Failed to restore shortcuts"
        log_info "  → You can manually regenerate via: zypper-auto-helper --dash-open"
        VERIFICATION_FAILED=1
    fi
fi

# Check 34: Memory headroom (solver safety)
log_debug "[34/${TOTAL_CHECKS}] Checking memory headroom for update solver..."
mem_avail_mb=""
if [ -r /proc/meminfo ]; then
    mem_avail_kb=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null || echo "")
    if [[ "${mem_avail_kb:-}" =~ ^[0-9]+$ ]]; then
        mem_avail_mb=$((mem_avail_kb / 1024))
    fi
fi
if [ -z "${mem_avail_mb:-}" ] && command -v free >/dev/null 2>&1; then
    # free(1) 'available' column is typically $7
    mem_avail_mb=$(free -m 2>/dev/null | awk '/^Mem:/ {print $7}' || echo "")
fi

if [[ "${mem_avail_mb:-}" =~ ^[0-9]+$ ]]; then
    if [ "$mem_avail_mb" -lt 150 ] 2>/dev/null; then
        log_error "✗ CRITICAL: Low available memory (${mem_avail_mb}MB). Updates may trigger OOM or fail mid-transaction."
        log_info "  → Recommended: close apps / stop heavy services, then re-run verification before updating"

        # Best-effort mitigation: dropping caches can help, but does not solve true memory pressure.
        if command -v sysctl >/dev/null 2>&1; then
            log_info "  → Attempting best-effort: drop filesystem caches (may temporarily free RAM)"
            REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))
            execute_guarded "Drop filesystem caches" sysctl -w vm.drop_caches=3 >/dev/null 2>&1 || true
        fi

        # Re-check memory after best-effort cache drop
        mem_avail_kb2=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null || echo "")
        if [[ "${mem_avail_kb2:-}" =~ ^[0-9]+$ ]]; then
            mem_avail_mb2=$((mem_avail_kb2 / 1024))
            if [ "$mem_avail_mb2" -ge 300 ] 2>/dev/null; then
                log_success "  ✓ Memory recovered (now ${mem_avail_mb2}MB available)"
            else
                log_warn "  ⚠ Still low on memory after cache drop (${mem_avail_mb2}MB available)"
            fi
        fi

        # Mark as failed: running updates under severe memory pressure is unsafe.
        VERIFICATION_FAILED=1
    elif [ "$mem_avail_mb" -lt 300 ] 2>/dev/null; then
        log_warn "⚠ Low available memory (${mem_avail_mb}MB). Large updates may be risky."
        log_info "  → Recommended: keep at least ~300MB+ available before running 'zypper dup'"
    else
        log_success "✓ Sufficient memory available (${mem_avail_mb}MB)"
    fi
else
    log_info "ℹ Unable to determine available memory; skipping memory headroom check"
fi

# Check 35: AppArmor security status (auto-fix enabled)
log_debug "[35/${TOTAL_CHECKS}] Verifying AppArmor security status..."
if systemctl is-active apparmor.service >/dev/null 2>&1 || systemctl is-active apparmor >/dev/null 2>&1; then
    if command -v aa-status >/dev/null 2>&1; then
        set +e
        aa-status --enabled >/dev/null 2>&1
        aa_rc=$?
        set -e

        if [ "$aa_rc" -eq 0 ]; then
            log_success "✓ AppArmor is active and profiles are loaded"
        else
            log_warn "⚠ AppArmor is active but profiles do not appear to be enabled"
            log_info "  → Attempting auto-repair: reloading AppArmor..."

            REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))
            execute_guarded "Reload AppArmor" systemctl reload apparmor >/dev/null 2>&1 || \
                execute_guarded "Restart AppArmor" systemctl restart apparmor >/dev/null 2>&1 || true

            set +e
            aa-status --enabled >/dev/null 2>&1
            aa_rc2=$?
            set -e
            if [ "$aa_rc2" -eq 0 ]; then
                log_success "  ✓ Auto-repair successful: AppArmor profiles enabled"
            else
                log_warn "  ⚠ AppArmor reload did not enable profiles (reboot or manual intervention may be required)"
            fi
        fi
    else
        log_success "✓ AppArmor service is active (aa-status not found)"
    fi
else
    log_info "ℹ AppArmor is not active (disabled or not installed)"
fi

# Check 36: Proactive disk space reclamation (auto-fix)
log_debug "[36/${TOTAL_CHECKS}] Verifying disk space headroom..."
disk_avail=""
disk_avail=$(df -BM / 2>/dev/null | awk 'NR==2 {print $4}' | tr -d 'M' || echo "")
if [[ "${disk_avail:-}" =~ ^[0-9]+$ ]] && [ "$disk_avail" -gt 2000 ] 2>/dev/null; then
    log_success "✓ Disk space is healthy (${disk_avail}MB free)"
else
    if [[ "${disk_avail:-}" =~ ^[0-9]+$ ]]; then
        log_warn "⚠ Disk space is low/critical (${disk_avail}MB free). Updates may fail."
    else
        log_warn "⚠ Unable to determine disk headroom reliably; attempting best-effort cleanup anyway"
    fi

    # Only run the aggressive cleanup if space is low OR earlier checks flagged it.
    if [ "${DISK_SPACE_CRITICAL:-0}" -eq 1 ] 2>/dev/null || { [[ "${disk_avail:-}" =~ ^[0-9]+$ ]] && [ "$disk_avail" -le 2000 ] 2>/dev/null; }; then
        log_info "  → Attempting auto-repair: vacuum journals and clean caches/snapshots..."
        REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))

        if command -v journalctl >/dev/null 2>&1; then
            if command -v timeout >/dev/null 2>&1; then
                execute_guarded "Vacuum system journals" timeout 30 journalctl --vacuum-size=50M >/dev/null 2>&1 || true
            else
                execute_guarded "Vacuum system journals" journalctl --vacuum-size=50M >/dev/null 2>&1 || true
            fi
        fi

        # Skip repeating zypper clean if we already did it in Check 15, or if
        # zypper appears to be running (lock held by a live process).
        if [ "${DISK_SPACE_CLEANED_ZYPPER:-0}" -ne 1 ] 2>/dev/null && [ "${ZYPPER_LOCK_ACTIVE:-0}" -ne 1 ] 2>/dev/null; then
            execute_guarded "Clean zypper caches" zypper --non-interactive clean --all >/dev/null 2>&1 || true
        fi

        if command -v snapper >/dev/null 2>&1; then
            if command -v timeout >/dev/null 2>&1; then
                execute_guarded "Run snapper cleanup" timeout 60 snapper cleanup number >/dev/null 2>&1 || true
            else
                execute_guarded "Run snapper cleanup" snapper cleanup number >/dev/null 2>&1 || true
            fi
        fi

        disk_avail_after=$(df -BM / 2>/dev/null | awk 'NR==2 {print $4}' | tr -d 'M' || echo "")
        if [[ "${disk_avail_after:-}" =~ ^[0-9]+$ ]] && [ "$disk_avail_after" -gt 1000 ] 2>/dev/null; then
            log_success "  ✓ Space reclaimed! Now ${disk_avail_after}MB free."
            DISK_SPACE_CRITICAL=0
        else
            log_error "  ✗ Disk still too full after cleanup (currently ${disk_avail_after:-unknown}MB). Manual intervention needed."
            VERIFICATION_FAILED=1
        fi
    fi
fi

# Check 37: Zypper lock state (deadlock killer)
log_debug "[37/${TOTAL_CHECKS}] Checking for zypper locks (stale vs active)..."
lock_found=0
for zlock in /run/zypp.pid /var/run/zypp.pid; do
    if [ -f "$zlock" ]; then
        lock_found=1
        lock_pid=$(cat "$zlock" 2>/dev/null || echo "")
        if [[ "${lock_pid:-}" =~ ^[0-9]+$ ]] && kill -0 "$lock_pid" 2>/dev/null; then
            ZYPPER_LOCK_ACTIVE=1
            ZYPPER_LOCK_PID_ACTIVE="$lock_pid"
            log_warn "⚠ Zypper lock held by running PID ${lock_pid} (${zlock}). Skipping auto-fix (may be legitimate update)."
        else
            # Never remove a lock file if any zypper process is currently running.
            if pgrep -x zypper >/dev/null 2>&1; then
                ZYPPER_LOCK_ACTIVE=1
                ZYPPER_LOCK_PID_ACTIVE="${lock_pid:-unknown}"
                log_warn "⚠ zypper is running but lock PID is invalid/unknown; NOT removing lock file (${zlock})"
            else
                log_warn "⚠ Found stale zypper lock file (${zlock}) (PID ${lock_pid:-unknown} not running)."
                log_info "  → Attempting auto-repair: removing stale lock file..."
                if execute_guarded "Remove stale zypper lock" rm -f "$zlock"; then
                    REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))
                    log_success "  ✓ Stale lock removed"
                else
                    log_error "  ✗ Failed to remove stale lock file"
                    VERIFICATION_FAILED=1
                fi
            fi
        fi
    fi
done
if [ "$lock_found" -eq 0 ] 2>/dev/null; then
    log_success "✓ No zypper lock files detected"
fi

# Check 38: RPM database repair (nuclear option; best-effort)
log_debug "[38/${TOTAL_CHECKS}] Verifying RPM database integrity and attempting repair if needed..."
rpmdb_needs_repair=0

# If earlier structural check failed, we already know we should repair.
if [ "${RPMDB_STRUCTURAL_FAILED:-0}" -eq 1 ] 2>/dev/null; then
    rpmdb_needs_repair=1
fi

# Re-evaluate DB path and verify again (defensive; does not assume Check 16 ran).
RPM_DB_PATH2=$(rpm --eval '%{_dbpath}' 2>/dev/null || true)
if [ -z "${RPM_DB_PATH2:-}" ]; then
    RPM_DB_PATH2="/usr/lib/sysimage/rpm"
fi
RPM_DB_FILE2=""
if [ -f "${RPM_DB_PATH2}/Packages" ]; then
    RPM_DB_FILE2="${RPM_DB_PATH2}/Packages"
elif [ -f "${RPM_DB_PATH2}/rpmdb.sqlite" ]; then
    RPM_DB_FILE2="${RPM_DB_PATH2}/rpmdb.sqlite"
fi
RPMDB_VERIFY_BIN2=""
if command -v rpmdb_verify >/dev/null 2>&1; then
    RPMDB_VERIFY_BIN2="$(command -v rpmdb_verify)"
elif [ -x /usr/lib/rpm/rpmdb_verify ]; then
    RPMDB_VERIFY_BIN2="/usr/lib/rpm/rpmdb_verify"
fi

if [ -n "${RPMDB_VERIFY_BIN2:-}" ] && [ -n "${RPM_DB_FILE2:-}" ]; then
    set +e
    if command -v timeout >/dev/null 2>&1; then
        timeout 15 "${RPMDB_VERIFY_BIN2}" "${RPM_DB_FILE2}" >/dev/null 2>&1
        rpmdb_verify_rc=$?
    else
        "${RPMDB_VERIFY_BIN2}" "${RPM_DB_FILE2}" >/dev/null 2>&1
        rpmdb_verify_rc=$?
    fi
    set -e

    if [ "$rpmdb_verify_rc" -eq 0 ] 2>/dev/null; then
        log_success "✓ RPM database is healthy"
    else
        rpmdb_needs_repair=1
    fi
else
    # Fallback: if we cannot structural-verify, attempt a cheap query.
    set +e
    if command -v timeout >/dev/null 2>&1; then
        timeout 20 rpm -qa >/dev/null 2>&1
        rpm_query_rc=$?
    else
        rpm -qa >/dev/null 2>&1
        rpm_query_rc=$?
    fi
    set -e

    if [ "$rpm_query_rc" -eq 0 ] 2>/dev/null; then
        log_success "✓ RPM query sanity check passed (structural verify not available)"
    else
        rpmdb_needs_repair=1
    fi
fi

if [ "$rpmdb_needs_repair" -eq 1 ] 2>/dev/null; then
    log_error "✗ RPM database appears unhealthy/corrupted"
    log_info "  → Attempting auto-repair: backing up and rebuilding RPM database..."

    ts="$(date +%s)"
    rpmdb_backup="${RPM_DB_PATH2}.bak.${ts}"

    REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))

    # Backup (best-effort)
    if [ -d "${RPM_DB_PATH2}" ]; then
        execute_guarded "Backup RPM DB directory" cp -a "${RPM_DB_PATH2}" "${rpmdb_backup}" >/dev/null 2>&1 || true
    fi

    # Rebuild (guard with timeout to avoid indefinite hangs)
    rebuild_ok=0
    set +e
    if command -v timeout >/dev/null 2>&1; then
        timeout 180 rpm --rebuilddb >/dev/null 2>&1
        rebuild_rc=$?
    else
        rpm --rebuilddb >/dev/null 2>&1
        rebuild_rc=$?
    fi
    set -e

    if [ "$rebuild_rc" -eq 0 ] 2>/dev/null; then
        rebuild_ok=1
    fi

    if [ "$rebuild_ok" -eq 1 ] 2>/dev/null; then
        # Re-verify after rebuild (best-effort)
        if [ -n "${RPMDB_VERIFY_BIN2:-}" ] && [ -n "${RPM_DB_FILE2:-}" ]; then
            set +e
            if command -v timeout >/dev/null 2>&1; then
                timeout 15 "${RPMDB_VERIFY_BIN2}" "${RPM_DB_FILE2}" >/dev/null 2>&1
                post_rc=$?
            else
                "${RPMDB_VERIFY_BIN2}" "${RPM_DB_FILE2}" >/dev/null 2>&1
                post_rc=$?
            fi
            set -e

            if [ "$post_rc" -eq 0 ] 2>/dev/null; then
                log_success "  ✓ RPM database rebuilt successfully"
                RPMDB_STRUCTURAL_FAILED=0
            else
                log_error "  ✗ RPM database rebuild completed but structural verify still fails"
                VERIFICATION_FAILED=1
            fi
        else
            # If we can't verify structurally, rely on rpm query sanity.
            set +e
            rpm -qa >/dev/null 2>&1
            post_query_rc=$?
            set -e
            if [ "$post_query_rc" -eq 0 ] 2>/dev/null; then
                log_success "  ✓ RPM database rebuilt successfully (rpm query OK)"
                RPMDB_STRUCTURAL_FAILED=0
            else
                log_error "  ✗ RPM database rebuild failed (rpm query still failing)"
                VERIFICATION_FAILED=1
            fi
        fi
    else
        log_error "  ✗ Failed to rebuild RPM database (rc=${rebuild_rc:-unknown})"
        VERIFICATION_FAILED=1
    fi
fi

# Check 39: Dependency & package consistency (deep repair)
log_debug "[39/${TOTAL_CHECKS}] Verifying package dependencies (zypper verify)..."
if [ "${ZYPPER_LOCK_ACTIVE:-0}" -eq 1 ] 2>/dev/null; then
    log_warn "⚠ Skipping dependency consistency check because zypper appears to be running (lock PID: ${ZYPPER_LOCK_PID_ACTIVE:-unknown})"
elif command -v zypper >/dev/null 2>&1; then
    set +e
    if command -v timeout >/dev/null 2>&1; then
        timeout 120 zypper --non-interactive --quiet verify >/dev/null 2>&1
        zypper_verify_rc=$?
    else
        zypper --non-interactive --quiet verify >/dev/null 2>&1
        zypper_verify_rc=$?
    fi
    set -e

    if [ "$zypper_verify_rc" -eq 0 ] 2>/dev/null; then
        log_success "✓ Package dependencies are consistent"
    else
        log_warn "⚠ Broken package dependencies detected (interrupted update?)"
        log_info "  → Capturing details: zypper verify --details"

        # NOTE: Older builds attempted 'zypper install --fix-broken' (APT-style).
        # openSUSE zypper does NOT support that flag. Instead, capture the
        # detailed verify output so the user can resolve it (usually via an
        # interactive 'zypper dup' that chooses a solver solution).
        if command -v timeout >/dev/null 2>&1; then
            execute_optional "Dependency verify details" timeout 120 zypper --non-interactive verify --details
        else
            execute_optional "Dependency verify details" zypper --non-interactive verify --details
        fi

        # Double-check
        set +e
        if command -v timeout >/dev/null 2>&1; then
            timeout 120 zypper --non-interactive --quiet verify >/dev/null 2>&1
            zypper_verify_rc2=$?
        else
            zypper --non-interactive --quiet verify >/dev/null 2>&1
            zypper_verify_rc2=$?
        fi
        set -e

        if [ "$zypper_verify_rc2" -eq 0 ] 2>/dev/null; then
            log_success "  ✓ Dependencies successfully repaired"
        else
            log_error "  ✗ Dependencies still broken after repair attempt"
            VERIFICATION_FAILED=1
        fi
    fi
else
    log_info "ℹ zypper not available; skipping dependency consistency check"
fi

# Check 40: Dashboard Settings API Health (deep verify)
# This is a functional check (HTTP probe), plus token security/integrity.
log_debug "[40/${TOTAL_CHECKS}] Verifying Dashboard Settings API (deep)..."
if [[ "${DASHBOARD_ENABLED,,}" == "true" ]]; then
    local dash_api_unit dash_api_unit_file dash_api_url api_code
    dash_api_unit="zypper-auto-dashboard-api.service"
    dash_api_unit_file="/etc/systemd/system/${dash_api_unit}"
    dash_api_url="http://127.0.0.1:8766/api/ping"

    if [ -f "${dash_api_unit_file}" ] || systemctl list-unit-files "${dash_api_unit}" >/dev/null 2>&1; then
        if systemctl is-active --quiet "${dash_api_unit}" 2>/dev/null; then
            if command -v curl >/dev/null 2>&1; then
                api_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "${dash_api_url}" 2>/dev/null || echo "000")
                if [ "${api_code}" = "200" ] 2>/dev/null; then
                    log_success "✓ Dashboard Settings API is responding (HTTP 200)"
                else
                    log_warn "⚠ Dashboard Settings API is active but unhealthy (HTTP ${api_code})"

                    # Diagnostic: check if port 8766 is actually listening
                    if command -v ss >/dev/null 2>&1; then
                        if ! ss -ltn 2>/dev/null | grep -qE '[:.]8766[[:space:]]'; then
                            log_warn "  ⚠ Port 8766 is NOT listening, despite the service being active"
                        fi
                    fi

                    log_info "  → Attempting auto-repair: restarting Dashboard Settings API..."
                    REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))

                    # Reset failed state first (best-effort)
                    systemctl reset-failed "${dash_api_unit}" >/dev/null 2>&1 || true

                    if execute_guarded "Restart dashboard settings API" systemctl restart "${dash_api_unit}"; then
                        sleep 2
                        api_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "${dash_api_url}" 2>/dev/null || echo "000")
                        if [ "${api_code}" = "200" ] 2>/dev/null; then
                            FOLLOWUP_SOON=1
                            log_success "  ✓ Auto-repair successful: API is now responding"
                        else
                            log_error "  ✗ API restart did not resolve connectivity (HTTP ${api_code})"
                            VERIFICATION_FAILED=1

                            log_info "  [API service logs] (last 15 lines):"
                            if command -v timeout >/dev/null 2>&1; then
                                timeout 3 journalctl -u "${dash_api_unit}" -n 15 --no-pager 2>/dev/null | sed 's/^/    /' | tee -a "${LOG_FILE}" || true
                            else
                                journalctl -u "${dash_api_unit}" -n 15 --no-pager 2>/dev/null | sed 's/^/    /' | tee -a "${LOG_FILE}" || true
                            fi
                        fi
                    else
                        log_error "  ✗ Failed to restart Dashboard Settings API (systemctl error)"
                        VERIFICATION_FAILED=1
                    fi
                fi
            else
                log_info "ℹ curl not available; skipping functional HTTP probe for Dashboard Settings API"
            fi
        else
            log_warn "⚠ Dashboard Settings API service is NOT active"

            # Reset failed state which can prevent normal starts
            if systemctl is-failed --quiet "${dash_api_unit}" 2>/dev/null; then
                log_info "  → Service is in failed state; resetting..."
                systemctl reset-failed "${dash_api_unit}" >/dev/null 2>&1 || true
            fi

            if attempt_repair "start dashboard settings API" \
                "systemctl enable --now ${dash_api_unit}" \
                "systemctl is-active ${dash_api_unit}"; then
                FOLLOWUP_SOON=1
                log_success "  ✓ Dashboard Settings API service started"
            else
                log_error "  ✗ Failed to start Dashboard Settings API service"
                VERIFICATION_FAILED=1

                log_info "  [API startup failure logs] (last 10 lines):"
                if command -v timeout >/dev/null 2>&1; then
                    timeout 3 journalctl -u "${dash_api_unit}" -n 10 --no-pager 2>/dev/null | sed 's/^/    /' | tee -a "${LOG_FILE}" || true
                else
                    journalctl -u "${dash_api_unit}" -n 10 --no-pager 2>/dev/null | sed 's/^/    /' | tee -a "${LOG_FILE}" || true
                fi
            fi
        fi

        # Token file security & integrity
        local token_path token_dir perms owner dperms downer
        token_path="/var/lib/zypper-auto/dashboard-api.token"
        token_dir="$(dirname "${token_path}")"

        # Ensure token directory perms are strict
        if [ -d "${token_dir}" ]; then
            dperms=$(stat -c %a "${token_dir}" 2>/dev/null || echo "")
            downer=$(stat -c %U:%G "${token_dir}" 2>/dev/null || echo "")
            if [ "${dperms}" != "700" ] 2>/dev/null || [ "${downer}" != "root:root" ] 2>/dev/null; then
                log_warn "⚠ Dashboard API token directory has insecure perms (${dperms:-?} ${downer:-?}); hardening"
                chmod 700 "${token_dir}" 2>/dev/null || true
                chown root:root "${token_dir}" 2>/dev/null || true
                REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))
                log_success "  ✓ Token directory hardened (700 root:root)"
            fi
        fi

        if [ -f "${token_path}" ]; then
            perms=$(stat -c %a "${token_path}" 2>/dev/null || echo "")
            owner=$(stat -c %U:%G "${token_path}" 2>/dev/null || echo "")

            # Enforce 600 root:root
            if [ "${perms}" != "600" ] 2>/dev/null || [ "${owner}" != "root:root" ] 2>/dev/null; then
                log_warn "⚠ Insecure dashboard API token permissions detected (${perms:-?} ${owner:-?})"
                log_info "  → Auto-repair: fixing token permissions (600 root:root)..."
                chmod 600 "${token_path}" 2>/dev/null || true
                chown root:root "${token_path}" 2>/dev/null || true
                REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))
                log_success "  ✓ Token permissions secured"
            fi

            # Ensure token is not empty
            if [ ! -s "${token_path}" ]; then
                log_warn "⚠ Dashboard API token file is empty"
                log_info "  → Auto-repair: regenerating token and restarting API..."
                REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))

                if command -v python3 >/dev/null 2>&1; then
                    python3 - <<'PY' >"${token_path}" 2>/dev/null
import secrets
print(secrets.token_urlsafe(24))
PY
                else
                    date +%s%N | sha256sum 2>/dev/null | head -c 32 >"${token_path}" 2>/dev/null || true
                fi

                chmod 600 "${token_path}" 2>/dev/null || true
                chown root:root "${token_path}" 2>/dev/null || true
                execute_guarded "Restart dashboard settings API (new token)" systemctl restart "${dash_api_unit}" || true
                FOLLOWUP_SOON=1
                log_success "  ✓ Token regenerated and API restarted"
            fi
        else
            log_warn "⚠ Dashboard API token file is missing"
            log_info "  → Auto-repair: creating token and restarting API..."
            REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))

            mkdir -p "${token_dir}" 2>/dev/null || true
            if command -v python3 >/dev/null 2>&1; then
                python3 - <<'PY' >"${token_path}" 2>/dev/null
import secrets
print(secrets.token_urlsafe(24))
PY
            else
                date +%s%N | sha256sum 2>/dev/null | head -c 32 >"${token_path}" 2>/dev/null || true
            fi
            chmod 600 "${token_path}" 2>/dev/null || true
            chown root:root "${token_path}" 2>/dev/null || true
            execute_guarded "Restart dashboard settings API (token created)" systemctl restart "${dash_api_unit}" || true
            FOLLOWUP_SOON=1
            log_success "  ✓ Token created and API restarted"
        fi
    else
        log_info "ℹ Dashboard Settings API unit not installed; skipping deep API check"
    fi
else
    log_info "ℹ Dashboard disabled (DASHBOARD_ENABLED=false); skipping deep API check"
fi

# Check 41: Btrfs metadata health (advanced repair)
log_debug "[41/${TOTAL_CHECKS}] Checking Btrfs metadata headroom (and balancing empty chunks if needed)..."
root_fstype2=""
if command -v findmnt >/dev/null 2>&1; then
    root_fstype2=$(findmnt -n -o FSTYPE / 2>/dev/null || true)
fi
if [ "${root_fstype2:-}" = "btrfs" ] && command -v btrfs >/dev/null 2>&1; then
    meta_total=""
    meta_used=""
    meta_line=$(btrfs filesystem df / 2>/dev/null | grep -E '^Metadata' | head -n 1 || true)
    if [ -n "${meta_line:-}" ]; then
        meta_total=$(printf '%s\n' "$meta_line" | sed -n 's/.*total=\([^,]*\),.*/\1/p')
        meta_used=$(printf '%s\n' "$meta_line" | sed -n 's/.*used=\(.*\)$/\1/p')
    fi

    # Convert size strings like 2.00GiB / 565.97MiB / 16.00KiB into MiB.
    __znh_to_mib() {
        local v="$1"
        local num unit
        num=$(printf '%s' "$v" | sed -E 's/^([0-9]+(\.[0-9]+)?).*/\1/')
        unit=$(printf '%s' "$v" | sed -E 's/^[0-9]+(\.[0-9]+)?//')
        case "$unit" in
            KiB) awk -v n="$num" 'BEGIN{printf "%.2f", n/1024}' ;;
            MiB) awk -v n="$num" 'BEGIN{printf "%.2f", n}' ;;
            GiB) awk -v n="$num" 'BEGIN{printf "%.2f", n*1024}' ;;
            TiB) awk -v n="$num" 'BEGIN{printf "%.2f", n*1024*1024}' ;;
            B)   awk -v n="$num" 'BEGIN{printf "%.2f", n/1024/1024}' ;;
            *)   echo "" ;;
        esac
    }

    meta_total_mib=$(__znh_to_mib "${meta_total:-}")
    meta_used_mib=$(__znh_to_mib "${meta_used:-}")

    meta_pct=""
    if [ -n "${meta_total_mib:-}" ] && [ -n "${meta_used_mib:-}" ]; then
        meta_pct=$(awk -v u="$meta_used_mib" -v t="$meta_total_mib" 'BEGIN{ if (t>0) printf "%d", (u/t)*100; else print "" }')
    fi

    if [[ "${meta_pct:-}" =~ ^[0-9]+$ ]] && [ "$meta_pct" -ge 85 ] 2>/dev/null; then
        log_warn "⚠ Btrfs metadata usage is high (~${meta_pct}% used). Attempting balance of empty chunks..."

        # Avoid starting a balance if one is already running.
        bal_out=$(btrfs balance status / 2>/dev/null || true)
        if printf '%s\n' "$bal_out" | grep -qi 'is running'; then
            log_warn "  ⚠ A btrfs balance is already running; skipping new balance start"
        else
            set +e
            if command -v timeout >/dev/null 2>&1; then
                timeout 180 btrfs balance start --enqueue --full-balance -dusage=0 -musage=0 / >/dev/null 2>&1
                bal_rc=$?
            else
                btrfs balance start --enqueue --full-balance -dusage=0 -musage=0 / >/dev/null 2>&1
                bal_rc=$?
            fi
            set -e

            if [ "$bal_rc" -eq 0 ] 2>/dev/null; then
                REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))
                log_success "✓ Btrfs empty-chunk balance completed"
            else
                log_warn "⚠ Btrfs balance failed or timed out (rc=${bal_rc}). Filesystem may be very full or read-only."
            fi
        fi
    else
        if [ -n "${meta_pct:-}" ]; then
            log_success "✓ Btrfs metadata usage OK (~${meta_pct}% used)"
        else
            log_info "ℹ Unable to parse Btrfs metadata usage; skipping balance"
        fi
    fi
else
    log_info "ℹ Root filesystem is not btrfs (or btrfs tools missing); skipping metadata balance"
fi

# Check 42: GPG keyring/signature handling (deep repair)
log_debug "[42/${TOTAL_CHECKS}] Verifying repository signature/GPG handling..."
if [ "${ZYPPER_LOCK_ACTIVE:-0}" -eq 1 ] 2>/dev/null; then
    log_warn "⚠ Skipping deep GPG check because zypper appears to be running (lock PID: ${ZYPPER_LOCK_PID_ACTIVE:-unknown})"
elif command -v zypper >/dev/null 2>&1; then
    # Only do deeper GPG repair when repo refresh is failing or required key auto-import.
    if [ "${REPO_REFRESH_FAILED:-0}" -eq 1 ] 2>/dev/null || [ "${REPO_REFRESH_USED_GPG_IMPORT:-0}" -eq 1 ] 2>/dev/null; then
        set +e
        if command -v timeout >/dev/null 2>&1; then
            gpg_test_out=$(timeout 60 zypper --non-interactive refresh --force 2>&1)
            gpg_test_rc=$?
        else
            gpg_test_out=$(zypper --non-interactive refresh --force 2>&1)
            gpg_test_rc=$?
        fi
        set -e

        if [ "$gpg_test_rc" -eq 0 ] 2>/dev/null; then
            log_success "✓ Repository refresh OK (GPG handling looks consistent)"
        else
            if printf '%s\n' "$gpg_test_out" | grep -qiE 'gpg|signature|NOKEY|public key|keyring|repomd\.xml.*signature'; then
                log_warn "⚠ Refresh failures look GPG/signature-related. Initiating deep GPG repair..."
                log_info "  → Step 1: zypper clean --all"
                execute_guarded "Clean zypper caches" zypper --non-interactive clean --all >/dev/null 2>&1 || true

                log_info "  → Step 2: wipe raw metadata cache (/var/cache/zypp/raw)"
                if [ -d /var/cache/zypp/raw ]; then
                    execute_guarded "Clear zypp raw metadata cache" rm -rf /var/cache/zypp/raw/* >/dev/null 2>&1 || true
                fi

                log_info "  → Step 3: force refresh with key auto-import"
                REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))
                if command -v timeout >/dev/null 2>&1; then
                    if execute_guarded "Rebuild repo keys and refresh" timeout 120 zypper --non-interactive --gpg-auto-import-keys refresh --force; then
                        log_success "  ✓ Deep GPG repair succeeded"
                        REPO_REFRESH_FAILED=0
                    else
                        log_error "  ✗ Deep GPG repair failed"
                        VERIFICATION_FAILED=1
                    fi
                else
                    if execute_guarded "Rebuild repo keys and refresh" zypper --non-interactive --gpg-auto-import-keys refresh --force; then
                        log_success "  ✓ Deep GPG repair succeeded"
                        REPO_REFRESH_FAILED=0
                    else
                        log_error "  ✗ Deep GPG repair failed"
                        VERIFICATION_FAILED=1
                    fi
                fi
            else
                log_info "ℹ Refresh failed, but error does not look GPG-related; skipping deep GPG repair"
                printf '%s\n' "$gpg_test_out" | head -n 20 | tee -a "${LOG_FILE}"
            fi
        fi
    else
        log_success "✓ No repo refresh failures detected earlier; skipping deep GPG repair"
    fi
else
    log_info "ℹ zypper not available; skipping deep GPG check"
fi

# Check 43: Stale zypper lock file detection (edge-case)
# NOTE: Other checks already manage locks, but this final pass catches
# lingering legacy /var/run/zypp.pid issues.
log_debug "[43/${TOTAL_CHECKS}] Checking for stale zypper locks (final pass)..."
local had_errexit stale_removed active_seen
had_errexit=0
[[ "$-" == *e* ]] && had_errexit=1

set +e
stale_removed=0
active_seen=0

# Prefer checking both common paths.
local zypp_lock lock_pid
for zypp_lock in /run/zypp.pid /var/run/zypp.pid; do
    [ -f "${zypp_lock}" ] || continue

    lock_pid=$(cat "${zypp_lock}" 2>/dev/null || echo "")

    if [[ "${lock_pid:-}" =~ ^[0-9]+$ ]]; then
        if kill -0 "${lock_pid}" 2>/dev/null; then
            active_seen=1
            log_info "ℹ zypper lock is active at ${zypp_lock} (PID ${lock_pid}); leaving it in place"
            continue
        fi

        # PID is numeric but not running.
        if pgrep -x zypper >/dev/null 2>&1; then
            # Extremely defensive: if any zypper process is running, do not
            # remove lock files even if the PID inside looks stale.
            active_seen=1
            log_warn "⚠ zypp lock at ${zypp_lock} looks stale (PID ${lock_pid} not running) but zypper is running; NOT removing lock"
            continue
        fi

        log_warn "⚠ Found stale zypper lock file at ${zypp_lock} (PID ${lock_pid} not running)"
        if execute_guarded "Remove stale zypper lock file (${zypp_lock})" rm -f "${zypp_lock}"; then
            REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))
            stale_removed=1
        fi
    else
        # Invalid PID content
        if pgrep -x zypper >/dev/null 2>&1; then
            active_seen=1
            log_warn "⚠ Invalid zypp lock file at ${zypp_lock} but zypper is running; NOT removing lock"
            continue
        fi

        log_warn "⚠ Found invalid zypper lock file at ${zypp_lock} (PID content: '${lock_pid:-empty}')"
        if execute_guarded "Remove invalid zypper lock file (${zypp_lock})" rm -f "${zypp_lock}"; then
            REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))
            stale_removed=1
        fi
    fi
done

[ "$had_errexit" -eq 1 ] 2>/dev/null && set -e

if [ "${stale_removed}" -eq 1 ] 2>/dev/null; then
    log_success "✓ Stale/invalid zypper lock(s) cleaned up"
elif [ "${active_seen}" -eq 1 ] 2>/dev/null; then
    log_info "ℹ zypper lock(s) appear active; no changes made"
else
    log_success "✓ No zypper lock files detected"
fi

# Check 44: Boot partition capacity
# Kernel/initrd updates can fail when /boot is nearly full.
log_debug "[44/${TOTAL_CHECKS}] Checking /boot partition space..."
boot_usage=""
boot_usage=$(df --output=pcent /boot 2>/dev/null | tail -n 1 | tr -d '%[:space:]' || true)
if [[ "${boot_usage:-}" =~ ^[0-9]+$ ]]; then
    if [ "${boot_usage}" -ge 90 ] 2>/dev/null; then
        log_warn "⚠ /boot partition is critically full (${boot_usage}%)"

        # Auto-repair: attempt kernel purge ONLY when explicitly enabled.
        # Guard: never run zypper-based cleanup when a lock is active.
        if [[ "${KERNEL_PURGE_ENABLED,,}" == "true" ]]; then
            if [ "${ZYPPER_LOCK_ACTIVE:-0}" -eq 1 ] 2>/dev/null || pgrep -x zypper >/dev/null 2>&1; then
                log_warn "  ⚠ Skipping kernel purge because zypper appears to be running (lock PID: ${ZYPPER_LOCK_PID_ACTIVE:-unknown})"
            else
                # Respect the interactive confirmation guard if present.
                if [ "${KERNEL_PURGE_CONFIRM:-true}" = "true" ] && [ ! -t 0 ]; then
                    log_warn "  ⚠ Refusing kernel purge without a TTY while KERNEL_PURGE_CONFIRM=true"
                else
                    log_info "  → Auto-repair: running kernel purge to free /boot space..."
                    REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))

                    if execute_guarded "Emergency kernel purge (zypper purge-kernels)" zypper --non-interactive purge-kernels; then
                        new_usage=$(df --output=pcent /boot 2>/dev/null | tail -n 1 | tr -d '%[:space:]' || true)
                        if [[ "${new_usage:-}" =~ ^[0-9]+$ ]] && [ "${new_usage}" -lt 90 ] 2>/dev/null; then
                            log_success "  ✓ /boot space reclaimed (now ${new_usage}%)"
                        else
                            log_warn "  ⚠ Kernel purge ran, but /boot is still high (${new_usage:-unknown}%)"
                        fi
                    else
                        log_error "  ✗ Kernel purge failed"
                        VERIFICATION_FAILED=1
                    fi
                fi
            fi
        else
            log_warn "  → Enable KERNEL_PURGE_ENABLED=true in /etc/zypper-auto.conf to auto-fix this"
            if [ "${boot_usage}" -ge 100 ] 2>/dev/null; then
                log_error "✗ /boot is 100% full; updates may fail"
                VERIFICATION_FAILED=1
            fi
        fi
    else
        log_success "✓ /boot space is healthy (${boot_usage}%)"
    fi
else
    log_warn "⚠ Unable to determine /boot usage (df parsing failed); skipping"
fi

# Check 45: System time synchronization (NTP)
# SSL/repo metadata verification can fail if the clock drifts.
log_debug "[45/${TOTAL_CHECKS}] Verifying time synchronization (NTP)..."
if command -v timedatectl >/dev/null 2>&1; then
    ntp_status=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo "unknown")

    if printf '%s' "${ntp_status}" | grep -qi '^yes$'; then
        log_success "✓ System clock is synchronized"
    else
        log_warn "⚠ System clock is NOT synchronized (SSL/cert errors may occur)"
        log_info "  → Attempting auto-repair: enabling NTP + restarting time sync services..."

        REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))
        execute_optional "Enable NTP (timedatectl set-ntp true)" timedatectl set-ntp true || true

        # Best-effort: restart whichever service exists.
        if __znh_unit_file_exists_system chronyd.service; then
            execute_optional "Restart chronyd" systemctl restart chronyd.service || true
        elif __znh_unit_file_exists_system chrony.service; then
            execute_optional "Restart chrony" systemctl restart chrony.service || true
        elif __znh_unit_file_exists_system systemd-timesyncd.service; then
            execute_optional "Restart systemd-timesyncd" systemctl restart systemd-timesyncd.service || true
        fi

        sleep 2
        ntp_status2=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo "unknown")
        if printf '%s' "${ntp_status2}" | grep -qi '^yes$'; then
            log_success "  ✓ Time synchronization restored"
        else
            log_error "  ✗ Time is still not synchronized (network/time service issue?)"
            # Soft failure: warn loudly but do not hard-fail verification.
        fi
    fi
else
    log_info "ℹ timedatectl not available; skipping time sync check"
fi

# Check 46: Systemd degraded state (final health)
# If other services are failed, updates/networking can break in subtle ways.
log_debug "[46/${TOTAL_CHECKS}] Checking overall systemd health (is-system-running)..."
sys_state=$(systemctl is-system-running 2>/dev/null || echo "unknown")
if printf '%s' "${sys_state}" | grep -qE '^(running|degraded)$'; then
    failed_units=$(systemctl list-units --state=failed --no-legend --plain 2>/dev/null | awk '{print $1}' | sed '/^$/d' || true)

    if [ -n "${failed_units:-}" ]; then
        log_warn "⚠ Systemd state is '${sys_state}'. Failed unit(s) detected:"
        printf '%s\n' "${failed_units}" | sed 's/^/  - /' | tee -a "${LOG_FILE}"

        log_info "  → Auto-repair: resetting failed unit states (best-effort)..."
        if execute_guarded "Reset failed systemd units (final health)" systemctl reset-failed; then
            REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))
            log_success "  ✓ Failed unit states cleared (monitor if they fail again)"
        else
            log_warn "  ⚠ Failed to reset failed unit states"
        fi
    else
        log_success "✓ Systemd reports healthy state (${sys_state})"
    fi
else
    log_info "ℹ Systemd state is '${sys_state}'; skipping failed-unit health check"
fi

# Check 47: RPM database integrity (final sanity)
# We already do structural checks + deep repairs earlier, but this late-stage
# check catches "rpm hangs" edge cases before we print the summary.
log_debug "[47/${TOTAL_CHECKS}] Verifying RPM database consistency (final sanity)..."
rpmqa_ok=0
if command -v rpm >/dev/null 2>&1; then
    if command -v timeout >/dev/null 2>&1; then
        if timeout 10 rpm -qa --qf '' >/dev/null 2>&1; then
            rpmqa_ok=1
        fi
    else
        # Without timeout, avoid potentially hanging forever.
        log_info "ℹ timeout not available; skipping rpm -qa hang-detection"
        rpmqa_ok=1
    fi

    if [ "${rpmqa_ok}" -eq 1 ] 2>/dev/null; then
        log_success "✓ RPM database is readable (rpm -qa)"
    else
        log_warn "⚠ RPM database appears unresponsive (rpm -qa timed out/failed)"

        if [ "${ZYPPER_LOCK_ACTIVE:-0}" -eq 1 ] 2>/dev/null || pgrep -x zypper >/dev/null 2>&1; then
            log_warn "  ⚠ Skipping rpmdb rebuild because zypper appears to be running (lock PID: ${ZYPPER_LOCK_PID_ACTIVE:-unknown})"
            VERIFICATION_FAILED=1
        else
            log_info "  → Auto-repair: rebuilding RPM database (best-effort)..."
            REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))

            # Derive db path (supports sqlite rpmdb too).
            RPM_DB_PATH3=$(rpm --eval '%{_dbpath}' 2>/dev/null || true)
            if [ -z "${RPM_DB_PATH3:-}" ]; then
                RPM_DB_PATH3="/usr/lib/sysimage/rpm"
            fi

            # Best-effort: remove legacy lock/temp files (ignore if absent).
            if [ -d "${RPM_DB_PATH3}" ]; then
                execute_optional "Remove rpmdb lock file" rm -f "${RPM_DB_PATH3}/.rpm.lock" || true
                execute_optional "Remove legacy rpmdb __db.* temp files" rm -f "${RPM_DB_PATH3}/__db."* || true
            fi

            if command -v timeout >/dev/null 2>&1; then
                if execute_guarded "Rebuild RPM DB (rpm --rebuilddb)" timeout 180 rpm --rebuilddb; then
                    log_success "  ✓ RPM database rebuilt successfully"
                else
                    log_error "  ✗ Failed to rebuild RPM database"
                    VERIFICATION_FAILED=1
                fi
            else
                if execute_guarded "Rebuild RPM DB (rpm --rebuilddb)" rpm --rebuilddb; then
                    log_success "  ✓ RPM database rebuilt successfully"
                else
                    log_error "  ✗ Failed to rebuild RPM database"
                    VERIFICATION_FAILED=1
                fi
            fi
        fi
    fi
else
    log_info "ℹ rpm not available; skipping rpmdb final sanity check"
fi

# Check 48: Snapper cleanup timers
log_debug "[48/${TOTAL_CHECKS}] Verifying Snapper cleanup timers..."
if __znh_unit_file_exists_system snapper-cleanup.timer; then
    if systemctl is-active --quiet snapper-cleanup.timer 2>/dev/null; then
        log_success "✓ Snapper cleanup timer is active"
    else
        log_warn "⚠ Snapper cleanup timer is INACTIVE (disk may fill over time)"
        if attempt_repair "enable snapper cleanup timer" \
            "systemctl enable --now snapper-cleanup.timer" \
            "systemctl is-active snapper-cleanup.timer"; then
            log_success "  ✓ Snapper cleanup timer enabled"
        else
            log_warn "  ⚠ Failed to enable snapper-cleanup.timer (non-fatal but risky)"
        fi
    fi
else
    log_info "ℹ snapper-cleanup.timer not installed; skipping"
fi

# Check 49: Repository metadata health (stale raw cache)
log_debug "[49/${TOTAL_CHECKS}] Checking repository metadata health (raw cache age)..."
if [ -d /var/cache/zypp/raw ]; then
    cache_hit=$(find /var/cache/zypp/raw -maxdepth 1 -mindepth 1 -type d -mtime +14 -print -quit 2>/dev/null || true)

    if [ -z "${cache_hit:-}" ] 2>/dev/null && [ "${REPO_REFRESH_FAILED:-0}" -ne 1 ] 2>/dev/null; then
        log_success "✓ Repository metadata seems fresh"
    else
        log_warn "⚠ Repository metadata cache looks stale (or refresh failed earlier)"

        if [ "${ZYPPER_LOCK_ACTIVE:-0}" -eq 1 ] 2>/dev/null || pgrep -x zypper >/dev/null 2>&1; then
            log_warn "  ⚠ Skipping metadata cleanup/refresh because zypper appears to be running (lock PID: ${ZYPPER_LOCK_PID_ACTIVE:-unknown})"
            VERIFICATION_FAILED=1
        else
            log_info "  → Auto-repair: forcing metadata cleanup and refresh..."
            REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))

            # Prefer targeted cache cleanup (raw metadata + solv) without wiping downloaded RPMs.
            execute_optional "Clear zypp raw metadata cache" rm -rf /var/cache/zypp/raw/* >/dev/null 2>&1 || true
            execute_optional "Clear zypp solv cache" rm -rf /var/cache/zypp/solv/* >/dev/null 2>&1 || true

            if command -v timeout >/dev/null 2>&1; then
                if execute_guarded "Refresh repos (forced)" timeout 90 zypper --non-interactive refresh --force; then
                    log_success "  ✓ Repositories refreshed successfully"
                    REPO_REFRESH_FAILED=0
                else
                    log_error "  ✗ Failed to refresh repositories"
                    VERIFICATION_FAILED=1
                fi
            else
                if execute_guarded "Refresh repos (forced)" zypper --non-interactive refresh --force; then
                    log_success "  ✓ Repositories refreshed successfully"
                    REPO_REFRESH_FAILED=0
                else
                    log_error "  ✗ Failed to refresh repositories"
                    VERIFICATION_FAILED=1
                fi
            fi
        fi
    fi
else
    log_info "ℹ /var/cache/zypp/raw not present; skipping metadata age check"
fi

# Check 50: Orphaned temporary files & cache garbage
log_debug "[50/${TOTAL_CHECKS}] Checking for orphaned zypp cache garbage..."
if [ -d /var/cache/zypp ]; then
    garbage_count=$(find /var/cache/zypp -xdev -type f \( -name '*.solv' -o -name 'cookies' \) 2>/dev/null | wc -l | tr -d ' ')
    if ! [[ "${garbage_count:-}" =~ ^[0-9]+$ ]]; then
        garbage_count=0
    fi

    if [ "${garbage_count}" -lt 50 ] 2>/dev/null; then
        log_success "✓ Cache hygiene is good (${garbage_count} stale file(s))"
    else
        log_warn "⚠ Found ${garbage_count} stale cache file(s); cleaning best-effort..."

        if [ "${ZYPPER_LOCK_ACTIVE:-0}" -eq 1 ] 2>/dev/null || pgrep -x zypper >/dev/null 2>&1; then
            log_warn "  ⚠ Skipping cache garbage cleanup because zypper appears to be running"
        else
            REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))
            execute_optional "Remove stale .solv/cookies" find /var/cache/zypp -xdev -type f \( -name '*.solv' -o -name 'cookies' \) -delete 2>/dev/null || true
            # Keep this narrow: only repodata metadata, not downloaded packages.
            execute_optional "Prune repodata temp files" find /var/cache/zypp/raw -type f -path '*/repodata/*' -delete 2>/dev/null || true
            log_success "  ✓ Cache garbage cleanup completed"
        fi
    fi
else
    log_info "ℹ /var/cache/zypp not present; skipping cache garbage check"
fi

# Dashboard UX: surface reboot-required state as a top-level status so users
# don't forget to reboot after kernel/core library updates.
if check_reboot_required; then
    log_warn "⚠ Reboot required to fully apply updates (kernel/core libs)."
    if [ "${VERIFICATION_FAILED}" -eq 0 ] 2>/dev/null; then
        update_status "Reboot Required"
    else
        update_status "FAILED: Reboot Required"
    fi
fi

# If we performed a critical repair (e.g. restarted the dashboard API), run a
# one-off follow-up verification soon so we can confirm the fix held.
if [ "${FOLLOWUP_SOON:-0}" -eq 1 ] 2>/dev/null || [ "${VERIFICATION_FAILED}" -gt 0 ] 2>/dev/null || [ "${REPAIR_ATTEMPTS:-0}" -gt 0 ] 2>/dev/null; then
    if command -v systemd-run >/dev/null 2>&1 && [ -x /usr/local/bin/zypper-auto-helper ]; then
        # Use a fixed unit name so repeated calls don't create a spam storm.
        log_info "Problems were found/fixed. Scheduling follow-up verification in 5 minutes..."
        systemd-run --on-active=5m --unit=zypper-auto-verify-followup \
            /usr/local/bin/zypper-auto-helper --verify >/dev/null 2>&1 || true
    fi
fi

# Calculate repair statistics
# We approximate "problems detected" as the combination of issues we
# attempted to repair plus any remaining failures, so the numbers always
# stay consistent and non-negative.
PROBLEMS_FIXED=$REPAIR_ATTEMPTS
PROBLEMS_DETECTED=$((REPAIR_ATTEMPTS + VERIFICATION_FAILED))

# Expose a few summary values for wrappers (e.g., retry logic).
VERIFICATION_LAST_TOTAL_CHECKS=$TOTAL_CHECKS
VERIFICATION_LAST_PROBLEMS_FIXED=$PROBLEMS_FIXED
VERIFICATION_LAST_PROBLEMS_DETECTED=$PROBLEMS_DETECTED
VERIFICATION_LAST_REMAINING=$VERIFICATION_FAILED

# Persist last verification summary for the dashboard.
# NOTE: do not source/execute this file; it's parsed as key=value.
local verify_summary_file
verify_summary_file="${LOG_DIR}/last-verify-summary.txt"
{
    echo "ts_iso=$(date -Iseconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')"
    echo "ts_human=$(date '+%Y-%m-%d %H:%M:%S')"
    echo "run_id=${RUN_ID}"
    echo "checks=${TOTAL_CHECKS}"
    echo "detected=${PROBLEMS_DETECTED}"
    echo "fixed=${PROBLEMS_FIXED}"
    echo "remaining=${VERIFICATION_FAILED}"
} >"${verify_summary_file}" 2>/dev/null || true
chmod 644 "${verify_summary_file}" 2>/dev/null || true

if [ "${ZNH_SUPPRESS_VERIFICATION_SUMMARY:-0}" -ne 1 ] 2>/dev/null; then
    log_info "=============================================="
    log_info "Verification Summary:"
    log_info "  - Checks performed: ${TOTAL_CHECKS}"
    log_info "  - Problems detected: ${PROBLEMS_DETECTED}"
    log_info "  - Problems auto-fixed: ${PROBLEMS_FIXED}"
    log_info "  - Remaining issues: ${VERIFICATION_FAILED}"
    log_info "=============================================="

    if [ "$VERIFICATION_FAILED" -eq 0 ]; then
        log_success ">>> All verification checks passed! ✓"
        if [ "$PROBLEMS_FIXED" -gt 0 ]; then
            log_success "  ✓ Auto-repair fixed $PROBLEMS_FIXED issue(s)"
        fi
    else
        log_error ">>> $VERIFICATION_FAILED verification check(s) failed!"
        log_error "  → Auto-repair attempted but could not fix all issues"
        log_info "  → Review logs: ${LOG_FILE}"
        if [ "${#CONFIG_WARNINGS[@]}" -gt 0 ]; then
            log_info "  → Config warnings detected; consider: sudo zypper-auto-helper --reset-config"
        fi
        log_info "  → Common fixes:"
        log_info "     - Check systemd permissions: sudo loginctl enable-linger $SUDO_USER"
        log_info "     - Verify DBUS session: echo \$DBUS_SESSION_BUS_ADDRESS"
        log_info "     - Re-run installation: sudo $0 install"
    fi
fi

# Optionally notify the primary user when auto-repair fixed issues.
# This is primarily intended for the periodic zypper-auto-verify.timer
# service, but also applies when --verify is run manually.
if [ "${ZNH_SUPPRESS_VERIFICATION_SUMMARY:-0}" -ne 1 ] 2>/dev/null && [ "$PROBLEMS_FIXED" -gt 0 ] && [[ "${VERIFY_NOTIFY_USER_ENABLED,,}" == "true" ]]; then
    if command -v notify-send >/dev/null 2>&1; then
        local summary details
        summary="Fixed ${PROBLEMS_FIXED} issue(s) with the update system"
        if [ "$VERIFICATION_FAILED" -gt 0 ]; then
            details="Some issues remain; see ${LOG_FILE} for details."
        else
            details="All detected issues were repaired successfully."
        fi

        if [ -n "${SUDO_USER:-}" ] && [ -n "${USER_BUS_PATH:-}" ]; then
            execute_guarded "Send repair notification to user" \
                sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" \
                notify-send -u normal -t 15000 \
                -i "dialog-information" \
                "${summary}" "${details}" || true
        fi
    fi
fi

    # Keep the live dashboard data fresh (best-effort): periodic verification
    # runs in the background, so it's a good place to refresh status-data.json.
    if [[ "${DASHBOARD_ENABLED,,}" == "true" ]]; then
        generate_dashboard || true
    fi

    # Return exit code based on verification results
    return $VERIFICATION_FAILED
}

# --- Helper: Smart verification with retries (Deep Repair orchestration) ---
# Runs run_verification_only up to N times, suppressing the full summary on
# intermediate attempts. This helps when deep repairs fix structural issues
# that require a second verification pass.
run_smart_verification() {
    local max_retries
    max_retries="${1:-2}"

    if ! [[ "${max_retries}" =~ ^[0-9]+$ ]] || [ "${max_retries}" -lt 1 ] 2>/dev/null; then
        max_retries=2
    fi

    local attempt rc
    attempt=1
    rc=1

    # Preserve cumulative repairs across attempts.
    local cumulative_repairs
    cumulative_repairs=${REPAIR_ATTEMPTS_BASE:-0}

    while [ "$attempt" -le "$max_retries" ] 2>/dev/null; do
        log_info "=== Verification Run (Attempt ${attempt}/${max_retries}) ==="

        REPAIR_ATTEMPTS_BASE=$cumulative_repairs
        if [ "$attempt" -lt "$max_retries" ] 2>/dev/null; then
            ZNH_SUPPRESS_VERIFICATION_SUMMARY=1
        else
            ZNH_SUPPRESS_VERIFICATION_SUMMARY=0
        fi

        run_verification_only
        rc=$?

        # Capture updated repair count from this attempt.
        cumulative_repairs=${REPAIR_ATTEMPTS:-$cumulative_repairs}

        if [ "$rc" -eq 0 ] 2>/dev/null; then
            # If the first attempt succeeded while summaries were suppressed,
            # print a compact summary so users still see "Checks performed".
            if [ "${ZNH_SUPPRESS_VERIFICATION_SUMMARY:-0}" -eq 1 ] 2>/dev/null; then
                log_info "=============================================="
                log_info "Verification Summary:"
                log_info "  - Checks performed: ${VERIFICATION_LAST_TOTAL_CHECKS:-unknown}"
                log_info "  - Problems detected: ${VERIFICATION_LAST_PROBLEMS_DETECTED:-?}"
                log_info "  - Problems auto-fixed: ${VERIFICATION_LAST_PROBLEMS_FIXED:-?}"
                log_info "  - Remaining issues: ${VERIFICATION_LAST_REMAINING:-?}"
                log_info "=============================================="
                log_success ">>> All verification checks passed! ✓"
                if [ "${VERIFICATION_LAST_PROBLEMS_FIXED:-0}" -gt 0 ] 2>/dev/null; then
                    log_success "  ✓ Auto-repair fixed ${VERIFICATION_LAST_PROBLEMS_FIXED} issue(s)"
                fi
            fi

            ZNH_SUPPRESS_VERIFICATION_SUMMARY=0
            return 0
        fi

        if [ "$attempt" -lt "$max_retries" ] 2>/dev/null; then
            log_warn "=== Verification detected remaining issues; retrying after repairs... ==="
            attempt=$((attempt + 1))
            sleep 2
        else
            ZNH_SUPPRESS_VERIFICATION_SUMMARY=0
            return $rc
        fi
    done

    ZNH_SUPPRESS_VERIFICATION_SUMMARY=0
    return $rc
}

# --- Helper: Snapper invocation (prefer --no-dbus when supported) ---
# Inspired by scrub-ghost: avoid D-Bus hangs by preferring `snapper --no-dbus`
# when available, and allow callers to wrap snapper commands in timeout.
ZNH_SNAPPER_NO_DBUS_SUPPORTED="${ZNH_SNAPPER_NO_DBUS_SUPPORTED:-}"

__znh_snapper_supports_no_dbus() {
    # Cache result to avoid repeatedly running `snapper --help`.
    if [ -n "${ZNH_SNAPPER_NO_DBUS_SUPPORTED:-}" ]; then
        [ "${ZNH_SNAPPER_NO_DBUS_SUPPORTED}" -eq 1 ] 2>/dev/null
        return $?
    fi

    local had_errexit=0
    [[ "$-" == *e* ]] && had_errexit=1

    local help_out rc
    help_out=""
    rc=1

    set +e
    if command -v timeout >/dev/null 2>&1; then
        help_out=$(timeout 2 snapper --help 2>&1)
        rc=$?
    else
        help_out=$(snapper --help 2>&1)
        rc=$?
    fi
    [ "$had_errexit" -eq 1 ] 2>/dev/null && set -e

    if [ "$rc" -eq 0 ] 2>/dev/null && printf '%s\n' "$help_out" | grep -q -- '--no-dbus'; then
        ZNH_SNAPPER_NO_DBUS_SUPPORTED=1
    else
        ZNH_SNAPPER_NO_DBUS_SUPPORTED=0
    fi

    [ "${ZNH_SNAPPER_NO_DBUS_SUPPORTED}" -eq 1 ] 2>/dev/null
}

__znh_snapper_cmd_timeout() {
    # Usage:
    #   __znh_snapper_cmd_timeout 10 -c root list
    #   __znh_snapper_cmd_timeout 90 create --type pre ...
    local t="$1"
    shift || true

    if command -v timeout >/dev/null 2>&1 && [[ "${t:-}" =~ ^[0-9]+$ ]] && [ "${t}" -gt 0 ] 2>/dev/null; then
        if __znh_snapper_supports_no_dbus; then
            timeout "${t}" snapper --no-dbus "$@"
        else
            timeout "${t}" snapper "$@"
        fi
    else
        if __znh_snapper_supports_no_dbus; then
            snapper --no-dbus "$@"
        else
            snapper "$@"
        fi
    fi
}

# --- Safety Net: pre/post Snapper snapshot for verification/repair ---
__znh_start_repair_safety_snapshot() {
    # Only snapshot once per invocation.
    if [ -n "${REPAIR_SAFETY_PRE_SNAP_ID:-}" ]; then
        return 0
    fi

    # Only attempt when snapper is present and we're root.
    if [ "${EUID:-1}" -ne 0 ] 2>/dev/null; then
        return 0
    fi
    if ! command -v snapper >/dev/null 2>&1; then
        return 0
    fi

    # If snapper is already running (e.g., timers), avoid competing.
    if pgrep -x snapper >/dev/null 2>&1; then
        log_warn "📸 Snapper is already running; skipping Pre-Repair Safety Snapshot"
        return 0
    fi

    log_info "📸 Creating Pre-Repair Safety Snapshot (Safety Net)..."

    # Safety: snapper create can occasionally block for a long time (e.g. very
    # large snapshot lists, btrfs contention, or snapperd/dbus weirdness). Guard
    # it with a timeout so the helper never hangs indefinitely.
    local snap_timeout
    snap_timeout="${ZNH_SAFETY_SNAPSHOT_TIMEOUT_SECONDS:-90}"
    if ! [[ "${snap_timeout}" =~ ^[0-9]+$ ]] || [ "${snap_timeout}" -lt 10 ] 2>/dev/null; then
        snap_timeout=90
    fi

    # Best-effort hint: if there are *many* snapshots, warn the user that safety
    # snapshot creation may be slow.
    local snap_count snapper_list rc_count
    snap_count=""
    rc_count=0
    set +e
    snapper_list=$(__znh_snapper_cmd_timeout 10 -c root list 2>/dev/null)
    rc_count=$?
    set -e

    if [ "$rc_count" -eq 0 ] 2>/dev/null && [ -n "${snapper_list:-}" ]; then
        snap_count=$(printf '%s\n' "$snapper_list" | awk '/^[[:space:]]*[0-9]+\*?[[:space:]]*[|│]/ {c++} END {print c+0}')
        if [[ "${snap_count:-}" =~ ^[0-9]+$ ]] && [ "${snap_count}" -gt 200 ] 2>/dev/null; then
            log_warn "📸 Snapper has many snapshots (${snap_count}); snapshot creation can be slow."
            log_info "  → Consider: sudo zypper-auto-helper snapper cleanup all"
        fi
    fi

    local out rc
    set +e
    out=$(__znh_snapper_cmd_timeout "${snap_timeout}" create --type pre --cleanup-algorithm number \
        --description "Zypper-Auto Repair Safety Net" --print-number 2>&1)
    rc=$?
    if [ "$rc" -eq 124 ] 2>/dev/null || [ "$rc" -eq 137 ] 2>/dev/null; then
        set -e
        log_warn "📸 Pre-Repair Safety Snapshot timed out after ${snap_timeout}s; proceeding without snapshot"
        if [ -n "${out:-}" ]; then
            printf '%s\n' "$out" | head -n 10 | sed 's/^/  [snapper] /' | tee -a "${LOG_FILE}" || true
        fi
        return 0
    fi
    set -e

    if [ "$rc" -eq 0 ] 2>/dev/null; then
        # snapper prints the snapshot number on stdout.
        REPAIR_SAFETY_PRE_SNAP_ID=$(printf '%s\n' "$out" | tail -n 1 | tr -d '\r' | tr -cd '0-9')
        if [[ "${REPAIR_SAFETY_PRE_SNAP_ID:-}" =~ ^[0-9]+$ ]]; then
            log_success "📸 Pre-Repair Safety Snapshot created (pre=${REPAIR_SAFETY_PRE_SNAP_ID})"
        else
            # If parsing failed, keep raw output for debugging but don't treat as fatal.
            REPAIR_SAFETY_PRE_SNAP_ID=""
            log_warn "📸 Snapper pre-snapshot succeeded but snapshot number could not be parsed (output: ${out})"
        fi
    else
        log_warn "📸 Failed to create Pre-Repair Safety Snapshot (snapper rc=${rc}); proceeding without snapshot"
        if [ -n "${out:-}" ]; then
            printf '%s\n' "$out" | head -n 10 | sed 's/^/  [snapper] /' | tee -a "${LOG_FILE}" || true
        fi
    fi

    return 0
}

__znh_finalize_repair_safety_snapshot() {
    # Finalize only once.
    if [ "${REPAIR_SAFETY_SNAPSHOT_FINALIZED:-0}" -eq 1 ] 2>/dev/null; then
        return 0
    fi

    if [ -z "${REPAIR_SAFETY_PRE_SNAP_ID:-}" ]; then
        return 0
    fi

    if [ "${EUID:-1}" -ne 0 ] 2>/dev/null; then
        return 0
    fi
    if ! command -v snapper >/dev/null 2>&1; then
        return 0
    fi

    local rc="${1:-0}"
    local desc
    desc="Zypper-Auto Repair Complete"
    if [ "$rc" -ne 0 ] 2>/dev/null; then
        desc="Zypper-Auto Repair Complete (rc=${rc})"
    fi

    log_info "📸 Finalizing Safety Snapshot (post)..."

    local snap_timeout
    snap_timeout="${ZNH_SAFETY_SNAPSHOT_TIMEOUT_SECONDS:-90}"
    if ! [[ "${snap_timeout}" =~ ^[0-9]+$ ]] || [ "${snap_timeout}" -lt 10 ] 2>/dev/null; then
        snap_timeout=90
    fi

    local out post_rc
    set +e
    out=$(__znh_snapper_cmd_timeout "${snap_timeout}" create --type post --cleanup-algorithm number \
        --pre-number "${REPAIR_SAFETY_PRE_SNAP_ID}" --description "${desc}" --print-number 2>&1)
    post_rc=$?
    if [ "$post_rc" -eq 124 ] 2>/dev/null || [ "$post_rc" -eq 137 ] 2>/dev/null; then
        set -e
        log_warn "📸 Post snapshot timed out after ${snap_timeout}s; pre snapshot ${REPAIR_SAFETY_PRE_SNAP_ID} is still available"
        if [ -n "${out:-}" ]; then
            printf '%s\n' "$out" | head -n 10 | sed 's/^/  [snapper] /' | tee -a "${LOG_FILE}" || true
        fi
        REPAIR_SAFETY_SNAPSHOT_FINALIZED=1
        return 0
    fi
    set -e

    if [ "$post_rc" -eq 0 ] 2>/dev/null; then
        REPAIR_SAFETY_POST_SNAP_ID=$(printf '%s\n' "$out" | tail -n 1 | tr -d '\r' | tr -cd '0-9')
        if [[ "${REPAIR_SAFETY_POST_SNAP_ID:-}" =~ ^[0-9]+$ ]]; then
            log_success "📸 Safety Snapshot finalized (post=${REPAIR_SAFETY_POST_SNAP_ID}, pre=${REPAIR_SAFETY_PRE_SNAP_ID})"
        else
            REPAIR_SAFETY_POST_SNAP_ID=""
            log_warn "📸 Snapper post-snapshot succeeded but snapshot number could not be parsed (output: ${out})"
        fi
    else
        log_warn "📸 Failed to create post snapshot (snapper rc=${post_rc}); pre snapshot ${REPAIR_SAFETY_PRE_SNAP_ID} is still available"
        if [ -n "${out:-}" ]; then
            printf '%s\n' "$out" | head -n 10 | sed 's/^/  [snapper] /' | tee -a "${LOG_FILE}" || true
        fi
    fi

    REPAIR_SAFETY_SNAPSHOT_FINALIZED=1
    return 0
}

run_smart_verification_with_safety_net() {
    local max_retries
    max_retries="${1:-2}"

    # Enable the Flight Report for this invocation.
    FLIGHT_REPORT_ENABLED=1

    __znh_start_repair_safety_snapshot || true

    run_smart_verification "${max_retries}"
    local rc=$?

    # Best-effort: finalize snapshot immediately, but also keep an EXIT trap
    # as a backstop in case of unexpected early exits.
    __znh_finalize_repair_safety_snapshot "$rc" || true

    return "$rc"
}

# --- Flight Report (executive summary) ---
print_flight_report() {
    local exit_rc="${1:-0}"

    # Only print for runs that actually executed verification.
    if [ "${FLIGHT_REPORT_ENABLED:-0}" -ne 1 ] 2>/dev/null; then
        return 0
    fi
    if [ "${FLIGHT_REPORT_PRINTED:-0}" -eq 1 ] 2>/dev/null; then
        return 0
    fi
    FLIGHT_REPORT_PRINTED=1

    local total remaining fixed detected
    total="${VERIFICATION_LAST_TOTAL_CHECKS:-unknown}"
    remaining="${VERIFICATION_LAST_REMAINING:-?}"
    fixed="${VERIFICATION_LAST_PROBLEMS_FIXED:-0}"
    detected="${VERIFICATION_LAST_PROBLEMS_DETECTED:-?}"

    echo ""
    echo "==================================================="
    echo "   ZYPPER-AUTO FLIGHT REPORT: $(date '+%Y-%m-%d %H:%M')"
    echo "==================================================="
    printf "%-30s : %s\n" "Total Checks Performed" "${total}"
    printf "%-30s : %s\n" "Problems Detected" "${detected}"
    printf "%-30s : %s\n" "Auto-Repairs Executed" "${fixed}"

    local status_plain
    if [ "${exit_rc}" -eq 0 ] 2>/dev/null && [ "${remaining}" -eq 0 ] 2>/dev/null; then
        status_plain="HEALTHY"
    else
        status_plain="UNHEALTHY (Intervention Needed)"
    fi

    if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
        if [ "${status_plain}" = "HEALTHY" ]; then
            printf "%-30s : \033[1;32m%s\033[0m\n" "System Status" "${status_plain}"
        else
            printf "%-30s : \033[1;31m%s\033[0m\n" "System Status" "${status_plain}"
        fi
    else
        printf "%-30s : %s\n" "System Status" "${status_plain}"
    fi

    if [ -n "${REPAIR_SAFETY_PRE_SNAP_ID:-}" ]; then
        echo "---------------------------------------------------"
        echo "📸 Safety Net (Snapper):"
        echo "  - Pre-Repair snapshot : ${REPAIR_SAFETY_PRE_SNAP_ID}"
        if [ -n "${REPAIR_SAFETY_POST_SNAP_ID:-}" ]; then
            echo "  - Post-Repair snapshot: ${REPAIR_SAFETY_POST_SNAP_ID}"
            echo "  - Inspect changes     : sudo snapper status ${REPAIR_SAFETY_PRE_SNAP_ID}..${REPAIR_SAFETY_POST_SNAP_ID}"
        fi
        echo "  - Rollback (undo)     : sudo snapper rollback ${REPAIR_SAFETY_PRE_SNAP_ID}"
    fi

    if [ "${fixed}" -gt 0 ] 2>/dev/null && [ -n "${LOG_FILE:-}" ] && [ -f "${LOG_FILE}" ]; then
        echo "---------------------------------------------------"
        echo "⚠ Actions Taken (recent repair intents from log):"
        grep -E "→ Attempting|Attempting to fix|Attempting deep repair|Attempting auto-repair" "${LOG_FILE}" 2>/dev/null \
            | tail -n 20 | sed 's/^/    - /' || true
    fi

    echo "==================================================="
    if [ -n "${LOG_FILE:-}" ]; then
        echo "Full logs available at: ${LOG_FILE}"
    fi
    echo ""

    # Also append a plain (no ANSI) copy of the report into the run log so
    # it can be retrieved later without scrolling through all checks.
    if [ -n "${LOG_FILE:-}" ] && [ -f "${LOG_FILE}" ]; then
        {
            echo ""
            echo "==================================================="
            echo "ZYPPER-AUTO FLIGHT REPORT: $(date '+%Y-%m-%d %H:%M')"
            echo "==================================================="
            printf "%-30s : %s\n" "Total Checks Performed" "${total}"
            printf "%-30s : %s\n" "Problems Detected" "${detected}"
            printf "%-30s : %s\n" "Auto-Repairs Executed" "${fixed}"
            printf "%-30s : %s\n" "System Status" "${status_plain}"
            if [ -n "${REPAIR_SAFETY_PRE_SNAP_ID:-}" ]; then
                echo "Safety Snapshot (pre)         : ${REPAIR_SAFETY_PRE_SNAP_ID}"
                if [ -n "${REPAIR_SAFETY_POST_SNAP_ID:-}" ]; then
                    echo "Safety Snapshot (post)        : ${REPAIR_SAFETY_POST_SNAP_ID}"
                fi
            fi
            echo "Full logs available at: ${LOG_FILE}"
            echo "==================================================="
            echo ""
        } >>"${LOG_FILE}" 2>/dev/null || true
    fi

    return 0
}

__znh_exit_handler() {
    # Preserve original exit code.
    local rc=$?

    # Avoid recursion.
    trap - EXIT

    # Ensure EXIT handler itself doesn't abort due to set -e.
    set +e

    # Backstop: finalize safety snapshot if a pre snapshot exists.
    __znh_finalize_repair_safety_snapshot "${rc}" || true

    # Print report (only when enabled).
    print_flight_report "${rc}" || true

    exit "${rc}"
}

# Always register the EXIT handler, but it is gated by FLIGHT_REPORT_ENABLED
# and REPAIR_SAFETY_PRE_SNAP_ID so it won't spam in non-verification modes.
trap '__znh_exit_handler' EXIT

# --- Helper: Config reset mode (CLI) ---
run_reset_config_only() {
    log_info ">>> Resetting zypper-auto-helper configuration to defaults..."

    echo "" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"
    echo "  zypper-auto-helper Config Reset" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"
    echo "This will replace ${CONFIG_FILE} with a fresh default configuration" | tee -a "${LOG_FILE}"
    echo "while keeping a timestamped backup copy alongside it." | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"

    if [ "${RESET_ASSUME_YES:-0}" -ne 1 ]; then
        read -p "Are you sure you want to reset ${CONFIG_FILE} to defaults? [y/N]: " -r CONFIRM
        echo
        if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
            log_info "Config reset aborted by user. No changes made."
            update_status "ABORTED: Config reset cancelled by user"
            return 0
        fi
    else
        log_info "Non-interactive mode: proceeding without confirmation (--yes)."
    fi

    # Backup existing config if present
    if [ -f "${CONFIG_FILE}" ]; then
        TS="$(date +%Y%m%d-%H%M%S)"
        BACKUP="${CONFIG_FILE}.bak-${TS}"
        if execute_guarded "Backup existing config to ${BACKUP}" cp -f "${CONFIG_FILE}" "${BACKUP}"; then
            log_info "Backed up existing config to ${BACKUP}"
        else
            log_error "Failed to back up existing config to ${BACKUP} (continuing)"
        fi
    fi

    # Rewrite a fresh default config by removing it and letting load_config
    # regenerate the template.
    execute_guarded "Remove existing config file to regenerate defaults" rm -f "${CONFIG_FILE}" || true
    load_config

    log_success "Configuration reset to defaults in ${CONFIG_FILE}"
    update_status "SUCCESS: zypper-auto-helper configuration reset to defaults"

    echo "" | tee -a "${LOG_FILE}"
    echo "You can now re-run installation to apply the new settings:" | tee -a "${LOG_FILE}"
    echo "  sudo ./zypper-auto.sh install" | tee -a "${LOG_FILE}"
}

# --- Helper: Send a webhook notification (CLI) ---
# Usage:
#   sudo zypper-auto-helper --send-webhook "Title" "Message" [color]
# Or pass via environment:
#   sudo WEBHOOK_TITLE=... WEBHOOK_MESSAGE=... WEBHOOK_COLOR=... zypper-auto-helper --send-webhook
run_send_webhook_only() {
    local title message color
    title="${1:-${WEBHOOK_TITLE:-}}"
    message="${2:-${WEBHOOK_MESSAGE:-}}"
    color="${3:-${WEBHOOK_COLOR:-}}"

    if [ -z "${title}" ] || [ -z "${message}" ]; then
        log_error "--send-webhook requires a title and message (either as args or WEBHOOK_TITLE/WEBHOOK_MESSAGE env vars)"
        return 1
    fi

    send_webhook "${title}" "${message}" "${color:-}"
    log_success "Webhook send attempted (best-effort)"
    update_status "SUCCESS: Webhook send attempted"
    return 0
}

# --- Helper: Generate status dashboard (CLI) ---
run_generate_dashboard_only() {
    generate_dashboard
    update_status "SUCCESS: Dashboard generated"
    echo "Dashboard generated (root): ${LOG_DIR}/status.html"
    if [ -n "${SUDO_USER_HOME:-}" ]; then
        echo "Dashboard generated (user): ${SUDO_USER_HOME}/.local/share/zypper-notify/status.html"
    fi
    return 0
}

# --- Helper: Enterprise quickstart (hooks + dashboard) ---
# Enables example hooks by copying templates into executable scripts (no overwrite)
# and opens the user dashboard in a browser (best-effort).
run_dash_install_only() {
    log_info ">>> Enterprise quickstart: enabling default hook scripts + opening dashboard"

    local base
    base="${HOOKS_BASE_DIR:-/etc/zypper-auto/hooks}"

    # Ensure hook directories exist + templates are present.
    ensure_hook_dirs || true
    install_hook_templates || true

    local pre_tpl post_tpl pre_hook post_hook
    pre_tpl="${base}/pre.d/00-example-pre.sh.example"
    post_tpl="${base}/post.d/00-example-post.sh.example"

    pre_hook="${base}/pre.d/10-enabled-example-pre.sh"
    post_hook="${base}/post.d/90-enabled-example-post.sh"

    # Enable default hooks by copying templates into executable scripts.
    # Never overwrite existing user hooks.
    if [ ! -f "${pre_hook}" ]; then
        if [ -f "${pre_tpl}" ]; then
            execute_guarded "Enable default pre-hook (${pre_hook})" cp -f "${pre_tpl}" "${pre_hook}" || true
        else
            if write_atomic "${pre_hook}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
stage="${HOOK_STAGE:-pre}"
run_id="${ZNH_RUN_ID:-}"
tid="${ZYPPER_TRACE_ID:-}"
msg="[HOOK] stage=${stage} RUN=${run_id}${tid:+ TID=${tid}} (auto-enabled default hook)"
command -v logger >/dev/null 2>&1 && logger -t zypper-auto-hook -- "$msg" || true
echo "$(date '+%Y-%m-%d %H:%M:%S') $msg" >>/var/log/zypper-auto/hooks.log 2>/dev/null || true
EOF
            then
                :
            else
                log_warn "Failed to create default pre-hook (non-fatal): ${pre_hook}"
            fi
        fi
        chown root:root "${pre_hook}" 2>/dev/null || true
        chmod 755 "${pre_hook}" 2>/dev/null || true
    else
        log_info "Pre-hook already exists; leaving in place: ${pre_hook}"
    fi

    if [ ! -f "${post_hook}" ]; then
        if [ -f "${post_tpl}" ]; then
            execute_guarded "Enable default post-hook (${post_hook})" cp -f "${post_tpl}" "${post_hook}" || true
        else
            if write_atomic "${post_hook}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
stage="${HOOK_STAGE:-post}"
run_id="${ZNH_RUN_ID:-}"
tid="${ZYPPER_TRACE_ID:-}"
msg="[HOOK] stage=${stage} RUN=${run_id}${tid:+ TID=${tid}} (auto-enabled default hook)"
command -v logger >/dev/null 2>&1 && logger -t zypper-auto-hook -- "$msg" || true
echo "$(date '+%Y-%m-%d %H:%M:%S') $msg" >>/var/log/zypper-auto/hooks.log 2>/dev/null || true
EOF
            then
                :
            else
                log_warn "Failed to create default post-hook (non-fatal): ${post_hook}"
            fi
        fi
        chown root:root "${post_hook}" 2>/dev/null || true
        chmod 755 "${post_hook}" 2>/dev/null || true
    else
        log_info "Post-hook already exists; leaving in place: ${post_hook}"
    fi

    # Refresh dashboard now.
    generate_dashboard || true

    # Best-effort: open user dashboard in browser.
    local dash_path dash_browser
    dash_path="${SUDO_USER_HOME:-}/.local/share/zypper-notify/status.html"
    dash_browser="${ZYPPER_AUTO_DASHBOARD_BROWSER:-${DASHBOARD_BROWSER:-}}"

    if [ -n "${SUDO_USER_HOME:-}" ] && [ -f "${dash_path}" ]; then
        log_info "Dashboard path: ${dash_path}"
        if [ -n "${dash_browser:-}" ]; then
            log_info "Dashboard browser override: ${dash_browser}"
        fi

        # Quiet best-effort open; do not dump noisy xdg-open output into logs.
        local user_bus
        user_bus="$(get_user_bus "${SUDO_USER:-}" 2>/dev/null || true)"

        if [ -n "${dash_browser:-}" ] && command -v "${dash_browser}" >/dev/null 2>&1; then
            if [ -n "${SUDO_USER:-}" ] && [ -n "${user_bus:-}" ]; then
                sudo -u "${SUDO_USER}" DBUS_SESSION_BUS_ADDRESS="${user_bus}" \
                    "${dash_browser}" "${dash_path}" >/dev/null 2>&1 || true
            else
                "${dash_browser}" "${dash_path}" >/dev/null 2>&1 || true
            fi
        elif command -v xdg-open >/dev/null 2>&1; then
            if [ -n "${SUDO_USER:-}" ] && [ -n "${user_bus:-}" ]; then
                sudo -u "${SUDO_USER}" DBUS_SESSION_BUS_ADDRESS="${user_bus}" \
                    xdg-open "${dash_path}" >/dev/null 2>&1 || true
            else
                xdg-open "${dash_path}" >/dev/null 2>&1 || true
            fi
        fi

        # Also print a copy-paste line for manual opening.
        echo "Open in browser: xdg-open ${dash_path}" | tee -a "${LOG_FILE}"
    else
        log_info "Dashboard file not found yet; run: sudo zypper-auto-helper --dashboard"
    fi

    echo "" | tee -a "${LOG_FILE}"
    echo "Enterprise quickstart complete." | tee -a "${LOG_FILE}"
    echo "Next:" | tee -a "${LOG_FILE}"
    echo "  1) Edit ${CONFIG_FILE} and set WEBHOOK_URL=\"...\" (optional)" | tee -a "${LOG_FILE}"
    echo "  2) Put your own executable scripts in:" | tee -a "${LOG_FILE}"
    echo "     - ${base}/pre.d/" | tee -a "${LOG_FILE}"
    echo "     - ${base}/post.d/" | tee -a "${LOG_FILE}"

    update_status "SUCCESS: Enterprise quickstart completed"
    return 0
}

# --- Helper: Open dashboard (CLI) ---
# Regenerates dashboard first (best-effort) then opens the user copy.
run_dash_stop_only() {
    log_info ">>> Stopping live dashboard server (best-effort)"

    local dash_dir pid_file port_file

    dash_dir=""
    if [ -n "${SUDO_USER_HOME:-}" ]; then
        dash_dir="${SUDO_USER_HOME}/.local/share/zypper-notify"
    elif [ -n "${SUDO_USER:-}" ]; then
        # Best-effort fallback if SUDO_USER_HOME isn't set
        local user_home
        user_home=$(getent passwd "${SUDO_USER}" 2>/dev/null | cut -d: -f6)
        if [ -n "${user_home:-}" ]; then
            dash_dir="${user_home}/.local/share/zypper-notify"
        fi
    else
        dash_dir="$HOME/.local/share/zypper-notify"
    fi

    # Stop sync worker first (best-effort)
    __znh_stop_dashboard_sync_worker "${dash_dir}" || true
    # Stop perf worker (best-effort)
    __znh_stop_dashboard_perf_worker "${dash_dir}" || true

    pid_file="${dash_dir}/dashboard-http.pid"
    port_file="${dash_dir}/dashboard-http.port"

    if [ -f "${pid_file}" ] && [ -f "${port_file}" ]; then
        local old_pid old_port
        old_pid=$(cat "${pid_file}" 2>/dev/null || echo "")
        old_port=$(cat "${port_file}" 2>/dev/null || echo "")
        if [[ "${old_port:-}" =~ ^[0-9]+$ ]] && __znh_pid_is_dashboard_http_server "${old_pid}" "${dash_dir}" "${old_port}"; then
            kill "${old_pid}" 2>/dev/null || true
            sleep 0.1
            if kill -0 "${old_pid}" 2>/dev/null; then
                kill -9 "${old_pid}" 2>/dev/null || true
            fi
            log_success "Dashboard server stopped (pid=${old_pid})"
            update_status "SUCCESS: Dashboard server stopped"
            echo "Stopped dashboard server (pid=${old_pid})."
        else
            log_info "Dashboard server not running or PID could not be validated (stale pid file: ${pid_file})"
            update_status "SUCCESS: Dashboard server not running"
            echo "Dashboard server not running or PID could not be validated (stale pid file: ${pid_file})."
        fi
        rm -f "${pid_file}" "${port_file}" 2>/dev/null || true
    else
        log_info "No dashboard server pid/port files found under ${dash_dir}"
        update_status "SUCCESS: No dashboard server pid/port files found"
        echo "No dashboard server pid/port files found under ${dash_dir}."
    fi

    return 0
}

run_dash_open_only() {
    log_info ">>> Opening dashboard (best-effort)"

    local dash_browser
    dash_browser="${1:-${ZYPPER_AUTO_DASHBOARD_BROWSER:-${DASHBOARD_BROWSER:-}}}"

    # Best-effort regenerate so the page is fresh.
    generate_dashboard || true

    local dash_path dash_dir
    dash_dir="${SUDO_USER_HOME:-}/.local/share/zypper-notify"
    dash_path="${dash_dir}/status.html"

    if [ -n "${SUDO_USER_HOME:-}" ] && [ -f "${dash_path}" ]; then
        log_info "Dashboard path: ${dash_path}"
        if [ -n "${dash_browser:-}" ]; then
            log_info "Dashboard browser override: ${dash_browser}"
        fi
        echo "Open in browser: xdg-open ${dash_path}" | tee -a "${LOG_FILE}"

        # Start the live dashboard server (same safeguards as non-sudo fast path).
        local port url pid_file port_file err_file reuse_existing_server
        port=8765
        pid_file="${dash_dir}/dashboard-http.pid"
        port_file="${dash_dir}/dashboard-http.port"
        err_file="${dash_dir}/dashboard-http.err"
        reuse_existing_server=0

        mkdir -p "${dash_dir}" 2>/dev/null || true
        if [ -n "${SUDO_USER:-}" ]; then
            chown "${SUDO_USER}:${SUDO_USER}" "${dash_dir}" 2>/dev/null || true
        fi

        # If a previous server is already running, reuse its port (validate PID is really our server).
        if [ -f "${pid_file}" ] && [ -f "${port_file}" ]; then
            local old_pid old_port
            old_pid=$(cat "${pid_file}" 2>/dev/null || echo "")
            old_port=$(cat "${port_file}" 2>/dev/null || echo "")
            if [[ "${old_port:-}" =~ ^[0-9]+$ ]] && __znh_pid_is_dashboard_http_server "${old_pid}" "${dash_dir}" "${old_port}"; then
                port="${old_port}"
                reuse_existing_server=1
            fi
        fi

        # If requested/default port is busy, pick a nearby free port.
        # IMPORTANT: if the port is in use by *our own validated* server, keep it.
        if __znh_port_listen_in_use "${port}" && [ "${reuse_existing_server}" -ne 1 ] 2>/dev/null; then
            local port_pick
            port_pick="$(__znh_pick_free_port 8765 8790 2>/dev/null || true)"
            if [[ "${port_pick:-}" =~ ^[0-9]+$ ]]; then
                port="${port_pick}"
            fi
        fi

        url="http://127.0.0.1:${port}/status.html?live=1"

        # Dashboard Settings API token: keep user token file in sync with the root API.
        local token_file old_token new_token api_ok
        token_file="${dash_dir}/dashboard-token.txt"
        old_token=""
        if [ -f "${token_file}" ]; then
            old_token=$(cat "${token_file}" 2>/dev/null || echo "")
        fi
        new_token=""
        if command -v python3 >/dev/null 2>&1; then
            new_token=$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(24))
PY
)
        else
            new_token="$(date +%s%N)"
        fi

        api_ok=0
        if run_dash_api_on_only "${new_token}" >/dev/null 2>&1; then
            api_ok=1
        fi

        if [ "${api_ok}" -eq 1 ] 2>/dev/null; then
            printf '%s' "${new_token}" >"${token_file}" 2>/dev/null || true
            chmod 600 "${token_file}" 2>/dev/null || true
            if [ -n "${SUDO_USER:-}" ]; then
                chown "${SUDO_USER}:${SUDO_USER}" "${token_file}" 2>/dev/null || true
            fi
        else
            # Keep existing token file untouched if API restart failed.
            if [ -n "${old_token}" ]; then
                chmod 600 "${token_file}" 2>/dev/null || true
            fi
        fi

        local server_running
        server_running=0
        if [ -f "${pid_file}" ] && [ -f "${port_file}" ]; then
            local p pp
            p=$(cat "${pid_file}" 2>/dev/null || echo "")
            pp=$(cat "${port_file}" 2>/dev/null || echo "")
            if [[ "${pp:-}" =~ ^[0-9]+$ ]] && __znh_pid_is_dashboard_http_server "${p}" "${dash_dir}" "${pp}"; then
                server_running=1
            fi
        fi

        if [ "${server_running}" -ne 1 ] 2>/dev/null; then
            if [ -n "${SUDO_USER:-}" ] && command -v python3 >/dev/null 2>&1; then
                rm -f "${err_file}" 2>/dev/null || true
                # Run the web server as the desktop user so file permissions + paths match.
                # Use nohup so the server survives terminal close.
                # Run at background priority (nice + idle IO) so it never contends with foreground apps.
                sudo -u "${SUDO_USER}" \
                    bash -lc "nohup bash -lc 'if command -v ionice >/dev/null 2>&1; then ionice -c3 -p \$\$ >/dev/null 2>&1 || true; fi; if command -v renice >/dev/null 2>&1; then renice -n 19 -p \$\$ >/dev/null 2>&1 || true; fi; exec python3 -m http.server --bind 127.0.0.1 --directory \"\$1\" \"\$2\"' _ \"${dash_dir}\" \"${port}\" >>\"${err_file}\" 2>&1 & echo \$! >\"${pid_file}\"; echo \"${port}\" >\"${port_file}\"" || true
                sleep 0.25
            fi
        fi

        # Verify server is listening before opening browser (best-effort)
        # Use a short retry loop so we don't emit a scary warning when the server
        # is still starting up.
        local ok
        ok=0
        for _i in $(seq 1 50); do
            if __znh_port_listen_in_use "${port}"; then
                ok=1
                break
            fi
            sleep 0.1
        done

        if [ "${ok}" -ne 1 ] 2>/dev/null; then
            log_warn "Dashboard server did not respond on port ${port}"
            if [ -s "${err_file}" ]; then
                log_warn "--- dashboard server error (last 20 lines):"
                tail -n 20 "${err_file}" 2>/dev/null | sed 's/^/[DASH_HTTP] /' | tee -a "${LOG_FILE}" || true
            fi
        fi

        echo "Open live dashboard: ${url}" | tee -a "${LOG_FILE}"

        local user_bus
        user_bus="$(get_user_bus "${SUDO_USER:-}" 2>/dev/null || true)"

        # When launching GUI apps as the desktop user from sudo context, propagate XDG_RUNTIME_DIR.
        local user_uid user_runtime
        user_uid=""
        if [ -n "${SUDO_USER:-}" ]; then
            user_uid=$(id -u "${SUDO_USER}" 2>/dev/null || echo "")
        fi
        user_runtime=""
        if [[ "${user_uid:-}" =~ ^[0-9]+$ ]]; then
            user_runtime="/run/user/${user_uid}"
        fi

        # Open the browser detached (best-effort) so terminal close doesn't kill it.
        if [ -n "${dash_browser:-}" ] && command -v "${dash_browser}" >/dev/null 2>&1; then
            local extra_args
            extra_args="$(__znh_browser_extra_args "${dash_browser}" 2>/dev/null | tr '\n' ' ' || true)"
            if [ -n "${SUDO_USER:-}" ] && [ -n "${user_bus:-}" ]; then
                sudo -u "${SUDO_USER}" DBUS_SESSION_BUS_ADDRESS="${user_bus}" XDG_RUNTIME_DIR="${user_runtime}" \
                    bash -lc "nohup \"${dash_browser}\" ${extra_args} \"${url}\" >/dev/null 2>&1 &" || true
            else
                # shellcheck disable=SC2207
                local extra=( $(__znh_browser_extra_args "${dash_browser}" 2>/dev/null || true) )
                __znh_detach_cmd "${dash_browser}" "${extra[@]}" "${url}" || true
            fi
        elif command -v xdg-open >/dev/null 2>&1; then
            if [ -n "${SUDO_USER:-}" ] && [ -n "${user_bus:-}" ]; then
                sudo -u "${SUDO_USER}" DBUS_SESSION_BUS_ADDRESS="${user_bus}" XDG_RUNTIME_DIR="${user_runtime}" \
                    bash -lc "nohup xdg-open \"${url}\" >/dev/null 2>&1 &" || true
            else
                __znh_detach_cmd xdg-open "${url}" || true
            fi
        fi

        # Start user sync worker (best-effort) so user dashboard dir stays up-to-date.
        if [ -n "${SUDO_USER:-}" ]; then
            local user_home
            user_home=$(getent passwd "${SUDO_USER}" 2>/dev/null | cut -d: -f6 || true)
            __znh_start_dashboard_sync_worker "${dash_dir}" "${SUDO_USER}" "${user_home}" || true
            # Start perf worker for live service performance charts (best-effort)
            __znh_start_dashboard_perf_worker "${dash_dir}" "${SUDO_USER}" "${user_home}" || true
            # Ensure Desktop/app launcher exists (best-effort)
            __znh_ensure_dash_desktop_shortcut "${SUDO_USER}" "${user_home}" || true
        fi

        update_status "SUCCESS: Dashboard open attempted"
        return 0
    fi

    log_error "Dashboard file not found yet: ${dash_path}"
    log_info "Try: sudo zypper-auto-helper --dashboard"
    update_status "FAILED: Dashboard file not found"
    return 1
}

# --- Helper: Dashboard settings API (localhost) ---
run_dash_api_on_only() {
    local token="$1"
    local unit="zypper-auto-dashboard-api.service"
    local token_dir="/var/lib/zypper-auto"
    local token_file="${token_dir}/dashboard-api.token"
    local env_file="${token_dir}/dashboard-api.env"
    local schema_file="${token_dir}/dashboard-schema.json"

    if [ "${EUID}" -ne 0 ] 2>/dev/null; then
        log_error "--dash-api-on must be run as root (use sudo)"
        return 1
    fi

    mkdir -p "${token_dir}" 2>/dev/null || true
    chown root:root "${token_dir}" 2>/dev/null || true
    chmod 700 "${token_dir}" 2>/dev/null || true

    # Ensure schema exists (needed by the API service for predefined allowed values)
    __znh_write_dashboard_schema_json "${schema_file}" || true

    if [ -z "${token:-}" ]; then
        if command -v python3 >/dev/null 2>&1; then
            token=$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(24))
PY
)
        else
            token="$(date +%s%N)"
        fi
    fi

    printf '%s' "${token}" >"${token_file}" 2>/dev/null || true
    chmod 600 "${token_file}" 2>/dev/null || true

    # Configure per-user mirror path so the dashboard can display API logs.
    # This is stored in a root-only EnvironmentFile used by the systemd unit.
    local user_home mirror_file
    user_home=""
    if [ -n "${SUDO_USER:-}" ]; then
        user_home=$(getent passwd "${SUDO_USER}" 2>/dev/null | cut -d: -f6 || true)
    fi
    mirror_file=""
    if [ -n "${user_home:-}" ]; then
        mirror_file="${user_home}/.local/share/zypper-notify/dashboard-api.log"
        mkdir -p "${user_home}/.local/share/zypper-notify" 2>/dev/null || true
        touch "${mirror_file}" 2>/dev/null || true
        if [ -n "${SUDO_USER:-}" ]; then
            chown "${SUDO_USER}:${SUDO_USER}" "${mirror_file}" 2>/dev/null || true
        fi
        chmod 644 "${mirror_file}" 2>/dev/null || true
    fi

    {
        echo "DASH_API_MIRROR_FILE=${mirror_file}"
        echo "DASH_API_LOG_LEVEL=${ZYPPER_AUTO_DASH_API_LOG_LEVEL:-info}"
    } >"${env_file}" 2>/dev/null || true
    chmod 600 "${env_file}" 2>/dev/null || true

    execute_guarded "systemd daemon-reload (dashboard api)" systemctl daemon-reload || true
    execute_guarded "Enable + start dashboard API" systemctl enable --now "${unit}" || true
    execute_guarded "Restart dashboard API (reload token)" systemctl restart "${unit}" || true

    log_success "Dashboard API is running (best-effort) on http://127.0.0.1:8766"
    update_status "SUCCESS: Dashboard API started"
    return 0
}

run_dash_api_off_only() {
    local unit="zypper-auto-dashboard-api.service"
    if [ "${EUID}" -ne 0 ] 2>/dev/null; then
        log_error "--dash-api-off must be run as root (use sudo)"
        return 1
    fi

    execute_guarded "Disable dashboard API" systemctl disable --now "${unit}" || true
    execute_guarded "systemd daemon-reload (dashboard api off)" systemctl daemon-reload || true
    log_success "Dashboard API stopped (best-effort)"
    update_status "SUCCESS: Dashboard API stopped"
    return 0
}

run_dash_api_status_only() {
    local unit="zypper-auto-dashboard-api.service"
    systemctl status "${unit}" --no-pager 2>/dev/null || systemctl is-active "${unit}" 2>/dev/null || true
    return 0
}

# --- Helper: Background diagnostic log follower (CLI) ---
#
# This mode ensures a *persistent* systemd service
# (zypper-auto-diag-logs.service) exists and is enabled so that diagnostics
# logging survives reboots. The actual follower work is performed by the
# internal runner mode (--diag-logs-runner).
run_diag_logs_on_only() {
    log_info ">>> Enabling background diagnostics log follower (zypper-auto-diag-logs.service)"
    update_status "Enabling diagnostics log follower..."

    local diag_dir
    diag_dir="${LOG_DIR}/diagnostics"
    execute_guarded "Ensure diagnostics log directory exists (${diag_dir})" mkdir -p "${diag_dir}" || true

    # Prune diagnostics logs older than 10 days to keep disk usage bounded.
    # This uses file mtime; a 10-day window is sufficient for troubleshooting.
    execute_guarded "Prune old diagnostics logs (>9 days)" \
        find "${diag_dir}" -type f -name 'diag-*.log' -mtime +9 -print -delete || true

    # Ensure source-tagging follower helper exists so each line in the
    # diagnostics log is tagged with its origin (INSTALL, DOWNLOADER,
    # NOTIFIER, etc.).
    local diag_follower
    diag_follower="/usr/local/bin/zypper-auto-diag-follow"
    if [ ! -x "${diag_follower}" ]; then
write_atomic "${diag_follower}" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -eq 0 ]; then
    exit 0
fi

for path in "$@"; do
    [ -e "$path" ] || continue
    base="$(basename "$path")"
    src="${base%.*}"
    src="${src^^}"
    # Tail each file and prefix lines with a source tag based on the basename.
    tail -n 0 -F "$path" | sed -u "s/^/[SRC=${src}] /" &
done

wait || true
EOF
        chmod +x "${diag_follower}" || true
    fi

    # (Re)write a persistent systemd service that calls back into this script in
    # runner mode so diagnostics logging survives reboots.
    log_debug "Writing diagnostics follower service unit: ${DIAG_SERVICE_FILE}"
    cat > "${DIAG_SERVICE_FILE}" <<EOF
[Unit]
Description=Zypper auto-helper diagnostics follower
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/zypper-auto-helper --diag-logs-runner
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd daemon and (re)start the diagnostics follower service.
    if execute_guarded "systemd daemon-reload (diagnostics follower)" systemctl daemon-reload && \
       execute_guarded "Enable + start ${DIAG_SERVICE_NAME}.service" systemctl enable --now "${DIAG_SERVICE_NAME}.service"; then
        log_success "Diagnostics follower enabled as persistent service (${DIAG_SERVICE_NAME}.service)"
        update_status "SUCCESS: Diagnostics log follower enabled (persistent)"
        return 0
    else
        log_error "Failed to enable diagnostics follower service (${DIAG_SERVICE_NAME}.service)"
        update_status "FAILED: Could not enable diagnostics log follower"
        return 1
    fi
}

# Internal runner: started by zypper-auto-diag-logs.service to actually follow
# logs and write into the per-day diagnostics file. This is not meant to be
# invoked directly by users; they should use --diag-logs-on instead.
run_diag_logs_runner_only() {
    log_info ">>> Diagnostics follower runner starting..."

    local diag_dir diag_file today
    diag_dir="${LOG_DIR}/diagnostics"
    execute_guarded "Ensure diagnostics log directory exists (${diag_dir})" mkdir -p "${diag_dir}" || true

    # Prune diagnostics logs older than 10 days here as well, in case the
    # runner is restarted independently of the CLI helper.
    execute_guarded "Prune old diagnostics logs (>9 days)" \
        find "${diag_dir}" -type f -name 'diag-*.log' -mtime +9 -print -delete || true

    # We still append an initial header to today's file, but the follower output
    # itself is written via an auto-rotating writer so it switches to a new
    # diag-YYYY-MM-DD.log automatically at midnight without restarting.
    today="$(date +%Y-%m-%d)"
    diag_file="${diag_dir}/diag-${today}.log"

    log_info "Diagnostics logs will be written under: ${diag_dir} (auto-rotating per day)"

    # Append a compact environment/config snapshot to the diagnostics file so
    # today's log starts with context.
    {
        echo "===== Zypper Auto-Helper Diagnostics Session Start: $(date '+%Y-%m-%d %H:%M:%S') ====="
        echo "Host: $(hostname 2>/dev/null || echo 'unknown')"
        if [ -f /etc/os-release ]; then
            . /etc/os-release 2>/dev/null || true
            echo "OS: ${NAME:-unknown} ${VERSION:-} (ID=${ID:-?}, VARIANT_ID=${VARIANT_ID:--})"
        fi
        if command -v zypper >/dev/null 2>&1; then
            echo "Zypper: $(zypper --version 2>/dev/null | head -1)"
        fi
        echo "Config snapshot (${CONFIG_FILE}):"
        if [ -f "${CONFIG_FILE}" ]; then
            grep -E '^(DOWNLOADER_DOWNLOAD_MODE|DL_TIMER_INTERVAL_MINUTES|NT_TIMER_INTERVAL_MINUTES|VERIFY_TIMER_INTERVAL_MINUTES|CACHE_EXPIRY_MINUTES|SNOOZE_SHORT_HOURS|SNOOZE_MEDIUM_HOURS|SNOOZE_LONG_HOURS|LOCK_REMINDER_ENABLED|NO_UPDATES_REMINDER_REPEAT_ENABLED|UPDATES_READY_REMINDER_REPEAT_ENABLED|INSTALL_CLICK_SUPPRESS_MINUTES|VERIFY_NOTIFY_USER_ENABLED)=' "${CONFIG_FILE}" 2>/dev/null || echo "  (no matching keys found)"
        else
            echo "  (config file missing)"
        fi
        echo "======================================================================"
    } >> "${diag_file}" 2>/dev/null || true

    # Build the list of log files to follow.
    local follow_paths=()

    # Best-effort: include the most recent install log at runner start.
    # Future installs will still be captured via TRACE_LOG mirroring.
    local latest_install_log
    latest_install_log=""
    latest_install_log=$(find "${LOG_DIR}" -maxdepth 1 -type f -name 'install-*.log' -printf '%T@\t%p\n' 2>/dev/null \
        | sort -nr | head -1 | cut -f2- || true)
    if [ -n "${latest_install_log}" ]; then
        follow_paths+=("${latest_install_log}")
    fi

    if [ -d "${LOG_DIR}/service-logs" ]; then
        local f
        for f in "${LOG_DIR}/service-logs"/*.log; do
            if [ -f "$f" ]; then
                follow_paths+=("$f")
            fi
        done
    fi

    if [ -n "${SUDO_USER_HOME:-}" ] && [ -f "${SUDO_USER_HOME}/.local/share/zypper-notify/notifier-detailed.log" ]; then
        follow_paths+=("${SUDO_USER_HOME}/.local/share/zypper-notify/notifier-detailed.log")
    fi

    # Include TRACE_LOG so diagnostics logs always capture structured install/
    # verify activity (the helper mirrors _log_write lines into TRACE_LOG).
    if [ -n "${TRACE_LOG:-}" ] && [ -f "${TRACE_LOG}" ]; then
        follow_paths+=("${TRACE_LOG}")
    fi

    if [ "${#follow_paths[@]}" -eq 0 ]; then
        log_info "No existing logs found to follow; diagnostics follower will idle until logs exist."
        : > "${diag_file}" 2>/dev/null || true
        return 0
    fi

    local diag_follower
    diag_follower="/usr/local/bin/zypper-auto-diag-follow"
    if [ ! -x "${diag_follower}" ]; then
        log_error "Diagnostics follower helper ${diag_follower} is missing or not executable"
        return 1
    fi

    # Auto-rotating writer: each line is appended to diag-YYYY-MM-DD.log based
    # on the current date, so at midnight it seamlessly starts writing to the
    # new day's file without restarting.
    log_debug "Starting diagnostic follower runner (auto-rotating output)..."
    "${diag_follower}" "${follow_paths[@]}" 2>&1 | \
        awk -v diag_dir="${diag_dir}" '{
            file = diag_dir "/diag-" strftime("%Y-%m-%d") ".log";
            print $0 >> file;
            fflush(file);
        }'
}

# --- Helper: Snapshot current system/helper state into diagnostics log (CLI) ---
run_snapshot_state_only() {
    log_info ">>> Capturing one-shot diagnostics snapshot into today's diag log..."

    local diag_dir today diag_file
    diag_dir="${LOG_DIR}/diagnostics"
    execute_guarded "Ensure diagnostics log directory exists (${diag_dir})" mkdir -p "${diag_dir}" || true
    today="$(date +%Y-%m-%d)"
    diag_file="${diag_dir}/diag-${today}.log"

    {
        echo "===== SNAPSHOT STATE at $(date '+%Y-%m-%d %H:%M:%S') [RUN=${RUN_ID}] ====="
        echo "-- Core systemd units (system) --"
        systemctl --no-pager status zypper-autodownload.service zypper-autodownload.timer 2>&1 || echo "(zypper-autodownload.* not found)"
        systemctl --no-pager status zypper-auto-verify.service zypper-auto-verify.timer 2>&1 || echo "(zypper-auto-verify.* not found)"
        echo
        echo "-- User notifier units (for ${SUDO_USER:-root}) --"
        if [ -n "${SUDO_USER:-}" ]; then
            USER_BUS_PATH="unix:path=/run/user/$(id -u "${SUDO_USER}")/bus"
            sudo -u "${SUDO_USER}" DBUS_SESSION_BUS_ADDRESS="${USER_BUS_PATH}" \
                systemctl --user --no-pager status zypper-notify-user.service zypper-notify-user.timer 2>&1 || echo "(user notifier units not found)"
        else
            echo "(no SUDO_USER; skipping user notifier status)"
        fi
        echo
        echo "-- Downloader status file --"
        if [ -f "${LOG_DIR}/download-status.txt" ]; then
            echo "Path: ${LOG_DIR}/download-status.txt"
            echo "Contents:"
            cat "${LOG_DIR}/download-status.txt" 2>/dev/null || echo "(unreadable)"
            echo "Metadata:"
            stat "${LOG_DIR}/download-status.txt" 2>/dev/null || echo "(no stat)"
        else
            echo "No download-status.txt present"
        fi
        echo
        echo "-- Notifier last-run-status (user ${SUDO_USER:-root}) --"
        if [ -n "${SUDO_USER_HOME:-}" ] && [ -f "${SUDO_USER_HOME}/.local/share/zypper-notify/last-run-status.txt" ]; then
            echo "Path: ${SUDO_USER_HOME}/.local/share/zypper-notify/last-run-status.txt"
            cat "${SUDO_USER_HOME}/.local/share/zypper-notify/last-run-status.txt" 2>/dev/null || echo "(unreadable)"
            stat "${SUDO_USER_HOME}/.local/share/zypper-notify/last-run-status.txt" 2>/dev/null || echo "(no stat)"
        else
            echo "No notifier last-run-status.txt present for user"
        fi
        echo
        echo "-- Disk and network summary --"
        df -h / 2>/dev/null || echo "(df failed)"
        if command -v nmcli >/dev/null 2>&1; then
            nmcli -t -f STATE g 2>/dev/null || echo "(nmcli general state failed)"
        fi
        echo
        echo "-- One-shot zypper preview (may be empty if command fails quickly) --"
        if command -v zypper >/dev/null 2>&1; then
            # Use non-interactive mode so diagnostics snapshots never block on
            # zypper prompts (e.g. license/vendor questions). This keeps the
            # debug menu responsive when option 1 triggers an immediate snapshot.
            zypper --non-interactive -q dup --dry-run 2>&1 | head -n 50 || echo "(zypper preview failed or produced no output)"
        fi
        echo "===== END SNAPSHOT STATE [RUN=${RUN_ID}] ====="
    } >> "${diag_file}" 2>&1 || true

    update_status "SUCCESS: Diagnostics snapshot captured into ${diag_file}"
    log_success "Diagnostics snapshot captured into ${diag_file}"
}

# --- Helper: Create a compact diagnostics bundle tarball (CLI) ---
run_diag_bundle_only() {
    log_info ">>> Creating diagnostics bundle tarball..."

    local diag_dir bundle_dir bundle_file ts
    diag_dir="${LOG_DIR}/diagnostics"
    bundle_dir="${SUDO_USER_HOME:-$HOME}"
    ts="$(date +%Y%m%d-%H%M%S)"
    bundle_file="${bundle_dir}/zypper-auto-diag-${ts}.tar.xz"

    execute_guarded "Ensure diagnostics log directory exists (${diag_dir})" mkdir -p "${diag_dir}" || true

    # Build list of files to include (best-effort)
    local include_files=()

    # All diagnostics logs (already pruned to ~10 days)
    mapfile -t __diag_logs < <(find "${diag_dir}" -maxdepth 1 -type f -name 'diag-*.log' -printf '%p\n' 2>/dev/null | sort || true)
    if [ "${#__diag_logs[@]}" -gt 0 ]; then
        include_files+=("-C" "${diag_dir}")
        for __f in "${__diag_logs[@]}"; do
            include_files+=("$(basename "${__f}")")
        done
    fi

    # Last-status summary
    if [ -f "${STATUS_FILE}" ]; then
        include_files+=("-C" "${LOG_DIR}" "$(basename "${STATUS_FILE}")")
    fi

    # Most recent installer logs (up to 3)
    local inst
    inst=$(find "${LOG_DIR}" -maxdepth 1 -type f -name 'install-*.log' -printf '%T@\t%p\n' 2>/dev/null \
        | sort -nr | head -3 | cut -f2- || true)
    if [ -n "${inst}" ]; then
        include_files+=("-C" "${LOG_DIR}")
        while IFS= read -r __f; do
            [ -n "${__f}" ] || continue
            include_files+=("$(basename "${__f}")")
        done <<<"${inst}"
    fi

    # High-volume TRACE_LOG (if present)
    if [ -n "${TRACE_LOG:-}" ] && [ -f "${TRACE_LOG}" ]; then
        include_files+=("-C" "${LOG_DIR}" "$(basename "${TRACE_LOG}")")
    fi

    # Any pre-install environment snapshots captured during installation
    local envsnap
    envsnap=$(find "${LOG_DIR}" -maxdepth 1 -type f -name 'pre-install-env-*.txt' -printf '%T@\t%p\n' 2>/dev/null \
        | sort -nr | cut -f2- || true)
    if [ -n "${envsnap}" ]; then
        include_files+=("-C" "${LOG_DIR}")
        while IFS= read -r __f; do
            [ -n "${__f}" ] || continue
            include_files+=("$(basename "${__f}")")
        done <<<"${envsnap}"
    fi

    # Notifier logs for user (including any per-run delta summaries)
    if [ -n "${SUDO_USER_HOME:-}" ]; then
        local ulogdir
        ulogdir="${SUDO_USER_HOME}/.local/share/zypper-notify"
        if [ -d "${ulogdir}" ]; then
            if [ -f "${ulogdir}/notifier-detailed.log" ]; then
                include_files+=("-C" "${ulogdir}" "notifier-detailed.log")
            fi
            if [ -f "${ulogdir}/last-run-status.txt" ]; then
                include_files+=("-C" "${ulogdir}" "last-run-status.txt")
            fi
            # Include recent package delta logs produced by the Ready-to-Install helper.
            local udelta
            mapfile -t __udelta_logs < <(
                find "${ulogdir}/pkg-deltas" -maxdepth 1 -type f -name 'update-delta-*.log' -printf '%T@\t%p\n' 2>/dev/null \
                    | sort -nr | head -5 | cut -f2- || true
            )
            for udelta in "${__udelta_logs[@]}"; do
                [ -n "${udelta}" ] || continue
                include_files+=("-C" "${ulogdir}/pkg-deltas" "$(basename "${udelta}")")
            done
        fi
    fi

    # System journal slices for deeper diagnostics (OOM, crashes, unit logs)
    local journal_dir
    journal_dir="${LOG_DIR}/journal-snapshots"
    execute_guarded "Ensure journal snapshots directory exists (${journal_dir})" mkdir -p "${journal_dir}" || true
    if command -v journalctl >/dev/null 2>&1; then
        log_debug "Dumping system journals into ${journal_dir} for diagnostics bundle"
        # Root downloader/verify units over the last 2 days
        journalctl -u "${DL_SERVICE_NAME}" --no-pager --since "2 days ago" \
            > "${journal_dir}/downloader-journal.log" 2>&1 || true
        journalctl -u "${VERIFY_SERVICE_NAME}" --no-pager --since "2 days ago" \
            > "${journal_dir}/verifier-journal.log" 2>&1 || true
        # Kernel-level OOM / kill events
        dmesg 2>/dev/null | grep -i "killed process" \
            > "${journal_dir}/dmesg_kills.txt" 2>&1 || true
        journalctl -k --grep="Out of memory" --since "2 days ago" --no-pager \
            > "${journal_dir}/oom_kills.txt" 2>&1 || true
    fi
    mapfile -t __jfiles < <(find "${journal_dir}" -maxdepth 1 -type f -printf '%p\n' 2>/dev/null | sort || true)
    if [ "${#__jfiles[@]}" -gt 0 ]; then
        include_files+=("-C" "${journal_dir}")
        for __f in "${__jfiles[@]}"; do
            include_files+=("$(basename "${__f}")")
        done
    fi

    # Config and version header (include whole config + script header)
    if [ -f "${CONFIG_FILE}" ]; then
        include_files+=("-C" "/" "${CONFIG_FILE#/}")
    fi
    # Include the installer script itself for version context
    if [ -f "$0" ]; then
        include_files+=("-C" "/" "${0#/}")
    fi

    if [ "${#include_files[@]}" -eq 0 ]; then
        log_error "No diagnostics-related files found to bundle."
        return 1
    fi

    # Create tar.xz bundle
    if execute_guarded "Create diagnostics bundle tarball (${bundle_file})" tar -cJf "${bundle_file}" "${include_files[@]}"; then
        log_success "Diagnostics bundle created at ${bundle_file}"
        update_status "SUCCESS: Diagnostics bundle created at ${bundle_file}"
        echo "Diagnostics bundle: ${bundle_file}"
        return 0
    else
        log_error "Failed to create diagnostics bundle at ${bundle_file}"
        update_status "FAILED: Could not create diagnostics bundle"
        return 1
    fi
}

# --- Helper: Snapper tools menu (CLI) ---
run_snapper_menu_only() {
    # This menu is intended for root-only maintenance tasks.
    # We intentionally disable 'set -e' while the menu is active so that
    # snapper/systemctl errors do not abort the entire helper.
    set +e

    if ! command -v snapper >/dev/null 2>&1; then
        log_error "Snapper is not installed (command 'snapper' not found)."
        echo "Snapper is not installed. Install it with:" 
        echo "  sudo zypper install snapper"
        set -e
        return 1
    fi

    # Prefer `snapper --no-dbus` when supported to reduce the risk of D-Bus / snapperd hangs.
    local snapper_mode
    snapper_mode="dbus"

    local -a SNAPPER_CMD
    SNAPPER_CMD=(snapper)
    if __znh_snapper_supports_no_dbus; then
        SNAPPER_CMD=(snapper --no-dbus)
        snapper_mode="no-dbus"
    fi

    # Print mode so users can see what we're doing (useful when troubleshooting hangs).
    log_info "[snapper-menu] Snapper invocation mode: ${snapper_mode} (cmd: ${SNAPPER_CMD[*]})"

    __znh_snapper_list_config_names() {
        # Prints config names, one per line (best-effort).
        # snapper output is a table; we skip header/separator lines.
        local out rc
        out=""
        rc=0

        if command -v timeout >/dev/null 2>&1; then
            out=$(timeout 10 "${SNAPPER_CMD[@]}" list-configs 2>/dev/null)
            rc=$?
        else
            out=$("${SNAPPER_CMD[@]}" list-configs 2>/dev/null)
            rc=$?
        fi

        if [ "$rc" -ne 0 ] 2>/dev/null || [ -z "${out:-}" ]; then
            printf '%s\n' root
            return 0
        fi

        printf '%s\n' "$out" | awk '
            /^[[:space:]]*$/ {next}
            tolower($1)=="config" {next}
            $0 ~ /─|┼/ {next}
            $1 ~ /^-+$/ {next}
            {print $1}
        '
        return 0
    }

    __znh_snapper_optimize_configs() {
        # Best-effort Snapper config self-heal (shared by option 4 and option 5).
        # Modes:
        #   enable  - set TIMELINE_CREATE/BOOT_CREATE=yes and apply retention caps
        #   disable - set TIMELINE_CREATE/BOOT_CREATE=no but ONLY if keys already exist
        #   cleanup - if systemd timers are enabled, ensure corresponding *_CREATE=yes; apply retention caps
        local action="${1:-cleanup}"

        if [ ! -d /etc/snapper/configs ]; then
            return 0
        fi

        local timeline_enabled boot_enabled
        timeline_enabled=0
        boot_enabled=0

        # Determine timer states (used by cleanup mode; harmless elsewhere)
        if systemctl is-enabled --quiet snapper-timeline.timer 2>/dev/null; then
            timeline_enabled=1
        fi
        if systemctl is-enabled --quiet snapper-boot.timer 2>/dev/null; then
            boot_enabled=1
        fi

        local target_val
        if [ "${action}" = "disable" ]; then
            target_val="no"
        else
            target_val="yes"
        fi

        __znh_cfg_tmp_get() {
            local file="$1" key="$2" line val
            line=$(grep -E "^${key}=" "${file}" 2>/dev/null | head -n 1 || true)
            [ -n "${line:-}" ] || return 1
            val="${line#*=}"
            val="${val%\"}"
            val="${val#\"}"
            printf '%s' "$val"
            return 0
        }

        __znh_cfg_tmp_set() {
            local file="$1" key="$2" val="$3"

            if grep -qE "^${key}=" "${file}" 2>/dev/null; then
                # Replace any existing assignment form with KEY="val".
                local tmp2
                tmp2="$(mktemp)"
                sed -E "s|^${key}=.*|${key}=\"${val}\"|" "${file}" >"${tmp2}" 2>/dev/null || {
                    rm -f "${tmp2}" 2>/dev/null || true
                    return 1
                }
                mv -f "${tmp2}" "${file}" 2>/dev/null || {
                    rm -f "${tmp2}" 2>/dev/null || true
                    return 1
                }
            else
                printf '\n%s="%s"\n' "${key}" "${val}" >>"${file}" 2>/dev/null || return 1
            fi
            return 0
        }

        __znh_cfg_tmp_cap_limit() {
            # Lowers KEY only if it is higher than safe_max.
            # Supports values like:
            #   KEY="50"      -> cap to 15
            #   KEY="2-50"    -> cap to 2-15
            local file="$1" key="$2" safe_max="$3"

            # If safe_max is not numeric, do nothing.
            if ! [[ "${safe_max}" =~ ^[0-9]+$ ]]; then
                return 0
            fi

            local cur
            cur=$(__znh_cfg_tmp_get "${file}" "${key}" 2>/dev/null) || return 0

            local min max new_min new_max new_val
            min=""
            max=""

            if [[ "${cur}" =~ ^[0-9]+$ ]]; then
                max="$cur"
            elif [[ "${cur}" =~ ^([0-9]+)-([0-9]+)$ ]]; then
                min="${BASH_REMATCH[1]}"
                max="${BASH_REMATCH[2]}"
            else
                # Unrecognized format -> do not touch.
                return 0
            fi

            if ! [[ "${max}" =~ ^[0-9]+$ ]]; then
                return 0
            fi

            if [ "${max}" -le "${safe_max}" ] 2>/dev/null; then
                return 0
            fi

            new_max="${safe_max}"
            if [ -n "${min}" ]; then
                new_min="${min}"
                if ! [[ "${new_min}" =~ ^[0-9]+$ ]]; then
                    new_min="${new_max}"
                fi
                if [ "${new_min}" -gt "${new_max}" ] 2>/dev/null; then
                    new_min="${new_max}"
                fi
                new_val="${new_min}-${new_max}"
            else
                new_val="${new_max}"
            fi

            log_info "Smart-Opt: Capping ${key} in $(basename "${file}") (${cur} -> ${new_val})"
            echo "  [tuned] ${key}: ${cur} -> ${new_val}"
            __znh_cfg_tmp_set "${file}" "${key}" "${new_val}" || return 1
            return 0
        }

        local configs=()
        local conf cfg_file
        while read -r conf; do
            [ -n "${conf:-}" ] || continue
            configs+=("${conf}")
        done < <(__znh_snapper_list_config_names || true)

        if [ "${#configs[@]}" -eq 0 ] 2>/dev/null; then
            configs=(root)
        fi

        local _action_hint
        case "${action}" in
            enable)  _action_hint="enable" ;;
            disable) _action_hint="disable" ;;
            cleanup) _action_hint="cleanup" ;;
            *)       _action_hint="${action}" ;;
        esac

        echo ""
        echo "[snapper][config] Smart config sync (${_action_hint})"
        if [ "${action}" = "cleanup" ]; then
            echo "  - Detected timers enabled: timeline=${timeline_enabled} boot=${boot_enabled}"
        fi

        for conf in "${configs[@]}"; do
            cfg_file="/etc/snapper/configs/${conf}"
            [ -f "${cfg_file}" ] || continue

            local ts bak mode uid gid tmp
            ts="$(date +%Y%m%d-%H%M%S)"
            bak="${cfg_file}.bak-${ts}"

            mode=$(stat -c %a "${cfg_file}" 2>/dev/null || echo 644)
            uid=$(stat -c %u "${cfg_file}" 2>/dev/null || echo 0)
            gid=$(stat -c %g "${cfg_file}" 2>/dev/null || echo 0)

            tmp="$(mktemp)"

            # Work on a temp copy so we only need ONE backup per config file.
            cat "${cfg_file}" >"${tmp}" 2>/dev/null || {
                rm -f "${tmp}" 2>/dev/null || true
                continue
            }

            if [ "${action}" = "disable" ]; then
                # Don't append missing keys (avoid surprising users).
                if grep -qE '^TIMELINE_CREATE=' "${tmp}" 2>/dev/null; then
                    __znh_cfg_tmp_set "${tmp}" TIMELINE_CREATE "${target_val}" || true
                fi
                if grep -qE '^BOOT_CREATE=' "${tmp}" 2>/dev/null; then
                    __znh_cfg_tmp_set "${tmp}" BOOT_CREATE "${target_val}" || true
                fi
            elif [ "${action}" = "cleanup" ]; then
                # Only force yes when the corresponding timer is enabled.
                if [ "${timeline_enabled}" -eq 1 ] 2>/dev/null; then
                    __znh_cfg_tmp_set "${tmp}" TIMELINE_CREATE "yes" || true
                fi
                if [ "${boot_enabled}" -eq 1 ] 2>/dev/null; then
                    __znh_cfg_tmp_set "${tmp}" BOOT_CREATE "yes" || true
                fi
            else
                # enable (or any other) -> force yes
                __znh_cfg_tmp_set "${tmp}" TIMELINE_CREATE "${target_val}" || true
                __znh_cfg_tmp_set "${tmp}" BOOT_CREATE "${target_val}" || true
            fi

            # Preventative tuning: cap overly aggressive defaults.
            # These are maxima; we never increase values.
            if [ "${action}" != "disable" ] && [ "${SNAP_RETENTION_OPTIMIZER_ENABLED:-true}" = "true" ]; then
                __znh_cfg_tmp_cap_limit "${tmp}" NUMBER_LIMIT "${SNAP_RETENTION_MAX_NUMBER_LIMIT:-15}" || true
                __znh_cfg_tmp_cap_limit "${tmp}" NUMBER_LIMIT_IMPORTANT "${SNAP_RETENTION_MAX_NUMBER_LIMIT_IMPORTANT:-5}" || true

                __znh_cfg_tmp_cap_limit "${tmp}" TIMELINE_LIMIT_HOURLY "${SNAP_RETENTION_MAX_TIMELINE_LIMIT_HOURLY:-10}" || true
                __znh_cfg_tmp_cap_limit "${tmp}" TIMELINE_LIMIT_DAILY "${SNAP_RETENTION_MAX_TIMELINE_LIMIT_DAILY:-7}" || true
                __znh_cfg_tmp_cap_limit "${tmp}" TIMELINE_LIMIT_WEEKLY "${SNAP_RETENTION_MAX_TIMELINE_LIMIT_WEEKLY:-2}" || true
                __znh_cfg_tmp_cap_limit "${tmp}" TIMELINE_LIMIT_MONTHLY "${SNAP_RETENTION_MAX_TIMELINE_LIMIT_MONTHLY:-2}" || true
                __znh_cfg_tmp_cap_limit "${tmp}" TIMELINE_LIMIT_YEARLY "${SNAP_RETENTION_MAX_TIMELINE_LIMIT_YEARLY:-0}" || true
            elif [ "${action}" != "disable" ]; then
                log_info "[snapper][config] Retention optimizer disabled (SNAP_RETENTION_OPTIMIZER_ENABLED=false); skipping retention caps"
            fi

            # Only write if content actually changed.
            if ! cmp -s "${cfg_file}" "${tmp}" 2>/dev/null; then
                log_info "[snapper][config] Updating: ${cfg_file}"
                execute_guarded "Backup snapper config (${cfg_file})" cp -a "${cfg_file}" "${bak}" || true
                mv -f "${tmp}" "${cfg_file}" 2>/dev/null || {
                    rm -f "${tmp}" 2>/dev/null || true
                    continue
                }
                chmod "${mode}" "${cfg_file}" 2>/dev/null || true
                chown "${uid}:${gid}" "${cfg_file}" 2>/dev/null || true

                echo "  [config:${conf}] synced/tuned"
            else
                rm -f "${tmp}" 2>/dev/null || true
            fi
        done

        return 0
    }

    __znh_snapper_list_last_root() {
        local n="${1:-10}"
        if [[ ! "${n}" =~ ^[0-9]+$ ]]; then
            n=10
        fi
        local out rc

        echo ""
        echo "-- Root snapshots (last ${n}) --"

        if command -v timeout >/dev/null 2>&1; then
            out=$(timeout 20 "${SNAPPER_CMD[@]}" -c root list --last "${n}" 2>&1)
            rc=$?
        else
            out=$("${SNAPPER_CMD[@]}" -c root list --last "${n}" 2>&1)
            rc=$?
        fi
        if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q "Unknown option '--last'"; then
            if command -v timeout >/dev/null 2>&1; then
                out=$(timeout 20 "${SNAPPER_CMD[@]}" -c root list 2>&1)
                rc=$?
            else
                out=$("${SNAPPER_CMD[@]}" -c root list 2>&1)
                rc=$?
            fi
            if [ "$rc" -eq 0 ]; then
                # Best-effort tail when --last is unsupported.
                printf '%s\n' "$out" | tail -n $((n + 6))
                return 0
            fi
        fi

        printf '%s\n' "$out"
        return $rc
    }

    __znh_snapper_status() {
        echo ""
        echo "=============================================="
        echo "  Zypper Auto-Helper: Snapper Status"
        echo "=============================================="
        echo "Snapper mode: ${snapper_mode}"

        echo ""
        echo "-- snapper list-configs --"
        if command -v timeout >/dev/null 2>&1; then
            timeout 10 "${SNAPPER_CMD[@]}" list-configs 2>&1 || true
        else
            "${SNAPPER_CMD[@]}" list-configs 2>&1 || true
        fi

        __znh_snapper_list_last_root 1 || true

        echo ""
        echo "-- snapper systemd timers (unit files) --"
        # Show unit-file state if available (enabled/disabled/static).
        systemctl list-unit-files --no-legend 'snapper-*.timer' 2>/dev/null || echo "(no snapper timers found via systemd)"

        echo ""
        echo "Tip: openSUSE typically provides these timers (if installed):"
        echo "  - snapper-timeline.timer (automatic snapshots)"
        echo "  - snapper-cleanup.timer  (automatic cleanup)"
        echo "  - snapper-boot.timer     (boot snapshots)"
    }

    __znh_snapper_create_snapshot() {
        local desc="${1:-}"
        if [ -z "${desc}" ]; then
            read -p "Snapshot description (blank = default): " -r desc
        fi
        desc="${desc:-Zypper Auto-Helper manual snapshot}"

        echo ""
        echo "Creating Snapper snapshot (single): ${desc}"

        local snap_timeout out rc
        snap_timeout="${ZNH_SAFETY_SNAPSHOT_TIMEOUT_SECONDS:-90}"
        if ! [[ "${snap_timeout}" =~ ^[0-9]+$ ]] || [ "${snap_timeout}" -lt 10 ] 2>/dev/null; then
            snap_timeout=90
        fi

        if command -v timeout >/dev/null 2>&1; then
            out=$(timeout "${snap_timeout}" "${SNAPPER_CMD[@]}" -c root create --type single --cleanup-algorithm number --description "${desc}" --print-number 2>&1)
            rc=$?
        else
            out=$("${SNAPPER_CMD[@]}" -c root create --type single --cleanup-algorithm number --description "${desc}" --print-number 2>&1)
            rc=$?
        fi

        printf '%s\n' "$out"
        return "$rc"
    }

    __znh_snapper_cleanup_now() {
        # Usage:
        #   __znh_snapper_cleanup_now            # default: all algorithms
        #   __znh_snapper_cleanup_now all        # same as default
        #   __znh_snapper_cleanup_now number     # single algorithm
        #   __znh_snapper_cleanup_now timeline
        #   __znh_snapper_cleanup_now empty-pre-post
        local mode="${1:-all}"

        # --- Professional Edition: audit report (text + JSON) ---
        local report_enabled report_dir report_format report_max
        report_enabled="${CLEANUP_REPORT_ENABLED:-true}"
        report_dir="${CLEANUP_REPORT_DIR:-/var/log/zypper-auto/cleanup-reports}"
        report_format="${CLEANUP_REPORT_FORMAT:-both}"
        report_max="${CLEANUP_REPORT_MAX_FILES:-30}"

        local __audit_ts __audit_log __audit_json
        __audit_ts="$(date +%Y%m%d-%H%M%S)"
        __audit_log="${report_dir}/cleanup-${__audit_ts}.log"
        __audit_json="${report_dir}/cleanup-${__audit_ts}.json"

        # Dynamic-scope data collectors (visible inside nested helpers)
        local -a __audit_actions=()
        local __audit_status="started"
        local __audit_start_time __audit_end_time
        __audit_start_time="$(date '+%Y-%m-%d %H:%M:%S')"

        __znh_audit_record() {
            # Record key actions in a compact, parseable form.
            local msg="$*"
            __audit_actions+=("${msg}")
            return 0
        }

        __znh_cleanup_report_init() {
            if [ "${report_enabled}" != "true" ]; then
                return 0
            fi

            # Ensure directory exists (best-effort)
            execute_optional "Ensure cleanup report dir exists (${report_dir})" mkdir -p -- "${report_dir}" || true

            # Best-effort retention on older runs
            if [[ "${report_max}" =~ ^[0-9]+$ ]] && [ "${report_max}" -gt 0 ] 2>/dev/null; then
                local -a logs
                mapfile -t logs < <(ls -1t "${report_dir}"/cleanup-*.log 2>/dev/null || true)
                if [ "${#logs[@]}" -gt "${report_max}" ] 2>/dev/null; then
                    local i f
                    for ((i=report_max; i<${#logs[@]}; i++)); do
                        f="${logs[$i]}"
                        rm -f -- "${f}" "${f%.log}.json" 2>/dev/null || true
                    done
                fi
            fi

            # Write header immediately so cancelled runs still leave a trace.
            {
                echo "=============================================="
                echo " SYSTEM CLEANUP AUDIT REPORT"
                echo "=============================================="
                echo "Start time: ${__audit_start_time}"
                echo "Mode: ${mode}"
                echo "Report: ${report_format}"
                echo "=============================================="
                echo ""
            } >>"${__audit_log}" 2>/dev/null || true

            return 0
        }

        __znh_cleanup_report_write_final() {
            # Args: start_kb end_kb freed_kb removed_csv_path removed_count
            local start_kb="$1" end_kb="$2" freed_kb="$3" removed_csv_path="$4" removed_count="$5"

            if [ "${report_enabled}" != "true" ]; then
                return 0
            fi

            __audit_end_time="$(date '+%Y-%m-%d %H:%M:%S')"

            # --- Text report ---
            if [ "${report_format}" = "text" ] || [ "${report_format}" = "both" ]; then
                {
                    echo "=============================================="
                    echo "RESULT SUMMARY"
                    echo "=============================================="
                    if [[ "${start_kb}" =~ ^[0-9]+$ ]]; then
                        echo "Start free: $((start_kb / 1024)) MB"
                    else
                        echo "Start free: (unknown)"
                    fi
                    if [[ "${end_kb}" =~ ^[0-9]+$ ]]; then
                        echo "End free:   $((end_kb / 1024)) MB"
                    else
                        echo "End free:   (unknown)"
                    fi
                    if [[ "${freed_kb}" =~ ^-?[0-9]+$ ]]; then
                        echo "Freed:      $((freed_kb / 1024)) MB"
                    else
                        echo "Freed:      (unknown)"
                    fi
                    echo "Status: ${__audit_status}"
                    echo "End time: ${__audit_end_time:-}"
                    echo ""
                    echo "Removed snapshots: ${removed_count}"
                    if [ -f "${removed_csv_path}" ] && [ "${removed_count}" -gt 0 ] 2>/dev/null; then
                        echo "-- Removed snapshot list (conf, id, type, description) --"
                        awk -F'\t' '{printf("%s\t#%s\t[%s]\t%s\n", $1, $2, $3, $4)}' "${removed_csv_path}" 2>/dev/null || true
                    fi
                    echo ""
                    echo "-- Actions taken --"
                    local a
                    for a in "${__audit_actions[@]}"; do
                        printf '  - %s\n' "${a}"
                    done
                    echo ""
                } >>"${__audit_log}" 2>/dev/null || true
            fi

            # --- JSON report ---
            if [ "${report_format}" = "json" ] || [ "${report_format}" = "both" ]; then
                {
                    echo "{" 
                    echo "  \"start_time\": \"$(_json_escape "${__audit_start_time}")\","
                    echo "  \"end_time\": \"$(_json_escape "${__audit_end_time}")\","
                    echo "  \"mode\": \"$(_json_escape "${mode}")\","
                    echo "  \"status\": \"$(_json_escape "${__audit_status}")\","
                    echo "  \"space_kb\": {\"start\": ${start_kb:-0}, \"end\": ${end_kb:-0}, \"freed\": ${freed_kb:-0}},"
                    echo "  \"removed_snapshots_count\": ${removed_count:-0},"
                    echo "  \"removed_snapshots\": ["

                    if [ -f "${removed_csv_path}" ] && [ "${removed_count}" -gt 0 ] 2>/dev/null; then
                        awk -F'\t' '
                            BEGIN{first=1}
                            {
                                conf=$1; id=$2; type=$3; desc=$4;
                                gsub(/\\/,"\\\\",conf); gsub(/\"/,"\\\"",conf);
                                gsub(/\\/,"\\\\",type); gsub(/\"/,"\\\"",type);
                                gsub(/\\/,"\\\\",desc); gsub(/\"/,"\\\"",desc);
                                if (!first) printf(",\n");
                                first=0;
                                printf("    {\"config\": \"%s\", \"id\": %s, \"type\": \"%s\", \"description\": \"%s\"}", conf, id, type, desc);
                            }
                            END{ if(!first) printf("\n"); }
                        ' "${removed_csv_path}" 2>/dev/null || true
                    fi

                    echo "  ],"
                    echo "  \"actions\": ["

                    local i
                    for ((i=0; i<${#__audit_actions[@]}; i++)); do
                        local esc
                        esc="$(_json_escape "${__audit_actions[$i]}")"
                        if [ "$i" -gt 0 ] 2>/dev/null; then
                            echo ","
                        fi
                        printf '    "%s"' "${esc}"
                    done
                    echo ""
                    echo "  ]"
                    echo "}"
                } >"${__audit_json}" 2>/dev/null || true
            fi

            echo ""
            echo "Audit report saved to: ${__audit_log}"
            if [ "${report_format}" = "json" ] || [ "${report_format}" = "both" ]; then
                echo "Audit JSON saved to:   ${__audit_json}"
            fi

            # Best-effort cleanup (removed snapshot list temp file)
            rm -f -- "${removed_csv_path}" 2>/dev/null || true

            return 0
        }

        __znh_cleanup_report_init || true

        echo ""
        echo "=============================================="
        echo " Smart Snapper Cleanup"
        echo "=============================================="

        echo "About to run Snapper cleanup (best-effort)."
        echo "This uses your Snapper retention rules (and any caps you configured in /etc/zypper-auto.conf)."
        echo "Algorithms:"
        echo "  1) empty-pre-post (orphaned pre snapshots)"
        echo "  2) timeline       (expired hourly/daily snapshots)"
        echo "  3) number         (enforce numeric limits)"
        echo ""
        echo "Optional extras (if enabled in /etc/zypper-auto.conf):"
        echo "  - Flatpak unused runtimes prune"
        echo "  - Snap revision retention tuning (refresh.retain)"
        echo "  - Coredump vacuum (crash dumps)"
        echo "  - Journal vacuum, zypper cache clean, thumbnails cleanup"
        echo "  - Kernel package purge + boot entry pruning"
        echo ""

        if [ "${mode}" = "all" ]; then
            echo "Mode: ALL algorithms (empty-pre-post -> timeline -> number)"
        else
            echo "Mode: single algorithm '${mode}'"
        fi

        # Priority order (safest first): empty-pre-post -> timeline -> number
        local algs=(empty-pre-post timeline number)
        if [ "${mode}" != "all" ]; then
            algs=("${mode}")
        fi

        # Prefer to run cleanup for every configured snapper config (root/home/etc.).
        local configs=()
        local cfg
        while read -r cfg; do
            [ -n "${cfg}" ] || continue
            configs+=("${cfg}")
        done < <(__znh_snapper_list_config_names || true)

        if [ "${#configs[@]}" -eq 0 ] 2>/dev/null; then
            configs=(root)
        fi

        # Snapshot inventory: show BEFORE/AFTER + removed IDs (best-effort).
        # Uses snapper's CSV output for robust parsing.
        local __snap_sep
        __snap_sep=$'\t'
        local before_csv after_csv removed_csv removed_csv_report
        before_csv="$(mktemp)"
        after_csv="$(mktemp)"
        removed_csv="$(mktemp)"
        removed_csv_report=""

        # Safety: clean up temp files when we exit early.
        __znh_cleanup_snapshot_tmpfiles() {
            rm -f "${before_csv}" "${after_csv}" "${removed_csv}" 2>/dev/null || true
        }

        # --- SAFETY 2: Critical free space check ---
        # Deleting btrfs snapshots can require metadata headroom.
        local free_kb critical_kb critical_mb
        local critical_low=0
        free_kb=$(df -Pk / 2>/dev/null | awk 'NR==2 {print $4}' | tr -dc '0-9')
        critical_mb="${SNAP_CLEANUP_CRITICAL_FREE_MB:-300}"
        if ! [[ "${critical_mb}" =~ ^[0-9]+$ ]]; then
            critical_mb=300
        fi
        critical_kb=$((critical_mb * 1024))

        if [[ "${free_kb:-}" =~ ^[0-9]+$ ]] && [ "${free_kb}" -lt "${critical_kb}" ] 2>/dev/null; then
            critical_low=1
            echo "CRITICAL WARNING: Disk is extremely full (<${critical_mb}MB free)."
            echo "Deleting btrfs snapshots may require free space for metadata and can hang the system."
        fi

        __znh_snapper_dump_snapshot_csv() {
            local out rc conf line
            : >"$1"

            for conf in "${configs[@]}"; do
                out=""
                rc=0
                if command -v timeout >/dev/null 2>&1; then
                    out=$(timeout 25 "${SNAPPER_CMD[@]}" --csvout --separator "${__snap_sep}" --no-headers -c "${conf}" list --columns number,type,description 2>/dev/null)
                    rc=$?
                else
                    out=$("${SNAPPER_CMD[@]}" --csvout --separator "${__snap_sep}" --no-headers -c "${conf}" list --columns number,type,description 2>/dev/null)
                    rc=$?
                fi

                if [ "${rc}" -ne 0 ] 2>/dev/null || [ -z "${out:-}" ]; then
                    continue
                fi

                # Format:
                #   conf<TAB>id<TAB>type<TAB>description
                while IFS=$'\t' read -r n t d_rest; do
                    [ -n "${n:-}" ] || continue
                    if [[ "${n}" =~ ^[0-9]+$ ]]; then
                        printf '%s\t%s\t%s\t%s\n' "${conf}" "${n}" "${t:-}" "${d_rest:-}" >>"$1"
                    fi
                done <<<"${out}"
            done

            return 0
        }

        __znh_snapper_preview_candidates() {
            # Best-effort preview of what may be removed/kept.
            # NOTE: Snapper has no reliable dry-run for cleanup algorithms.
            local rx
            rx="${SNAP_BROKEN_SNAPSHOT_HUNTER_REGEX:-aborted|failed}"
            if [ -z "${rx}" ]; then
                rx="aborted|failed"
            fi

            echo ""
            if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                printf "%b%s%b\n" "${C_CYAN}" "Removal Preview (best-effort)" "${C_RESET}"
            else
                echo "Removal Preview (best-effort)"
            fi
            echo "NOTE: Snapper cleanup has no true dry-run; the final removed list will be shown AFTER cleanup."

            __znh_get_number_limit_max() {
                local conf="$1" cfg_file val
                cfg_file="/etc/snapper/configs/${conf}"
                [ -f "${cfg_file}" ] || return 1
                val=$(grep -E '^NUMBER_LIMIT=' "${cfg_file}" 2>/dev/null | head -n 1 | cut -d= -f2- | tr -d '"' | tr -d '\r' | tr -d ' ')
                [ -n "${val:-}" ] || return 1
                if [[ "${val}" =~ ^[0-9]+$ ]]; then
                    printf '%s\n' "${val}"
                    return 0
                fi
                if [[ "${val}" =~ ^([0-9]+)-([0-9]+)$ ]]; then
                    printf '%s\n' "${BASH_REMATCH[2]}"
                    return 0
                fi
                return 1
            }

            local conf out
            for conf in "${configs[@]}"; do
                echo ""
                echo "-- Preview for config: ${conf} --"

                out=""
                if command -v timeout >/dev/null 2>&1; then
                    out=$(timeout 25 "${SNAPPER_CMD[@]}" --csvout --separator "${__snap_sep}" --no-headers -c "${conf}" list --columns number,type,pre-number,cleanup,date,description 2>/dev/null || true)
                else
                    out=$("${SNAPPER_CMD[@]}" --csvout --separator "${__snap_sep}" --no-headers -c "${conf}" list --columns number,type,pre-number,cleanup,date,description 2>/dev/null || true)
                fi

                if [ -z "${out:-}" ]; then
                    echo "  (could not read snapshot list)"
                    continue
                fi

                # 1) Orphan pre snapshots (empty-pre-post candidates)
                local orphan
                orphan=$(printf '%s\n' "${out}" | awk -F'\t' '
                    $2=="post" && $3 ~ /^[0-9]+$/ {ref[$3]=1}
                    $2=="pre" && $1 ~ /^[0-9]+$/ {pre[$1]=1}
                    END {for (p in pre) if (!(p in ref)) print p}
                ' | sort -n | tr '\n' ' ' | sed 's/[[:space:]]*$//')

                if [ -n "${orphan:-}" ]; then
                    if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                        printf "  %b[CANDIDATE empty-pre-post]%b orphan pre snapshot IDs: %b%s%b\n" "${C_YELLOW}" "${C_RESET}" "${C_RED}" "${orphan}" "${C_RESET}"
                    else
                        echo "  [CANDIDATE empty-pre-post] orphan pre snapshot IDs: ${orphan}"
                    fi
                else
                    echo "  [empty-pre-post] no obvious orphan pre snapshots detected."
                fi

                # 2) Broken snapshot hunter candidates (regex match)
                local broken
                broken=$(printf '%s\n' "${out}" | awk -F'\t' -v rx="${rx}" '
                    BEGIN{IGNORECASE=1}
                    ($2=="single" || $2=="pre") && $6 ~ rx && $1 ~ /^[0-9]+$/ && $1 != "0" {print $1}
                ' | sort -n | tr '\n' ' ' | sed 's/[[:space:]]*$//')

                if [ -n "${broken:-}" ]; then
                    if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                        printf "  %b[CANDIDATE deep-clean]%b regex '%s' matched snapshot IDs: %b%s%b\n" "${C_YELLOW}" "${C_RESET}" "${rx}" "${C_RED}" "${broken}" "${C_RESET}"
                    else
                        echo "  [CANDIDATE deep-clean] regex '${rx}' matched snapshot IDs: ${broken}"
                    fi
                else
                    echo "  [deep-clean] no obvious aborted/failed snapshots detected by regex."
                fi

                # 3) Number cleanup candidates (very rough)
                local limit
                limit=$(__znh_get_number_limit_max "${conf}" 2>/dev/null || true)
                if [[ "${limit:-}" =~ ^[0-9]+$ ]] && [ "${limit}" -gt 0 ] 2>/dev/null; then
                    local num_lines num_count remove_n
                    num_lines=$(printf '%s\n' "${out}" | awk -F'\t' '$4=="number" && $1 ~ /^[0-9]+$/ && $1 != "0" {print $1"\t"$2"\t"$5"\t"$6}' | sort -t $'\t' -k1,1n)
                    num_count=$(printf '%s\n' "${num_lines}" | awk 'NF{n++} END{print n+0}')
                    if [ "${num_count}" -gt "${limit}" ] 2>/dev/null; then
                        remove_n=$((num_count - limit))
                        if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                            printf "  %b[number]%b snapshots with cleanup=number: %s (limit max=%s)\n" "${C_CYAN}" "${C_RESET}" "${num_count}" "${limit}"
                            printf "    %b[CANDIDATE number]%b oldest %s snapshot(s) may be removed:\n" "${C_YELLOW}" "${C_RESET}" "${remove_n}"
                        else
                            echo "  [number] snapshots with cleanup=number: ${num_count} (limit max=${limit})"
                            echo "    [CANDIDATE number] oldest ${remove_n} snapshot(s) may be removed:"
                        fi

                        printf '%s\n' "${num_lines}" | head -n "${remove_n}" | head -n 20 | while IFS=$'\t' read -r n t dt d; do
                            if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                                printf "      %b[REMOVE?]%b #%s [%s] %s %s\n" "${C_RED}" "${C_RESET}" "${n}" "${t}" "${dt}" "${d}"
                            else
                                printf "      [REMOVE?] #%s [%s] %s %s\n" "${n}" "${t}" "${dt}" "${d}"
                            fi
                        done

                        if [ "${num_count}" -gt $((limit + 20)) ] 2>/dev/null; then
                            echo "      ... (truncated preview)"
                        fi
                    else
                        echo "  [number] cleanup=number snapshots (${num_count}) are within NUMBER_LIMIT max (${limit})."
                    fi
                else
                    echo "  [number] could not read NUMBER_LIMIT for config ${conf}; skipping number preview."
                fi

                # Timeline cleanup preview (informational)
                local tl_count
                tl_count=$(printf '%s\n' "${out}" | awk -F'\t' '$4=="timeline" && $1 ~ /^[0-9]+$/ && $1 != "0" {n++} END{print n+0}')
                echo "  [timeline] snapshots with cleanup=timeline: ${tl_count} (Snapper will prune per TIMELINE_LIMIT_* rules)."
            done

            return 0
        }

        __znh_print_snapper_snapshot_list() {
            # Usage: __znh_print_snapper_snapshot_list <title> <csv_file> [label] [label_color]
            # Shows up to the last 20 snapshots per config.
            local title="$1" csv_file="$2" label="${3:-}" label_color="${4:-}"
            local limit_per_cfg=20

            echo ""
            if [ -n "${title}" ]; then
                if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                    printf "%b%s%b\n" "${C_CYAN}" "${title}" "${C_RESET}"
                else
                    echo "${title}"
                fi
            fi

            local conf
            for conf in "${configs[@]}"; do
                local total
                total=$(awk -F'\t' -v c="${conf}" '$1==c {n++} END{print n+0}' "${csv_file}" 2>/dev/null)

                echo "- Config: ${conf} (snapshots: ${total})"

                # Print last N snapshots by number
                awk -F'\t' -v c="${conf}" '$1==c {print $0}' "${csv_file}" 2>/dev/null \
                    | sort -t $'\t' -k2,2n \
                    | tail -n "${limit_per_cfg}" \
                    | while IFS=$'\t' read -r _c _n _t _d; do
                        if [ -n "${label}" ]; then
                            if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null && [ -n "${label_color}" ]; then
                                printf '    %b[%s]%b #%s [%s] %s\n' "${label_color}" "${label}" "${C_RESET}" "${_n}" "${_t}" "${_d}"
                            else
                                printf '    [%s] #%s [%s] %s\n' "${label}" "${_n}" "${_t}" "${_d}"
                            fi
                        else
                            printf '    #%s [%s] %s\n' "${_n}" "${_t}" "${_d}"
                        fi
                    done
            done

            return 0
        }

        # Capture BEFORE snapshot state
        __znh_snapper_dump_snapshot_csv "${before_csv}" || true
        __znh_print_snapper_snapshot_list "Snapshots BEFORE cleanup (showing last 20 per config)" "${before_csv}" "BEFORE" "${C_CYAN}" || true

        __znh_snapper_preview_candidates || true

        # --- SAFETY 1: Concurrency guard ---
        # Avoid fighting an already-running timer/service/process.
        local cleanup_busy=0
        if [ "${SNAP_CLEANUP_CONCURRENCY_GUARD_ENABLED:-true}" = "true" ]; then
            if systemctl is-active --quiet snapper-cleanup.service 2>/dev/null; then
                cleanup_busy=1
            elif pgrep -a -f 'snapper[[:space:]].*cleanup' >/dev/null 2>&1; then
                cleanup_busy=1
            elif pgrep -x snapper >/dev/null 2>&1; then
                # Broader guard: snapper running at all (could be timeline or manual)
                cleanup_busy=1
            fi

            if [ "${cleanup_busy}" -eq 1 ] 2>/dev/null; then
                echo "WARNING: Snapper appears to be busy (background cleanup/timer or another snapper command)."
                __znh_audit_record "snapper:busy-detected"
                if [ -t 0 ]; then
                    read -p "Force another cleanup run anyway? [y/N]: " -r ans_busy
                    if [[ ! "${ans_busy:-}" =~ ^[Yy]$ ]]; then
                        echo "Cleanup cancelled (snapper busy)."
                        __audit_status="cancelled"
                        __znh_audit_record "cleanup:cancelled:snapper-busy"
                        __znh_cleanup_snapshot_tmpfiles
                        __znh_cleanup_report_write_final "${free_kb:-}" "${free_kb:-}" 0 "${removed_csv}" 0 || true
                        return 0
                    fi
                    __znh_audit_record "snapper:busy-override:true"
                else
                    log_warn "[snapper][cleanup] Refusing to run cleanup without a TTY while snapper appears busy"
                    __audit_status="refused"
                    __znh_audit_record "cleanup:refused:no-tty:snapper-busy"
                    __znh_cleanup_snapshot_tmpfiles
                    __znh_cleanup_report_write_final "${free_kb:-}" "${free_kb:-}" 0 "${removed_csv}" 0 || true
                    return 1
                fi
            fi
        fi

        # If critically low, ask once more before proceeding.
        if [ "${critical_low}" -eq 1 ] 2>/dev/null; then
            __znh_audit_record "disk:critical-low"
            if [ -t 0 ]; then
                read -p "Are you ABSOLUTELY sure you want to continue? [y/N]: " -r ans_full
                if [[ ! "${ans_full:-}" =~ ^[Yy]$ ]]; then
                    echo "Cleanup cancelled (low disk space)."
                    __audit_status="cancelled"
                    __znh_audit_record "cleanup:cancelled:critical-low"
                    __znh_cleanup_snapshot_tmpfiles
                    __znh_cleanup_report_write_final "${free_kb:-}" "${free_kb:-}" 0 "${removed_csv}" 0 || true
                    return 1
                fi
                __znh_audit_record "critical-low-override:true"
            else
                log_warn "[snapper][cleanup] Refusing to run cleanup without a TTY while free space is critically low"
                __audit_status="refused"
                __znh_audit_record "cleanup:refused:no-tty:critical-low"
                __znh_cleanup_snapshot_tmpfiles
                __znh_cleanup_report_write_final "${free_kb:-}" "${free_kb:-}" 0 "${removed_csv}" 0 || true
                return 1
            fi
        fi

        echo ""
        read -p "Proceed with cleanup now? [y/N]: " -r ans
        if [[ ! "${ans:-}" =~ ^[Yy]$ ]]; then
            echo "Cleanup cancelled."
            __audit_status="cancelled"
            __znh_audit_record "cleanup:cancelled:user"
            __znh_cleanup_snapshot_tmpfiles
            __znh_cleanup_report_write_final "${free_kb:-}" "${free_kb:-}" 0 "${removed_csv}" 0 || true
            return 0
        fi
        __znh_audit_record "cleanup:confirmed:true"

        # Smart pre-step: keep snapper configs sane (same spirit as option 5).
        # We only do this when a TTY is available.
        if [ -t 0 ]; then
            __znh_snapper_optimize_configs cleanup || true
        else
            log_info "[snapper][cleanup] No TTY; skipping snapper config self-heal"
        fi

        # --- SMART: Space tracking start ---
        echo ""
        echo "Analyzing disk usage before cleanup..."
        local start_space end_space freed_kb
        start_space=$(df -Pk / 2>/dev/null | awk 'NR==2 {print $4}' | tr -dc '0-9')
        __znh_audit_record "space:start_kb=${start_space:-unknown}"

        local conf alg
        for conf in "${configs[@]}"; do
            echo ""
            echo "== Snapper config: ${conf} =="

            local step=0
            for alg in "${algs[@]}"; do
                step=$((step + 1))
                case "${alg}" in
                    empty-pre-post|timeline|number)
                        :
                        ;;
                    *)
                        echo "Skipping unknown cleanup algorithm: ${alg}"
                        continue
                        ;;
                esac

                case "${alg}" in
                    empty-pre-post)
                        echo "${step}. Scanning for orphaned/broken snapshots (empty-pre-post)..."
                        ;;
                    timeline)
                        echo "${step}. Cleaning expired timeline snapshots (timeline)..."
                        ;;
                    number)
                        echo "${step}. Enforcing snapshot limits (number)..."
                        ;;
                esac

                __znh_audit_record "snapper:cleanup:${conf}:${alg}:start"
                if command -v timeout >/dev/null 2>&1; then
                    execute_guarded "Snapper cleanup (${conf}): ${alg}" \
                        timeout 180 "${SNAPPER_CMD[@]}" -c "${conf}" cleanup "${alg}" || true
                else
                    execute_guarded "Snapper cleanup (${conf}): ${alg}" \
                        "${SNAPPER_CMD[@]}" -c "${conf}" cleanup "${alg}" || true
                fi
                __znh_audit_record "snapper:cleanup:${conf}:${alg}:done"
            done
        done

        # Optional Deep Clean: hunt for obviously aborted/failed snapshots that may
        # not be removed by standard algorithms (best-effort emergency recovery).
        __znh_snapper_broken_snapshot_hunter() {
            # Run if enabled OR if disk is in critical-low mode.
            if [ "${SNAP_BROKEN_SNAPSHOT_HUNTER_ENABLED:-false}" != "true" ] && [ "${critical_low:-0}" -ne 1 ] 2>/dev/null; then
                return 0
            fi

            if [ ! -t 0 ] && [ "${SNAP_BROKEN_SNAPSHOT_HUNTER_CONFIRM:-true}" = "true" ]; then
                log_warn "[snapper][deep-clean] No TTY; skipping broken snapshot hunter while confirmation is required"
                return 0
            fi

            local rx
            rx="${SNAP_BROKEN_SNAPSHOT_HUNTER_REGEX:-aborted|failed}"
            if [ -z "${rx}" ]; then
                rx="aborted|failed"
            fi

            echo ""
            echo "== Deep Clean (broken snapshot hunter) =="
            echo "This will scan snapshot descriptions for keywords (regex): ${rx}"
            echo "It will only consider snapshot types: single / pre"

            if [ "${SNAP_BROKEN_SNAPSHOT_HUNTER_CONFIRM:-true}" = "true" ] && [ -t 0 ]; then
                local ans_dc
                if [ "${critical_low:-0}" -eq 1 ] 2>/dev/null; then
                    read -p "Disk is critical-low. Run Deep Clean snapshot hunter now? [Y/n]: " -r ans_dc
                    if [[ "${ans_dc:-y}" =~ ^[Nn]$ ]]; then
                        echo "Skipping Deep Clean."
                        return 0
                    fi
                else
                    read -p "Run Deep Clean snapshot hunter now? [y/N]: " -r ans_dc
                    if [[ ! "${ans_dc:-}" =~ ^[Yy]$ ]]; then
                        echo "Skipping Deep Clean."
                        return 0
                    fi
                fi
            fi

            local any_found=0
            local conf out ids
            for conf in "${configs[@]}"; do
                out=""
                if command -v timeout >/dev/null 2>&1; then
                    out=$(timeout 25 "${SNAPPER_CMD[@]}" --csvout --separator "${__snap_sep}" --no-headers -c "${conf}" list --columns number,type,description 2>/dev/null || true)
                else
                    out=$("${SNAPPER_CMD[@]}" --csvout --separator "${__snap_sep}" --no-headers -c "${conf}" list --columns number,type,description 2>/dev/null || true)
                fi

                if [ -z "${out:-}" ]; then
                    continue
                fi

                ids=$(printf '%s\n' "${out}" \
                    | awk -F'\t' -v rx="${rx}" '
                        BEGIN {IGNORECASE=1}
                        {
                            n=$1; t=$2; d=$3;
                            gsub(/^[[:space:]]+|[[:space:]]+$/, "", n);
                            gsub(/^[[:space:]]+|[[:space:]]+$/, "", t);
                            gsub(/^[[:space:]]+|[[:space:]]+$/, "", d);
                            if (n ~ /^[0-9]+$/ && n != "0" && (t=="single" || t=="pre") && d ~ rx) {
                                print n
                            }
                        }
                    ' | sort -uV | tr '\n' ' ' | sed 's/[[:space:]]*$//')

                if [ -n "${ids:-}" ]; then
                    any_found=1
                    if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                        printf "%b[deep-clean]%b %s: found potential junk snapshot IDs: %b%s%b\n" "${C_YELLOW}" "${C_RESET}" "${conf}" "${C_RED}" "${ids}" "${C_RESET}"
                    else
                        echo "[deep-clean] ${conf}: found potential junk snapshot IDs: ${ids}"
                    fi
                    # shellcheck disable=SC2086
                    # We intentionally expand ${ids} into multiple snapshot-number arguments.
                    if command -v timeout >/dev/null 2>&1; then
                        execute_guarded "Delete suspected junk snapshots (${conf})" timeout 300 "${SNAPPER_CMD[@]}" -c "${conf}" delete ${ids} || true
                    else
                        execute_guarded "Delete suspected junk snapshots (${conf})" "${SNAPPER_CMD[@]}" -c "${conf}" delete ${ids} || true
                    fi
                fi
            done

            if [ "${any_found}" -eq 0 ] 2>/dev/null; then
                echo "[deep-clean] No obvious broken snapshots found."
            fi

            return 0
        }

        __znh_snapper_broken_snapshot_hunter || true

        # Optional: deep scrub system caches & logs (beyond snapper).
        __znh_system_deep_scrub() {
            local ran_any=0

            __znh_du_sh() {
                local p="$1"
                du -sh -- "$p" 2>/dev/null | awk '{print $1}'
            }

            __znh_print_stage() {
                local title="$1"
                echo ""
                if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                    printf "%b%s%b\n" "${C_CYAN}" "${title}" "${C_RESET}"
                else
                    echo "${title}"
                fi
            }

            # 0) Flatpak unused runtimes cleanup (space saver)
            if [ "${FLATPAK_UNUSED_CLEAN_ENABLED:-false}" = "true" ] && command -v flatpak >/dev/null 2>&1; then
                ran_any=1
                __znh_print_stage "== System Deep Scrub: Flatpak unused runtimes =="

                local do_fp=0
                if [ "${FLATPAK_UNUSED_CLEAN_CONFIRM:-true}" = "true" ]; then
                    if [ -t 0 ]; then
                        local ans_fp
                        read -p "Prune unused Flatpak runtimes now? (flatpak uninstall --unused) [y/N]: " -r ans_fp
                        if [[ "${ans_fp:-}" =~ ^[Yy]$ ]]; then
                            do_fp=1
                        else
                            echo "Skipping Flatpak prune."
                        fi
                    else
                        log_warn "[deep-scrub] Refusing Flatpak prune without a TTY while FLATPAK_UNUSED_CLEAN_CONFIRM=true"
                    fi
                else
                    do_fp=1
                fi

                if [ "${do_fp}" -eq 1 ] 2>/dev/null; then
                    # Prune system installation (root)
                    execute_guarded "Flatpak prune (unused) [system]" flatpak uninstall --unused --noninteractive --system || true

                    # Prune user installation (SUDO_USER) when available
                    if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
                        execute_optional "Flatpak prune (unused) [user:${SUDO_USER}]" \
                            sudo -u "${SUDO_USER}" flatpak uninstall --unused --noninteractive --user || true
                    fi
                fi
            fi

            # 0.5) Snap revision retention tuning (space saver)
            if [ "${SNAP_REFRESH_RETAIN_TUNE_ENABLED:-false}" = "true" ] && command -v snap >/dev/null 2>&1; then
                ran_any=1
                __znh_print_stage "== System Deep Scrub: Snap revision retention =="

                local retain
                retain="${SNAP_REFRESH_RETAIN_VALUE:-2}"
                if ! [[ "${retain}" =~ ^[0-9]+$ ]] || [ "${retain}" -lt 2 ] 2>/dev/null; then
                    retain=2
                fi

                local cur_retain
                cur_retain=$(snap get system refresh.retain 2>/dev/null | tr -d '\r' | head -n 1 || true)
                echo "Current snap refresh.retain: ${cur_retain:-unknown}"
                echo "Target snap refresh.retain: ${retain}"

                local do_sr=0
                if [ "${SNAP_REFRESH_RETAIN_TUNE_CONFIRM:-true}" = "true" ]; then
                    if [ -t 0 ]; then
                        local ans_sr
                        read -p "Apply snap refresh.retain=${retain} now? [y/N]: " -r ans_sr
                        if [[ "${ans_sr:-}" =~ ^[Yy]$ ]]; then
                            do_sr=1
                        else
                            echo "Skipping snap retention tuning."
                        fi
                    else
                        log_warn "[deep-scrub] Refusing snap retention tuning without a TTY while SNAP_REFRESH_RETAIN_TUNE_CONFIRM=true"
                    fi
                else
                    do_sr=1
                fi

                if [ "${do_sr}" -eq 1 ] 2>/dev/null; then
                    execute_guarded "Tune snap refresh retention" snap set system "refresh.retain=${retain}" || true
                fi
            fi

            # 0.75) Coredump vacuum (crash dumps)
            if [ "${COREDUMP_VACUUM_ENABLED:-false}" = "true" ] && command -v coredumpctl >/dev/null 2>&1; then
                ran_any=1
                __znh_print_stage "== System Deep Scrub: coredumps (crash dumps) =="

                local before_cd after_cd max_mb
                before_cd=$(coredumpctl --disk-usage 2>/dev/null | tr -d '\r' || true)
                max_mb="${COREDUMP_VACUUM_MAX_SIZE_MB:-200}"
                if ! [[ "${max_mb}" =~ ^[0-9]+$ ]] || [ "${max_mb}" -lt 0 ] 2>/dev/null; then
                    max_mb=200
                fi

                if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                    printf "%b[BEFORE]%b %s\n" "${C_YELLOW}" "${C_RESET}" "${before_cd:-coredumpctl --disk-usage unavailable}"
                else
                    echo "[BEFORE] ${before_cd:-coredumpctl --disk-usage unavailable}"
                fi

                local do_cd=0
                if [ "${COREDUMP_VACUUM_CONFIRM:-true}" = "true" ]; then
                    if [ -t 0 ]; then
                        local ans_cd
                        read -p "Vacuum coredumps to keep under ${max_mb}MB? [y/N]: " -r ans_cd
                        if [[ "${ans_cd:-}" =~ ^[Yy]$ ]]; then
                            do_cd=1
                        else
                            echo "Skipping coredump vacuum."
                        fi
                    else
                        log_warn "[deep-scrub] Refusing coredump vacuum without a TTY while COREDUMP_VACUUM_CONFIRM=true"
                    fi
                else
                    do_cd=1
                fi

                if [ "${do_cd}" -eq 1 ] 2>/dev/null; then
                    execute_guarded "Coredump vacuum" coredumpctl --vacuum-size="${max_mb}M" || true
                fi

                after_cd=$(coredumpctl --disk-usage 2>/dev/null | tr -d '\r' || true)
                if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                    printf "%b[AFTER]%b  %s\n" "${C_GREEN}" "${C_RESET}" "${after_cd:-coredumpctl --disk-usage unavailable}"
                else
                    echo "[AFTER] ${after_cd:-coredumpctl --disk-usage unavailable}"
                fi
            fi

            # 1) Zypper cache cleanup
            if [ "${ZYPPER_CACHE_CLEAN_ENABLED:-false}" = "true" ] && command -v zypper >/dev/null 2>&1; then
                ran_any=1
                __znh_print_stage "== System Deep Scrub: Zypper cache =="

                local zypp_dir zypp_before zypp_after
                zypp_dir="/var/cache/zypp"
                zypp_before=""
                zypp_after=""
                if [ -d "${zypp_dir}" ]; then
                    zypp_before="$(__znh_du_sh "${zypp_dir}")"
                fi

                if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                    printf "%b[BEFORE]%b %s size: %s\n" "${C_YELLOW}" "${C_RESET}" "${zypp_dir}" "${zypp_before:-unknown}"
                else
                    echo "[BEFORE] ${zypp_dir} size: ${zypp_before:-unknown}"
                fi

                if [ "${ZYPPER_CACHE_CLEAN_CONFIRM:-true}" = "true" ]; then
                    if [ -t 0 ]; then
                        local ans_zc
                        if [ "${critical_low:-0}" -eq 1 ] 2>/dev/null; then
                            read -p "Disk is critical-low. Run 'zypper clean --all' now? [Y/n]: " -r ans_zc
                            if [[ "${ans_zc:-y}" =~ ^[Nn]$ ]]; then
                                echo "Skipping zypper cache clean."
                            else
                                execute_guarded "Zypper cache clean" zypper clean --all || true
                            fi
                        else
                            read -p "Also run 'zypper clean --all' (clears cached RPMs/metadata)? [y/N]: " -r ans_zc
                            if [[ "${ans_zc:-}" =~ ^[Yy]$ ]]; then
                                execute_guarded "Zypper cache clean" zypper clean --all || true
                            else
                                echo "Skipping zypper cache clean."
                            fi
                        fi
                    else
                        log_warn "[deep-scrub] Refusing zypper cache clean without a TTY while ZYPPER_CACHE_CLEAN_CONFIRM=true"
                    fi
                else
                    execute_guarded "Zypper cache clean" zypper clean --all || true
                fi

                if [ -d "${zypp_dir}" ]; then
                    zypp_after="$(__znh_du_sh "${zypp_dir}")"
                fi

                if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                    printf "%b[AFTER]%b  %s size: %s\n" "${C_GREEN}" "${C_RESET}" "${zypp_dir}" "${zypp_after:-unknown}"
                else
                    echo "[AFTER] ${zypp_dir} size: ${zypp_after:-unknown}"
                fi
            fi

            # 2) Journald vacuum
            if [ "${JOURNAL_VACUUM_ENABLED:-false}" = "true" ] && command -v journalctl >/dev/null 2>&1; then
                ran_any=1
                __znh_print_stage "== System Deep Scrub: systemd journal =="

                local before_usage after_usage days size_mb
                before_usage=$(journalctl --disk-usage 2>/dev/null | tr -d '\r' || true)
                days="${JOURNAL_VACUUM_DAYS:-7}"
                size_mb="${JOURNAL_VACUUM_SIZE_MB:-0}"
                if ! [[ "${days}" =~ ^[0-9]+$ ]] || [ "${days}" -lt 1 ] 2>/dev/null; then
                    days=7
                fi
                if ! [[ "${size_mb}" =~ ^[0-9]+$ ]] || [ "${size_mb}" -lt 0 ] 2>/dev/null; then
                    size_mb=0
                fi

                if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                    printf "%b[BEFORE]%b %s\n" "${C_YELLOW}" "${C_RESET}" "${before_usage:-journalctl --disk-usage unavailable}"
                else
                    echo "[BEFORE] ${before_usage:-journalctl --disk-usage unavailable}"
                fi

                __znh_run_journal_vacuum() {
                    if [ "${size_mb}" -gt 0 ] 2>/dev/null; then
                        execute_guarded "Journal vacuum" journalctl --vacuum-size="${size_mb}M" || true
                    else
                        execute_guarded "Journal vacuum" journalctl --vacuum-time="${days}d" || true
                    fi
                }

                if [ "${JOURNAL_VACUUM_CONFIRM:-true}" = "true" ]; then
                    if [ -t 0 ]; then
                        local ans_jv
                        if [ "${size_mb}" -gt 0 ] 2>/dev/null; then
                            read -p "Also vacuum systemd journal (keep under ${size_mb}M)? [y/N]: " -r ans_jv
                        else
                            if [ "${critical_low:-0}" -eq 1 ] 2>/dev/null; then
                                read -p "Disk is critical-low. Vacuum journals to keep last ${days}d? [Y/n]: " -r ans_jv
                                if [[ "${ans_jv:-y}" =~ ^[Nn]$ ]]; then
                                    echo "Skipping journal vacuum."
                                    ans_jv=""
                                fi
                            else
                                read -p "Also vacuum systemd journal (keep last ${days}d)? [y/N]: " -r ans_jv
                            fi
                        fi

                        if [ -n "${ans_jv:-}" ] && [[ "${ans_jv:-}" =~ ^[Yy]$ ]]; then
                            __znh_run_journal_vacuum
                        elif [ "${size_mb}" -gt 0 ] 2>/dev/null && [[ ! "${ans_jv:-}" =~ ^[Yy]$ ]]; then
                            echo "Skipping journal vacuum."
                        fi
                    else
                        log_warn "[deep-scrub] Refusing journal vacuum without a TTY while JOURNAL_VACUUM_CONFIRM=true"
                    fi
                else
                    __znh_run_journal_vacuum
                fi

                after_usage=$(journalctl --disk-usage 2>/dev/null | tr -d '\r' || true)
                if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                    printf "%b[AFTER]%b  %s\n" "${C_GREEN}" "${C_RESET}" "${after_usage:-journalctl --disk-usage unavailable}"
                else
                    echo "[AFTER] ${after_usage:-journalctl --disk-usage unavailable}"
                fi
            fi

            # 3) User thumbnails cleanup (best-effort)
            if [ "${USER_THUMBNAILS_CLEAN_ENABLED:-false}" = "true" ] && [ -n "${SUDO_USER_HOME:-}" ] && [ -n "${SUDO_USER:-}" ]; then
                ran_any=1
                __znh_print_stage "== System Deep Scrub: user thumbnails =="

                local -a tdirs
                tdirs=("${SUDO_USER_HOME}/.cache/thumbnails" "${SUDO_USER_HOME}/.thumbnails")

                local before_sz after_sz
                before_sz=""
                after_sz=""

                local d
                for d in "${tdirs[@]}"; do
                    if [ -d "${d}" ]; then
                        local s
                        s="$(__znh_du_sh "${d}")"
                        before_sz+="${d}:${s} "
                    fi
                done

                if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                    printf "%b[BEFORE]%b %s\n" "${C_YELLOW}" "${C_RESET}" "${before_sz:-no thumbnail dirs found}"
                else
                    echo "[BEFORE] ${before_sz:-no thumbnail dirs found}"
                fi

                local do_it=0
                if [ "${USER_THUMBNAILS_CLEAN_CONFIRM:-true}" = "true" ]; then
                    if [ -t 0 ]; then
                        local ans_tc
                        read -p "Delete cached thumbnails for user '${SUDO_USER}'? [y/N]: " -r ans_tc
                        if [[ "${ans_tc:-}" =~ ^[Yy]$ ]]; then
                            do_it=1
                        else
                            echo "Skipping thumbnails cleanup."
                        fi
                    else
                        log_warn "[deep-scrub] Refusing thumbnails cleanup without a TTY while USER_THUMBNAILS_CLEAN_CONFIRM=true"
                    fi
                else
                    do_it=1
                fi

                if [ "${do_it}" -eq 1 ] 2>/dev/null; then
                    local days
                    days="${USER_THUMBNAILS_CLEAN_DAYS:-0}"
                    if ! [[ "${days}" =~ ^[0-9]+$ ]] || [ "${days}" -lt 0 ] 2>/dev/null; then
                        days=0
                    fi

                    for d in "${tdirs[@]}"; do
                        if [ -d "${d}" ]; then
                            if [ "${days}" -gt 0 ] 2>/dev/null; then
                                execute_optional "Clear thumbnails older than ${days}d in ${d}" \
                                    find "${d}" -type f -atime +"${days}" -delete 2>/dev/null || true
                            else
                                # Remove contents only (keep dir). Use find to avoid glob
                                # expansion errors when the directory is empty.
                                execute_optional "Clear thumbnails in ${d}" \
                                    find "${d}" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + || true
                            fi
                            chown -R "${SUDO_USER}:${SUDO_USER}" "${d}" 2>/dev/null || true
                        fi
                    done
                fi

                for d in "${tdirs[@]}"; do
                    if [ -d "${d}" ]; then
                        local s
                        s="$(__znh_du_sh "${d}")"
                        after_sz+="${d}:${s} "
                    fi
                done

                if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                    printf "%b[AFTER]%b  %s\n" "${C_GREEN}" "${C_RESET}" "${after_sz:-no thumbnail dirs found}"
                else
                    echo "[AFTER] ${after_sz:-no thumbnail dirs found}"
                fi
            fi

            if [ "${ran_any}" -eq 1 ] 2>/dev/null; then
                echo ""
                echo "[deep-scrub] Completed selected system hygiene steps."
            fi

            return 0
        }

        __znh_audit_record "deep-scrub:start"
        __znh_system_deep_scrub || true
        __znh_audit_record "deep-scrub:done"

        # Optional: purge old kernel *packages* using openSUSE's official
        # `purge-kernels` (via zypper). This respects:
        #   /etc/zypp/zypp.conf:multiversion.kernels
        # and is disabled by default (see /etc/zypper-auto.conf).
        __znh_kernel_purge_old_kernels() {
            if [ "${KERNEL_PURGE_ENABLED:-false}" != "true" ]; then
                return 0
            fi

            if ! command -v zypper >/dev/null 2>&1; then
                log_warn "[kernel-purge] zypper not found; cannot run purge-kernels"
                return 0
            fi

            # Guard: don't run while zypper appears active (package manager lock).
            # NOTE: best-effort; we keep it simple to avoid false positives.
            if pgrep -x zypper >/dev/null 2>&1; then
                log_warn "[kernel-purge] zypper appears to be running already; skipping purge-kernels to avoid lock conflicts"
                return 0
            fi

            local policy_line
            policy_line=""
            if [ -f /etc/zypp/zypp.conf ]; then
                policy_line=$(grep -E '^[[:space:]]*multiversion\.kernels' /etc/zypp/zypp.conf 2>/dev/null | tail -n 1 | tr -d '\r' || true)
            fi

            local mode timeout_s
            mode="${KERNEL_PURGE_MODE:-auto}"
            timeout_s="${KERNEL_PURGE_TIMEOUT_SECONDS:-900}"
            if ! [[ "${timeout_s}" =~ ^[0-9]+$ ]] || [ "${timeout_s}" -le 0 ] 2>/dev/null; then
                timeout_s=900
            fi

            echo ""
            echo "== Kernel package cleanup (purge-kernels) =="
            if [ -n "${policy_line:-}" ]; then
                echo "Policy (from /etc/zypp/zypp.conf): ${policy_line}"
            else
                echo "Policy (from /etc/zypp/zypp.conf): (multiversion.kernels not found; zypper default will apply)"
            fi
            echo "Mode: ${mode}"

            __znh_kernel_purge_preview() {
                local out rc
                out=""
                rc=0

                if command -v timeout >/dev/null 2>&1; then
                    out=$(timeout "${timeout_s}" zypper -n purge-kernels --dry-run --details 2>&1)
                    rc=$?
                else
                    out=$(zypper -n purge-kernels --dry-run --details 2>&1)
                    rc=$?
                fi

                echo ""
                if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                    printf "%b%s%b\n" "${C_CYAN}" "[kernel-purge] Preview (dry-run):" "${C_RESET}"
                else
                    echo "[kernel-purge] Preview (dry-run):"
                fi

                if [ "${rc}" -ne 0 ] 2>/dev/null; then
                    printf '%s\n' "$out"
                    return 1
                fi

                # Highlight key lines for readability.
                while IFS= read -r line; do
                    if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                        if printf '%s\n' "$line" | grep -qi "nothing to do"; then
                            printf "%b%s%b\n" "${C_GREEN}" "$line" "${C_RESET}"
                        elif printf '%s\n' "$line" | grep -Eq "REMOV|remove"; then
                            printf "%b%s%b\n" "${C_RED}" "$line" "${C_RESET}"
                        elif printf '%s\n' "$line" | grep -Eq "^Configuration:|^Running kernel"; then
                            printf "%b%s%b\n" "${C_YELLOW}" "$line" "${C_RESET}"
                        else
                            printf '%s\n' "$line"
                        fi
                    else
                        printf '%s\n' "$line"
                    fi
                done <<<"${out}"

                return 0
            }

            # Always show a preview in interactive runs so the user can see what
            # would be removed/kept.
            if [ -t 0 ]; then
                __znh_kernel_purge_preview || true
            fi

            if [ "${KERNEL_PURGE_DRY_RUN:-false}" = "true" ]; then
                echo "[kernel-purge] KERNEL_PURGE_DRY_RUN=true: preview only (no changes)."
                return 0
            fi

            if [ "${KERNEL_PURGE_CONFIRM:-true}" = "true" ]; then
                if [ -t 0 ]; then
                    read -p "Purge old kernel packages now? [y/N]: " -r ans_kp
                    if [[ ! "${ans_kp:-}" =~ ^[Yy]$ ]]; then
                        echo "Skipping kernel package cleanup."
                        return 0
                    fi
                else
                    log_warn "[kernel-purge] Refusing to purge kernels without a TTY while KERNEL_PURGE_CONFIRM=true"
                    return 0
                fi
            fi

            case "${mode}" in
                zypper)
                    if command -v timeout >/dev/null 2>&1; then
                        execute_guarded "Kernel purge (zypper purge-kernels)" timeout "${timeout_s}" zypper -n purge-kernels || true
                    else
                        execute_guarded "Kernel purge (zypper purge-kernels)" zypper -n purge-kernels || true
                    fi
                    ;;
                systemd)
                    if __znh_unit_file_exists_system purge-kernels.service; then
                        # The unit is gated by /boot/do_purge_kernels; create the marker and start it.
                        execute_guarded "Create /boot/do_purge_kernels marker" touch /boot/do_purge_kernels || true
                        if command -v timeout >/dev/null 2>&1; then
                            execute_guarded "Kernel purge (purge-kernels.service)" timeout "${timeout_s}" systemctl start purge-kernels.service || true
                        else
                            execute_guarded "Kernel purge (purge-kernels.service)" systemctl start purge-kernels.service || true
                        fi
                    else
                        log_warn "[kernel-purge] purge-kernels.service not found; falling back to direct zypper purge-kernels"
                        if command -v timeout >/dev/null 2>&1; then
                            execute_guarded "Kernel purge (zypper purge-kernels)" timeout "${timeout_s}" zypper -n purge-kernels || true
                        else
                            execute_guarded "Kernel purge (zypper purge-kernels)" zypper -n purge-kernels || true
                        fi
                    fi
                    ;;
                auto|*)
                    # Prefer direct zypper invocation; it's the most portable.
                    if command -v timeout >/dev/null 2>&1; then
                        execute_guarded "Kernel purge (zypper purge-kernels)" timeout "${timeout_s}" zypper -n purge-kernels || true
                    else
                        execute_guarded "Kernel purge (zypper purge-kernels)" zypper -n purge-kernels || true
                    fi
                    ;;
            esac

            # Show AFTER state (dry-run should now say Nothing to do)
            if [ -t 0 ]; then
                __znh_kernel_purge_preview || true
            fi

            return 0
        }

        __znh_audit_record "kernel-purge:maybe"
        __znh_kernel_purge_old_kernels || true
        __znh_audit_record "kernel-purge:done"

        # Optional: prune old boot menu entry files (BLS/systemd-boot) so the boot
        # menu doesn't fill up with many older kernels.
        __znh_prune_old_kernel_boot_entries() {
            if [ "${BOOT_ENTRY_CLEANUP_ENABLED:-true}" != "true" ]; then
                return 0
            fi

            # Detect entries dir
            local entries_dir
            entries_dir="${BOOT_ENTRY_CLEANUP_ENTRIES_DIR:-}"
            if [ -n "${entries_dir}" ] && [ ! -d "${entries_dir}" ]; then
                log_warn "[boot-entry-clean] Configured BOOT_ENTRY_CLEANUP_ENTRIES_DIR not found: ${entries_dir}"
                entries_dir=""
            fi

            if [ -z "${entries_dir}" ]; then
                for d in /boot/loader/entries /boot/efi/loader/entries /efi/loader/entries; do
                    if [ -d "$d" ]; then
                        entries_dir="$d"
                        break
                    fi
                done
            fi

            if [ -z "${entries_dir}" ]; then
                log_info "[boot-entry-clean] No BLS entries directory found; skipping boot menu cleanup"
                return 0
            fi

            # Determine keep kernels: running kernel + latest N installed kernels.
            local running_kver keep_n
            running_kver=$(uname -r 2>/dev/null || true)
            keep_n="${BOOT_ENTRY_CLEANUP_KEEP_LATEST:-2}"
            if ! [[ "${keep_n}" =~ ^[0-9]+$ ]] || [ "${keep_n}" -lt 1 ] 2>/dev/null; then
                keep_n=1
            fi

            # Collect installed kernels from module directories.
            local installed
            installed=$( {
                find /lib/modules /usr/lib/modules -maxdepth 1 -mindepth 1 -type d -printf '%f\n' 2>/dev/null || true
            } | sort -uV || true)

            local keep_list=""
            if [ -n "${installed}" ]; then
                keep_list=$(printf '%s\n' "$installed" | tail -n "${keep_n}" | tr '\n' ' ' | sed 's/[[:space:]]*$//')
            fi

            log_info "[boot-entry-clean] entries_dir=${entries_dir} running=${running_kver:-unknown} keep_latest=${keep_n} keep_list='${keep_list}'"

            local mode
            mode="${BOOT_ENTRY_CLEANUP_MODE:-backup}"
            case "${mode}" in
                backup|delete) : ;;
                *) mode="backup" ;;
            esac

            local ts backup_dir
            ts="$(date +%Y%m%d-%H%M%S)"
            backup_dir="/var/backups/zypper-auto/boot-entries-${ts}"

            local removed=0 kept=0 unknown=0

            # Build plan first so we can show KEEP/REMOVE before doing anything.
            # NOTE: With 'set -u' (nounset), empty arrays that were never assigned can still
            # behave as "unbound" in some Bash versions/contexts. Initialize all arrays.
            local -a plan_keep=() plan_remove=() plan_unknown=() remove_items=()

            __znh_bls_get_linux_path() {
                # Extract linux/linuxefi path from a BLS entry file (best-effort)
                local f="$1"
                awk '
                    /^[[:space:]]*#/ {next}
                    NF < 2 {next}
                    tolower($1) ~ /^linux(efi)?$/ {
                      $1="";
                      sub(/^[[:space:]]+/, "");
                      # strip simple surrounding quotes
                      gsub(/^"|"$/, "");
                      gsub(/^\x27|\x27$/, "");
                      split($0, a, /[[:space:]]+/);
                      print a[1];
                      exit
                    }
                ' "$f" 2>/dev/null || true
            }

            __znh_kernel_ver_from_linux_path() {
                local p="$1"
                p="${p#/}"

                # sd-boot style: /<distro>/<kver>/linux-...
                local rest="${p#*/}"
                if [ "${rest}" != "${p}" ]; then
                    local kver="${rest%%/*}"
                    if [ -n "${kver}" ] && [ "${kver}" != "${rest}" ]; then
                        printf '%s\n' "$kver"
                        return 0
                    fi
                fi

                # flat: vmlinuz-<kver>
                local base="${p##*/}"
                case "$base" in
                    vmlinuz-*) printf '%s\n' "${base#vmlinuz-}"; return 0 ;;
                    linux-*)   printf '%s\n' "${base#linux-}"; return 0 ;;
                esac

                return 1
            }

            local f
            shopt -s nullglob
            for f in "${entries_dir}"/*.conf; do
                local linux_path kver
                linux_path=$(__znh_bls_get_linux_path "$f")
                if [ -z "${linux_path:-}" ]; then
                    plan_unknown+=("$(basename "$f") [unparsed]")
                    continue
                fi

                kver=$(__znh_kernel_ver_from_linux_path "$linux_path" 2>/dev/null || true)
                if [ -z "${kver:-}" ]; then
                    plan_unknown+=("$(basename "$f") [kver-unknown]")
                    continue
                fi

                if [ -n "${running_kver:-}" ] && [ "${kver}" = "${running_kver}" ]; then
                    plan_keep+=("$(basename "$f") (kver=${kver}) [running]")
                    continue
                fi

                if [ -n "${keep_list:-}" ] && printf '%s\n' "$keep_list" | tr ' ' '\n' | grep -Fxq "${kver}"; then
                    plan_keep+=("$(basename "$f") (kver=${kver}) [keep-latest]")
                    continue
                fi

                plan_remove+=("$(basename "$f") (kver=${kver})")
                remove_items+=("${f}|${kver}")
            done
            shopt -u nullglob

            echo ""
            if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                printf "%b%s%b\n" "${C_CYAN}" "Boot entry cleanup plan:" "${C_RESET}"
            else
                echo "Boot entry cleanup plan:"
            fi
            echo "  - Entries dir: ${entries_dir}"
            echo "  - Mode: ${mode}"
            echo "  - Will keep: ${#plan_keep[@]}"
            echo "  - Will remove: ${#plan_remove[@]}"
            echo "  - Unknown/unparsed: ${#plan_unknown[@]}"

            local item
            if [ "${#plan_keep[@]}" -gt 0 ] 2>/dev/null; then
                if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                    printf "%bKEEP%b\n" "${C_GREEN}" "${C_RESET}"
                else
                    echo "KEEP"
                fi
                for item in "${plan_keep[@]}"; do
                    printf '  - %s\n' "$item"
                done
            fi

            if [ "${#plan_remove[@]}" -gt 0 ] 2>/dev/null; then
                if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                    printf "%bREMOVE%b\n" "${C_RED}" "${C_RESET}"
                else
                    echo "REMOVE"
                fi
                for item in "${plan_remove[@]}"; do
                    printf '  - %s\n' "$item"
                done
            fi

            if [ "${#plan_unknown[@]}" -gt 0 ] 2>/dev/null; then
                if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                    printf "%bUNKNOWN%b\n" "${C_YELLOW}" "${C_RESET}"
                else
                    echo "UNKNOWN"
                fi
                for item in "${plan_unknown[@]}"; do
                    printf '  - %s\n' "$item"
                done
            fi

            if [ "${BOOT_ENTRY_CLEANUP_CONFIRM:-true}" = "true" ]; then
                if [ -t 0 ]; then
                    echo ""
                    echo "Boot menu cleanup (BLS entries) will keep:"
                    echo "  - running kernel: ${running_kver:-unknown}"
                    echo "  - latest ${keep_n} installed kernels: ${keep_list:-<none>}"
                    echo "Mode: ${mode}"
                    read -p "Also prune older boot entry files now? [y/N]: " -r ans_be
                    if [[ ! "${ans_be:-}" =~ ^[Yy]$ ]]; then
                        echo "Skipping boot menu cleanup."
                        return 0
                    fi
                else
                    log_warn "[boot-entry-clean] Refusing to prune boot entries without a TTY while BOOT_ENTRY_CLEANUP_CONFIRM=true"
                    return 0
                fi
            fi

            # Execute plan
            local entry
            for entry in "${remove_items[@]}"; do
                local path kver
                path="${entry%%|*}"
                kver="${entry#*|}"

                if [ "$mode" = "delete" ]; then
                    log_warn "[boot-entry-clean] Deleting old boot entry: $(basename "$path") (kver=${kver})"
                    rm -f -- "$path" 2>/dev/null || true
                else
                    mkdir -p "$backup_dir" 2>/dev/null || true
                    log_info "[boot-entry-clean] Moving old boot entry: $(basename "$path") (kver=${kver}) -> ${backup_dir}/"
                    mv -f -- "$path" "$backup_dir/" 2>/dev/null || true
                fi
                removed=$((removed + 1))
            done

            kept=${#plan_keep[@]}
            unknown=${#plan_unknown[@]}

            echo ""
            echo "Boot entry cleanup summary:"
            echo "  - Entries dir: ${entries_dir}"
            echo "  - Kept entries: ${kept}"
            echo "  - Removed entries: ${removed}"
            echo "  - Unknown/unparsed entries: ${unknown}"
            if [ "$removed" -gt 0 ] 2>/dev/null && [ "$mode" = "backup" ]; then
                echo "  - Backup dir: ${backup_dir}"
            fi

            return 0
        }

        __znh_audit_record "boot-entries:cleanup:maybe"
        __znh_prune_old_kernel_boot_entries || true
        __znh_audit_record "boot-entries:cleanup:done"

        # --- SMART: Space tracking end ---
        end_space=$(df -Pk / 2>/dev/null | awk 'NR==2 {print $4}' | tr -dc '0-9')
        freed_kb=0
        if [[ "${start_space:-}" =~ ^[0-9]+$ ]] && [[ "${end_space:-}" =~ ^[0-9]+$ ]]; then
            freed_kb=$((end_space - start_space))
        fi

        # Capture AFTER snapshot state and compute removed items
        __znh_snapper_dump_snapshot_csv "${after_csv}" || true

        # removed = BEFORE - AFTER
        awk -F'\t' 'NR==FNR {k=$1"\t"$2; a[k]=$0; next} {k=$1"\t"$2; b[k]=1} END {for (k in a) if (!(k in b)) print a[k]}' \
            "${before_csv}" "${after_csv}" \
            | sort -t $'\t' -k1,1 -k2,2n \
            >"${removed_csv}" 2>/dev/null || true

        echo ""
        if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
            printf "%b%s%b\n" "${C_CYAN}" "Snapshots AFTER cleanup (showing last 20 per config)" "${C_RESET}"
        else
            echo "Snapshots AFTER cleanup (showing last 20 per config)"
        fi
        __znh_print_snapper_snapshot_list "" "${after_csv}" "KEEP" "${C_GREEN}" || true

        local removed_count
        removed_count=$(wc -l <"${removed_csv}" 2>/dev/null | tr -dc '0-9')
        removed_count="${removed_count:-0}"

        echo ""
        if [ "${removed_count}" -gt 0 ] 2>/dev/null; then
            if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                printf "%bRemoved snapshots:%b\n" "${C_RED}" "${C_RESET}"
            else
                echo "Removed snapshots:"
            fi
            while IFS=$'\t' read -r conf n t d; do
                [ -n "${conf:-}" ] || continue
                if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                    printf "  %b[REMOVE]%b %s #%s [%s] %s\n" "${C_RED}" "${C_RESET}" "${conf}" "${n}" "${t}" "${d}"
                else
                    printf "  [REMOVE] %s #%s [%s] %s\n" "${conf}" "${n}" "${t}" "${d}"
                fi
            done <"${removed_csv}"
        else
            if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                printf "%bNo snapshots were removed in this run.%b\n" "${C_GREEN}" "${C_RESET}"
            else
                echo "No snapshots were removed in this run."
            fi
        fi

        # Preserve removed snapshot list for audit report (cleanup tmpfiles below will delete removed_csv).
        removed_csv_report="$(mktemp)"
        cp -f -- "${removed_csv}" "${removed_csv_report}" 2>/dev/null || true

        # Cleanup temp files
        __znh_cleanup_snapshot_tmpfiles

        echo ""
        echo "=============================================="
        echo " Cleanup Summary"
        echo "=============================================="

        if [ "${freed_kb}" -gt 0 ] 2>/dev/null; then
            local freed_mb
            freed_mb=$((freed_kb / 1024))
            echo "SUCCESS: Reclaimed approx. ${freed_mb} MB of free space."
        elif [ "${freed_kb}" -lt 0 ] 2>/dev/null; then
            echo "NOTE: Free space decreased (new data written or metadata expanded)."
        else
            echo "NOTE: No net free-space reclaimed (already clean or snapshots too young)."
        fi

        __audit_status="completed"
        __znh_cleanup_report_write_final "${start_space:-}" "${end_space:-}" "${freed_kb:-0}" "${removed_csv_report:-${removed_csv}}" "${removed_count:-0}" || true

        echo ""
        echo "Current filesystem usage:"
        if command -v btrfs >/dev/null 2>&1; then
            btrfs filesystem df / 2>/dev/null || df -h / 2>/dev/null || true

            # Tip only (do not run balance automatically): if you reclaimed a lot
            # of space, btrfs metadata may still be fragmented.
            if [ "${freed_kb}" -gt 1048576 ] 2>/dev/null; then
                echo ""
                echo "TIP: You reclaimed over ~1GB. If the system still feels 'full' due to btrfs metadata, consider:"
                echo "  sudo btrfs balance start -dusage=5 /"
                echo "(This can take a long time on slow disks; run it when idle.)"
            fi
        else
            df -h / 2>/dev/null || true
        fi

        return 0
    }

    __znh_snapper_timer_exists() {
        local unit="$1"
        local out first
        out=$(systemctl list-unit-files --no-legend "${unit}" 2>/dev/null)
        first=$(awk 'NR==1 {print $1}' <<<"${out}")
        [ "${first}" = "${unit}" ]
    }

    __znh_snapper_auto_timers() {
        local action="${1:-enable}"
        local units=(snapper-timeline.timer snapper-cleanup.timer snapper-boot.timer)

        # When disabling, also disable the optional maintenance timers that option 5
        # may have enabled (btrfsmaintenance + fstrim) so the user gets a true
        # "undo" for the AUTO enable option.
        if [ "${action}" = "disable" ]; then
            units+=(btrfs-scrub.timer btrfs-balance.timer btrfs-trim.timer btrfs-defrag.timer fstrim.timer)
        fi

        # --- Professional Edition: system health score (0-100) ---
        local __hs_score=100
        local -a __hs_issues=()

        __znh_hs_add_issue() {
            local penalty="$1" msg="$2"
            if ! [[ "${penalty}" =~ ^[0-9]+$ ]]; then
                penalty=0
            fi
            __hs_score=$((__hs_score - penalty))
            if [ "${__hs_score}" -lt 0 ] 2>/dev/null; then
                __hs_score=0
            fi
            __hs_issues+=("${msg}")
        }

        __znh_hs_unit_active_check() {
            # Args: unit penalty label
            local unit="$1" penalty="$2" label="$3"

            # If unit file is missing, don't hard-fail; just report.
            if ! __znh_unit_file_exists_system "${unit}"; then
                __znh_hs_add_issue 0 "${label}: timer not found (${unit})"
                return 0
            fi

            if ! systemctl is-active --quiet "${unit}" 2>/dev/null; then
                __znh_hs_add_issue "${penalty}" "${label}: inactive (${unit})"
            fi

            return 0
        }

        __znh_hs_snapper_config_check() {
            # Best-effort: detect dangerous snapper retention values.
            # IMPORTANT: only check active snapper configs (ignore backup files).
            if [ ! -d /etc/snapper/configs ]; then
                return 0
            fi

            local conf f
            while read -r conf; do
                [ -n "${conf}" ] || continue
                f="/etc/snapper/configs/${conf}"
                [ -f "${f}" ] || continue

                # NUMBER_LIMIT can be "50" or "2-50". We look at upper bound.
                local nl upper
                nl=$(grep -E '^NUMBER_LIMIT=' "${f}" 2>/dev/null | head -n 1 | cut -d'"' -f2)
                if [ -n "${nl:-}" ]; then
                    upper="${nl##*-}"
                    if [[ "${upper}" =~ ^[0-9]+$ ]] && [ "${upper}" -gt 20 ] 2>/dev/null; then
                        __znh_hs_add_issue 20 "Dangerous NUMBER_LIMIT upper bound (>20) in ${conf}: ${nl}"
                    fi
                fi

                # Timeline disabled in config while automation exists -> warn.
                if grep -q '^TIMELINE_CREATE="no"' "${f}" 2>/dev/null; then
                    __znh_hs_add_issue 10 "TIMELINE_CREATE is disabled in ${conf}"
                fi
            done < <(__znh_snapper_list_config_names 2>/dev/null || printf '%s\n' root)

            return 0
        }

        __znh_hs_compute_and_print() {
            local title="$1"

            __hs_score=100
            __hs_issues=()

            # Snapper timers (core)
            __znh_hs_unit_active_check snapper-cleanup.timer 20 "Snapper cleanup"
            __znh_hs_unit_active_check snapper-timeline.timer 20 "Snapper timeline"
            __znh_hs_unit_active_check snapper-boot.timer 10 "Snapper boot"

            # Btrfs maintenance (optional)
            __znh_hs_unit_active_check btrfs-scrub.timer 10 "Btrfs scrub"
            __znh_hs_unit_active_check btrfs-balance.timer 10 "Btrfs balance"
            __znh_hs_unit_active_check btrfs-trim.timer 5 "Btrfs trim"

            # SSD health (trim)
            __znh_hs_unit_active_check fstrim.timer 10 "SSD trim"

            __znh_hs_snapper_config_check

            echo ""
            echo "=============================================="
            echo " System Health Score: ${title}"
            echo "=============================================="
            echo "Score: ${__hs_score}/100"
            if [ "${#__hs_issues[@]}" -gt 0 ] 2>/dev/null; then
                echo "Issues detected:"
                local it
                for it in "${__hs_issues[@]}"; do
                    echo "  - ${it}"
                done
            else
                echo "No obvious issues detected."
            fi

            return 0
        }

        echo ""
        echo "Snapper timer management (${action})"

        local pre_score
        pre_score=0
        __znh_hs_compute_and_print "before (${action})" || true
        pre_score="${__hs_score}"

        # 1) systemd unit management (self-healing)
        local u
        for u in "${units[@]}"; do
            if __znh_snapper_timer_exists "${u}"; then
                if [ "${action}" = "enable" ]; then
                    # SMART: reset failed state (otherwise enable/start can be confusing)
                    if systemctl is-failed --quiet "${u}" 2>/dev/null; then
                        echo "  [fix] Resetting failed state: ${u}"
                        execute_guarded "Reset failed state for ${u}" systemctl reset-failed "${u}" || true
                    fi

                    # SMART: unmask if user masked it
                    if systemctl is-enabled "${u}" 2>/dev/null | grep -q "masked"; then
                        echo "  [fix] Unmasking: ${u}"
                        execute_guarded "Unmask ${u}" systemctl unmask "${u}" || true
                    fi

                    execute_guarded "Enable + start ${u}" systemctl enable --now "${u}" || true
                else
                    execute_guarded "Disable + stop ${u}" systemctl disable --now "${u}" || true
                fi
            else
                echo "  [skip] Timer not found: ${u}"
            fi
        done

        # 2) Smart config sync + preventative optimization
        # Shared helper also used by option 4 cleanup.
        if command -v snapper >/dev/null 2>&1; then
            __znh_snapper_optimize_configs "${action}" || true
        fi

        # 3) Optional: btrfs maintenance timers (system health)
        __znh_enable_btrfs_maintenance_timers() {
            if [ "${BTRFS_MAINTENANCE_TIMERS_ENABLED:-true}" != "true" ]; then
                return 0
            fi

            local units=(btrfs-scrub.timer btrfs-balance.timer btrfs-trim.timer btrfs-defrag.timer)
            local found=0

            # Only meaningful when enabling automation.
            if [ "${action}" != "enable" ]; then
                return 0
            fi

            # Ask once (interactive) before enabling.
            if [ "${BTRFS_MAINTENANCE_TIMERS_CONFIRM:-true}" = "true" ]; then
                if [ -t 0 ]; then
                    local ans_bt
                    read -p "Also enable btrfs maintenance timers (scrub/balance/trim) if available? [Y/n]: " -r ans_bt
                    if [[ "${ans_bt:-y}" =~ ^[Nn]$ ]]; then
                        log_info "[btrfs][maint] User declined enabling btrfs maintenance timers"
                        return 0
                    fi
                else
                    log_warn "[btrfs][maint] No TTY; skipping btrfs maintenance timers while confirmation is required"
                    return 0
                fi
            fi

            echo ""
            echo "Btrfs maintenance timers:"

            local u
            for u in "${units[@]}"; do
                if __znh_unit_file_exists_system "${u}"; then
                    found=1
                    # Reset failed state if needed
                    if systemctl is-failed --quiet "${u}" 2>/dev/null; then
                        execute_guarded "Reset failed state for ${u}" systemctl reset-failed "${u}" || true
                    fi
                    # Unmask if masked
                    if systemctl is-enabled "${u}" 2>/dev/null | grep -q "masked"; then
                        execute_guarded "Unmask ${u}" systemctl unmask "${u}" || true
                    fi
                    execute_guarded "Enable + start ${u}" systemctl enable --now "${u}" || true
                else
                    echo "  [skip] Timer not found: ${u}"
                fi
            done

            if [ "${found}" -eq 0 ] 2>/dev/null; then
                echo "  (No btrfsmaintenance timers found. If desired, install: btrfsmaintenance)"
            fi

            echo ""
            echo "Current btrfs timers (if any):"
            systemctl --no-pager list-unit-files --no-legend 'btrfs-*.timer' 2>/dev/null || true
            return 0
        }

        __znh_enable_btrfs_maintenance_timers || true

        # 4) SSD health: enable fstrim.timer (safe)
        __znh_enable_fstrim_timer() {
            if [ "${action}" != "enable" ]; then
                return 0
            fi
            if [ "${FSTRIM_TIMER_ENABLED:-true}" != "true" ]; then
                return 0
            fi

            if [ "${FSTRIM_TIMER_CONFIRM:-true}" = "true" ]; then
                if [ -t 0 ]; then
                    local ans_ft
                    read -p "Also enable fstrim.timer (SSD trim) if available? [Y/n]: " -r ans_ft
                    if [[ "${ans_ft:-y}" =~ ^[Nn]$ ]]; then
                        log_info "[fstrim] User declined enabling fstrim.timer"
                        return 0
                    fi
                else
                    log_warn "[fstrim] No TTY; skipping fstrim.timer while confirmation is required"
                    return 0
                fi
            fi

            echo ""
            echo "SSD trim timer (fstrim.timer):"
            if __znh_unit_file_exists_system fstrim.timer; then
                if systemctl is-failed --quiet fstrim.timer 2>/dev/null; then
                    execute_guarded "Reset failed state for fstrim.timer" systemctl reset-failed fstrim.timer || true
                fi
                if systemctl is-enabled fstrim.timer 2>/dev/null | grep -q "masked"; then
                    execute_guarded "Unmask fstrim.timer" systemctl unmask fstrim.timer || true
                fi
                execute_guarded "Enable + start fstrim.timer" systemctl enable --now fstrim.timer || true
            else
                echo "  [skip] Timer not found: fstrim.timer"
            fi
            return 0
        }

        __znh_enable_fstrim_timer || true

        # 5) Optional: tune btrfsmaintenance scheduling (reduce slowdowns)
        __znh_tune_btrfsmaintenance_sysconfig() {
            if [ "${action}" != "enable" ]; then
                return 0
            fi
            if [ "${BTRFS_MAINTENANCE_TUNE_ENABLED:-false}" != "true" ]; then
                return 0
            fi

            local cfg
            cfg="/etc/sysconfig/btrfsmaintenance"
            if [ ! -f "${cfg}" ]; then
                log_info "[btrfs][tune] ${cfg} not found; skipping tuning"
                return 0
            fi

            if [ "${BTRFS_MAINTENANCE_TUNE_CONFIRM:-true}" = "true" ]; then
                if [ -t 0 ]; then
                    local ans_bmt
                    read -p "Also tune btrfsmaintenance periods to monthly (balance/scrub) to reduce slowdowns? [y/N]: " -r ans_bmt
                    if [[ ! "${ans_bmt:-}" =~ ^[Yy]$ ]]; then
                        log_info "[btrfs][tune] User declined btrfsmaintenance sysconfig tuning"
                        return 0
                    fi
                else
                    log_warn "[btrfs][tune] No TTY; skipping btrfsmaintenance tuning while confirmation is required"
                    return 0
                fi
            fi

            echo ""
            echo "Btrfs maintenance tuning (best-effort):"
            echo "  - File: ${cfg}"

            local ts backup_dir backup
            ts="$(date +%Y%m%d-%H%M%S)"
            backup_dir="/var/backups/zypper-auto"
            backup="${backup_dir}/btrfsmaintenance-${ts}.bak"
            execute_optional "Ensure backup dir exists (${backup_dir})" mkdir -p "${backup_dir}" || true
            execute_guarded "Backup ${cfg} -> ${backup}" cp -a -- "${cfg}" "${backup}" || true

            local changed=0
            if grep -qE '^BTRFS_BALANCE_PERIOD="(daily|weekly)"' "${cfg}" 2>/dev/null; then
                execute_guarded "Tune BTRFS_BALANCE_PERIOD -> monthly" \
                    sed -i -E 's/^BTRFS_BALANCE_PERIOD="(daily|weekly)"/BTRFS_BALANCE_PERIOD="monthly"/' "${cfg}" || true
                changed=1
            fi
            if grep -qE '^BTRFS_SCRUB_PERIOD="(daily|weekly)"' "${cfg}" 2>/dev/null; then
                execute_guarded "Tune BTRFS_SCRUB_PERIOD -> monthly" \
                    sed -i -E 's/^BTRFS_SCRUB_PERIOD="(daily|weekly)"/BTRFS_SCRUB_PERIOD="monthly"/' "${cfg}" || true
                changed=1
            fi

            if [ "${changed}" -eq 1 ] 2>/dev/null; then
                echo "  [tuned] Balance/Scrub periods adjusted to monthly"

                # Reload/refresh units if present (unit name differs across distros/versions)
                local unit
                for unit in btrfsmaintenance-refresh.service btrfs-maintenance-refresh.service; do
                    if __znh_unit_file_exists_system "${unit}"; then
                        execute_guarded "Restart ${unit}" systemctl restart "${unit}" || true
                    fi
                done
            else
                echo "  [ok] No tuning needed (already monthly or configured differently)"
            fi

            return 0
        }

        __znh_tune_btrfsmaintenance_sysconfig || true

        echo ""
        echo "Current snapper timers (if any):"
        systemctl --no-pager list-timers 'snapper-*.timer' 2>/dev/null || true
        echo ""
        echo "Current btrfs timers (if any):"
        systemctl --no-pager list-timers 'btrfs-*.timer' 2>/dev/null || true
        echo ""
        echo "Current trim timers (if any):"
        systemctl --no-pager list-timers 'fstrim.timer' 2>/dev/null || true

        local post_score
        post_score=0
        __znh_hs_compute_and_print "after (${action})" || true
        post_score="${__hs_score}"

        echo ""
        echo "Health score delta: ${pre_score}/100 -> ${post_score}/100"

        return 0
    }

    # Non-interactive subcommands:
    #   zypper-auto-helper snapper status
    #   zypper-auto-helper snapper list [N]
    #   zypper-auto-helper snapper create [DESCRIPTION]
    #   zypper-auto-helper snapper cleanup [all|number|timeline|empty-pre-post]
    #   zypper-auto-helper snapper auto   (enable timers)
    #   zypper-auto-helper snapper auto-off (disable timers)
    local sub="${1:-}"
    case "${sub}" in
        status)
            shift
            __znh_snapper_status
            set -e
            return 0
            ;;
        list)
            shift
            __znh_snapper_list_last_root "${1:-10}" || true
            set -e
            return 0
            ;;
        create)
            shift
            __znh_snapper_create_snapshot "${*:-}"
            local rc=$?
            set -e
            return $rc
            ;;
        cleanup)
            shift
            __znh_snapper_cleanup_now "${1:-all}"
            local rc=$?
            set -e
            return $rc
            ;;
        auto)
            shift
            __znh_snapper_auto_timers enable
            set -e
            return 0
            ;;
        auto-off)
            shift
            __znh_snapper_auto_timers disable
            set -e
            return 0
            ;;
        "")
            # Interactive menu below
            ;;
        *)
            echo "Unknown snapper subcommand: ${sub}"
            echo "Try: zypper-auto-helper snapper status"
            set -e
            return 1
            ;;
    esac

    __znh_timer_state() {
        # Prints: enabled | partial | disabled | missing
        local unit="$1"
        if ! __znh_unit_file_exists_system "${unit}"; then
            printf '%s' "missing"
            return 0
        fi

        local en=0 act=0
        if systemctl is-enabled --quiet "${unit}" 2>/dev/null; then
            en=1
        fi
        if systemctl is-active --quiet "${unit}" 2>/dev/null; then
            act=1
        fi

        if [ "${en}" -eq 1 ] 2>/dev/null && [ "${act}" -eq 1 ] 2>/dev/null; then
            printf '%s' "enabled"
        elif [ "${en}" -eq 1 ] 2>/dev/null || [ "${act}" -eq 1 ] 2>/dev/null; then
            printf '%s' "partial"
        else
            printf '%s' "disabled"
        fi
        return 0
    }

    __znh_timer_state_color() {
        local state="$1"
        case "${state}" in
            enabled) printf '%s' "${C_GREEN}" ;;
            partial) printf '%s' "${C_YELLOW}" ;;
            *) printf '%s' "${C_RED}" ;;
        esac
        return 0
    }

    __znh_print_snapper_timer_status_block() {
        # Compact timer status so users can see at a glance whether automation is active.
        # Printed on menu load and on each re-render.
        local u state color prefix suffix
        echo ""
        echo "Snapper timers (systemd):"
        for u in snapper-timeline.timer snapper-cleanup.timer snapper-boot.timer; do
            state="$(__znh_timer_state "${u}" 2>/dev/null || echo "unknown")"
            if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
                color="$(__znh_timer_state_color "${state}" 2>/dev/null || echo "")"
                prefix="${color}"
                suffix="${C_RESET}"
                printf "  - %s: %b%s%b\n" "${u}" "${prefix}" "${state}" "${suffix}"
            else
                printf "  - %s: %s\n" "${u}" "${state}"
            fi
        done
        return 0
    }

    while true; do
        echo ""
        echo "=============================================="
        echo "  Zypper Auto-Helper Snapper Menu"
        echo "=============================================="
        echo "  (Snapper mode: ${snapper_mode})"
        __znh_print_snapper_timer_status_block || true
        echo "  1) Status (configs + snapshot detection + timers)"
        echo "  2) List recent snapshots (root)"
        echo "  3) Create snapshot (single)"
        echo "  4) Full Cleanup (number + timeline + orphaned)"

        # Colorize option 5 based on whether snapper timers are enabled.
        local _s_total _s_on _s_color _s_prefix _s_suffix
        _s_total=0
        _s_on=0
        for _u in snapper-timeline.timer snapper-cleanup.timer snapper-boot.timer; do
            if __znh_unit_file_exists_system "${_u}"; then
                _s_total=$((_s_total + 1))
                if systemctl is-enabled --quiet "${_u}" 2>/dev/null; then
                    _s_on=$((_s_on + 1))
                fi
            fi
        done

        # Always show a short status suffix so it's clear even without colors.
        local _s_state
        _s_state="disabled"
        if [ "${_s_total}" -gt 0 ] 2>/dev/null && [ "${_s_on}" -eq "${_s_total}" ] 2>/dev/null; then
            _s_state="enabled"
        elif [ "${_s_on}" -gt 0 ] 2>/dev/null; then
            _s_state="partial"
        fi

        _s_color=""
        _s_prefix=""
        _s_suffix=""
        if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
            if [ "${_s_state}" = "enabled" ]; then
                _s_color="${C_GREEN}"
            elif [ "${_s_state}" = "partial" ]; then
                _s_color="${C_YELLOW}"
            else
                _s_color="${C_RED}"
            fi
            _s_prefix="${_s_color}"
            _s_suffix="${C_RESET}"
        fi

        if [ "${USE_COLOR:-0}" -eq 1 ] 2>/dev/null; then
            # Use printf %b so the ANSI sequences are interpreted.
            printf "%b\n" "  5) ${_s_prefix}AUTO: Enable snapper timers (timeline + cleanup + boot) + sync configs${_s_suffix} (${_s_state})"
        else
            echo "  5) AUTO: Enable snapper timers (timeline + cleanup + boot) + sync configs (${_s_state})"
        fi
        echo "  6) AUTO: Disable option-5 timers (snapper + btrfsmaintenance + fstrim)"
        echo "  7) Exit (7 / E / Q)"
        echo ""
        read -p "Select an option [1-7, E, Q]: " -r choice
        log_info "[snapper-menu] User selected: ${choice}"

        case "${choice}" in
            1)
                __znh_snapper_status
                ;;
            2)
                __znh_snapper_list_last_root 10 || true
                ;;
            3)
                __znh_snapper_create_snapshot
                ;;
            4)
                __znh_snapper_cleanup_now
                ;;
            5)
                __znh_snapper_auto_timers enable
                ;;
            6)
                __znh_snapper_auto_timers disable
                ;;
            7|e|E|q|Q)
                echo "Exiting Snapper menu."
                break
                ;;
            *)
                echo "Invalid selection: '${choice}'."
                ;;
        esac
    done

    set -e
    return 0
}

# --- Helper: Interactive debug / diagnostics menu (CLI) ---
run_debug_menu_only() {
    log_info ">>> Interactive debug / diagnostics tools menu..."

    # Capture a compact snapshot of the diagnostics environment at menu entry so
    # the follower / bundle logs show what state we started from.
    local _dbg_diag_dir _dbg_follower_active _dbg_follower_enabled
    _dbg_diag_dir="${LOG_DIR}/diagnostics"
    _dbg_follower_active=$(systemctl is-active --quiet "${DIAG_SERVICE_NAME}.service" 2>/dev/null && echo "active" || echo "inactive-or-missing")
    _dbg_follower_enabled=$(systemctl is-enabled --quiet "${DIAG_SERVICE_NAME}.service" 2>/dev/null && echo "enabled" || echo "disabled-or-missing")
    log_info "[debug-menu] Session start for RUN=${RUN_ID}; SUDO_USER=${SUDO_USER:-?}; LOG_DIR=${LOG_DIR}; DIAG_DIR=${_dbg_diag_dir}"
    log_info "[debug-menu] Diagnostics follower at menu entry: active=${_dbg_follower_active}, enabled=${_dbg_follower_enabled}"

    while true; do
        # Detect whether the diagnostics follower is currently enabled so we
        # can show a dynamic, coloured toggle label for option 1. We use
        # systemctl is-enabled here so the toggle controls the persistent
        # service state, not just the current runtime status.
        local follower_active follower_label
        if systemctl is-enabled --quiet zypper-auto-diag-logs.service 2>/dev/null; then
            follower_active=1
            # Red "Disable" label
            follower_label="\033[31mDisable diagnostics follower\033[0m"
        else
            follower_active=0
            # Green "Enable" label
            follower_label="\033[32mEnable diagnostics follower\033[0m"
        fi

        echo ""
        echo "=============================================="
        echo "  Zypper Auto-Helper Debug / Diagnostics Menu"
        echo "=============================================="
        printf '  1) %b\n' "${follower_label}"
        echo "  2) View live diagnostics logs"
        echo "  3) Capture one-shot diagnostics snapshot"
        echo "  4) Create diagnostics bundle tarball"
        echo "  5) Open diagnostics logs folder"
        echo "  6) Run notification self-test"
        echo "  7) Run helper self-check (syntax / config)"
        echo "  8) Folder opener self-test (xdg-open / file managers)"
        echo "  9) Run log health report (recent history)"
        echo " 10) Analyze last GUI-triggered run (by Trace ID)"
        echo " 11) Show last diagnostics snapshot path + tail"
        echo " 12) Tail dashboard Settings API log"
        echo " 13) Exit menu (13 / E / Q)"
        echo ""
        read -p "Select an option [1-13, E, Q]: " -r choice
        log_info "[debug-menu] User selected menu option: ${choice}"

        case "${choice}" in
            1)
                if [ "${follower_active}" -eq 1 ] 2>/dev/null; then
                    # Currently enabled -> toggle OFF (stop and disable persistent service)
                    log_info "[debug-menu] Disabling diagnostics follower via toggle"
                    execute_guarded "Stop diagnostics follower service" systemctl stop zypper-auto-diag-logs.service || true
                    execute_guarded "Disable diagnostics follower service" systemctl disable zypper-auto-diag-logs.service || true
                    update_status "SUCCESS: Diagnostics log follower disabled via debug menu toggle"
                    echo "Diagnostics follower disabled."
                else
                    # Currently disabled -> toggle ON
                    log_info "[debug-menu] Enabling diagnostics follower via toggle"
                    run_diag_logs_on_only || true
                    # Immediately capture a one-shot diagnostics snapshot so that
                    # the diagnostics folder contains at least today's diag-*.log
                    # when the user opens it via option 5.
                    run_snapshot_state_only || true
                    echo "Diagnostics follower enabled and initial diagnostics snapshot captured. Use option 5 to open the folder or option 2 to view live logs."
                fi
                ;;
            2)
                log_info "[debug-menu] Viewing live diagnostics logs"

                # Prefer aggregated diagnostics log when follower is running.
                local diag_dir today diag_file
                diag_dir="${LOG_DIR}/diagnostics"
                today="$(date +%Y-%m-%d)"
                diag_file="${diag_dir}/diag-${today}.log"

                if [ -f "${diag_file}" ] && systemctl is-active --quiet zypper-auto-diag-logs.service 2>/dev/null; then
                    echo "- Diagnostics log (aggregated): ${diag_file}"
                    echo "Press E or Enter to stop viewing logs and return to the menu."
                    log_info "[debug-menu] Live diagnostics viewer started (aggregated file: ${diag_file})"
                    tail -n 50 -F "${diag_file}" &
                    local tail_pid=$!
                    # Wait for user to press a single key (E or Enter) instead
                    # of using Ctrl+C, so we can return cleanly to the debug
                    # menu without killing the whole helper.
                    local key
                    read -r -n1 key
                    kill "${tail_pid}" 2>/dev/null || true
                    wait "${tail_pid}" 2>/dev/null || true
                    log_info "[debug-menu] Live diagnostics viewer stopped by user (aggregated file: ${diag_file})"
                    # After stopping the tail, re-render the menu.
                    continue
                fi

                # Fallback: tagged multi-source view mirroring --live-logs when
                # no aggregated diagnostics file is available.
                local latest_install_log=""
                latest_install_log=$(find "${LOG_DIR}" -maxdepth 1 -type f -name 'install-*.log' -printf '%T@\t%p\n' 2>/dev/null \
                    | sort -nr | head -1 | cut -f2- || true)

                # Build list of tagged sources to follow (INS, SYS, USR, TRC)
                local LIVE_SOURCES=()
                if [ -n "${latest_install_log}" ]; then
                    echo "- [INS] Installer log: ${latest_install_log}"
                    LIVE_SOURCES+=("INS:${latest_install_log}")
                fi

                if [ -d "${LOG_DIR}/service-logs" ]; then
                    # shellcheck disable=SC2086
                    for f in "${LOG_DIR}/service-logs"/*.log; do
                        if [ -f "$f" ]; then
                            echo "- [SYS] Service log: $f"
                            LIVE_SOURCES+=("SYS:${f}")
                        fi
                    done
                fi

                if [ -n "${SUDO_USER_HOME:-}" ] && [ -f "${SUDO_USER_HOME}/.local/share/zypper-notify/notifier-detailed.log" ]; then
                    echo "- [USR] Notifier log: ${SUDO_USER_HOME}/.local/share/zypper-notify/notifier-detailed.log"
                    LIVE_SOURCES+=("USR:${SUDO_USER_HOME}/.local/share/zypper-notify/notifier-detailed.log")
                fi

                if [ -n "${TRACE_LOG:-}" ] && [ -f "${TRACE_LOG}" ]; then
                    echo "- [TRC] Trace log: ${TRACE_LOG}"
                    LIVE_SOURCES+=("TRC:${TRACE_LOG}")
                fi

                if [ "${#LIVE_SOURCES[@]}" -eq 0 ]; then
                    echo "No log files found yet under ${LOG_DIR} or notifier directory."
                    continue
                fi

                # Record exactly which files we are about to follow so the
                # diagnostics bundle shows the same view the user saw.
                local _dbg_entry _dbg_tag _dbg_path
                for _dbg_entry in "${LIVE_SOURCES[@]}"; do
                    _dbg_tag="${_dbg_entry%%:*}"
                    _dbg_path="${_dbg_entry#*:}"
                    log_info "[debug-menu] Raw live-log target: TAG=${_dbg_tag} path=${_dbg_path}"
                done

                echo "Press E or Enter to stop viewing logs and return to the menu."
                log_info "[debug-menu] Live diagnostics viewer started (raw tagged logs)"

                # Launch one tail per source, prefixing each line with its tag,
                # and keep track of PIDs so we can cleanly stop on keypress.
                local live_pids=()
                local entry tag path
                for entry in "${LIVE_SOURCES[@]}"; do
                    tag="${entry%%:*}"
                    path="${entry#*:}"
                    if [ ! -f "${path}" ]; then
                        continue
                    fi
                    (
                        tail -n 50 -F "${path}" 2>/dev/null | sed -u "s/^/[${tag}] /"
                    ) &
                    live_pids+=("$!")
                done

                if [ "${#live_pids[@]}" -eq 0 ]; then
                    echo "No readable log files available to follow."
                    continue
                fi

                local key
                read -r -n1 key
                for pid in "${live_pids[@]}"; do
                    kill "${pid}" 2>/dev/null || true
                done
                for pid in "${live_pids[@]}"; do
                    wait "${pid}" 2>/dev/null || true
                done
                log_info "[debug-menu] Live diagnostics viewer stopped by user (raw tagged logs)"
                continue
                ;;
            3)
                log_info "[debug-menu] Capturing diagnostics snapshot"
                run_snapshot_state_only || true
                echo "Snapshot captured into today's diagnostics log."
                ;;
            4)
                log_info "[debug-menu] Creating diagnostics bundle"
                if run_diag_bundle_only; then
                    echo "Diagnostics bundle created successfully."
                else
                    echo "Failed to create diagnostics bundle (see install log)."
                fi
                ;;
            5)
                log_info "[debug-menu] Opening diagnostics logs folder"
                local diag_dir USER_BUS_PATH
                # Try to derive the desktop user's DBus session bus explicitly so
                # we do not depend on whatever DBUS_SESSION_BUS_ADDRESS happens to
                # be preserved by sudo. This mirrors how other helper modes
                # compute USER_BUS_PATH.
                USER_BUS_PATH="$(get_user_bus "${SUDO_USER:-}" 2>/dev/null || true)"
                diag_dir="${LOG_DIR}/diagnostics"
                echo "Diagnostics logs directory: ${diag_dir}"
                echo "Clickable:"
                print_clickable_url "file://${diag_dir}"
                execute_guarded "Ensure diagnostics log directory exists (${diag_dir})" mkdir -p "${diag_dir}" || true
                # Allow the desktop user to traverse the parent log directory
                # without making all logs world-readable. 751 = traverse but
                # not list contents; diagnostics subdir is then responsible for
                # exposing only the intended files.
                execute_guarded "Allow desktop user to traverse ${LOG_DIR}" chmod 751 "${LOG_DIR}" || true
                execute_guarded "Ensure diagnostics dir is user-traversable" chmod 755 "${diag_dir}" || true
                execute_guarded "Ensure diagnostics logs are user-readable" \
                    find "${diag_dir}" -type f -name 'diag-*.log' -exec chmod 644 {} \; || true

                # Try to open the diagnostics folder in the user's desktop session.
                local _open_rc
                if open_folder_in_desktop_session "${diag_dir}" "${SUDO_USER:-}"; then
                    _open_rc=0
                else
                    _open_rc=$?
                fi

                if [ "${_open_rc}" -ne 0 ] 2>/dev/null; then
                    log_warn "[debug-menu] Could not open diagnostics folder automatically (exit code ${_open_rc})"
                    log_warn "[debug-menu][SUMMARY] option=5 action=open-folder outcome=FAIL rc=${_open_rc} diag_dir=${diag_dir} user=${SUDO_USER:-<unset>}"
                    echo "Could not launch the file manager automatically. You can still access diagnostics logs at: ${diag_dir}"
                    echo "Clickable URL (many terminals/terminals-in-IDE will detect this): file://${diag_dir}"
                    echo "Tip: run 'systemd-run --user --scope xdg-open ${diag_dir}' or open it with your preferred file manager as your normal user."
                    # Automatically capture a one-shot diagnostics snapshot so that
                    # the aggregated diagnostics log contains detailed state
                    # around this failure (systemd unit status, status files,
                    # disk/network summary, and a short zypper preview).
                    if ! run_snapshot_state_only; then
                        log_warn "[debug-menu] Auto diagnostics snapshot after option 5 failure failed"
                    else
                        log_info "[debug-menu] Auto diagnostics snapshot captured after option 5 failure"
                    fi
                fi
                ;;
            6)
                log_info "[debug-menu] Notification system self-test"
                if [ -z "${SUDO_USER:-}" ]; then
                    log_error "Cannot run notification self-test without SUDO_USER (run via sudo)."
                    echo "This option must be run via sudo so we know which desktop user to notify."
                else
                    USER_BUS_PATH="unix:path=/run/user/$(id -u "${SUDO_USER}")/bus"
                    log_debug "Using user bus path for debug-menu test-notify: ${USER_BUS_PATH}"
                    # Launch the notifier self-test in the background so the
                    # debug menu remains responsive. The Python script itself
                    # keeps the test notification visible until you dismiss it.
                    sudo -u "${SUDO_USER}" DBUS_SESSION_BUS_ADDRESS="${USER_BUS_PATH}" \
                        ZNH_RUN_ID="${RUN_ID}" \
                        /usr/bin/python3 "${NOTIFY_SCRIPT_PATH}" --test-notify \
                        >/dev/null 2>&1 &
                    echo "Test notification launched. Close it from your desktop when you are done."
                fi
                ;;
            7)
                log_info "[debug-menu] Running helper self-check (syntax / config)"
                echo "Running installer/notifier self-check... (see latest install log for full details)."
                if ( run_self_check ); then
                    log_success "[debug-menu] Helper self-check completed successfully"
                    echo "Self-check completed successfully."
                else
                    rc=$?
                    log_error "[debug-menu] Helper self-check exited with rc=${rc} (see install log and last-status.txt)"
                    echo "Self-check reported problems (rc=${rc}). See the latest install log and last-status.txt for details."
                fi
                ;;
            8)
                log_info "[debug-menu] Folder opener self-test starting"
                local target_user target_uid run_dir bus candidates tool
                target_user="${SUDO_USER:-${USER:-}}"
                target_uid=$(id -u "${target_user}" 2>/dev/null || echo "")
                run_dir="/run/user/${target_uid}"
                bus="unix:path=${run_dir}/bus"

                echo "Folder opener self-test for user: ${target_user}"
                echo "  XDG_RUNTIME_DIR=${run_dir}"
                echo "  DBUS_SESSION_BUS_ADDRESS=${bus}"

                candidates=""
                if [ -n "${LOG_FOLDER_OPENER:-}" ]; then
                    candidates="${LOG_FOLDER_OPENER}"
                fi
                candidates="${candidates} kioclient5 kioclient kde-open5 kde-open exo-open xfce4-open gio xdg-open dolphin nautilus nemo thunar pcmanfm caja konqueror"

                for tool in ${candidates}; do
                    # Skip duplicates in the candidates list
                    [ -z "${tool}" ] && continue
                    if echo " ${seen_tools:-} " | grep -q " ${tool} "; then
                        continue
                    fi
                    seen_tools="${seen_tools:-} ${tool}"

                    if [ -n "${SUDO_USER:-}" ]; then
                        # NOTE: 'command -v' is a shell builtin. Do NOT run it directly via sudo.
                        tool_path=$(sudo -u "${target_user}" env PATH="/usr/local/bin:/usr/bin:/bin" \
                            sh -lc "command -v ${tool} 2>/dev/null | head -n 1" 2>/dev/null || true)
                        if [ -z "${tool_path}" ]; then
                            echo "  - ${tool}: not in PATH for ${target_user}"
                            log_debug "[debug-menu][opener-test] ${tool} not in PATH for ${target_user}"
                            continue
                        fi
                        echo "  - ${tool}: FOUND (${tool_path})"
                        log_info "[debug-menu][opener-test] ${tool} found: ${tool_path}"
                    else
                        tool_path=$(command -v "${tool}" 2>/dev/null || true)
                        if [ -z "${tool_path}" ]; then
                            echo "  - ${tool}: not in PATH (no SUDO_USER)"
                            log_debug "[debug-menu][opener-test] ${tool} not in PATH (no SUDO_USER)"
                            continue
                        fi
                        echo "  - ${tool}: FOUND (${tool_path})"
                        log_info "[debug-menu][opener-test] ${tool} found: ${tool_path} (no SUDO_USER)"
                    fi
                done

                echo "Folder opener self-test completed. Review any FAILED lines above and corresponding log entries for details."
                ;;
            9)
                log_info "[debug-menu] Running log health report (recent history)"
                echo "Running health analysis across recent installer logs... (see latest install log for full details)."
                if run_analyze_logs_only; then
                    echo "Health analysis completed successfully."
                else
                    rc=$?
                    log_error "[debug-menu] Health analysis exited with rc=${rc} (see install log and last-status.txt)"
                    echo "Health analysis reported problems (rc=${rc}). See the latest install log and last-status.txt for details."
                fi
                ;;
            10)
                log_info "[debug-menu] Running TID-scoped health report for last GUI trace"
                if [ -z "${SUDO_USER_HOME:-}" ]; then
                    echo "Cannot locate user notifier logs (SUDO_USER_HOME is not set)."
                    log_error "[debug-menu] Cannot run TID-scoped health report: SUDO_USER_HOME unset"
                    # Return to menu without exiting the whole helper.
                    continue
                fi

                local _user_log _last_tid
                _user_log="${SUDO_USER_HOME}/.local/share/zypper-notify/notifier-detailed.log"
                if [ ! -f "${_user_log}" ]; then
                    echo "User notifier log not found at ${_user_log}. Falling back to generic health report."
                    log_error "[debug-menu] User notifier log missing at ${_user_log}; falling back to generic health report"
                    if run_analyze_logs_only; then
                        echo "Generic health analysis completed successfully."
                    else
                        rc=$?
                        log_error "[debug-menu] Generic health analysis exited with rc=${rc}"
                        echo "Health analysis reported problems (rc=${rc}). See the latest install log and last-status.txt for details."
                    fi
                    continue
                fi

                _last_tid=$(grep "Generated Trace ID for install action" "${_user_log}" 2>/dev/null | tail -n 1 | sed -E 's/.*Trace ID for install action: ([A-Za-z0-9_-]+).*/\1/' || true)
                if [ -z "${_last_tid}" ]; then
                    echo "No recent GUI Trace ID found in ${_user_log}. Falling back to generic health report."
                    log_error "[debug-menu] No Trace ID found in notifier logs; falling back to generic health report"
                    if run_analyze_logs_only; then
                        echo "Generic health analysis completed successfully."
                    else
                        rc=$?
                        log_error "[debug-menu] Generic health analysis exited with rc=${rc}"
                        echo "Health analysis reported problems (rc=${rc}). See the latest install log and last-status.txt for details."
                    fi
                    continue
                fi

                echo "Using Trace ID: ${_last_tid}"
                log_info "[debug-menu] Running TID-scoped health analysis for TID=${_last_tid}"
                if run_analyze_logs_only "TID=${_last_tid}"; then
                    echo "TID-scoped health analysis completed successfully."
                else
                    rc=$?
                    log_error "[debug-menu] TID-scoped health analysis exited with rc=${rc} (TID=${_last_tid})"
                    echo "Health analysis for TID=${_last_tid} reported problems (rc=${rc}). See the latest install log and last-status.txt for details."
                fi
                ;;
            11)
                log_info "[debug-menu] Showing last diagnostics snapshot info (path + tail)"
                local _snap_dir _latest_snap
                _snap_dir="${LOG_DIR}/diagnostics"
                _latest_snap=$(find "${_snap_dir}" -maxdepth 1 -type f -name 'diag-*.log' -printf '%T@\t%p\n' 2>/dev/null \
                    | sort -nr | head -1 | cut -f2- || true)
                if [ -z "${_latest_snap}" ] || [ ! -f "${_latest_snap}" ]; then
                    echo "No diagnostics snapshot files found under ${_snap_dir}."
                    log_error "[debug-menu] No diagnostics snapshot files found under ${_snap_dir} when option 11 selected"
                else
                    echo "Latest diagnostics snapshot file: ${_latest_snap}"
                    log_info "[debug-menu] Latest diagnostics snapshot file: ${_latest_snap}"
                    echo ""
                    echo "---- Last 40 lines of snapshot ----"
                    tail -n 40 "${_latest_snap}" 2>/dev/null || echo "(unreadable or empty)"
                    echo "-----------------------------------"
                fi
                ;;
            12)
                log_info "[debug-menu] Tailing dashboard API log"
                local api_log
                api_log="${LOG_DIR}/service-logs/dashboard-api.log"
                if [ ! -f "${api_log}" ]; then
                    echo "Dashboard API log not found yet at ${api_log}."
                    echo "Tip: open dashboard once to start API: zypper-auto-helper --dash-open"
                    continue
                fi
                echo "- [API] ${api_log}"
                echo "Press E or Enter to stop viewing logs and return to the menu."
                tail -n 60 -F "${api_log}" &
                local tail_pid=$!
                local key
                read -r -n1 key
                kill "${tail_pid}" 2>/dev/null || true
                wait "${tail_pid}" 2>/dev/null || true
                continue
                ;;
            13|q|Q|e|E)
                log_info "[debug-menu] Exiting debug/diagnostics menu"
                break
                ;;
            *)
                echo "Invalid selection: '${choice}'. Please enter a number between 1 and 12, or E/Q to exit."
                ;;
        esac
    done
}

# --- Helper: Reset download/notifier state (CLI) ---
run_reset_download_state_only() {
    log_info ">>> Resetting zypper-auto-helper download/notifier state..."

    echo "" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"
    echo "  zypper-auto-helper State Reset" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"
    echo "This will clear cached download status and notifier state files" | tee -a "${LOG_FILE}"
    echo "without removing any services, timers, or configuration." | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"

    update_status "Resetting download/notifier state..."

    # 1. Root-level downloader state under /var/log/zypper-auto
    if [ -d "${LOG_DIR}" ]; then
        log_debug "Clearing root download state files under ${LOG_DIR}..."
        execute_guarded "Clear downloader state files" rm -f \
              "${LOG_DIR}/download-status.txt" \
              "${LOG_DIR}/download-last-check.txt" \
              "${LOG_DIR}/download-start-time.txt" \
              "${LOG_DIR}/dry-run-last.txt" || true
    else
        log_debug "Log directory ${LOG_DIR} does not exist; nothing to reset at root level"
    fi

    # 2. User-level notifier logs and caches
    if [ -n "${SUDO_USER_HOME:-}" ]; then
        USER_LOG_DIR="${SUDO_USER_HOME}/.local/share/zypper-notify"
        USER_CACHE_DIR="${SUDO_USER_HOME}/.cache/zypper-notify"

        log_debug "Clearing user notifier state under ${USER_LOG_DIR} and ${USER_CACHE_DIR}..."

        execute_guarded "Ensure user notifier state dirs exist" mkdir -p "${USER_LOG_DIR}" "${USER_CACHE_DIR}" || true

        execute_guarded "Clear user notifier state files" rm -f \
              "${USER_LOG_DIR}/last-run-status.txt" \
              "${USER_LOG_DIR}/last-notified-snapshot.txt" \
              "${USER_CACHE_DIR}/last-output.txt" || true
    fi

    log_success "Download/notifier state reset completed"
    update_status "SUCCESS: zypper-auto-helper download/notifier state reset"
}

# --- Helper: Analyze logs and print a health report (CLI) ---
run_analyze_logs_only() {
    log_info ">>> Running log health analysis..."

    # Optional: allow a TID filter via arguments, e.g. TID=GUI-xxxx or --tid=GUI-xxxx.
    local TID_FILTER=""
    for arg in "$@"; do
        case "${arg}" in
            TID=*)
                TID_FILTER="${arg#TID=}"
                ;;
            --tid=*)
                TID_FILTER="${arg#--tid=}"
                ;;
        esac
    done

    echo "" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"
    echo "  Zypper Auto-Helper Health Report"               | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"

    if [ -n "${TID_FILTER}" ]; then
        echo "Trace ID filter: ${TID_FILTER} (only lines with TID=${TID_FILTER})" | tee -a "${LOG_FILE}"
    fi

    # Collect up to the 10 most recent installer logs.
    local log_files=()
    while IFS= read -r f; do
        [ -n "${f}" ] && log_files+=("${f}")
    done < <(
        find "${LOG_DIR}" -maxdepth 1 -type f -name 'install-*.log' -printf '%T@\t%p\n' 2>/dev/null \
            | sort -nr | head -10 | cut -f2- || true
    )

    if [ "${#log_files[@]}" -eq 0 ]; then
        echo "No installer logs found under ${LOG_DIR}." | tee -a "${LOG_FILE}"
        update_status "FAILED: Health analysis could not find any installer logs"
        return 1
    fi

    echo "Installer logs scanned (up to 10): ${#log_files[@]}" | tee -a "${LOG_FILE}"
    echo "  - Latest: ${log_files[0]}" | tee -a "${LOG_FILE}"

    # 1. Calculate Success/Failure markers across logs (optionally filtered by TID)
    local total_runs=0 errors=0 successes=0
    local lf
    for lf in "${log_files[@]}"; do
        local tr e s
        if [ -n "${TID_FILTER}" ]; then
            tr=$(grep "TID=${TID_FILTER}" "${lf}" 2>/dev/null | grep -c "Invoked as" || echo 0)
            e=$(grep "TID=${TID_FILTER}" "${lf}" 2>/dev/null | grep -c "\[ERROR\]" || echo 0)
            s=$(grep "TID=${TID_FILTER}" "${lf}" 2>/dev/null | grep -c "\[SUCCESS\]" || echo 0)
        else
            tr=$(grep -c "Invoked as" "${lf}" 2>/dev/null || echo 0)
            e=$(grep -c "\[ERROR\]" "${lf}" 2>/dev/null || echo 0)
            s=$(grep -c "\[SUCCESS\]" "${lf}" 2>/dev/null || echo 0)
        fi
        total_runs=$((total_runs + tr))
        errors=$((errors + e))
        successes=$((successes + s))
    done

    echo "" | tee -a "${LOG_FILE}"
    echo "History (aggregated across recent installer logs):" | tee -a "${LOG_FILE}"
    echo "  - Total Invocations: ${total_runs}"               | tee -a "${LOG_FILE}"
    echo "  - Errors Detected:   ${errors}"                   | tee -a "${LOG_FILE}"
    echo "  - Success Markers:   ${successes}"                | tee -a "${LOG_FILE}"

    # 2. Find Most Frequent Errors
    echo "" | tee -a "${LOG_FILE}"
    echo "Top 3 Recurring Errors (recent logs):" | tee -a "${LOG_FILE}"
    if [ "${errors}" -gt 0 ]; then
        if [ -n "${TID_FILTER}" ]; then
            grep "TID=${TID_FILTER}" "${log_files[@]}" 2>/dev/null \
                | grep "\[ERROR\]" \
                | cut -d']' -f4- | sed 's/^ *//' \
                | sort | uniq -c | sort -nr | head -3 \
                | awk '{print "  " $0}' | tee -a "${LOG_FILE}"
        else
            grep "\[ERROR\]" "${log_files[@]}" 2>/dev/null \
                | cut -d']' -f4- | sed 's/^ *//' \
                | sort | uniq -c | sort -nr | head -3 \
                | awk '{print "  " $0}' | tee -a "${LOG_FILE}"
        fi
    else
        echo "  (No errors found in recent installer logs)" | tee -a "${LOG_FILE}"
    fi

    # 3. Analyze Lock Contention (how often zypper was locked)
    local locks_raw
    if [ -n "${TID_FILTER}" ]; then
        locks_raw=$(grep "TID=${TID_FILTER}" "${log_files[@]}" 2>/dev/null \
            | grep -cE "Zypper is locked by another process|System management is locked" || echo 0)
    else
        locks_raw=$(grep -cE "Zypper is locked by another process|System management is locked" \
            "${log_files[@]}" 2>/dev/null || echo 0)
    fi
    local locks="${locks_raw:-0}"
    echo "" | tee -a "${LOG_FILE}"
    echo "Concurrency Check:"                       | tee -a "${LOG_FILE}"
    echo "  - Zypper Lock Contentions: ${locks}"    | tee -a "${LOG_FILE}"

    # 4. Download Performance from downloader service logs
    echo "" | tee -a "${LOG_FILE}"
    echo "Download Performance (last 5 entries):" | tee -a "${LOG_FILE}"
    if [ -f "${LOG_DIR}/service-logs/downloader.log" ]; then
        grep "Downloaded" "${LOG_DIR}/service-logs/downloader.log" 2>/dev/null \
            | tail -n 5 | sed 's/^/  - /' | tee -a "${LOG_FILE}" || true
    else
        echo "  (No downloader logs found at ${LOG_DIR}/service-logs/downloader.log)" \
            | tee -a "${LOG_FILE}"
    fi

    # 5. Notifier Health (user side)
    echo "" | tee -a "${LOG_FILE}"
    echo "Notifier Health:" | tee -a "${LOG_FILE}"
    local user_log
    if [ -n "${SUDO_USER_HOME:-}" ]; then
        user_log="${SUDO_USER_HOME}/.local/share/zypper-notify/notifier-detailed.log"
    else
        user_log=""
    fi

    if [ -n "${user_log}" ] && [ -f "${user_log}" ]; then
        local last_seen crashes
        last_seen=$(tail -n 1 "${user_log}" 2>/dev/null | cut -d']' -f1 | tr -d '[' || echo "unknown")
        echo "  - Last User Notification Activity: ${last_seen}" | tee -a "${LOG_FILE}"
        crashes=$(grep -c "Traceback" "${user_log}" 2>/dev/null || echo 0)
        if [ "${crashes}" -gt 0 ]; then
            echo -e "  - \033[31mCRITICAL: ${crashes} Python crashes detected in user logs\033[0m" \
                | tee -a "${LOG_FILE}"
        else
            echo "  - No Python crashes detected." | tee -a "${LOG_FILE}"
        fi
    else
        echo "  (User notifier logs not accessible or missing)" | tee -a "${LOG_FILE}"
    fi

    # 6. Deep Zypper System Log Analysis
    echo "" | tee -a "${LOG_FILE}"
    echo "Deep Zypper System Log Analysis (/var/log/zypper.log):" | tee -a "${LOG_FILE}"
    if [ -f "/var/log/zypper.log" ]; then
        local solver_fails sig_kills
        solver_fails=$(tail -n 1000 /var/log/zypper.log 2>/dev/null | grep -c "solver test detected problem" || echo 0)
        sig_kills=$(tail -n 1000 /var/log/zypper.log 2>/dev/null | grep -c "received signal" || echo 0)
        echo "  - Recent Solver Problems: ${solver_fails}" | tee -a "${LOG_FILE}"
        if [ "${sig_kills}" -gt 0 ] 2>/dev/null; then
            echo -e "  - \033[31mCRITICAL: Zypper process was killed ${sig_kills} times (OOM or user signal)\033[0m" | tee -a "${LOG_FILE}"
        else
            echo "  - No signal kills detected (clean exits)." | tee -a "${LOG_FILE}"
        fi
    else
        echo "  (System zypper.log not accessible)" | tee -a "${LOG_FILE}"
    fi

    echo "==============================================" | tee -a "${LOG_FILE}"
    update_status "SUCCESS: Health analysis completed"
}

# --- Helper: Duplicate RPM conflict cleanup (CLI) ---
run_rm_conflict_only() {
    log_info ">>> Running duplicate RPM conflict cleanup..."
    update_status "Cleaning duplicate RPM conflicts..."

    # Colour setup for interactive clarity
    local RED GREEN YELLOW BLUE RESET
    RED=$'\033[0;31m'
    GREEN=$'\033[0;32m'
    YELLOW=$'\033[0;33m'
    BLUE=$'\033[0;34m'
    RESET=$'\033[0m'

    # Unified audit log: record manual duplicate removals in the same
    # duplicate-cleanup log used by the zypper-with-ps wrapper.
    local AUDIT_LOG="/var/log/zypper-auto/duplicate-cleanup.log"
    log_audit() {
        local msg="$1" ts
        ts=$(date '+%Y-%m-%d %H:%M:%S')
        mkdir -p "/var/log/zypper-auto" 2>/dev/null || true
        printf '%s\n' "[$ts] [rm-conflict] $msg" >> "$AUDIT_LOG"
    }

    local mode
    mode=${AUTO_DUPLICATE_RPM_MODE:-whitelist}

    echo "Duplicate RPM cleanup mode: ${mode}"
    log_info "Duplicate RPM cleanup mode (run_rm_conflict_only): ${mode}"

    # Ultimate safety net for manual mode: create a Snapper snapshot
    # before attempting any duplicate cleanup, if available.
    if command -v snapper >/dev/null 2>&1; then
        if pgrep -x snapper >/dev/null 2>&1; then
            printf '%b\n' "${YELLOW}   Snapper is already running; skipping pre-cleanup snapshot.${RESET}"
            log_info "[rm-conflict][snapshot] Snapper busy; skipped pre-cleanup snapshot"
        else
            local SNAP_DESC="zypper-auto: duplicate RPM cleanup (--rm-conflict)"
            log_info "[rm-conflict][snapshot] Creating snapper single snapshot: '$SNAP_DESC'"

            local snap_timeout snap_rc
            snap_timeout="${ZNH_SAFETY_SNAPSHOT_TIMEOUT_SECONDS:-90}"
            if ! [[ "${snap_timeout}" =~ ^[0-9]+$ ]] || [ "${snap_timeout}" -lt 10 ] 2>/dev/null; then
                snap_timeout=90
            fi

            local -a _snapper_cmd
            _snapper_cmd=(snapper)
            if __znh_snapper_supports_no_dbus; then
                _snapper_cmd=(snapper --no-dbus)
            fi

            set +e
            if command -v timeout >/dev/null 2>&1; then
                timeout "${snap_timeout}" "${_snapper_cmd[@]}" create -t single -p -d "$SNAP_DESC" >/dev/null 2>&1
                snap_rc=$?
            else
                "${_snapper_cmd[@]}" create -t single -p -d "$SNAP_DESC" >/dev/null 2>&1
                snap_rc=$?
            fi
            set -e

            if [ "${snap_rc:-1}" -eq 0 ] 2>/dev/null; then
                printf '%b\n' "${GREEN}   Created snapper snapshot before manual duplicate cleanup.${RESET}"
                log_success "[rm-conflict][snapshot] Snapshot created successfully"
            elif [ "${snap_rc:-1}" -eq 124 ] 2>/dev/null || [ "${snap_rc:-1}" -eq 137 ] 2>/dev/null; then
                printf '%b\n' "${YELLOW}   WARNING: Snapper snapshot timed out after ${snap_timeout}s; proceeding without snapshot.${RESET}"
                log_warn "[rm-conflict][snapshot] Snapshot creation timed out after ${snap_timeout}s; proceeding without snapshot"
            else
                printf '%b\n' "${YELLOW}   WARNING: Failed to create snapper snapshot; proceeding without snapshot.${RESET}"
                log_error "[rm-conflict][snapshot] FAILED to create snapshot; proceeding without snapshot"
            fi
        fi
    else
        log_info "[rm-conflict][snapshot] snapper not installed; skipping snapshot creation"
    fi

    # 1) Whitelist-driven cleanup (uses AUTO_DUPLICATE_RPM_CLEANUP_PACKAGES)
    if [ "$mode" = "whitelist" ] || [ "$mode" = "both" ]; then
        local packages name
        packages=${AUTO_DUPLICATE_RPM_CLEANUP_PACKAGES:-insync}

        for name in $packages; do
            [ -z "$name" ] && continue
            if ! rpm -q "$name" >/dev/null 2>&1; then
                continue
            fi

            local count
            count=$(rpm -q "$name" 2>/dev/null | wc -l || echo 0)
            if [ "$count" -le 1 ]; then
                continue
            fi

            echo ""
            echo "[whitelist] Detected multiple installed versions of '$name'."
            echo "  Attempting to remove older versions (keeping the newest) before upgrades..."
            log_info "[rm-conflict][whitelist] Detected multiple versions for '$name'"

            local lines newest
            # List full NVRAs for this package and sort by version; keep the
            # newest line and treat the rest as older duplicates.
            lines=$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' "$name" 2>/dev/null | sort -V) || continue
            newest=$(echo "$lines" | tail -n1)
            if [ -z "$newest" ]; then
                continue
            fi

            echo "  - Keeping newest: $newest"
            log_info "[rm-conflict][whitelist] Keeping newest for '$name': $newest"
            echo "$lines" | head -n -1 | while read -r pkg; do
                [ -z "$pkg" ] && continue
            echo "  - Removing older duplicate: $pkg"
            log_info "[rm-conflict][whitelist] Removing older duplicate: $pkg (keeping $newest)"
            # Dependency pre-flight: simulate removal before actually erasing
                if rpm -e --test --noscripts "$pkg" >/dev/null 2>&1; then
                if rpm -e --noscripts "$pkg"; then
                    echo "      ✓ Removed $pkg"
                    log_success "[rm-conflict][whitelist] Removed $pkg"
                    log_audit "Removed whitelist duplicate: $pkg (keeping $newest)"
                else
                    echo "      ✗ Failed to remove $pkg"
                    log_error "[rm-conflict][whitelist] Failed to remove $pkg"
                    log_audit "FAILED to remove whitelist duplicate: $pkg (keeping $newest)"
                fi
            else
                echo "      ⚠ Skipping $pkg: rpm -e --test reported dependency failures"
                log_info "[rm-conflict][whitelist] Skipping $pkg: rpm -e --test reported dependency failures"
                log_audit "Skipped whitelist duplicate (dependency test failed): $pkg (keeping $newest)"
            fi
            done
        done
    fi

    # 2) Optional vendor-based third-party duplicate cleanup (same rules
    # as the wrapper's cleanup_thirdparty_duplicates, but using rpm
    # directly as root instead of sudo).
    if [ "$mode" = "thirdparty" ] || [ "$mode" = "both" ]; then
        local SAFE_VENDORS CRITICAL_PKGS
        SAFE_VENDORS="openSUSE|SUSE|Packman|NVIDIA|Intel|http://packman|obs://build.opensuse.org"
        # NOTE: include 'filesystem' here – if rpm ever forgets ownership
        # of /usr or /bin, future upgrades can break badly.
        CRITICAL_PKGS="^kernel-|nvidia|glibc|systemd|grub|shim|mokutil|filesystem"

        echo ""
        printf '%b\n' "${BLUE}[thirdparty] Scanning for duplicate third-party packages (safe vendors: ${SAFE_VENDORS}, critical patterns: ${CRITICAL_PKGS})...${RESET}"

        # Find duplicate package *name+arch* pairs (multi-version within the
        # same architecture) to avoid treating legitimate multi-arch installs
        # (e.g. x86_64 + i686) as conflicts.
        local DUPLICATE_PAIRS
        DUPLICATE_PAIRS=$(rpm -qa --qf '%{NAME} %{ARCH}\\n' 2>/dev/null | sort | uniq -d)
        if [ -z "$DUPLICATE_PAIRS" ]; then
            echo "   No duplicate third-party packages found."
        else
            # Sanity limit: if there are *too many* duplicate name+arch pairs,
            # assume something is wrong with the RPM DB and abort automatic
            # third-party cleanup to avoid mass deletions.
            local num_pairs
            num_pairs=$(echo "$DUPLICATE_PAIRS" | wc -l | awk '{print $1}')
            if [ "$num_pairs" -gt 10 ]; then
                echo "   WARNING: Found $num_pairs duplicate (name+arch) pairs; safety limit is 10."
                echo "            Aborting automatic third-party duplicate cleanup; please investigate manually."
                return 0
            fi

            local PKG ARCH VENDOR ALL_VERSIONS REMOVE_LIST OLD_PKG
            echo "$DUPLICATE_PAIRS" | while read -r PKG ARCH; do
                [ -z "$PKG" ] && continue

                if echo "$PKG" | grep -qE "$CRITICAL_PKGS"; then
                    printf '%b\n' "${YELLOW}   Skipping CRITICAL package: $PKG.$ARCH (safety override)${RESET}"
                    log_info "[rm-conflict][thirdparty] Skipping CRITICAL package: $PKG.$ARCH"
                    continue
                fi

                # Extra safety: never touch GPG pubkey packages.
                if echo "$PKG" | grep -qi '^gpg-pubkey'; then
                    printf '%b\n' "${YELLOW}   Skipping GPG key package: $PKG.$ARCH${RESET}"
                    log_info "[rm-conflict][thirdparty] Skipping GPG key package: $PKG.$ARCH"
                    continue
                fi

                VENDOR=$(rpm -q --qf '%{VENDOR}\\n' "${PKG}.${ARCH}" 2>/dev/null | head -n 1)
                VENDOR=${VENDOR:-UnknownVendor}

                if echo "$VENDOR" | grep -qiE "$SAFE_VENDORS"; then
                    printf '%b\n' "${YELLOW}   Skipping trusted-vendor package: $PKG.$ARCH (Vendor: $VENDOR)${RESET}"
                    log_info "[rm-conflict][thirdparty] Skipping trusted-vendor package: $PKG.$ARCH (Vendor: $VENDOR)"
                    continue
                fi

                printf '%b\n' "${RED}   Found third-party duplicate: $PKG.$ARCH (Vendor: $VENDOR)${RESET}"
                log_info "[rm-conflict][thirdparty] Found third-party duplicate: $PKG.$ARCH (Vendor: $VENDOR)"

                ALL_VERSIONS=$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n' --last "${PKG}.${ARCH}" 2>/dev/null)
                REMOVE_LIST=$(echo "$ALL_VERSIONS" | tail -n +2 | awk '{print $1}')

                if [ -z "$REMOVE_LIST" ]; then
                    echo "      (Duplicate reported but no removable versions found; skipping.)"
                    continue
                fi

                for OLD_PKG in $REMOVE_LIST; do
                    [ -z "$OLD_PKG" ] && continue
                    printf '%b\n' "${RED}      Removing old/broken version: $OLD_PKG${RESET}"
                    log_info "[rm-conflict][thirdparty] Removing old/broken version: $OLD_PKG (from $PKG.$ARCH; vendor=$VENDOR)"
                    # Dependency pre-flight: simulate removal before actually erasing
                    if sudo rpm -e --test --noscripts "$OLD_PKG" >/dev/null 2>&1; then
                        if sudo rpm -e --noscripts "$OLD_PKG"; then
                            printf '%b\n' "${GREEN}         Cleaned successfully.${RESET}"
                            log_success "[rm-conflict][thirdparty] Cleaned $OLD_PKG successfully"
                            log_audit "Removed third-party duplicate: $OLD_PKG (from $PKG.$ARCH; vendor=$VENDOR)"
                        else
                            printf '%b\n' "${YELLOW}         Failed to clean $OLD_PKG (possibly RPM lock or manual intervention needed).${RESET}"
                            log_error "[rm-conflict][thirdparty] Failed to clean $OLD_PKG"
                            log_audit "FAILED to remove third-party duplicate: $OLD_PKG (from $PKG.$ARCH; vendor=$VENDOR)"
                        fi
                    else
                        printf '%b\n' "${YELLOW}         Skipping $OLD_PKG: rpm -e --test reported dependency failures${RESET}"
                        log_info "[rm-conflict][thirdparty] Skipping $OLD_PKG: rpm -e --test reported dependency failures"
                        log_audit "Skipped third-party duplicate (dependency test failed): $OLD_PKG (from $PKG.$ARCH; vendor=$VENDOR)"
                    fi
                done
            done
        fi
    fi

    log_success "Duplicate RPM conflict cleanup completed"
    update_status "SUCCESS: Duplicate RPM conflict cleanup completed"
}

# --- Helper: Status report (CLI) ---
run_status_only() {
    log_info ">>> zypper-auto-helper status report..."

    echo "" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"
    echo "  zypper-auto-helper Status" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"

    # 1. Core system timers/services
    for unit in "${DL_SERVICE_NAME}.timer" "${VERIFY_SERVICE_NAME}.timer"; do
        if systemctl list-unit-files "$unit" >/dev/null 2>&1; then
            active=$(systemctl is-active "$unit" 2>/dev/null || echo "unknown")
            enabled=$(systemctl is-enabled "$unit" 2>/dev/null || echo "unknown")
            echo "- [system] $unit: active=$active, enabled=$enabled" | tee -a "${LOG_FILE}"
        else
            echo "- [system] $unit: not installed" | tee -a "${LOG_FILE}"
        fi
    done

    # Diagnostics follower (root)
    if systemctl list-unit-files "${DIAG_SERVICE_NAME}.service" >/dev/null 2>&1; then
        d_active=$(systemctl is-active "${DIAG_SERVICE_NAME}.service" 2>/dev/null || echo "unknown")
        d_enabled=$(systemctl is-enabled "${DIAG_SERVICE_NAME}.service" 2>/dev/null || echo "unknown")
        echo "- [system] ${DIAG_SERVICE_NAME}.service: active=$d_active, enabled=$d_enabled" | tee -a "${LOG_FILE}"
    else
        echo "- [system] ${DIAG_SERVICE_NAME}.service: not installed" | tee -a "${LOG_FILE}"
    fi

    # 2. User notifier timer/service
    if [ -n "${SUDO_USER:-}" ]; then
        USER_BUS_PATH="$(get_user_bus "$SUDO_USER" || true)"
        if [ -n "${USER_BUS_PATH}" ]; then
            if sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" \
                systemctl --user list-unit-files "${NT_SERVICE_NAME}.timer" >/dev/null 2>&1; then
                nt_active=$(sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" \
                    systemctl --user is-active "${NT_SERVICE_NAME}.timer" 2>/dev/null || echo "unknown")
                nt_enabled=$(sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" \
                    systemctl --user is-enabled "${NT_SERVICE_NAME}.timer" 2>/dev/null || echo "unknown")
                echo "- [user:$SUDO_USER] ${NT_SERVICE_NAME}.timer: active=$nt_active, enabled=$nt_enabled" | tee -a "${LOG_FILE}"
            else
                echo "- [user:$SUDO_USER] ${NT_SERVICE_NAME}.timer: not installed" | tee -a "${LOG_FILE}"
            fi
        else
            echo "- [user:$SUDO_USER] systemd user bus not available; cannot query notifier timer" | tee -a "${LOG_FILE}"
        fi
    fi

    # 3. Downloader status file
    if [ -f "${LOG_DIR}/download-status.txt" ]; then
        ds_contents=$(cat "${LOG_DIR}/download-status.txt" 2>/dev/null || echo "(unreadable)")
        echo "- download-status.txt: $ds_contents" | tee -a "${LOG_FILE}"
    else
        echo "- download-status.txt: not present (created on first downloader run)" | tee -a "${LOG_FILE}"
    fi

    # 4. Notifier last-run-status and environment state
    if [ -n "${SUDO_USER_HOME:-}" ]; then
        USER_LOG_DIR="${SUDO_USER_HOME}/.local/share/zypper-notify"
        USER_CACHE_DIR="${SUDO_USER_HOME}/.cache/zypper-notify"
        if [ -f "${USER_LOG_DIR}/last-run-status.txt" ]; then
            last_status=$(tail -n 1 "${USER_LOG_DIR}/last-run-status.txt" 2>/dev/null || echo "(unreadable)")
            echo "- last-run-status.txt: $last_status" | tee -a "${LOG_FILE}"
        else
            echo "- last-run-status.txt: not present" | tee -a "${LOG_FILE}"
        fi
        if [ -f "${USER_CACHE_DIR}/env_state.txt" ]; then
            env_state=$(cat "${USER_CACHE_DIR}/env_state.txt" 2>/dev/null || echo "(unreadable)")
            echo "- env_state.txt: $env_state" | tee -a "${LOG_FILE}"
        else
            echo "- env_state.txt: not present (set after first notifier run)" | tee -a "${LOG_FILE}"
        fi
    fi

    update_status "SUCCESS: Status report generated"
}

# --- Helper: Soar-only installation mode (CLI) ---
run_soar_install_only() {
    update_status "Running Soar installation helper..."

    SOAR_PRESENT=0

    # Detect Soar for the target user in common locations
    if sudo -u "$SUDO_USER" command -v soar >/dev/null 2>&1; then
        SOAR_PRESENT=1
    elif [ -x "$SUDO_USER_HOME/.local/bin/soar" ]; then
        SOAR_PRESENT=1
    elif [ -d "$SUDO_USER_HOME/pkgforge" ] && \
         find "$SUDO_USER_HOME/pkgforge" -maxdepth 1 -type f -name 'soar*' -perm -u+x 2>/dev/null | grep -q .; then
        SOAR_PRESENT=1
    fi

    if [ "$SOAR_PRESENT" -eq 1 ]; then
        log_success "Soar already appears to be installed for user $SUDO_USER"
        echo "Soar appears to be installed for user $SUDO_USER." | tee -a "${LOG_FILE}"
        echo "Try: sudo -u $SUDO_USER soar --help" | tee -a "${LOG_FILE}"
        return 0
    fi

    if ! command -v curl >/dev/null 2>&1; then
        log_error "curl is required to install Soar but is not installed."
        echo "Install curl with: sudo zypper install curl" | tee -a "${LOG_FILE}"
        return 1
    fi

    SOAR_INSTALL_CMD='curl -fsSL "https://raw.githubusercontent.com/pkgforge/soar/main/install.sh" | sh'

    echo "" | tee -a "${LOG_FILE}"
    echo "This will run the official Soar installer as user $SUDO_USER:" | tee -a "${LOG_FILE}"
    echo "  $SOAR_INSTALL_CMD" | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"

    if sudo -u "$SUDO_USER" bash -lc "$SOAR_INSTALL_CMD"; then
        log_success "Soar installation finished for user $SUDO_USER"
        echo "" | tee -a "${LOG_FILE}"
        echo "You can now run: sudo -u $SUDO_USER soar sync" | tee -a "${LOG_FILE}"
        return 0
    else
        local rc=$?
        log_error "Soar installer exited with code $rc"
        return $rc
    fi
}

# --- Helper: Uninstall core zypper-auto-helper components ---
run_uninstall_helper_only() {
    log_info ">>> Uninstalling zypper-auto-helper core components..."

    local hooks_dir="${HOOKS_BASE_DIR:-/etc/zypper-auto/hooks}"
    local cleanup_report_dir="${CLEANUP_REPORT_DIR:-${LOG_DIR}/cleanup-reports}"
    local helper_backup_dir="/var/backups/zypper-auto"

    echo "" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"
    echo "  zypper-auto-helper Uninstall" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"
    echo "This will remove timers, services, helper binaries, logs, and user" | tee -a "${LOG_FILE}"
    echo "scripts/aliases installed by zypper-auto-helper for user $SUDO_USER." | tee -a "${LOG_FILE}"
    echo "The installer script (zypper-auto.sh) and your Soar/Homebrew installs" | tee -a "${LOG_FILE}"
    echo "will be left untouched. It also does NOT remove snapd, Flatpak, Soar," | tee -a "${LOG_FILE}"
    echo "Homebrew itself, or any zypper configuration such as /etc/zypp/zypper.conf." | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"
    echo "NOTE: Snapper/btrfs/fstrim timers are OS features and are NOT disabled by" | tee -a "${LOG_FILE}"
    echo "default. If you want the uninstaller to also disable those timers (Option 5" | tee -a "${LOG_FILE}"
    echo "automation), run the uninstaller with: --disable-maintenance-timers" | tee -a "${LOG_FILE}"
    echo "This uninstaller NEVER deletes OS unit files under /usr/lib/systemd/system" | tee -a "${LOG_FILE}"
    echo "(it only removes zypper-auto-helper's own units under /etc/systemd/system)." | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"

    # Handle dry-run and non-interactive flags from the CLI dispatcher.
    if [ "${UNINSTALL_DRY_RUN:-0}" -eq 1 ]; then
        log_info "Dry-run mode active: NO changes will be made."
        echo "" | tee -a "${LOG_FILE}"
        echo "The following items WOULD be removed if you run without --dry-run:" | tee -a "${LOG_FILE}"
        echo "  - System services/timers: zypper-autodownload.service, zypper-autodownload.timer" | tee -a "${LOG_FILE}"
        echo "    zypper-cache-cleanup.service, zypper-cache-cleanup.timer" | tee -a "${LOG_FILE}"
        echo "    zypper-auto-verify.service, zypper-auto-verify.timer" | tee -a "${LOG_FILE}"
        echo "    zypper-auto-diag-logs.service (diagnostics follower)" | tee -a "${LOG_FILE}"
        echo "  - Cleanup audit reports: ${cleanup_report_dir}" | tee -a "${LOG_FILE}"
        echo "  - Helper backups: ${helper_backup_dir}/boot-entries-* and ${helper_backup_dir}/btrfsmaintenance-*.bak" | tee -a "${LOG_FILE}"
        echo "  - /boot/do_purge_kernels marker (if present)" | tee -a "${LOG_FILE}"
        if [ "${UNINSTALL_DISABLE_MAINT_TIMERS:-0}" -eq 1 ]; then
            echo "  - ALSO disable OS timers (requested): snapper-*.timer, btrfs-*.timer, fstrim.timer" | tee -a "${LOG_FILE}"
            echo "    (NOTE: this only disables timers; it does NOT delete OS unit files)" | tee -a "${LOG_FILE}"
        else
            echo "  - OS timers (snapper/btrfs/fstrim) would NOT be disabled (default)." | tee -a "${LOG_FILE}"
            echo "    (OS unit files are never deleted by this uninstaller)" | tee -a "${LOG_FILE}"
        fi
        echo "  - Root binaries: /usr/local/bin/zypper-download-with-progress, /usr/local/bin/zypper-auto-helper" | tee -a "${LOG_FILE}"
        echo "    /usr/local/bin/zypper-auto-diag-follow (diagnostics follower helper)" | tee -a "${LOG_FILE}"
        echo "    /usr/local/bin/zypper-auto-dashboard-perf-worker (dashboard perf worker)" | tee -a "${LOG_FILE}"
        echo "  - User units: $SUDO_USER_HOME/.config/systemd/user/zypper-notify-user.service/timer" | tee -a "${LOG_FILE}"
        echo "  - Helper scripts: $SUDO_USER_HOME/.local/bin/zypper-notify-updater.py, zypper-run-install," | tee -a "${LOG_FILE}"
        echo "    zypper-with-ps, zypper-view-changes, zypper-soar-install-helper" | tee -a "${LOG_FILE}"
        echo "  - Desktop/menu shortcuts: $SUDO_USER_HOME/.local/share/applications/zypper-auto-dashboard.desktop" | tee -a "${LOG_FILE}"
        echo "    (and a Desktop shortcut if present: 'Zypper Auto Dashboard.desktop')" | tee -a "${LOG_FILE}"

        if [ "${UNINSTALL_KEEP_HOOKS:-0}" -eq 1 ]; then
            echo "  - Hooks under ${hooks_dir} would be LEFT IN PLACE (--keep-hooks)" | tee -a "${LOG_FILE}"
        else
            echo "  - Hooks under ${hooks_dir} would be REMOVED (use --keep-hooks to preserve)" | tee -a "${LOG_FILE}"
        fi

        if [ "${UNINSTALL_KEEP_LOGS:-0}" -eq 1 ]; then
            echo "  - Logs under $LOG_DIR (including service logs, diagnostics logs, cleanup reports, and status.html dashboard) would be LEFT IN PLACE (--keep-logs)" | tee -a "${LOG_FILE}"
            echo "  - Cleanup reports under ${cleanup_report_dir} would be LEFT IN PLACE (--keep-logs)" | tee -a "${LOG_FILE}"
            echo "  - Helper backups under ${helper_backup_dir} (boot-entry backups, btrfsmaintenance backups) would be LEFT IN PLACE (--keep-logs)" | tee -a "${LOG_FILE}"
        else
            echo "  - Logs under $LOG_DIR (other than the current log), service logs, diagnostics logs, cleanup reports, and status.html dashboard" | tee -a "${LOG_FILE}"
            echo "  - Helper backups under ${helper_backup_dir} (boot-entry backups, btrfsmaintenance backups)" | tee -a "${LOG_FILE}"
        fi

        if [ -n "${SUDO_USER_HOME:-}" ]; then
            echo "  - User notifier logs/caches under $SUDO_USER_HOME/.local/share/zypper-notify and $SUDO_USER_HOME/.cache/zypper-notify" | tee -a "${LOG_FILE}"
            echo "    (this also removes the user dashboard copy: $SUDO_USER_HOME/.local/share/zypper-notify/status.html)" | tee -a "${LOG_FILE}"
        fi

        echo "" | tee -a "${LOG_FILE}"
        echo "Run again WITHOUT --dry-run to actually uninstall." | tee -a "${LOG_FILE}"
        update_status "DRY-RUN: zypper-auto-helper uninstall (no changes made)"
        return 0
    fi

    if [ "${UNINSTALL_ASSUME_YES:-0}" -ne 1 ]; then
        read -p "Are you sure you want to uninstall zypper-auto-helper components? [y/N]: " -r CONFIRM
        echo
        if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
            log_info "Uninstall aborted by user. No changes made."
            update_status "ABORTED: zypper-auto-helper uninstall cancelled by user"
            return 0
        fi
    else
        log_info "Non-interactive mode: proceeding without confirmation (--yes)."
    fi

    update_status "Uninstalling zypper-auto-helper components..."

    # 1. Stop and disable root timers/services
    log_debug "Disabling root timers and services..."
    execute_guarded "Disable root downloader timer" systemctl disable --now zypper-autodownload.timer || true
    execute_guarded "Disable cache cleanup timer" systemctl disable --now zypper-cache-cleanup.timer || true
    execute_guarded "Disable verification timer" systemctl disable --now zypper-auto-verify.timer || true

    # Optional: disable OS-provided maintenance timers (Option 5 automation)
    # IMPORTANT: We only disable them; we never delete the unit files.
    if [ "${UNINSTALL_DISABLE_MAINT_TIMERS:-0}" -eq 1 ]; then
        log_info "[uninstall] Disabling maintenance timers (requested): snapper/btrfs/fstrim"
        execute_guarded "Disable snapper timers" systemctl disable --now snapper-timeline.timer snapper-cleanup.timer snapper-boot.timer || true
        execute_guarded "Disable btrfs timers" systemctl disable --now btrfs-scrub.timer btrfs-balance.timer btrfs-trim.timer btrfs-defrag.timer || true
        execute_guarded "Disable fstrim timer" systemctl disable --now fstrim.timer || true
        log_info "[uninstall] Maintenance timers disabled (unit files preserved under /usr/lib/systemd/system)"
    fi
    execute_guarded "Stop downloader service" systemctl stop zypper-autodownload.service || true
    execute_guarded "Stop cache cleanup service" systemctl stop zypper-cache-cleanup.service || true
    execute_guarded "Stop verification service" systemctl stop zypper-auto-verify.service || true
    # Diagnostics follower service (may or may not be enabled)
    execute_guarded "Disable diagnostics follower service" systemctl disable --now zypper-auto-diag-logs.service || true
    # Dashboard settings API service (optional)
    execute_guarded "Disable dashboard API service" systemctl disable --now zypper-auto-dashboard-api.service || true

    # 2. Stop and disable user timer/service
    if [ -n "${SUDO_USER:-}" ]; then
        log_debug "Disabling user timer and service for $SUDO_USER..."
        USER_BUS_PATH="$(get_user_bus "$SUDO_USER")"
        execute_guarded "Disable user notifier timer" \
            sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" \
            systemctl --user disable --now zypper-notify-user.timer || true
        execute_guarded "Stop user notifier service" \
            sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" \
            systemctl --user stop zypper-notify-user.service || true
    fi

    # 3. Remove systemd unit files and root binaries
    log_debug "Removing root systemd units and binaries..."
    execute_guarded "Remove root unit files and binaries" rm -f \
        /usr/share/polkit-1/actions/org.opensuse.zypper-auto.policy \
        /etc/systemd/system/zypper-autodownload.service \
        /etc/systemd/system/zypper-autodownload.timer \
        /etc/systemd/system/zypper-cache-cleanup.service \
        /etc/systemd/system/zypper-cache-cleanup.timer \
        /etc/systemd/system/zypper-auto-verify.service \
        /etc/systemd/system/zypper-auto-verify.timer \
        /etc/systemd/system/zypper-auto-diag-logs.service \
        /etc/systemd/system/zypper-auto-dashboard-api.service \
        /usr/local/bin/zypper-download-with-progress \
        /usr/local/bin/zypper-auto-helper \
        /usr/local/bin/zypper-auto-diag-follow \
        /usr/local/bin/zypper-auto-dashboard-api \
        /usr/local/bin/zypper-auto-dashboard-perf-worker || true

    # 4. Remove user-level scripts, systemd units, and desktop/menu shortcuts
    if [ -n "${SUDO_USER_HOME:-}" ]; then
        log_debug "Removing user scripts and units under $SUDO_USER_HOME..."

        # Desktop shortcut location can vary by locale; use xdg-user-dir when available.
        local _desk_dir _dash_desktop_shortcut
        _desk_dir=""
        if command -v xdg-user-dir >/dev/null 2>&1; then
            _desk_dir=$(sudo -u "${SUDO_USER}" XDG_CONFIG_HOME="${SUDO_USER_HOME}/.config" XDG_DATA_HOME="${SUDO_USER_HOME}/.local/share" xdg-user-dir DESKTOP 2>/dev/null || true)
        fi
        if [ -z "${_desk_dir:-}" ]; then
            _desk_dir="${SUDO_USER_HOME}/Desktop"
        fi
        _dash_desktop_shortcut="${_desk_dir}/Zypper Auto Dashboard.desktop"

        execute_guarded "Remove user scripts, unit files, and desktop shortcuts" rm -f \
            "$SUDO_USER_HOME/.config/systemd/user/zypper-notify-user.service" \
            "$SUDO_USER_HOME/.config/systemd/user/zypper-notify-user.timer" \
            "$SUDO_USER_HOME/.local/bin/zypper-notify-updater.py" \
            "$SUDO_USER_HOME/.local/bin/zypper-run-install" \
            "$SUDO_USER_HOME/.local/bin/zypper-with-ps" \
            "$SUDO_USER_HOME/.local/bin/zypper-view-changes" \
            "$SUDO_USER_HOME/.local/bin/zypper-soar-install-helper" \
            "$SUDO_USER_HOME/.config/fish/conf.d/zypper-wrapper.fish" \
            "$SUDO_USER_HOME/.config/fish/conf.d/zypper-auto-helper-alias.fish" \
            "$SUDO_USER_HOME/.config/fish/completions/zypper-auto-helper.fish" \
            "$SUDO_USER_HOME/.local/share/applications/zypper-auto-dashboard.desktop" \
            "${_dash_desktop_shortcut}" || true

        # Remove system-wide completions (best-effort)
        execute_guarded "Remove bash/zsh completion files" rm -f \
            /etc/bash_completion.d/zypper-auto-helper \
            /usr/share/bash-completion/completions/zypper-auto-helper \
            /usr/share/zsh/site-functions/_zypper-auto-helper \
            /usr/local/share/zsh/site-functions/_zypper-auto-helper || true

        # Remove bash/zsh aliases we added (non-fatal if missing).
        # Avoid `bash -lc` and ensure $SUDO_USER_HOME expands correctly.
        if [ -f "${SUDO_USER_HOME}/.bashrc" ]; then
            execute_guarded "Remove helper aliases from .bashrc" \
                sed -i \
                    -e '/# Zypper wrapper for auto service check/d' \
                    -e '/alias zypper=/d' \
                    -e '/# zypper-auto-helper command alias/d' \
                    -e '/alias zypper-auto-helper=/d' \
                    "${SUDO_USER_HOME}/.bashrc" 2>/dev/null || true
        fi
        if [ -f "${SUDO_USER_HOME}/.zshrc" ]; then
            execute_guarded "Remove helper aliases from .zshrc" \
                sed -i \
                    -e '/# Zypper wrapper for auto service check/d' \
                    -e '/alias zypper=/d' \
                    -e '/# zypper-auto-helper command alias/d' \
                    -e '/alias zypper-auto-helper=/d' \
                    "${SUDO_USER_HOME}/.zshrc" 2>/dev/null || true
        fi
    fi

    # 5. Remove custom hook scripts (enterprise extension)
    if [ "${UNINSTALL_KEEP_HOOKS:-0}" -eq 1 ]; then
        log_info "Leaving hook scripts directory intact (--keep-hooks requested): ${hooks_dir}"
    else
        # Safety guard: never rm -rf an empty or suspicious path.
        if [ -z "${hooks_dir:-}" ] || [ "${hooks_dir}" = "/" ] || [ "${hooks_dir}" = "/etc" ]; then
            log_error "Refusing to remove hooks directory due to suspicious path: '${hooks_dir}'"
        elif [ -d "${hooks_dir}" ]; then
            log_debug "Removing hook scripts directory: ${hooks_dir}"
            execute_guarded "Remove hooks directory (${hooks_dir})" rm -rf -- "${hooks_dir}" || true
        fi
    fi

    # 6. Remove logs and caches
    if [ "${UNINSTALL_KEEP_LOGS:-0}" -eq 1 ]; then
        log_info "Leaving all logs under $LOG_DIR intact (--keep-logs requested)."
    else
        # Keep the current uninstall log file so we don't break logging while
        # this function is still running, but remove other helper logs and
        # caches.
        log_debug "Removing logs and caches (preserving this uninstall log)..."
        if [ -d "$LOG_DIR" ]; then
            # Delete all files in $LOG_DIR except the current LOG_FILE
            execute_guarded "Remove old log files (preserving current log)" \
                find "$LOG_DIR" -maxdepth 1 -type f ! -name "$(basename "$LOG_FILE")" -delete || true
            # Remove any service sub-logs directory completely
            execute_guarded "Remove service logs directory" rm -rf "$LOG_DIR/service-logs" || true
            # Remove diagnostics logs directory completely
            execute_guarded "Remove diagnostics logs directory" rm -rf "$LOG_DIR/diagnostics" || true
        fi

        # Remove cleanup audit reports (may be inside LOG_DIR or custom)
        if [ -z "${cleanup_report_dir:-}" ] || [ "${cleanup_report_dir}" = "/" ] || [ "${cleanup_report_dir}" = "/var" ] || [ "${cleanup_report_dir}" = "/var/log" ]; then
            log_error "Refusing to remove cleanup report directory due to suspicious path: '${cleanup_report_dir}'"
        elif [ -d "${cleanup_report_dir}" ]; then
            execute_guarded "Remove cleanup report directory (${cleanup_report_dir})" rm -rf -- "${cleanup_report_dir}" || true
        fi

        # Remove helper-created backups (boot entries + btrfsmaintenance)
        if [ -d "${helper_backup_dir}" ]; then
            # Remove helper-created boot-entry backup folders (best-effort).
            # Use find to avoid rm errors when the glob does not match.
            execute_guarded "Remove boot-entry backup folders" \
                find "${helper_backup_dir}" -maxdepth 1 -mindepth 1 -type d -name 'boot-entries-*' -exec rm -rf -- {} + 2>/dev/null || true
            # Remove any btrfsmaintenance backups (best-effort).
            execute_guarded "Remove btrfsmaintenance backups" \
                find "${helper_backup_dir}" -maxdepth 1 -type f -name 'btrfsmaintenance-*.bak' -delete 2>/dev/null || true
            # Remove the directory itself only if it is now empty
            rmdir "${helper_backup_dir}" 2>/dev/null || true
        fi

        # If we created the purge-kernels marker in /boot, remove it as well.
        if [ -f /boot/do_purge_kernels ]; then
            execute_guarded "Remove /boot/do_purge_kernels marker" rm -f -- /boot/do_purge_kernels || true
        fi

        # Remove dashboard API token (best-effort)
        if [ -d /var/lib/zypper-auto ]; then
            execute_guarded "Remove dashboard API token" rm -f -- /var/lib/zypper-auto/dashboard-api.token 2>/dev/null || true
            rmdir /var/lib/zypper-auto 2>/dev/null || true
        fi
    fi
    if [ -n "${SUDO_USER_HOME:-}" ]; then
        execute_guarded "Remove notifier logs" rm -rf -- "$SUDO_USER_HOME/.local/share/zypper-notify" || true
        execute_guarded "Remove notifier caches" rm -rf -- "$SUDO_USER_HOME/.cache/zypper-notify" || true
    fi

    # 7. Reload systemd daemons
    log_debug "Reloading systemd daemons after uninstall..."
    execute_guarded "systemd daemon-reload (post-uninstall)" systemctl daemon-reload || true
    if [ -n "${SUDO_USER:-}" ]; then
        USER_BUS_PATH="$(get_user_bus "$SUDO_USER")"
        execute_guarded "systemctl --user daemon-reload (post-uninstall)" \
            sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" \
            systemctl --user daemon-reload || true
    fi

    # 8. Clear any failed state in systemd for the removed units so
    #    `systemctl --user status` looks clean after uninstall.
    log_debug "Resetting failed state for removed systemd units (if any)..."
    execute_guarded "Reset failed state for removed system units" \
        systemctl reset-failed zypper-autodownload.service zypper-cache-cleanup.service zypper-auto-verify.service || true
    if [ -n "${SUDO_USER:-}" ]; then
        USER_BUS_PATH="$(get_user_bus "$SUDO_USER")"
        execute_guarded "Reset failed state for removed user units" \
            sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" \
            systemctl --user reset-failed zypper-notify-user.service || true
    fi

    log_success "Core zypper-auto-helper components uninstalled (installer script left in place)."
    update_status "SUCCESS: zypper-auto-helper core components uninstalled"

    echo "" | tee -a "${LOG_FILE}"
    echo "Uninstall summary:" | tee -a "${LOG_FILE}"
    echo "  - System services and timers removed: zypper-autodownload, zypper-cache-cleanup, zypper-auto-verify" | tee -a "${LOG_FILE}"
    echo "  - User notifier units and helper scripts removed for user $SUDO_USER" | tee -a "${LOG_FILE}"
    if [ "${UNINSTALL_KEEP_HOOKS:-0}" -eq 1 ]; then
        echo "  - Hook scripts left in place at ${hooks_dir} (--keep-hooks)" | tee -a "${LOG_FILE}"
    else
        echo "  - Hook scripts removed from ${hooks_dir}" | tee -a "${LOG_FILE}"
    fi
    echo "  - No changes made to /etc/zypper-auto.conf, snapd, Flatpak, Soar, Homebrew or /etc/zypp/zypper.conf" | tee -a "${LOG_FILE}"
    if [ "${UNINSTALL_KEEP_LOGS:-0}" -eq 1 ]; then
        echo "  - Logs under $LOG_DIR left in place (--keep-logs)" | tee -a "${LOG_FILE}"
    else
        echo "  - Logs and caches cleaned up (current uninstall log preserved)" | tee -a "${LOG_FILE}"
    fi
    echo "" | tee -a "${LOG_FILE}"
    echo "You can reinstall the helper at any time with:" | tee -a "${LOG_FILE}"
    echo "  sudo sh zypper-auto.sh install" | tee -a "${LOG_FILE}"
}

# --- Helper function to check and install a dependency ---
check_and_install() {
    local cmd=$1
    local package=$2
    local purpose=$3

    log_debug "Checking for command: $cmd (package: $package)"

    if ! command -v "$cmd" &> /dev/null; then
        log_info "---"
        log_info "⚠️  Dependency missing: '$cmd' ($purpose)."
        log_info "   This is provided by the package '$package'."
        read -p "   Install it now? [Y/n]: " -r REPLY
        REPLY="${REPLY:-Y}"
        log_debug "User response: $REPLY"

        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Installing $package..."
            update_status "Installing dependency: $package"

            if ! execute_guarded "Install dependency package '$package' (provides '$cmd')" sudo zypper install -y "$package"; then
                log_error "Failed to install $package. Please install it manually and re-run this script."
                update_status "FAILED: Could not install $package"
                exit 1
            fi
            log_success "Successfully installed $package"
        else
            log_error "Dependency '$package' is required. Please install it manually and re-run this script."
            update_status "FAILED: Required dependency $package not installed"
            exit 1
        fi
    else
        log_success "Command '$cmd' found"
    fi
}

# --- Helper: Homebrew-only installation mode (CLI) ---
run_brew_install_only() {
    log_info ">>> Homebrew (brew) installation helper mode..."
    update_status "Running Homebrew installation helper..."

    # Detect an existing brew installation for the target user and, if found,
    # prefer to run a self-update (brew update && brew upgrade) instead of
    # re-running the installer.
    BREW_PATH=""

    # 1) In the user's PATH
    if sudo -u "$SUDO_USER" command -v brew >/dev/null 2>&1; then
        BREW_PATH="brew"
    # 2) In a per-user ~/.linuxbrew or ~/.homebrew prefix
    elif [ -x "$SUDO_USER_HOME/.linuxbrew/bin/brew" ]; then
        BREW_PATH="$SUDO_USER_HOME/.linuxbrew/bin/brew"
    elif [ -x "$SUDO_USER_HOME/.homebrew/bin/brew" ]; then
        BREW_PATH="$SUDO_USER_HOME/.homebrew/bin/brew"
    # 3) In the default Linuxbrew prefix /home/linuxbrew/.linuxbrew
    elif [ -x "/home/linuxbrew/.linuxbrew/bin/brew" ]; then
        BREW_PATH="/home/linuxbrew/.linuxbrew/bin/brew"
    fi

    if [ -n "$BREW_PATH" ]; then
        log_success "Homebrew already appears to be installed for user $SUDO_USER"
        echo "brew appears to be installed for user $SUDO_USER." | tee -a "${LOG_FILE}"

        # Build the brew command to run as the target user
        if [ "$BREW_PATH" = "brew" ]; then
            BREW_CMD=(sudo -u "$SUDO_USER" brew)
        else
            BREW_CMD=(sudo -u "$SUDO_USER" "$BREW_PATH")
        fi

        echo "Checking for Homebrew updates from GitHub (brew update) for user $SUDO_USER" | tee -a "${LOG_FILE}"
        if ! execute_guarded "Homebrew: brew update" "${BREW_CMD[@]}" update; then
            local rc=$?
            log_error "Homebrew 'brew update' failed for user $SUDO_USER (exit code $rc)"
            return $rc
        fi

        # After syncing with GitHub, see if anything needs upgrading
        OUTDATED=$("${BREW_CMD[@]}" outdated --quiet 2>/dev/null || true)
        OUTDATED_COUNT=$(printf '%s\n' "$OUTDATED" | sed '/^$/d' | wc -l | tr -d ' ')

        if [ "${OUTDATED_COUNT:-0}" -eq 0 ]; then
            echo "Homebrew is already up to date for user $SUDO_USER (no formulae to upgrade)." | tee -a "${LOG_FILE}"
            return 0
        fi

        echo "Homebrew has ${OUTDATED_COUNT} outdated formulae for user $SUDO_USER; running 'brew upgrade'..." | tee -a "${LOG_FILE}"
        if execute_guarded "Homebrew: brew upgrade" "${BREW_CMD[@]}" upgrade; then
            log_success "Homebrew upgrade completed for user $SUDO_USER (upgraded ${OUTDATED_COUNT} formulae)"
            return 0
        else
            local rc=$?
            log_error "Homebrew 'brew upgrade' failed for user $SUDO_USER (exit code $rc)"
            return $rc
        fi
    fi

    # Ensure basic prerequisites for the installer (use common dependency helper)
    check_and_install curl curl "required to download the Homebrew installer script"
    check_and_install git git "required for Homebrew operations (manages formula repositories)"

    # shellcheck disable=SC2016
    # This is a user-facing string; we intentionally keep it single-quoted.
    BREW_INSTALL_CMD='/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'

    echo "" | tee -a "${LOG_FILE}"
    echo "This will run the official Homebrew installer as user $SUDO_USER:" | tee -a "${LOG_FILE}"
    echo "  $BREW_INSTALL_CMD" | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"

    if sudo -u "$SUDO_USER" bash -lc "$BREW_INSTALL_CMD"; then
        log_success "Homebrew installation finished for user $SUDO_USER"
        echo "" | tee -a "${LOG_FILE}"

        # Best-effort: automatically add Homebrew to the user's shell PATH if
        # they are using common shells and the recommended snippet is not
        # already present. This avoids the common "brew not in PATH" warning.
        # shellcheck disable=SC2016
        # This is a user-facing string snippet; we intentionally keep it single-quoted.
        BREW_SHELLENV_LINE='eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"'

        # fish
        FISH_CONFIG_DIR="$SUDO_USER_HOME/.config/fish"
        FISH_CONFIG_FILE="$FISH_CONFIG_DIR/config.fish"
        if [ -d "$FISH_CONFIG_DIR" ]; then
            if ! sudo -u "$SUDO_USER" grep -F "$BREW_SHELLENV_LINE" "$FISH_CONFIG_FILE" >/dev/null 2>&1; then
                mkdir -p "$FISH_CONFIG_DIR"
                # shellcheck disable=SC2016
                sudo -u "$SUDO_USER" bash -lc "echo >> '$FISH_CONFIG_FILE'"
                # shellcheck disable=SC2016
                sudo -u "$SUDO_USER" bash -lc "echo '$BREW_SHELLENV_LINE' >> '$FISH_CONFIG_FILE'"
                echo "Added Homebrew PATH setup to $FISH_CONFIG_FILE" | tee -a "${LOG_FILE}"
            fi
        fi

        # bash
        BASH_RC="$SUDO_USER_HOME/.bashrc"
        if [ -f "$BASH_RC" ]; then
            if ! sudo -u "$SUDO_USER" grep -F "$BREW_SHELLENV_LINE" "$BASH_RC" >/dev/null 2>&1; then
                # shellcheck disable=SC2016
                sudo -u "$SUDO_USER" bash -lc "echo >> '$BASH_RC'"
                # shellcheck disable=SC2016
                sudo -u "$SUDO_USER" bash -lc "echo '$BREW_SHELLENV_LINE' >> '$BASH_RC'"
                echo "Added Homebrew PATH setup to $BASH_RC" | tee -a "${LOG_FILE}"
            fi
        fi

        # zsh
        ZSH_RC="$SUDO_USER_HOME/.zshrc"
        if [ -f "$ZSH_RC" ]; then
            if ! sudo -u "$SUDO_USER" grep -F "$BREW_SHELLENV_LINE" "$ZSH_RC" >/dev/null 2>&1; then
                # shellcheck disable=SC2016
                sudo -u "$SUDO_USER" bash -lc "echo >> '$ZSH_RC'"
                # shellcheck disable=SC2016
                sudo -u "$SUDO_USER" bash -lc "echo '$BREW_SHELLENV_LINE' >> '$ZSH_RC'"
                echo "Added Homebrew PATH setup to $ZSH_RC" | tee -a "${LOG_FILE}"
            fi
        fi

        echo "You may need to add brew to your PATH. For example:" | tee -a "${LOG_FILE}"
        # shellcheck disable=SC2016
        echo '  eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"' | tee -a "${LOG_FILE}"
        echo 'or see:  https://docs.brew.sh/Homebrew-on-Linux' | tee -a "${LOG_FILE}"
        return 0
    else
        local rc=$?
        log_error "Homebrew installer exited with code $rc"
        return $rc
    fi
}

# --- Helper: pipx / Python CLI tools helper mode (CLI) ---
run_pipx_helper_only() {
    log_info ">>> pipx (Python CLI tools) helper mode..."
    update_status "Running pipx helper..."

    echo "" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"
    echo "  Python command-line tools via pipx" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"
    echo "Path A: You want to install a command-line tool (yt-dlp, black, ansible, httpie, etc.)." | tee -a "${LOG_FILE}"
    echo "Use pipx so each tool lives in its own isolated environment and won't break your system Python." | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"

    # Check if pipx is already available for the target user
    if sudo -u "$SUDO_USER" command -v pipx >/dev/null 2>&1; then
        log_success "pipx already appears to be installed for user $SUDO_USER"
        echo "pipx is already installed for user $SUDO_USER." | tee -a "${LOG_FILE}"
    else
        echo "pipx is not installed yet for user $SUDO_USER." | tee -a "${LOG_FILE}"
        echo "The recommended way on openSUSE is:" | tee -a "${LOG_FILE}"
        echo "  sudo zypper install python3-pipx" | tee -a "${LOG_FILE}"
        echo "" | tee -a "${LOG_FILE}"

        read -p "May I install python3-pipx for you now via zypper? [y/N]: " -r REPLY
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Installing python3-pipx via zypper..."
            update_status "Installing dependency: python3-pipx"
            if ! execute_guarded "Install python3-pipx via zypper" zypper -n install python3-pipx; then
                log_error "Failed to install python3-pipx. Please install it manually and re-run with --pip-package."
                update_status "FAILED: Could not install python3-pipx"
                return 1
            fi
            log_success "Successfully installed python3-pipx"

            # Best-effort: ensure pipx adds its binaries to the user's PATH
            if sudo -u "$SUDO_USER" command -v pipx >/dev/null 2>&1; then
                execute_guarded "pipx ensurepath" sudo -u "$SUDO_USER" pipx ensurepath || true
            fi
        else
            log_info "User declined automatic pipx installation"
        fi
    fi

    echo "" | tee -a "${LOG_FILE}"
    echo "How to use pipx for Python CLI tools:" | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"
    echo "  1) Install a tool into its own isolated environment:" | tee -a "${LOG_FILE}"
    echo "       pipx install <package_name>" | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"
    echo "  2) Upgrade all your pipx-installed tools at once (recommended instead of 'pip install --upgrade'):" | tee -a "${LOG_FILE}"
    echo "       pipx upgrade-all" | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"

    # Offer to run a safe upgrade-all for the user
    if sudo -u "$SUDO_USER" command -v pipx >/dev/null 2>&1; then
        read -p "Do you want me to run 'pipx upgrade-all' for user $SUDO_USER now? [y/N]: " -r UPGRADE
        echo
        if [[ $UPGRADE =~ ^[Yy]$ ]]; then
            log_info "Running 'pipx upgrade-all' for user $SUDO_USER..."
            update_status "Running pipx upgrade-all for $SUDO_USER"
            if execute_guarded "pipx upgrade-all" sudo -u "$SUDO_USER" pipx upgrade-all; then
                log_success "pipx upgrade-all completed for user $SUDO_USER"
            else
                local rc=$?
                log_error "pipx upgrade-all failed for user $SUDO_USER (exit code $rc)"
                return $rc
            fi
        else
            log_info "User chose not to run pipx upgrade-all automatically"
        fi
    fi

    echo "" | tee -a "${LOG_FILE}"
    echo "Summary:" | tee -a "${LOG_FILE}"
    echo "  - pipx is now the recommended/default way to install and upgrade standalone Python CLI tools." | tee -a "${LOG_FILE}"
    echo "  - Use 'pipx install <package>' to add a new tool." | tee -a "${LOG_FILE}"
    echo "  - Use 'pipx upgrade-all' instead of 'pip install --upgrade' for those tools." | tee -a "${LOG_FILE}"

    update_status "SUCCESS: pipx helper completed"
    return 0
}

# --- Helper: Snap & Flatpak setup mode (CLI) ---
run_setup_sf_only() {
    log_info ">>> Snapd / Flatpak setup helper mode..."
    update_status "Running Snapd/Flatpak setup helper..."

    echo "" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"
    echo "  Snapd and Flatpak Setup" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"
    echo "This helper will:" | tee -a "${LOG_FILE}"
    echo "  - Ensure snapd (snap) is installed" | tee -a "${LOG_FILE}"
    echo "  - Ensure flatpak is installed" | tee -a "${LOG_FILE}"
    echo "  - Add common Flatpak remotes (Flathub, Flathub Beta, AppCenter)" | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"

    local rc=0
    local snap_ok=0 flatpak_ok=0 flathub_ok=0 flathub_beta_ok=0 appcenter_ok=0

    # 1) Ensure snapd (snap command) is installed
    if command -v snap >/dev/null 2>&1; then
        log_success "snap command already available (snapd installed)"
        snap_ok=1
    else
        log_info "snap command not found; installing 'snapd' via zypper..."
        update_status "Installing snapd..."
        if execute_guarded "Install snapd via zypper" zypper -n install snapd; then
            log_success "snapd successfully installed"
            snap_ok=1
        else
            log_error "Failed to install snapd via zypper. Check your repositories or install manually."

            # On openSUSE systems where 'snapd' is not provided by the
            # currently enabled zypper repositories, the recommended way
            # to install it is often via the openSUSE Package Installer
            # helper:
            #   opi snapd
            # Offer an optional fallback to run this automatically when
            # 'opi' is available.
            if command -v opi >/dev/null 2>&1; then
                echo "" | tee -a "${LOG_FILE}"
                echo "On openSUSE, 'snapd' may be provided via the openSUSE" | tee -a "${LOG_FILE}"
                echo "Package Installer (opi) instead of the standard zypper" | tee -a "${LOG_FILE}"
                echo "repositories. The usual manual command is:" | tee -a "${LOG_FILE}"
                echo "  sudo opi snapd" | tee -a "${LOG_FILE}"
                echo "" | tee -a "${LOG_FILE}"
                echo "When opi asks what to install, choose the plain 'snapd'" | tee -a "${LOG_FILE}"
                echo "package (usually option 1), then select the 'system:snappy'" | tee -a "${LOG_FILE}"
                echo "repository entry (also typically option 1)." | tee -a "${LOG_FILE}"
                echo "" | tee -a "${LOG_FILE}"
                read -p "Do you want me to run 'opi snapd' now to install snapd? [y/N]: " -r OPI_SNAPD
                echo
                if [[ $OPI_SNAPD =~ ^[Yy]$ ]]; then
                    log_info "Attempting to install snapd via 'opi snapd'..."
                    update_status "Installing snapd via opi..."
                    if opi snapd >> "${LOG_FILE}" 2>&1; then
                        log_success "snapd successfully installed via opi"
                        snap_ok=1
                        # Do not override rc here if later steps fail; we
                        # only clear the snap-specific error.
                    else
                        log_error "'opi snapd' failed. Please run 'opi snapd' manually in a terminal and review its prompts/output."
                    fi
                else
                    log_info "User declined automatic 'opi snapd' fallback; leaving snapd uninstalled."
                fi
            else
                log_info "The 'opi' helper is not installed; cannot offer automatic 'opi snapd' fallback."
            fi

            # Keep rc marked as non-zero so the overall helper reports that
            # at least one step encountered an issue. This will be overridden
            # later only if all individual components succeeded.
            rc=1
        fi
    fi

    # 1a) Ensure snapd core services are enabled and running so that
    #     'snap install' and 'snap refresh' can talk to the daemon.
    if [ "$snap_ok" -eq 1 ]; then
        log_info "Ensuring snapd core services are enabled and running..."
        if systemctl list-unit-files snapd.service >/dev/null 2>&1; then
        if execute_guarded "Enable + start snapd core services" systemctl enable --now snapd.apparmor.service snapd.seeded.service snapd.service snapd.socket; then
            log_success "snapd core services enabled and started (snapd.apparmor, snapd.seeded, snapd, snapd.socket)"
        else
                log_error "Failed to enable/start snapd core services automatically. You may need to run the commands below manually."
                # Keep rc marked as non-zero so the final status reports a warning.
                rc=1
            fi
        else
            log_debug "snapd.service unit not found in systemd; skipping automatic snapd enablement."
        fi
    fi

    echo "" | tee -a "${LOG_FILE}"
    echo "After snapd installation completes, the helper attempts to enable the core" | tee -a "${LOG_FILE}"
    echo "snapd services automatically. If something still fails, you can run:" | tee -a "${LOG_FILE}"
    echo "  sudo systemctl enable --now snapd.apparmor.service snapd.seeded.service snapd.service snapd.socket" | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"

    # 2) Ensure Flatpak is installed
    if command -v flatpak >/dev/null 2>&1; then
        log_success "Flatpak already installed"
        flatpak_ok=1
    else
        log_info "Flatpak not found; installing 'flatpak' via zypper..."
        update_status "Installing flatpak..."
        if execute_guarded "Install flatpak via zypper" zypper -n install flatpak; then
            log_success "Flatpak successfully installed"
            flatpak_ok=1
        else
            log_error "Failed to install flatpak via zypper. Check your repositories or install manually."
            rc=1
        fi
    fi

    # 3) Configure common Flatpak remotes
    if command -v flatpak >/dev/null 2>&1; then
        log_info "Configuring common Flatpak remotes (Flathub, Flathub Beta, AppCenter)..."
        if execute_guarded "Add Flatpak remote: flathub" flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo; then
            log_success "Flathub remote configured (or already present)"
            flathub_ok=1
        else
            log_error "Failed to add Flathub remote (check network/connectivity)."
            rc=1
        fi

        if execute_guarded "Add Flatpak remote: flathub-beta" flatpak remote-add --if-not-exists flathub-beta https://flathub.org/beta-repo/flathub-beta.flatpakrepo; then
            log_success "Flathub Beta remote configured (or already present)"
            flathub_beta_ok=1
        else
            log_error "Failed to add Flathub Beta remote (check network/connectivity)."
            rc=1
        fi

        if execute_guarded "Add Flatpak remote: appcenter" flatpak remote-add --if-not-exists appcenter https://flatpak.elementary.io/repo.flatpakrepo; then
            log_success "AppCenter remote configured (or already present)"
            appcenter_ok=1
        else
            log_error "Failed to add AppCenter remote (check network/connectivity or remote URL)."
            rc=1
        fi
    else
        log_error "Flatpak is not installed; skipping remote configuration."
        rc=1
    fi

    # 4) Optionally remove KDE Discover (discover6) to avoid conflicting
    # update stacks on openSUSE when this helper is managing system
    # upgrades and Flatpak/Snap integration.
    if rpm -q discover6 >/dev/null 2>&1; then
        echo "" | tee -a "${LOG_FILE}"
        echo "KDE Discover (package: discover6) is currently installed." | tee -a "${LOG_FILE}"
        echo "" | tee -a "${LOG_FILE}"
        echo "On openSUSE Tumbleweed/Slowroll, Discover provides a graphical" | tee -a "${LOG_FILE}"
        echo "software center and its own offline-update mechanism on top of" | tee -a "${LOG_FILE}"
        echo "libzypp. Running Discover in parallel with this zypper auto-helper" | tee -a "${LOG_FILE}"
        echo "means two independent tools can schedule and apply system updates." | tee -a "${LOG_FILE}"
        echo "This can lead to:" | tee -a "${LOG_FILE}"
        echo "  - duplicated or conflicting update notifications" | tee -a "${LOG_FILE}"
        echo "  - partial or out-of-order upgrades when Discover performs" | tee -a "${LOG_FILE}"
        echo "    offline updates while this helper expects zypper dup snapshots" | tee -a "${LOG_FILE}"
        echo "  - confusing rollbacks when Btrfs snapshots are created from" | tee -a "${LOG_FILE}"
        echo "    different update tools" | tee -a "${LOG_FILE}"
        echo "" | tee -a "${LOG_FILE}"
        echo "To keep the update stack simple and aligned with how openSUSE" | tee -a "${LOG_FILE}"
        echo "expects zypper-based upgrades to run, this helper recommends" | tee -a "${LOG_FILE}"
        echo "removing Discover and relying on:" | tee -a "${LOG_FILE}"
        echo "  - zypper dup (or this helper) for system upgrades" | tee -a "${LOG_FILE}"
        echo "  - Flatpak/Snap tooling only for user-space apps when needed" | tee -a "${LOG_FILE}"
        echo "" | tee -a "${LOG_FILE}"
        read -p "Remove discover6 now so only zypper-based tools manage system updates? [y/N]: " -r RM_DISCOVER
        echo
        if [[ $RM_DISCOVER =~ ^[Yy]$ ]]; then
            log_info "User accepted removal of discover6 to avoid conflicting update managers"
            update_status "Removing discover6 (KDE Discover) to avoid conflicting update managers"
            if execute_guarded "Remove discover6 via zypper" zypper -n remove discover6; then
                log_success "discover6 removed successfully"
            else
                rc=1
                log_error "Failed to remove discover6 automatically. Please review the log and, if needed, run 'sudo zypper remove discover6' manually."
            fi
        else
            log_info "User chose to keep discover6 installed; multiple update tools will remain active."
        fi
    else
        log_debug "discover6 is not installed; no conflicting KDE Discover instance detected"
    fi

    # 5) Install default app stores when base tooling is available
    #
    # a) Snap Store (snap-store) via snap (edge channel)
    if [ "$snap_ok" -eq 1 ] && command -v snap >/dev/null 2>&1; then
        log_info "Ensuring Snap Store (snap-store) is installed via snap..."
        echo "  → Installing Snap Store with: snap install snap-store --edge (this may take a few minutes)..." | tee -a "${LOG_FILE}"
        if snap list snap-store >/dev/null 2>&1; then
            log_success "Snap Store (snap-store) is already installed"
        else
            # Stream snap's own progress/output both to the console and the log so
            # the user can see that work is happening while the command runs.
            if snap install snap-store --edge 2>&1 | tee -a "${LOG_FILE}"; then
                log_success "Snap Store (snap-store) installed via snap (edge channel)"
            else
                log_error "Failed to install Snap Store (snap-store) via snap. You can retry manually with: sudo snap install snap-store --edge"
                rc=1
            fi
        fi
    else
        log_debug "Skipping Snap Store installation; snapd/snap not fully available (snap_ok=${snap_ok})."
    fi

    # b) Bazaar (io.github.kolunmi.Bazaar) from Flathub via Flatpak
    if [ "$flatpak_ok" -eq 1 ] && [ "$flathub_ok" -eq 1 ] && command -v flatpak >/dev/null 2>&1; then
        log_info "Ensuring Bazaar (io.github.kolunmi.Bazaar) is installed from Flathub..."
        echo "  → Installing Bazaar with: flatpak install flathub io.github.kolunmi.Bazaar (this may take a few minutes)..." | tee -a "${LOG_FILE}"
        if flatpak list --app --columns=application 2>/dev/null | grep -qx 'io.github.kolunmi.Bazaar'; then
            log_success "Bazaar (io.github.kolunmi.Bazaar) is already installed"
        else
            # Stream Flatpak's own progress/output both to the console and the log
            # so the user can see downloads and installation steps.
            if flatpak install -y flathub io.github.kolunmi.Bazaar 2>&1 | tee -a "${LOG_FILE}"; then
                log_success "Bazaar (io.github.kolunmi.Bazaar) installed from Flathub"
            else
                log_error "Failed to install Bazaar (io.github.kolunmi.Bazaar) from Flathub. You can retry manually with: flatpak install flathub io.github.kolunmi.Bazaar"
                rc=1
            fi
        fi
    else
        log_debug "Skipping Bazaar Flatpak installation; flatpak/flathub not fully available (flatpak_ok=${flatpak_ok}, flathub_ok=${flathub_ok})."
    fi

    # 6) Explain the overall update model for the user
    echo "" | tee -a "${LOG_FILE}"
    echo "Update model after Snapd/Flatpak setup:" | tee -a "${LOG_FILE}"
    echo "  - KDE Discover is removed (optional) to avoid a second GUI updater" | tee -a "${LOG_FILE}"
    echo "    competing with zypper dup and Btrfs snapshots." | tee -a "${LOG_FILE}"
    echo "  - System (RPM) updates are handled only by zypper dup and this helper." | tee -a "${LOG_FILE}"
    echo "  - Flatpak apps use Bazaar as the graphical store, with 'flatpak update'" | tee -a "${LOG_FILE}"
    echo "    run automatically after dup when ENABLE_FLATPAK_UPDATES=true." | tee -a "${LOG_FILE}"
    echo "  - Snap apps use Snap Store as the graphical store, with 'snap refresh'" | tee -a "${LOG_FILE}"
    echo "    run automatically after dup when ENABLE_SNAP_UPDATES=true." | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"
    echo "In other words: one updater (zypper) for the system, and dedicated app" | tee -a "${LOG_FILE}"
    echo "stores (Bazaar and Snap Store) for user applications, all kept in sync" | tee -a "${LOG_FILE}"
    echo "by this helper so system + Flatpak + Snap apps are updated together." | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"

    if [ "$rc" -eq 0 ]; then
        update_status "SUCCESS: Snapd/Flatpak setup helper completed"
        log_success "Snapd & Flatpak setup completed successfully"
    else
        update_status "COMPLETED WITH WARNINGS: Snapd/Flatpak setup encountered some issues"
        log_error "Snapd & Flatpak setup completed with one or more errors. See ${LOG_FILE} for details."

        # Write a compact one-shot report so the user has a quick summary
        # without digging through the full installer log.
        local report
        report="${LOG_DIR}/setup-sf-last-report.txt"
        {
            echo "Snapd / Flatpak Setup Report ($(date '+%Y-%m-%d %H:%M:%S'))"
            echo "Log file     : ${LOG_FILE}"
            echo "Exit status  : ${rc}"
            echo ""
            echo "Checks:"
            echo "  - snapd installed        : $([ "$snap_ok" -eq 1 ] && echo OK || echo FAILED)"
            echo "  - flatpak installed      : $([ "$flatpak_ok" -eq 1 ] && echo OK || echo FAILED)"
            echo "  - Flathub remote         : $([ "$flathub_ok" -eq 1 ] && echo OK || echo FAILED)"
            echo "  - Flathub Beta remote    : $([ "$flathub_beta_ok" -eq 1 ] && echo OK || echo FAILED)"
            echo "  - AppCenter remote       : $([ "$appcenter_ok" -eq 1 ] && echo OK || echo FAILED)"
            echo ""
            echo "Next steps:"
            echo "  - For any FAILED item, re-run 'zypper-auto-helper --setup-SF' after fixing network/remote issues."
            echo "  - Full details: ${LOG_FILE}"
        } >"${report}" 2>/dev/null || true
        log_info "Snapd/Flatpak setup summary report written to ${report}"
    fi

    return "$rc"
}

# Show help if requested, or when invoked as the installed CLI with no arguments
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" || "${1:-}" == "help" \
   || ( $# -eq 0 && "$(basename "$0")" == "zypper-auto-helper" ) ]]; then
    echo "Zypper Auto-Helper - Installation and Maintenance Tool"
    echo ""
    echo "Usage: zypper-auto-helper [COMMAND]"
    echo "   or: sudo $0 [COMMAND]  # when running the script directly without the shell alias"
    echo ""
    echo "Commands:"
    echo "  install                 Install or update the zypper auto-updater system (default)"
    echo "  debug                   Open interactive debug/diagnostics tools menu"
    echo "  snapper                 Open Snapper tools menu (status/list/create/cleanup/timers)"
    echo "  --verify                Run verification and auto-repair checks"
    echo "  --repair                Same as --verify (alias)"
    echo "  --diagnose              Same as --verify (alias)"
    echo "  --check                 Run syntax checks only"
    echo "  --self-check            Same as --check (alias)"
    echo "  --soar                  Install/upgrade optional Soar CLI helper for the user"
    echo "  --brew                  Install/upgrade Homebrew (brew) for the user"
    echo "  --pip-package           Install/upgrade pipx and show how to manage Python CLI tools with pipx"
    echo "  --setup-SF              Install/configure Snapd and Flatpak (packages + common Flatpak remotes, optional Discover removal)"
    echo "  --reset-config          Reset /etc/zypper-auto.conf to documented defaults (with backup)"
    echo "  --reset-downloads       Clear cached download/notifier state and restart timers (alias: --reset-state)"
    echo "  --rm-conflict           Scan for duplicate RPMs and auto-clean safe conflicts before manual zypper dup"
    echo "  --reset-state           Alias for --reset-downloads"
    echo "  --logs                  Show tails of installer, service, and notifier logs"
    echo "  --live-logs             Follow installer/service/notifier logs in real time (Ctrl+C to exit)"
    echo "  --analyze, --health     Analyze recent logs and print a health report (errors, locks, notifier crashes)"
    echo "  --test-notify           Send a test desktop notification to verify GUI/DBus wiring"
    echo "  --dashboard             Generate/update a static HTML status page"
    echo "  --dash-open             Generate/refresh and open the dashboard in your browser"
    echo "  --dash-stop             Stop the local live dashboard server started by --dash-open"
    echo "  --dash-install          Enterprise quickstart: enable default hooks + generate/open dashboard"
    echo "  --dash-api-on           Start the localhost dashboard Settings API (root; used by Settings drawer)"
    echo "  --dash-api-off          Stop the localhost dashboard Settings API (root)"
    echo "  --dash-api-status       Show status of the dashboard Settings API (root)"
    echo "  --send-webhook          Send a one-shot webhook notification (for testing)"
    echo "  --uninstall-zypper      Remove zypper-auto-helper services, timers, logs, and user scripts"
    echo "  --help                  Show this help message"
    echo ""
    echo "Global flags:"
    echo "  --debug                 Enable verbose debug logging and shell tracing"
    echo ""
    echo "Examples:"
    echo "  zypper-auto-helper install         # Full installation (via shell alias, runs with sudo)"
    echo "  zypper-auto-helper --verify        # Check system health and auto-fix issues"
    echo "  zypper-auto-helper --check         # Verify script syntax"
    echo "  zypper-auto-helper --soar          # Install or upgrade Soar CLI helper"
    echo ""
    echo "Verification checks (--verify):"
    echo "  - System/user services active and enabled"
    echo "  - Python scripts executable and valid syntax"
    echo "  - Shell wrappers installed correctly"
    echo "  - No stale processes or bytecode cache"
    echo "  - Auto-repairs most common issues"
    echo ""
    echo "Note: After installation, you can use 'zypper-auto-helper' from anywhere."
    echo ""
    exit 0
fi

# Optional mode: only run self-check and exit
if [[ "${1:-}" == "--self-check" || "${1:-}" == "--check" ]]; then
    log_info "Self-check mode requested"
    run_self_check
    log_success "Self-check mode completed"
    exit 0
fi

# Optional modes: Soar, Homebrew, pipx, reset-state, diagnostics, and uninstall helper-only
if [[ "${1:-}" == "--soar" ]]; then
    log_info "Soar helper-only mode requested"
    run_soar_install_only
    exit $?
elif [[ "${1:-}" == "--brew" ]]; then
    log_info "Homebrew helper-only mode requested"
    run_brew_install_only
    exit $?
elif [[ "${1:-}" == "--pip-package" || "${1:-}" == "--pipx" ]]; then
    log_info "pipx helper-only mode requested"
    run_pipx_helper_only
    exit $?
elif [[ "${1:-}" == "--setup-SF" ]]; then
    log_info "Snapd/Flatpak setup helper-only mode requested"
    # In helper-only mode we may intentionally return a non-zero status
    # (e.g. when a Flatpak remote cannot be added) without wanting to
    # trigger the global ERR trap or treat it as a fatal installer
    # failure. Temporarily disable set -e and the ERR trap while running
    # the helper and propagate its exit code directly.
    trap - ERR
    set +e
    run_setup_sf_only
    rc=$?
    set -e
    exit $rc
elif [[ "${1:-}" == "--reset-config" ]]; then
    shift || true
    # Optional flags:
    #   --yes / -y / --non-interactive : skip confirmation prompt
    RESET_ASSUME_YES=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --yes|-y|--non-interactive)
                RESET_ASSUME_YES=1
                ;;
            *)
                log_error "Unknown option for --reset-config: $1"
                exit 1
                ;;
        esac
        shift
    done
    log_info "Config reset mode requested"
    run_reset_config_only
    exit $?
elif [[ "${1:-}" == "--reset-downloads" || "${1:-}" == "--reset-state" ]]; then
    log_info "Download/notifier state reset mode requested"
    run_reset_download_state_only
    exit $?
elif [[ "${1:-}" == "--analyze" || "${1:-}" == "--health" ]]; then
    log_info "Log health analysis mode requested"
    # Pass any additional arguments (e.g. TID=GUI-xxxx) through to the analyzer.
    run_analyze_logs_only "${@:2}"
    exit $?
elif [[ "${1:-}" == "--rm-conflict" ]]; then
    log_info "Duplicate RPM conflict cleanup mode requested"
    run_rm_conflict_only
    exit $?
elif [[ "${1:-}" == "--logs" || "${1:-}" == "--log" ]]; then
    log_info "Log viewer mode requested"
    echo "=== System/Installer Log (last 40 lines) ==="
    tail -n 40 "${LOG_DIR}"/install-*.log 2>/dev/null | tail -n 40 || true
    echo ""
    echo "=== Service Logs (last 40 lines) ==="
    tail -n 40 "${LOG_DIR}"/service-logs/*.log 2>/dev/null || true
    echo ""
    if [ -n "${SUDO_USER_HOME:-}" ]; then
        echo "=== User Notifier Log (last 40 lines) ==="
        tail -n 40 "${SUDO_USER_HOME}/.local/share/zypper-notify/notifier-detailed.log" 2>/dev/null || true
    fi
    exit 0
elif [[ "${1:-}" == "--live-logs" ]]; then
    log_info "Live log follow mode requested"
    echo "Following zypper auto-helper logs. Press Ctrl+C to exit."

    # If diagnostics follower is active and today's diagnostics file exists,
    # prefer to follow that single aggregated log so both you and I can see
    # the exact same combined view.
    diag_dir="${LOG_DIR}/diagnostics"
    today="$(date +%Y-%m-%d)"
    diag_file="${diag_dir}/diag-${today}.log"
    if [ -f "${diag_file}" ] && systemctl is-active --quiet zypper-auto-diag-logs.service 2>/dev/null; then
        echo "- Diagnostics log (aggregated): ${diag_file}"
        tail -n 50 -F "${diag_file}"
        exit 0
    fi

    latest_install_log=""
    latest_install_log=$(find "${LOG_DIR}" -maxdepth 1 -type f -name 'install-*.log' -printf '%T@\t%p\n' 2>/dev/null \
        | sort -nr | head -1 | cut -f2- || true)

    # Build list of tagged sources to follow. Each entry is TAG:path where
    # TAG is one of INS (installer), SYS (services), USR (notifier), TRC
    # (trace log).
    LIVE_SOURCES=()
    if [ -n "${latest_install_log}" ]; then
        echo "- [INS] Installer log: ${latest_install_log}"
        LIVE_SOURCES+=("INS:${latest_install_log}")
    fi

    if [ -d "${LOG_DIR}/service-logs" ]; then
        # shellcheck disable=SC2086
        for f in "${LOG_DIR}/service-logs"/*.log; do
            if [ -f "$f" ]; then
                echo "- [SYS] Service log: $f"
                LIVE_SOURCES+=("SYS:${f}")
            fi
        done
    fi

    if [ -n "${SUDO_USER_HOME:-}" ] && [ -f "${SUDO_USER_HOME}/.local/share/zypper-notify/notifier-detailed.log" ]; then
        echo "- [USR] Notifier log: ${SUDO_USER_HOME}/.local/share/zypper-notify/notifier-detailed.log"
        LIVE_SOURCES+=("USR:${SUDO_USER_HOME}/.local/share/zypper-notify/notifier-detailed.log")
    fi

    if [ -n "${TRACE_LOG:-}" ] && [ -f "${TRACE_LOG}" ]; then
        echo "- [TRC] Trace log: ${TRACE_LOG}"
        LIVE_SOURCES+=("TRC:${TRACE_LOG}")
    fi

    if [ "${#LIVE_SOURCES[@]}" -eq 0 ]; then
        echo "No log files found yet under ${LOG_DIR} or notifier directory."
        exit 0
    fi

    # Record exactly which files we are about to follow so the diagnostics
    # follower and bundles can reconstruct the same view the user saw.
    for entry in "${LIVE_SOURCES[@]}"; do
        _tag="${entry%%:*}"
        _path="${entry#*:}"
        log_info "[cli][live-logs] source=${_tag} path=${_path}"
    done

    # Launch one tail per source, prefixing each line with its tag. We keep
    # track of PIDs and ensure they are cleaned up on Ctrl+C.
    live_pids=()
    for entry in "${LIVE_SOURCES[@]}"; do
        _tag="${entry%%:*}"
        _path="${entry#*:}"
        if [ ! -f "${_path}" ]; then
            continue
        fi
        (
            tail -n 50 -F "${_path}" 2>/dev/null | sed -u "s/^/[${_tag}] /"
        ) &
        live_pids+=("$!")
    done

    if [ "${#live_pids[@]}" -eq 0 ]; then
        echo "No readable log files available to follow."
        exit 0
    fi

    cleanup_live_logs() {
        # shellcheck disable=SC2317
        for pid in "${live_pids[@]}"; do
            # shellcheck disable=SC2317
            kill "${pid}" 2>/dev/null || true
        done
    }

    trap 'cleanup_live_logs; exit 0' INT TERM

    # Wait for all tails; ignore non-zero status so set -e does not abort
    # the helper when the user presses Ctrl+C.
    wait || true
    trap - INT TERM
    exit 0
elif [[ "${1:-}" == "snapper" ]]; then
    log_info "Snapper tools menu requested"
    shift || true
    # Snapper submenu is best-effort and can legitimately return non-zero
    # (safety refusal, snapper/zypper issues, etc.). Disable the global ERR trap
    # so these are not treated as "critical crashes".
    trap - ERR
    set +e
    run_snapper_menu_only "$@"
    rc=$?
    set -e
    exit ${rc}
elif [[ "${1:-}" == "debug" || "${1:-}" == "--debug-menu" ]]; then
    log_info "Interactive debug/diagnostics menu requested"
    run_debug_menu_only
    exit $?
elif [[ "${1:-}" == "--diag-logs-on" ]]; then
    log_info "Diagnostics log follower enable mode requested"
    run_diag_logs_on_only
    exit $?
elif [[ "${1:-}" == "--diag-logs-off" ]]; then
    log_info "Diagnostics log follower disable mode requested"
    execute_guarded "Stop diagnostics follower service" systemctl stop zypper-auto-diag-logs.service || true
    execute_guarded "Disable diagnostics follower service" systemctl disable zypper-auto-diag-logs.service || true
    update_status "SUCCESS: Diagnostics log follower disabled"
    exit 0
elif [[ "${1:-}" == "--snapshot-state" ]]; then
    log_info "Diagnostics snapshot mode requested"
    run_snapshot_state_only
    exit $?
elif [[ "${1:-}" == "--diag-bundle" ]]; then
    log_info "Diagnostics bundle mode requested"
    run_diag_bundle_only
    exit $?
elif [[ "${1:-}" == "--diag-logs-runner" ]]; then
    # Internal mode: invoked by the persistent zypper-auto-diag-logs.service
    # unit to actually follow logs. Users should not call this directly.
    log_info "Diagnostics follower runner mode requested (service)"
    run_diag_logs_runner_only
    exit $?
elif [[ "${1:-}" == "--show-logs" || "${1:-}" == "--show-loggs" ]]; then
    log_info "Diagnostics logs browser requested"
    diag_dir="${LOG_DIR}/diagnostics"
    echo "Diagnostics logs directory: ${diag_dir}"
    echo "Clickable:"
    print_clickable_url "file://${diag_dir}"

    # Ensure directory exists and is user-readable
    execute_guarded "Ensure diagnostics log directory exists (${diag_dir})" mkdir -p "${diag_dir}" || true

    # Allow the desktop user to traverse the parent log directory without
    # making all logs world-readable.
    execute_guarded "Allow desktop user to traverse ${LOG_DIR}" chmod 751 "${LOG_DIR}" || true

    execute_guarded "Ensure diagnostics directory is traversable" chmod 755 "${diag_dir}" || true
    execute_guarded "Ensure diagnostics logs are user-readable" \
        find "${diag_dir}" -type f -name 'diag-*.log' -exec chmod 644 {} \; || true

    # Try to open the folder (best-effort). If no GUI session is available,
    # this may fail; the clickable path printed above is the fallback.
    if ! open_folder_in_desktop_session "${diag_dir}" "${SUDO_USER:-}"; then
        rc=$?
        log_warn "--show-logs: could not open folder automatically (rc=${rc}). Use the printed file:// URL."
    fi

    exit 0
elif [[ "${1:-}" == "--test-notify" ]]; then
    log_info "Notification system self-test requested"
    if [ -z "${SUDO_USER:-}" ]; then
        log_error "Cannot run --test-notify without SUDO_USER (run via sudo)."
        exit 1
    fi
    USER_BUS_PATH="unix:path=/run/user/$(id -u "${SUDO_USER}")/bus"
    log_debug "Using user bus path for test-notify: ${USER_BUS_PATH}"
    # Propagate our RUN_ID into the Python notifier so notifier-detailed.log
    # can be correlated back to this helper invocation.
    sudo -u "${SUDO_USER}" DBUS_SESSION_BUS_ADDRESS="${USER_BUS_PATH}" \
        ZNH_RUN_ID="${RUN_ID}" \
        /usr/bin/python3 "${NOTIFY_SCRIPT_PATH}" --test-notify || true
    exit 0
elif [[ "${1:-}" == "--dashboard" || "${1:-}" == "--generate-dashboard" ]]; then
    log_info "Dashboard generation requested"
    run_generate_dashboard_only
    exit $?
elif [[ "${1:-}" == "--dash-stop" ]]; then
    log_info "Dashboard server stop requested"
    run_dash_stop_only
    exit $?
elif [[ "${1:-}" == "--dash-open" ]]; then
    log_info "Dashboard open requested"
    shift || true
    # Pass through optional browser override argument(s)
    run_dash_open_only "$@"
    exit $?
elif [[ "${1:-}" == "--dash-install" ]]; then
    log_info "Enterprise quickstart requested"
    run_dash_install_only
    exit $?
elif [[ "${1:-}" == "--dash-api-on" ]]; then
    shift || true
    token="${1:-}"
    log_info "Dashboard API enable requested"
    run_dash_api_on_only "${token}"
    exit $?
elif [[ "${1:-}" == "--dash-api-off" ]]; then
    log_info "Dashboard API disable requested"
    run_dash_api_off_only
    exit $?
elif [[ "${1:-}" == "--dash-api-status" ]]; then
    log_info "Dashboard API status requested"
    run_dash_api_status_only
    exit $?
elif [[ "${1:-}" == "--send-webhook" || "${1:-}" == "--webhook" ]]; then
    log_info "Webhook send requested"
    shift || true
    run_send_webhook_only "$@"
    exit $?
elif [[ "${1:-}" == "--status" ]]; then
    log_info "Status report mode requested"
    run_status_only
    exit $?
elif [[ "${1:-}" == "--uninstall-zypper" || "${1:-}" == "--uninstall-zypper-helper" ]]; then
    shift
    # Parse optional flags for the uninstaller:
    #   --yes / -y / --non-interactive : skip confirmation prompt
    #   --dry-run                      : show what would be removed, no changes
    #   --keep-logs                    : do not delete any log files under $LOG_DIR
    #   --keep-hooks                   : do not delete /etc/zypper-auto/hooks (custom scripts)
    #   --disable-maintenance-timers    : ALSO disable snapper/btrfs/fstrim timers enabled via Snapper Option 5
    UNINSTALL_ASSUME_YES=0
    UNINSTALL_DRY_RUN=0
    UNINSTALL_KEEP_LOGS=0
    UNINSTALL_KEEP_HOOKS=0
    UNINSTALL_DISABLE_MAINT_TIMERS=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --yes|-y|--non-interactive)
                UNINSTALL_ASSUME_YES=1
                ;;
            --dry-run)
                UNINSTALL_DRY_RUN=1
                ;;
            --keep-logs)
                UNINSTALL_KEEP_LOGS=1
                ;;
            --keep-hooks)
                UNINSTALL_KEEP_HOOKS=1
                ;;
            --disable-maintenance-timers)
                UNINSTALL_DISABLE_MAINT_TIMERS=1
                ;;
            *)
                log_error "Unknown option for --uninstall-zypper-helper: $1"
                exit 1
                ;;
        esac
        shift
    done
    log_info "Uninstall zypper-auto-helper mode requested"
    run_uninstall_helper_only
    exit $?
fi

# Optional mode: run verification and auto-repair
if [[ "${1:-}" == "--verify" || "${1:-}" == "--repair" || "${1:-}" == "--diagnose" ]]; then
    log_info "Verification and auto-repair mode requested"
    log_info "=============================================="
    log_info "Zypper Auto-Helper - Verification Mode"
    log_info "=============================================="

    # Set a flag to skip to verification section
    VERIFICATION_ONLY_MODE=1
    # We'll jump to the verification section after defining all variables
fi

# Skip installation if we're only verifying
if [ "${VERIFICATION_ONLY_MODE:-0}" -eq 1 ]; then
    log_info "Skipping installation steps - verification mode"
    # Need to set DOWNLOADER_SCRIPT path for verification
    DOWNLOADER_SCRIPT="/usr/local/bin/zypper-download-with-progress"
    ZYPPER_WRAPPER_PATH="$USER_BIN_DIR/zypper-with-ps"
    USER_LOG_DIR="$SUDO_USER_HOME/.local/share/zypper-notify"
    USER_BUS_PATH="unix:path=/run/user/$(id -u "$SUDO_USER")/bus"

    # In verification-only mode we *expect* a non-zero exit code when
    # problems are found, so disable the installer-wide ERR trap and
    # temporarily turn off 'set -e' so that run_verification_only can
    # complete and return its status cleanly instead of being treated as
    # a fatal installer error.
    trap - ERR
    set +e
    run_smart_verification_with_safety_net 2
    rc=$?
    set -e

    # Best-effort: refresh dashboard after verification/repairs.
    generate_dashboard || true

    # Remote monitoring: only notify on verification failure by default.
    if [ "$rc" -ne 0 ] 2>/dev/null; then
        send_webhook "zypper-auto-helper: Verification FAILED" \
            "One or more verification checks failed (rc=${rc}).\nLog: ${LOG_FILE}" \
            "16711680" || true
    fi

    exit $rc
fi

# If we reach this point, all supported option-like commands (e.g. --verify,
# --reset-config, --reset-downloads, --uninstall-zypper-helper, etc.) have
# already been handled and exited above. Reject any unknown option that starts
# with '-' so a typo like '-reset' does NOT silently fall back to a full
# installation.
if [[ $# -gt 0 && "${1:-}" == -* ]]; then
    log_error "Unknown option: $1"
    echo "Run 'zypper-auto-helper --help' for usage." | tee -a "${LOG_FILE}"
    exit 1
fi

# --- 2a. Pre-install environment snapshot ---
# Capture a detailed snapshot of the system and zypper environment at the
# start of installation so debug bundles can correlate failures even when
# they happen early in the flow.
if command -v uname >/dev/null 2>&1; then
    pre_env_ts="$(date +%Y%m%d-%H%M%S)"
    pre_env_file="${LOG_DIR}/pre-install-env-${pre_env_ts}.txt"
    {
        echo "===== Pre-install environment snapshot: $(date '+%Y-%m-%d %H:%M:%S') ====="
        echo "Host: $(hostname 2>/dev/null || echo 'unknown')"
        echo "Kernel: $(uname -srmo 2>/dev/null || echo 'unknown')"
        if [ -f /etc/os-release ]; then
            . /etc/os-release 2>/dev/null || true
            echo "OS: ${NAME:-unknown} ${VERSION:-} (ID=${ID:-?}, VARIANT_ID=${VARIANT_ID:--})"
        fi
        if command -v zypper >/dev/null 2>&1; then
            echo "--- zypper --version ---"
            zypper --version 2>&1 || echo "(zypper --version failed)"
            echo "--- zypper lr -d ---"
            zypper lr -d 2>&1 || echo "(zypper lr -d failed)"
        fi
        echo "--- Root filesystem usage (df -h /) ---"
        df -h / 2>&1 || echo "(df -h / failed)"
        if command -v systemctl >/dev/null 2>&1; then
            echo "--- systemctl --version ---"
            systemctl --version 2>&1 || echo "(systemctl --version failed)"
        fi
        echo "===== End pre-install environment snapshot ====="
    } >> "${pre_env_file}" 2>&1 || true
    log_success "Pre-install environment snapshot captured at ${pre_env_file}"
fi

# --- 2b. Dependency Checks ---
update_status "Checking dependencies..."
log_info ">>> Checking dependencies..."
check_and_install "nmcli" "NetworkManager" "checking metered connection"
check_and_install "upower" "upower" "battery/AC power detection (laptop safety)"
check_and_install "python3" "python3" "running the notifier script"
check_and_install "pkexec" "polkit" "graphical authentication"

# ShellCheck is not strictly required at runtime, but is highly recommended
# for safer maintenance of this bash-heavy project.
if ! command -v shellcheck >/dev/null 2>&1; then
    log_info "---"
    log_info "ℹ Recommended tool missing: 'shellcheck' (ShellCheck)"
    log_info "   Purpose: Bash static analysis (helps catch quoting/syntax bugs early)"
    log_info "   Package: ShellCheck"
    read -p "   Install ShellCheck now? [Y/n]: " -r REPLY_SHELLCHECK
    REPLY_SHELLCHECK="${REPLY_SHELLCHECK:-Y}"
    log_debug "User response (ShellCheck): $REPLY_SHELLCHECK"

    if [[ $REPLY_SHELLCHECK =~ ^[Yy]$ ]]; then
        log_info "Installing ShellCheck..."
        update_status "Installing recommended tool: ShellCheck"
        if execute_guarded "Install ShellCheck (recommended)" sudo zypper install -y "ShellCheck"; then
            log_success "ShellCheck installed"
        else
            # Non-fatal: leave install continuing.
            log_warn "ShellCheck install failed (non-fatal). You can install it later with: sudo zypper install ShellCheck"
        fi
    else
        log_info "ShellCheck install skipped (continuing)."
    fi
fi

# Check Python version (must be 3.7+)
log_debug "Checking Python version..."
PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
log_debug "Python version: $PY_VERSION"

if [ "$(echo -e "$PY_VERSION\n3.7" | sort -V | head -n1)" != "3.7" ]; then
    log_error "Python 3.7 or newer is required. Found $PY_VERSION."
    update_status "FAILED: Python version too old ($PY_VERSION)"
    exit 1
fi
log_success "Python version check passed: $PY_VERSION"

# Check for PyGobject (the notification library)
log_debug "Checking for PyGObject..."
if ! python3 -c "import gi" &> /dev/null; then
    log_info "---"
    log_info "⚠️  Dependency missing: 'python3-gobject' (for notifications)."
    read -p "   Install python3-gobject now? [Y/n]: " -r REPLY_GI
    REPLY_GI="${REPLY_GI:-Y}"
    log_debug "User response (PyGObject): $REPLY_GI"

    if [[ $REPLY_GI =~ ^[Yy]$ ]]; then
        log_info "Installing python3-gobject..."
        update_status "Installing python3-gobject..."

        if ! execute_guarded "Install python3-gobject" sudo zypper install -y "python3-gobject"; then
            log_error "Failed to install python3-gobject. Please install it manually and re-run this script."
            update_status "FAILED: Could not install python3-gobject"
            exit 1
        fi
        log_success "Successfully installed python3-gobject"
    else
        log_error "Dependency 'python3-gobject' is required. Please install it manually and re-run this script."
        update_status "FAILED: python3-gobject not installed"
        exit 1
    fi
else
    log_success "PyGObject found"
fi
log_success "All dependencies passed"
update_status "All dependencies verified"

# Ensure hook directories exist (enterprise extensibility).
ensure_hook_dirs || true
# Best-effort: provide hook templates so users can quickly enable hooks.
install_hook_templates || true

# --- 3. Clean Up Old Logs First ---
log_info ">>> Cleaning up old log files..."
update_status "Cleaning up old installation logs..."
cleanup_old_logs

# --- 4. Clean Up ALL Previous Versions (System & User) ---
log_info ">>> Cleaning up all old system-wide services..."
update_status "Removing old system services..."
log_debug "Disabling old timers and services..."

# These legacy units may or may not exist depending on which older build was
# previously installed. Treat missing units as normal.
if __znh_unit_file_exists_system zypper-autodownload.timer; then
    execute_optional "Disable legacy downloader timer" systemctl disable --now zypper-autodownload.timer
else
    log_debug "Legacy unit not present (skipping): zypper-autodownload.timer"
fi
if __znh_unit_file_exists_system zypper-autodownload.service; then
    execute_optional "Stop legacy downloader service" systemctl stop zypper-autodownload.service
else
    log_debug "Legacy unit not present (skipping): zypper-autodownload.service"
fi

if __znh_unit_file_exists_system zypper-notify.timer; then
    execute_optional "Disable legacy notifier timer" systemctl disable --now zypper-notify.timer
else
    log_debug "Legacy unit not present (skipping): zypper-notify.timer"
fi
if __znh_unit_file_exists_system zypper-notify.service; then
    execute_optional "Stop legacy notifier service" systemctl stop zypper-notify.service
else
    log_debug "Legacy unit not present (skipping): zypper-notify.service"
fi

if __znh_unit_file_exists_system zypper-smart-updater.timer; then
    execute_optional "Disable legacy smart-updater timer" systemctl disable --now zypper-smart-updater.timer
else
    log_debug "Legacy unit not present (skipping): zypper-smart-updater.timer"
fi
if __znh_unit_file_exists_system zypper-smart-updater.service; then
    execute_optional "Stop legacy smart-updater service" systemctl stop zypper-smart-updater.service
else
    log_debug "Legacy unit not present (skipping): zypper-smart-updater.service"
fi

log_debug "Removing old system binaries..."
execute_guarded "Remove legacy system binaries" rm -f \
    /usr/local/bin/zypper-run-install* \
    /usr/local/bin/notify-updater \
    /usr/local/bin/zypper-smart-updater-script || true
log_success "Old system services disabled and files removed"

log_info ">>> Cleaning up old user-space services..."
update_status "Removing old user services..."
SUDO_USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
log_debug "Disabling user timer..."
USER_BUS_PATH="$(get_user_bus "$SUDO_USER")"
if __znh_unit_file_exists_user "${SUDO_USER}" zypper-notify-user.timer; then
    execute_optional "Disable legacy user notifier timer" \
        sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" \
        systemctl --user disable --now zypper-notify-user.timer
else
    log_debug "Legacy user unit not present (skipping): zypper-notify-user.timer"
fi

# Force kill any running Python notifier processes
log_debug "Force-killing any running Python notifier processes..."
if pgrep -f "zypper-notify-updater.py" &>/dev/null; then
    execute_optional "Kill any running legacy notifier processes" pkill -9 -f "zypper-notify-updater.py"
    sleep 1
else
    log_debug "No legacy notifier processes found (skipping pkill)"
fi

# Clear Python bytecode cache
log_debug "Clearing Python bytecode cache..."
execute_guarded "Clear legacy .pyc files" find "$SUDO_USER_HOME/.local/bin" -name "*.pyc" -delete || true
execute_guarded "Clear legacy __pycache__ directories" find "$SUDO_USER_HOME/.local/bin" -type d -name "__pycache__" -exec rm -rf {} + || true

log_debug "Removing old user binaries and configs..."
execute_guarded "Remove legacy user scripts and units" rm -f \
    "$SUDO_USER_HOME/.local/bin/zypper-run-install*" \
    "$SUDO_USER_HOME/.local/bin/zypper-open-terminal*" \
    "$SUDO_USER_HOME/.local/bin/zypper-notify-updater" \
    "$SUDO_USER_HOME/.local/bin/zypper-notify-updater.py" \
    "$SUDO_USER_HOME/.config/systemd/user/zypper-notify-user."* || true
log_success "Old user services disabled and files removed"

# --- 5. Create/Update DOWNLOADER (Root Service) ---
log_info ">>> Creating (root) downloader service: ${DL_SERVICE_FILE}"
update_status "Creating system downloader service..."
log_debug "Writing service file: ${DL_SERVICE_FILE}"

# Derive systemd OnCalendar/OnBootSec values from the configured
# DL_TIMER_INTERVAL_MINUTES. We keep this constrained to a small
# set of safe values (1,5,10,15,30,60) via load_config.
DL_ONBOOTSEC="${DL_TIMER_INTERVAL_MINUTES}min"
DL_ONCALENDAR="minutely"
if [ "$DL_TIMER_INTERVAL_MINUTES" -eq 60 ]; then
    DL_ONCALENDAR="hourly"
elif [ "$DL_TIMER_INTERVAL_MINUTES" -ne 1 ]; then
    DL_ONCALENDAR="*:0/${DL_TIMER_INTERVAL_MINUTES}"
fi

# Create service log directory
execute_guarded "Ensure service logs directory exists" mkdir -p "${LOG_DIR}/service-logs" || true
execute_guarded "Set service logs directory permissions" chmod 755 "${LOG_DIR}/service-logs" || true

# First, create the downloader script with progress tracking
DOWNLOADER_SCRIPT="/usr/local/bin/zypper-download-with-progress"
log_debug "Creating downloader script with progress tracking: $DOWNLOADER_SCRIPT"
write_atomic "$DOWNLOADER_SCRIPT" << 'DLSCRIPT'
#!/bin/bash
# Zypper downloader with real-time progress tracking
set -euo pipefail

LOG_DIR="/var/log/zypper-auto"
STATUS_FILE="$LOG_DIR/download-status.txt"
START_TIME_FILE="$LOG_DIR/download-start-time.txt"
CACHE_DIR="/var/cache/zypp/packages"

# Per-run correlation ID for the downloader (separate from the install helper
# RUN_ID). This helps correlate downloader activity inside journalctl.
RUN_ID="DL-$(date +%Y%m%dT%H%M%S)-$$"

# Best-effort journald/syslog integration for key events.
# Disabled when ZYPPER_AUTO_JOURNAL_LOGGING=0 is set in the environment.
JOURNAL_LOGGING_ENABLED="${ZYPPER_AUTO_JOURNAL_LOGGING:-1}"

dlog() {
    # Always include a stable tag and a per-run RUN id.
    local msg="$*"
    if [ "${JOURNAL_LOGGING_ENABLED}" = "0" ]; then
        return 0
    fi
    command -v logger >/dev/null 2>&1 || return 0
    logger -t "zypper-auto-helper" -p user.info -- "[DOWNLOADER] [RUN=${RUN_ID}] ${msg}" 2>/dev/null || true
}

derr() {
    local msg="$*"
    if [ "${JOURNAL_LOGGING_ENABLED}" = "0" ]; then
        return 0
    fi
    command -v logger >/dev/null 2>&1 || return 0
    logger -t "zypper-auto-helper" -p user.err -- "[DOWNLOADER] [RUN=${RUN_ID}] ${msg}" 2>/dev/null || true
}

dlog "Downloader run started"

# Atomic write helper for the shared status file so the user notifier
# never sees partially-written lines.
write_status() {
    local value="$1" tmp
    tmp="${STATUS_FILE}.tmp.$$"
    printf '%s\n' "$value" >"$tmp" 2>/dev/null && mv -f "$tmp" "$STATUS_FILE"
}

# Optional: read extra dup flags from /etc/zypper-auto.conf so users can
# tweak solver behaviour (e.g. --allow-vendor-change) without editing
# this script directly.
CONFIG_FILE="/etc/zypper-auto.conf"
if [ -f "$CONFIG_FILE" ]; then
    # shellcheck source=/etc/zypper-auto.conf
    . "$CONFIG_FILE"
fi
DUP_EXTRA_FLAGS="${DUP_EXTRA_FLAGS:-}"
CACHE_EXPIRY_MINUTES="${CACHE_EXPIRY_MINUTES:-10}"
DOWNLOADER_DOWNLOAD_MODE="${DOWNLOADER_DOWNLOAD_MODE:-full}"

# Skip running any downloads on metered connections.
# We cannot rely on systemd's ConditionNotOnMeteredConnection everywhere,
# so we enforce it inside the downloader as well.
#
# Optimization: cache the metered result for a short TTL so very frequent
# timers (e.g. minutely) don't call nmcli every run when the network state
# is stable.
METERED_CACHE_FILE="${LOG_DIR}/metered-state.txt"
METERED_CACHE_TTL_SECONDS=300

is_metered() {
    command -v nmcli >/dev/null 2>&1 || return 1

    local line name uuid active ident metered

    # Format: NAME:UUID:ACTIVE
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        IFS=':' read -r name uuid active <<<"$line" || true
        [ "${active:-}" = "yes" ] || continue
        ident="${uuid:-${name:-}}"
        [ -n "$ident" ] || continue

        metered=$(nmcli -g GENERAL.METERED connection show "$ident" 2>/dev/null | tr -d '\r' | tr '[:upper:]' '[:lower:]' | head -n1 || true)
        case "${metered}" in
            yes|guess-yes|payg|guess-payg)
                return 0
                ;;
        esac
    done < <(nmcli -t -f NAME,UUID,ACTIVE connection show 2>/dev/null || true)

    return 1
}

is_metered_cached() {
    local force="${1:-0}" now ts state

    # If nmcli is missing, treat as unmetered to avoid false skips.
    command -v nmcli >/dev/null 2>&1 || return 1

    now=$(date +%s 2>/dev/null || echo 0)

    if [ "$force" != "1" ] && [ -f "${METERED_CACHE_FILE}" ]; then
        read -r ts state <"${METERED_CACHE_FILE}" 2>/dev/null || true
        if [[ "${ts:-}" =~ ^[0-9]+$ ]] && [ "${now:-0}" -gt 0 ] 2>/dev/null; then
            if [ $((now - ts)) -lt "${METERED_CACHE_TTL_SECONDS}" ] 2>/dev/null; then
                if [ "${state:-}" = "metered" ]; then
                    return 0
                fi
                return 1
            fi
        fi
    fi

    if is_metered; then
        printf '%s %s\n' "${now}" metered >"${METERED_CACHE_FILE}" 2>/dev/null || true
        return 0
    fi

    printf '%s %s\n' "${now}" unmetered >"${METERED_CACHE_FILE}" 2>/dev/null || true
    return 1
}

if is_metered_cached; then
    echo "Metered connection detected via nmcli; skipping downloader run." >&2
    dlog "Metered connection detected; skipping downloader run"
    # Reset status to idle so the user notifier doesn't get stuck showing stale stages.
    write_status "idle"
    exit 0
fi

# Smart minimum interval between refresh/dry-run runs. This reuses the
# same CACHE_EXPIRY_MINUTES knob as the notifier so we don't hammer
# mirrors with constant metadata/solver checks when the timer is very
# frequent (e.g. every minute).
LAST_CHECK_FILE="$LOG_DIR/download-last-check.txt"
NOW=$(date +%s)
if [ -f "$LAST_CHECK_FILE" ]; then
    LAST=$(cat "$LAST_CHECK_FILE" 2>/dev/null || echo 0)
    if [ "$LAST" -gt 0 ] 2>/dev/null; then
        MIN_INTERVAL=$((CACHE_EXPIRY_MINUTES * 60))
        if [ "$MIN_INTERVAL" -gt 0 ] && [ $((NOW - LAST)) -lt "$MIN_INTERVAL" ]; then
            # Too soon since last full check; skip this run quietly and
            # let the existing status/notifications stand.
            exit 0
        fi
    fi
fi
echo "$NOW" > "$LAST_CHECK_FILE"

# Helper: trigger the user notifier immediately after downloads complete
trigger_notifier() {
    # Best-effort detection of the primary non-root user with a systemd user session.
    local user uid
    user=$(loginctl list-users --no-legend 2>/dev/null | awk '$1 != 0 {print $2; exit}') || user=""
    if [ -z "$user" ]; then
        return 0
    fi
    uid=$(id -u "$user" 2>/dev/null || echo "")
    if [ -z "$uid" ]; then
        return 0
    fi
    sudo -u "$user" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${uid}/bus" \
        systemctl --user start zypper-notify-user.service \
        >/dev/null 2>&1 || true
}

# Write status: refreshing
# downloader doesn't spam errors when the user is running zypper/YaST. We
# rely on zypper's official exit code 7 to detect a held ZYPP lock instead
# of grepping error messages or inspecting /run/zypp.pid, which can be
# racy and fragile.
handle_lock_or_fail() {
    local exit_code="$1" err_file="$2"
    if [ "$exit_code" -eq 7 ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Zypper is locked by another process; skipping this downloader run (will retry on next timer)" >&2
        dlog "Zypper lock detected (exit 7); skipping this run"
        write_status "idle"
        if [ -n "$err_file" ] && [ -f "$err_file" ]; then
            rm -f "$err_file"
        fi
        exit 0
    fi
}

# Write status: refreshing
write_status "refreshing"
date +%s > "$START_TIME_FILE"

# Refresh repos
REFRESH_ERR=$(mktemp)
# Run with *low* CPU/IO priority so background checks don't cause interactive lag.
/usr/bin/nice -n 10 /usr/bin/ionice -c2 -n7 /usr/bin/zypper --non-interactive --no-gpg-checks refresh >/dev/null 2>"$REFRESH_ERR"
ZYP_EXIT=$?
if [ "$ZYP_EXIT" -ne 0 ]; then
    # If another zypper instance holds the lock, handle_lock_or_fail will
    # mark the status as idle and exit 0 so we do not treat it as an
    # error here.
    handle_lock_or_fail "$ZYP_EXIT" "$REFRESH_ERR"

    # At this point we know the error was not a simple lock. Classify it
    # as a network/repository problem so the notifier can surface a clear
    # error message instead of silently doing nothing.
    if grep -qi "could not resolve host" "$REFRESH_ERR" || \
       grep -qi "Failed to retrieve new repository metadata" "$REFRESH_ERR"; then
        # If network state changed mid-run and is now metered, treat this as a
        # skip instead of an error to avoid noisy notifications.
        if is_metered_cached 1; then
            write_status "idle"
            dlog "Network error during refresh but connection is now metered; treating as idle"
        else
            write_status "error:network"
        fi
    else
        write_status "error:repo"
    fi

    cat "$REFRESH_ERR" >&2 || true
    STATUS_NOW=$(cat "$STATUS_FILE" 2>/dev/null || echo unknown)
    derr "Refresh failed (rc=${ZYP_EXIT}); status=${STATUS_NOW}"
    rm -f "$REFRESH_ERR"
    # Exit 0 so systemd does not mark the service failed; the notifier
    # will pick up the error:* status on the next run.
    exit 0
fi
rm -f "$REFRESH_ERR"

# Get update info
DRY_OUTPUT=$(mktemp)
DRY_ERR=$(mktemp)
/usr/bin/nice -n 10 /usr/bin/ionice -c2 -n7 /usr/bin/zypper --non-interactive dup --dry-run > "$DRY_OUTPUT" 2>"$DRY_ERR"
ZYP_EXIT=$?
if [ "$ZYP_EXIT" -ne 0 ]; then
    # Handle lock first; if it is just a lock, this will mark status idle
    # and exit 0 so we do not need to set an additional error state.
    handle_lock_or_fail "$ZYP_EXIT" "$DRY_ERR"

    # Non-lock failure at the dry-run stage – mirror the refresh handling
    # so the notifier can display a meaningful error notification.
    if grep -qi "could not resolve host" "$DRY_ERR" || \
       grep -qi "Failed to retrieve new repository metadata" "$DRY_ERR"; then
        if is_metered_cached 1; then
            write_status "idle"
            dlog "Network error during dry-run but connection is now metered; treating as idle"
        else
            write_status "error:network"
        fi
    else
        write_status "error:repo"
    fi

    cat "$DRY_ERR" >&2 || true
    STATUS_NOW=$(cat "$STATUS_FILE" 2>/dev/null || echo unknown)
    derr "Dry-run failed (rc=${ZYP_EXIT}); status=${STATUS_NOW}"
    rm -f "$DRY_ERR" "$DRY_OUTPUT"
    exit 0
fi
rm -f "$DRY_ERR"

# Persist full dry-run output so the user-space notifier can parse it
# without running zypper itself. Use an atomic rename so readers never
# see a partially-written file.
DRYRUN_OUTPUT_FILE="$LOG_DIR/dry-run-last.txt"
DRYRUN_TMP=$(mktemp)
cp "$DRY_OUTPUT" "$DRYRUN_TMP"
chmod 644 "$DRYRUN_TMP"
mv "$DRYRUN_TMP" "$DRYRUN_OUTPUT_FILE"

if ! grep -q "packages to upgrade" "$DRY_OUTPUT"; then
    # No packages to upgrade; mark idle so the notifier shows a
    # "no updates" state on the next run. DRYRUN_OUTPUT_FILE already
    # contains the latest "Nothing to do" output for reference.
    write_status "idle"
    dlog "No packages to upgrade (idle)"
    rm -f "$DRY_OUTPUT"
    exit 0
fi

# Extract package count and size
PKG_COUNT=$(grep -oP "\d+(?= packages to upgrade)" "$DRY_OUTPUT" | head -1)
DOWNLOAD_SIZE=$(grep -oP "Overall download size: ([\d.]+ [KMG]iB)" "$DRY_OUTPUT" | grep -oP "[\d.]+ [KMG]iB" || echo "unknown")

# Detect case where everything is already cached so we don't show a fake
# download progress bar. In that situation zypper's summary contains a
    # line similar to:
#   0 B  |  -   88.3 MiB  already in cache
if grep -q "already in cache" "$DRY_OUTPUT" && \
   grep -qE "^[[:space:]]*0 B[[:space:]]*\\|" "$DRY_OUTPUT"; then
    # All data is already in the local cache; mark as a completed
    # download with 0 newly-downloaded packages and skip the
    # --download-only pass entirely.
    write_status "complete:0:0"
    trigger_notifier
    rm -f "$DRY_OUTPUT"
    exit 0
fi

rm -f "$DRY_OUTPUT"

# Count packages before download
# NOTE: limit depth to keep the scan cheap; cache layout is typically:
#   /var/cache/zypp/packages/<repo>/<arch>/*.rpm
BEFORE_COUNT=$(find "$CACHE_DIR" -maxdepth 4 -type f -name "*.rpm" 2>/dev/null | wc -l)

# Write initial downloading status so the tracker loop sees it immediately
write_status "downloading:$PKG_COUNT:$DOWNLOAD_SIZE:0:0"

# Start background progress tracker (coarse; avoids aggressive disk scans)
# Optimization: only rescan the cache when the cache directory tree mtime changes.
get_cache_tree_mtime() {
    # Avoid a full rpm scan when nothing has changed.
    # Note: CACHE_DIR mtime alone may not change for nested directory writes,
    # so we include up to 2 directory levels as a low-cost approximation.
    local newest
    newest=$( {
        stat -c %Y "$CACHE_DIR" 2>/dev/null || true
        # Prefer directories only to keep this cheap even when rpms exist at unexpected paths.
        stat -c %Y "$CACHE_DIR"/*/ 2>/dev/null || true
        stat -c %Y "$CACHE_DIR"/*/*/ 2>/dev/null || true
    } | awk 'BEGIN{m=0} {if($1>m)m=$1} END{print m}' 2>/dev/null || true)
    echo "${newest:-0}"
}

CACHE_MTIME_LAST=$(get_cache_tree_mtime)
CURRENT_COUNT_CACHED=$BEFORE_COUNT

wait_for_cache_event_or_timeout() {
    # Event-driven wait (0% CPU when idle): sleep until the cache changes.
    # Uses inotify-tools when available; otherwise falls back to sleep.
    local timeout_s="${1:-300}"

    if command -v inotifywait >/dev/null 2>&1; then
        # Best-effort recursive watch. If there are too many repos/dirs and
        # the watch fails, we fall back to a timed sleep.
        set +e
        inotifywait -qq -r -t "${timeout_s}" \
            -e create,delete,moved_to,moved_from,close_write "${CACHE_DIR}" \
            2>/dev/null
        local rc=$?
        set -e
        case "${rc}" in
            0|2) return 0 ;;  # 0=event, 2=timeout
            *) : ;;
        esac
    fi

    sleep 10
}

(
    while [ -f "$STATUS_FILE" ] && grep -q "^downloading:" "$STATUS_FILE" 2>/dev/null; do
        # Wait for a cache event OR a timeout (so the dashboard still updates
        # occasionally even if downloads stall).
        wait_for_cache_event_or_timeout 300

        CACHE_MTIME_NOW=$(get_cache_tree_mtime)
        if [ "${CACHE_MTIME_NOW}" != "${CACHE_MTIME_LAST}" ]; then
            CACHE_MTIME_LAST="${CACHE_MTIME_NOW}"
            CURRENT_COUNT_CACHED=$(find "$CACHE_DIR" -maxdepth 4 -type f -name "*.rpm" 2>/dev/null | wc -l)
        fi

        CURRENT_COUNT=$CURRENT_COUNT_CACHED
        DOWNLOADED=$((CURRENT_COUNT - BEFORE_COUNT))
        if [ $DOWNLOADED -lt 0 ]; then DOWNLOADED=0; fi
        if [ $DOWNLOADED -gt $PKG_COUNT ]; then DOWNLOADED=$PKG_COUNT; fi

        # Calculate percentage
        if [ $PKG_COUNT -gt 0 ]; then
            PERCENT=$((DOWNLOADED * 100 / PKG_COUNT))
        else
            PERCENT=0
        fi

        write_status "downloading:$PKG_COUNT:$DOWNLOAD_SIZE:$DOWNLOADED:$PERCENT"
    done
) &
TRACKER_PID=$!

# If the downloader is running in detect-only mode, skip the heavy
# "dup --download-only" pass and just trigger the notifier so it can
# inform the user that updates are available. This avoids extra
# bandwidth and disk usage when the user only cares about detection.
if [ "$DOWNLOADER_DOWNLOAD_MODE" = "detect-only" ]; then
    # Mark as a completed detection-only cycle; no new packages were
    # downloaded by this helper, but the notifier will see that updates
    # exist from its own dry-run.
    write_status "complete:0:0"
    dlog "Detection-only mode; skipping download-only pass"
    trigger_notifier
    exit 0
fi

# Do the actual download. We intentionally ignore most non-zero exit codes so
# that partial downloads remain in the cache even if zypper encounters solver
# problems that require manual intervention later. We still special-case the
# lock error to avoid noisy logs when another zypper instance is running.
set +e
DL_ERR=$(mktemp)
/usr/bin/nice -n 10 /usr/bin/ionice -c2 -n7 /usr/bin/zypper --non-interactive --no-gpg-checks dup --download-only $DUP_EXTRA_FLAGS >/dev/null 2>"$DL_ERR"
ZYP_RET=$?
if [ "$ZYP_RET" -ne 0 ]; then
    handle_lock_or_fail "$ZYP_RET" "$DL_ERR"
fi
rm -f "$DL_ERR"
set -e

# Kill the progress tracker
kill $TRACKER_PID 2>/dev/null || true
wait $TRACKER_PID 2>/dev/null || true

# Count packages after download
AFTER_COUNT=$(find "$CACHE_DIR" -maxdepth 4 -type f -name "*.rpm" 2>/dev/null | wc -l)
ACTUAL_DOWNLOADED=$((AFTER_COUNT - BEFORE_COUNT))

# Calculate duration
START_TIME=$(cat "$START_TIME_FILE" 2>/dev/null || date +%s)
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Decide final status:
#  - If we actually downloaded new packages, mark as complete
#  - If nothing was downloaded but zypper returned an error, mark an error
#    so the notifier can tell the user that manual intervention is required
#  - Otherwise, leave the previous status (e.g. idle or complete:0:0)
if [ $ACTUAL_DOWNLOADED -gt 0 ]; then
    # Triggered maintenance marker: only request cache cleanup when we actually
    # downloaded something.
    touch "${LOG_DIR}/cleanup-needed.stamp" 2>/dev/null || true
    if command -v systemctl >/dev/null 2>&1; then
        systemctl start zypper-cache-cleanup.service >/dev/null 2>&1 || true
    fi

    write_status "complete:$DURATION:$ACTUAL_DOWNLOADED"
    dlog "Download complete: downloaded=${ACTUAL_DOWNLOADED} duration=${DURATION}s"
    trigger_notifier
elif [ $ZYP_RET -ne 0 ]; then
    write_status "error:solver:$ZYP_RET"
    derr "Download-only returned rc=${ZYP_RET} (solver/manual intervention may be required)"
fi

# Keep the live dashboard data fresh (best-effort): regenerate status.html + status-data.json
# at the end of downloader runs so long-lived dashboard tabs don't go stale.
if [ "${DASHBOARD_ENABLED:-true}" = "true" ] && [ -x /usr/local/bin/zypper-auto-helper ]; then
    /usr/local/bin/zypper-auto-helper --dashboard >/dev/null 2>&1 || true
fi

DLSCRIPT
chmod +x "$DOWNLOADER_SCRIPT"
log_success "Downloader script created with progress tracking"

# Now create the service file
write_atomic "${DL_SERVICE_FILE}" << EOF
[Unit]
Description=Download Tumbleweed updates in background
ConditionACPower=true
Wants=network-online.target
After=network-online.target nss-lookup.target

[Service]
Type=oneshot
# Run in the background with low CPU/IO priority to avoid interactive lag.
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7

# Resource caps (best-effort; ignored on older systemd / cgroup setups)
CPUWeight=20
IOWeight=20
MemoryHigh=750M
MemoryMax=1G

StandardOutput=append:${LOG_DIR}/service-logs/downloader.log
StandardError=append:${LOG_DIR}/service-logs/downloader-error.log
ExecStart=${DOWNLOADER_SCRIPT}

# Systemd hardening (optional but safe for this service)
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
NoNewPrivileges=yes
ReadWritePaths=/var/cache/zypp /var/log/zypper-auto
EOF
log_success "Downloader service file created"
chmod 644 "${DL_SERVICE_FILE}" 2>/dev/null || true
chown root:root "${DL_SERVICE_FILE}" 2>/dev/null || true

# --- 6. Create/Update DOWNLOADER (Root Timer) ---
log_info ">>> Creating (root) downloader timer: ${DL_TIMER_FILE}"
log_debug "Writing timer file: ${DL_TIMER_FILE}"
write_atomic "${DL_TIMER_FILE}" << EOF
[Unit]
Description=Run ${DL_SERVICE_NAME} periodically to download updates

[Timer]
OnBootSec=${DL_ONBOOTSEC}
OnCalendar=${DL_ONCALENDAR}
Persistent=true

[Install]
WantedBy=timers.target
EOF
log_success "Downloader timer file created"
chmod 644 "${DL_TIMER_FILE}" 2>/dev/null || true
chown root:root "${DL_TIMER_FILE}" 2>/dev/null || true

log_info ">>> Enabling (root) downloader timer: ${DL_SERVICE_NAME}.timer"
update_status "Enabling system downloader timer..."
log_debug "Reloading systemd daemon..."
execute_guarded "systemd daemon-reload" systemctl daemon-reload

log_debug "Enabling and starting timer..."
if execute_guarded "Enable + start ${DL_SERVICE_NAME}.timer" systemctl enable --now "${DL_SERVICE_NAME}.timer"; then
    log_success "Downloader timer enabled and started"
else
    log_error "Failed to enable downloader timer"
    update_status "FAILED: Could not enable downloader timer"
    exit 1
fi

# --- 6b. Create Cache Cleanup Service ---
log_info ">>> Creating (root) cache cleanup service: ${CLEANUP_SERVICE_FILE}"
update_status "Creating cache cleanup service..."
log_debug "Writing service file: ${CLEANUP_SERVICE_FILE}"
write_atomic "${CLEANUP_SERVICE_FILE}" << EOF
[Unit]
Description=Clean up old zypper cache packages
# Only run when an update/download actually happened (marker created by
# the downloader or the interactive install helper).
ConditionPathExists=${LOG_DIR}/cleanup-needed.stamp

[Service]
Type=oneshot
ExecStart=/usr/bin/find /var/cache/zypp/packages -type f -name '*.rpm' -mtime +30 -delete
ExecStart=/usr/bin/find /var/cache/zypp/packages -type d -empty -delete
ExecStartPost=/usr/bin/rm -f ${LOG_DIR}/cleanup-needed.stamp
StandardOutput=append:${LOG_DIR}/service-logs/cleanup.log
StandardError=append:${LOG_DIR}/service-logs/cleanup-error.log
EOF
log_success "Cache cleanup service file created"
chmod 644 "${CLEANUP_SERVICE_FILE}" 2>/dev/null || true
chown root:root "${CLEANUP_SERVICE_FILE}" 2>/dev/null || true

log_info ">>> Creating (root) cache cleanup timer: ${CLEANUP_TIMER_FILE}"
log_debug "Writing timer file: ${CLEANUP_TIMER_FILE}"
write_atomic "${CLEANUP_TIMER_FILE}" << EOF
[Unit]
Description=Run cache cleanup weekly

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
EOF
log_success "Cache cleanup timer file created"
chmod 644 "${CLEANUP_TIMER_FILE}" 2>/dev/null || true
chown root:root "${CLEANUP_TIMER_FILE}" 2>/dev/null || true

log_info ">>> Enabling (root) cache cleanup timer: ${CLEANUP_SERVICE_NAME}.timer"
update_status "Enabling cache cleanup timer..."
execute_guarded "systemd daemon-reload (cache cleanup)" systemctl daemon-reload
if execute_guarded "Enable + start ${CLEANUP_SERVICE_NAME}.timer" systemctl enable --now "${CLEANUP_SERVICE_NAME}.timer"; then
log_success "Cache cleanup timer enabled and started"
else
    log_error "Failed to enable cache cleanup timer (non-fatal)"
fi

# --- 6c. Create verification/auto-repair service and timer ---
log_info ">>> Creating (root) verification/auto-repair service: ${VERIFY_SERVICE_FILE}"
update_status "Creating verification service..."
log_debug "Writing service file: ${VERIFY_SERVICE_FILE}"

# Derive systemd schedule for the verification timer from
# VERIFY_TIMER_INTERVAL_MINUTES. We mirror the downloader's
# behaviour: minutely/hourly for 1/60, or "*:0/N" for other values.
# Run shortly after boot instead of waiting a full interval.
VERIFY_ONBOOTSEC="30s"
VERIFY_ONCALENDAR="minutely"
if [ "${VERIFY_TIMER_INTERVAL_MINUTES}" -eq 60 ]; then
    VERIFY_ONCALENDAR="hourly"
elif [ "${VERIFY_TIMER_INTERVAL_MINUTES}" -ne 1 ]; then
    VERIFY_ONCALENDAR="*:0/${VERIFY_TIMER_INTERVAL_MINUTES}"
fi

write_atomic "${VERIFY_SERVICE_FILE}" << EOF
[Unit]
Description=Verify and auto-repair zypper-auto-helper installation
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
# Run in the background with low CPU/IO priority.
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7

# Resource caps (best-effort; ignored on older systemd / cgroup setups)
CPUWeight=20
IOWeight=20
MemoryHigh=750M
MemoryMax=1G

ExecStart=/usr/local/bin/zypper-auto-helper --verify
StandardOutput=append:${LOG_DIR}/service-logs/verify.log
StandardError=append:${LOG_DIR}/service-logs/verify-error.log

# Hardening
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
NoNewPrivileges=yes
ReadWritePaths=${LOG_DIR} /run /var/run /var/cache/zypp
EOF
log_success "Verification service file created"
chmod 644 "${VERIFY_SERVICE_FILE}" 2>/dev/null || true
chown root:root "${VERIFY_SERVICE_FILE}" 2>/dev/null || true

log_info ">>> Creating (root) verification timer: ${VERIFY_TIMER_FILE}"
log_debug "Writing timer file: ${VERIFY_TIMER_FILE}"
write_atomic "${VERIFY_TIMER_FILE}" << EOF
[Unit]
Description=Run ${VERIFY_SERVICE_NAME} periodically to verify and auto-repair helper

[Timer]
OnBootSec=${VERIFY_ONBOOTSEC}
OnCalendar=${VERIFY_ONCALENDAR}
Persistent=true

[Install]
WantedBy=timers.target
EOF
log_success "Verification timer file created"
chmod 644 "${VERIFY_TIMER_FILE}" 2>/dev/null || true
chown root:root "${VERIFY_TIMER_FILE}" 2>/dev/null || true

log_info ">>> Enabling (root) verification timer: ${VERIFY_SERVICE_NAME}.timer"
update_status "Enabling verification timer..."
execute_guarded "systemd daemon-reload (verification timer)" systemctl daemon-reload
if execute_guarded "Enable + start ${VERIFY_SERVICE_NAME}.timer" systemctl enable --now "${VERIFY_SERVICE_NAME}.timer"; then
    log_success "Verification timer enabled and started"
else
    log_error "Failed to enable verification timer (non-fatal)"
fi

# --- 7. Create User Directories ---
log_info ">>> Creating user directories (if needed)..."
update_status "Creating user directories..."
log_debug "Creating $USER_CONFIG_DIR"
mkdir -p "$USER_CONFIG_DIR"
chown -R "$SUDO_USER:$SUDO_USER" "$SUDO_USER_HOME/.config"

log_debug "Creating $USER_BIN_DIR"
mkdir -p "$USER_BIN_DIR"
chown -R "$SUDO_USER:$SUDO_USER" "$SUDO_USER_HOME/.local"
log_success "User directories created"

# Create user log directory
USER_LOG_DIR="$SUDO_USER_HOME/.local/share/zypper-notify"
log_debug "Creating user log directory: $USER_LOG_DIR"
mkdir -p "$USER_LOG_DIR"
chown -R "$SUDO_USER:$SUDO_USER" "$USER_LOG_DIR"

# --- 7b. Create Zypper Wrapper for Manual Updates ---
log_info ">>> Creating zypper wrapper script for manual updates..."
update_status "Creating zypper wrapper..."
ZYPPER_WRAPPER_PATH="$USER_BIN_DIR/zypper-with-ps"
log_debug "Writing zypper wrapper to: $ZYPPER_WRAPPER_PATH"
write_atomic "$ZYPPER_WRAPPER_PATH" << 'EOF'
#!/usr/bin/env bash
# Zypper wrapper that automatically runs 'zypper ps -s' after 'zypper dup'
# This shows which services need restarting after updates

# Load feature toggles from the same config used by the installer.
CONFIG_FILE="/etc/zypper-auto.conf"

# Default feature toggles (can be overridden by CONFIG_FILE)
ENABLE_FLATPAK_UPDATES="true"
ENABLE_SNAP_UPDATES="true"
ENABLE_SOAR_UPDATES="true"
ENABLE_BREW_UPDATES="true"
ENABLE_PIPX_UPDATES="true"

if [ -r "$CONFIG_FILE" ]; then
    # shellcheck disable=SC1090
    . "$CONFIG_FILE"
fi

# Enterprise extensions (optional)
HOOKS_ENABLED="${HOOKS_ENABLED:-true}"
HOOKS_BASE_DIR="${HOOKS_BASE_DIR:-/etc/zypper-auto/hooks}"
WEBHOOK_URL="${WEBHOOK_URL:-}"
DASHBOARD_ENABLED="${DASHBOARD_ENABLED:-true}"
RUN_ID="WRAP-$(date +%Y%m%dT%H%M%S)-$$"

HELPER_STATUS_FILE="/var/log/zypper-auto/last-status.txt"

_json_escape() {
    local s="$*"
    s=${s//\\/\\\\}
    s=${s//"/\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

_redact_url() {
    local url="$1"
    printf '%s' "$url" | sed -E 's#^(https?://[^/]+).*$#\1/...#'
}

send_webhook() {
    local title="$1" message="$2" color="${3:-}"
    [ -z "${WEBHOOK_URL:-}" ] && return 0
    command -v curl >/dev/null 2>&1 || return 0

    local url
    url="${WEBHOOK_URL}"

    message="${message}\n\nRUN=${RUN_ID}"
    local title_esc msg_esc
    title_esc="$(_json_escape "$title")"
    msg_esc="$(_json_escape "$message")"

    # Keep URL out of stdout; only log redacted to the audit log if needed.
    if [[ "$url" == *"discord.com/api/webhooks"* ]] || [[ "$url" == *"discordapp.com/api/webhooks"* ]]; then
        local c
        c="${color:-65280}"
        curl -fsS --connect-timeout 5 --max-time 10 \
            -H "Content-Type: application/json" \
            -d "{\"embeds\":[{\"title\":\"${title_esc}\",\"description\":\"${msg_esc}\",\"color\":${c}}]}" \
            "$url" >/dev/null 2>&1 || true
        return 0
    fi

    if [[ "$url" == *"hooks.slack.com/services"* ]]; then
        curl -fsS --connect-timeout 5 --max-time 10 \
            -H "Content-Type: application/json" \
            -d "{\"text\":\"${title_esc}: ${msg_esc}\"}" \
            "$url" >/dev/null 2>&1 || true
        return 0
    fi

    if [[ "$url" == *"ntfy.sh/"* ]]; then
        curl -fsS --connect-timeout 5 --max-time 10 \
            -H "Title: ${title}" \
            -H "Tags: zypper-auto" \
            -d "${message}" \
            "$url" >/dev/null 2>&1 || true
        return 0
    fi

    curl -fsS --connect-timeout 5 --max-time 10 \
        -H "Content-Type: text/plain" \
        -d "${title}: ${message}" \
        "$url" >/dev/null 2>&1 || true
    return 0
}

run_hooks() {
    local stage="$1" base hook_dir hook

    if [[ "${HOOKS_ENABLED,,}" != "true" ]]; then
        return 0
    fi

    base="${HOOKS_BASE_DIR:-/etc/zypper-auto/hooks}"
    hook_dir="${base}/${stage}.d"

    if [ ! -d "$hook_dir" ]; then
        return 0
    fi

    echo "Running ${stage}-update hooks from $hook_dir..."
    for hook in "$hook_dir"/*; do
        [ -e "$hook" ] || continue
        if [ -f "$hook" ] && [ -x "$hook" ]; then
            echo "  -> Hook: $(basename "$hook")"
            # Hook failures are non-fatal for the wrapper.
            "$hook" || echo "  !! Hook $(basename "$hook") failed (continuing)"
        fi
    done

    return 0
}

_html_escape() {
    local s="$*"
    s=${s//&/\&amp;}
    s=${s//</\&lt;}
    s=${s//>/\&gt;}
    printf '%s' "$s"
}

generate_dashboard() {
    if [[ "${DASHBOARD_ENABLED,,}" != "true" ]]; then
        return 0
    fi

    # Prefer delegating dashboard generation to the main helper (keeps UI consistent).
    if [ -x /usr/local/bin/zypper-auto-helper ]; then
        sudo /usr/local/bin/zypper-auto-helper --dashboard >/dev/null 2>&1 || true
        return 0
    fi

    # Fallback: minimal status page (only if helper is not installed).
    local out_root out_user now last_status last_tail
    out_root="${LOG_DIR:-/var/log/zypper-auto}/status.html"
    out_user=""
    if [ -n "${SUDO_USER:-}" ]; then
        user_home=$(getent passwd "${SUDO_USER}" 2>/dev/null | cut -d: -f6)
        if [ -n "${user_home:-}" ]; then
            out_user="${user_home}/.local/share/zypper-notify/status.html"
        fi
    fi

    now="$(date '+%Y-%m-%d %H:%M:%S')"
    last_status=$(cat "$HELPER_STATUS_FILE" 2>/dev/null || echo "Unknown")

    last_tail=""
    if ls -1 "${LOG_DIR:-/var/log/zypper-auto}"/install-*.log >/dev/null 2>&1; then
        last_log=$(ls -1t "${LOG_DIR:-/var/log/zypper-auto}"/install-*.log 2>/dev/null | head -1 || true)
        if [ -n "$last_log" ]; then
            last_tail=$(tail -n 40 "$last_log" 2>/dev/null || true)
        fi
    fi

    last_status_esc="$(_html_escape "$last_status")"
    last_tail_esc="$(_html_escape "$last_tail")"

    sudo mkdir -p "$(dirname "$out_root")" >/dev/null 2>&1 || true
    cat >"$out_root" <<DASHBOARD_EOF
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Zypper Auto Status</title>
<style>body{font-family:sans-serif;padding:20px;background:#f4f4f9}.card{background:#fff;padding:16px;border-radius:10px;box-shadow:0 2px 6px rgba(0,0,0,.1);max-width:980px}pre{background:#111;color:#eee;padding:12px;border-radius:8px;overflow:auto}</style>
</head><body><div class="card">
<h1>Zypper Auto Status (Fallback)</h1>
<p><strong>Generated:</strong> ${now}</p>
<p><strong>Current state:</strong> ${last_status_esc}</p>
<p><strong>Wrapper RUN:</strong> <code>${RUN_ID}</code></p>
<h3>Recent install log tail</h3>
<pre>${last_tail_esc}</pre>
</div></body></html>
DASHBOARD_EOF
    sudo chmod 644 "$out_root" >/dev/null 2>&1 || true

    if [ -n "$out_user" ]; then
        sudo -u "${SUDO_USER}" mkdir -p "$(dirname "$out_user")" >/dev/null 2>&1 || true
        sudo cp -f "$out_root" "$out_user" >/dev/null 2>&1 || true
        sudo chown "${SUDO_USER}:${SUDO_USER}" "$out_user" >/dev/null 2>&1 || true
        sudo chmod 644 "$out_user" >/dev/null 2>&1 || true
    fi

    return 0
}

# Helper to detect whether system management is currently locked by
# zypp/zypper (e.g. YaST, another zypper, systemd-zypp-refresh, etc.).
ZYPP_LOCK_FILE="/run/zypp.pid"

has_zypp_lock() {
    # Prefer the zypp.pid lock file, which is what YaST/zypper use.
    if [ -f "$ZYPP_LOCK_FILE" ]; then
        local pid
        pid=$(cat "$ZYPP_LOCK_FILE" 2>/dev/null || echo "")
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            # Best-effort check that the recorded PID really looks like a
            # zypper/YaST/zypp-related process and not some unrelated PID
            # that re-used the number.
            local comm cmd
            comm=$(ps -p "$pid" -o comm= 2>/dev/null || echo "")
            cmd=$(ps -p "$pid" -o args= 2>/dev/null || echo "")
            if printf '%s\n%s\n' "$comm" "$cmd" | grep -qiE 'zypper|yast|y2base|zypp|packagekitd'; then
                return 0
            fi
            # If the process is alive but not obviously zypper/YaST, treat the
            # lock file as stale and fall through to the process scan below.
        fi
    fi

    # Fallback: any obviously zypper/YaST/zypp-related process. This is a
    # broader net than just "zypper" so we also catch YaST and zypp-refresh.
    if pgrep -x zypper >/dev/null 2>&1; then
        return 0
    fi
    if pgrep -f -i 'yast' >/dev/null 2>&1; then
        return 0
    fi
    if pgrep -f 'zypp.*refresh' >/dev/null 2>&1; then
        return 0
    fi

    return 1
}

# Opportunistic clean-up for packages that are known to leave multiple
# RPM versions installed with broken %preun/%postun scriptlets.
# Behaviour is controlled via the following config keys:
#   AUTO_DUPLICATE_RPM_CLEANUP_PACKAGES - space-separated whitelist
#   AUTO_DUPLICATE_RPM_MODE             - whitelist | thirdparty | both
#
# In whitelist / both modes we:
#   - detect when more than one version of a whitelisted package is installed
#   - keep the newest version
#   - attempt to remove older versions with 'rpm -e --noscripts'
#
# In thirdparty / both modes we also scan for duplicate packages whose
# Vendor is not SUSE/openSUSE and clean their older versions (see
# cleanup_thirdparty_duplicates below).

# Minimal audit logger for duplicate cleanup when running inside the
# zypper-with-ps wrapper. This writes to a persistent log so you can
# later see exactly which RPMs were removed or skipped.
LOG_DIR="/var/log/zypper-auto"
AUDIT_LOG="$LOG_DIR/duplicate-cleanup.log"

log_duplicate_audit() {
    local msg="$1" ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    # Ensure log directory exists and append a single line in a root-owned file.
    sudo mkdir -p "$LOG_DIR" >/dev/null 2>&1 || true
    printf '%s\n' "$ts [duplicate-cleanup] $msg" | sudo tee -a "$AUDIT_LOG" >/dev/null
}

cleanup_duplicate_rpms() {
    local mode
    mode=${AUTO_DUPLICATE_RPM_MODE:-whitelist}

    # 1) Whitelist-driven cleanup (safest and default)
    if [ "$mode" = "whitelist" ] || [ "$mode" = "both" ]; then
        local packages name
        packages=${AUTO_DUPLICATE_RPM_CLEANUP_PACKAGES:-insync}

        for name in $packages; do
            [ -z "$name" ] && continue
            if ! rpm -q "$name" >/dev/null 2>&1; then
                continue
            fi

            local count
            count=$(rpm -q "$name" 2>/dev/null | wc -l || echo 0)
            if [ "$count" -le 1 ]; then
                continue
            fi

            echo ""
            echo "Detected multiple installed versions of '$name'."
            echo "Attempting to remove older versions (keeping the newest) before running zypper..."
            log_duplicate_audit "[wrapper][whitelist] Detected multiple versions for '$name'"

            local lines newest
            # List full NVRAs and sort by version; keep the newest, remove the rest.
            lines=$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' "$name" 2>/dev/null | sort -V) || continue
            newest=$(echo "$lines" | tail -n1)
            if [ -z "$newest" ]; then
                continue
            fi

            echo "  - Keeping newest: $newest"
            log_duplicate_audit "[wrapper][whitelist] Keeping newest for '$name': $newest"
            echo "$lines" | head -n -1 | while read -r pkg; do
                [ -z "$pkg" ] && continue
                echo "  - Removing older duplicate: $pkg"
                log_duplicate_audit "[wrapper][whitelist] Removing older duplicate: $pkg (keeping $newest)"
                # Dependency pre-flight: simulate removal before actually erasing
                if sudo rpm -e --test --noscripts "$pkg" >/dev/null 2>&1; then
                    if ! sudo rpm -e --noscripts "$pkg"; then
                        echo "    ! Failed to remove $pkg; you can remove it manually with:"
                        echo "      sudo rpm -e --noscripts $pkg"
                        log_duplicate_audit "[wrapper][whitelist] FAILED to remove $pkg (rpm -e --noscripts error)"
                    else
                        log_duplicate_audit "[wrapper][whitelist] Removed $pkg successfully"
                    fi
                else
                    echo "    ! Skipping $pkg: rpm -e --test reported dependency failures"
                    log_duplicate_audit "[wrapper][whitelist] Skipping $pkg: rpm -e --test reported dependency failures"
                fi
            done
        done
    fi

    # 2) Optional vendor-based third-party duplicate cleanup
    if [ "$mode" = "thirdparty" ] || [ "$mode" = "both" ]; then
        cleanup_thirdparty_duplicates
    fi
}

# Auto-detect and clean duplicate third-party packages in a more
# conservative way. A "third-party" package here is one whose Vendor is
# not in a trusted list (openSUSE/SUSE/Packman/NVIDIA/Intel, etc.), and
# whose name does not match a list of critical packages (kernels, glibc,
# systemd, bootloaders, drivers). For each such package with multiple
# installed versions we keep the newest and attempt to remove older ones
# with 'rpm -e --noscripts'.
cleanup_thirdparty_duplicates() {
    # --- COLOUR SETUP (for interactive clarity) ---
    local RED GREEN YELLOW BLUE RESET
    RED=$'\033[0;31m'
    GREEN=$'\033[0;32m'
    YELLOW=$'\033[0;33m'
    BLUE=$'\033[0;34m'
    RESET=$'\033[0m'

    # --- SAFETY CONFIGURATION ---
    # 1. Trusted Vendors (Regex)
    #    We match case-insensitively to catch variations like "Nvidia",
    #    "NVIDIA", "Suse", "SUSE". This covers official repos
    #    (openSUSE/SUSE), multimedia (Packman), and common hardware
    #    vendors (NVIDIA, Intel), plus known Packman/OBS URLs.
    local SAFE_VENDORS="openSUSE|SUSE|Packman|NVIDIA|Intel|http://packman|obs://build.opensuse.org"

    # 2. Critical Packages (Regex)
    #    We NEVER touch these:
    #      - kernel-*   : multi-version by design
    #      - glibc/systemd/grub/shim/mokutil : breaking them can brick the OS
    #      - nvidia     : graphics drivers are too fragile to auto-clean
    #      - filesystem : owns core directories like /usr and /bin; losing
    #                     ownership metadata can break future upgrades.
    local CRITICAL_PKGS="^kernel-|nvidia|glibc|systemd|grub|shim|mokutil|filesystem"

    printf '%b\n' "${BLUE}Scanning for duplicate third-party packages (safe vendors: ${SAFE_VENDORS}, critical patterns: ${CRITICAL_PKGS})...${RESET}"

    # 1. Find duplicate package *name+arch* pairs (multi-version within the
    #    same architecture). This avoids treating legitimate multi-arch
    #    installs (e.g. x86_64 + i686) as conflicts.
    local DUPLICATE_PAIRS
    DUPLICATE_PAIRS=$(rpm -qa --qf '%{NAME} %{ARCH}\\n' 2>/dev/null | sort | uniq -d)

    if [ -z "$DUPLICATE_PAIRS" ]; then
        echo "   No duplicate packages found."
        return 0
    fi

    # Sanity limit: if there are *too many* duplicate name+arch pairs, assume
    # something is wrong with the RPM DB and abort automatic cleanup to avoid
    # mass deletions.
    local num_pairs
    num_pairs=$(echo "$DUPLICATE_PAIRS" | wc -l | awk '{print $1}')
    if [ "$num_pairs" -gt 10 ]; then
        printf '%b\n' "${YELLOW}   WARNING: Found $num_pairs duplicate (name+arch) pairs; safety limit is 10.${RESET}"
        echo "            Aborting automatic third-party duplicate cleanup; please investigate manually."
        log_duplicate_audit "[wrapper][thirdparty] Aborting: $num_pairs duplicate pairs exceed safety limit (10)"
        return 0
    fi

    # --- ULTIMATE SAFETY NET: Snapper snapshot before any destructive action ---
    local SNAPSHOT_DONE=0
    if command -v snapper >/dev/null 2>&1; then
        # Avoid starting another snapper instance if one is already active.
        if pgrep -x snapper >/dev/null 2>&1; then
            printf '%b\n' "${YELLOW}   Snapper is already running; skipping pre-cleanup snapshot.${RESET}"
            log_duplicate_audit "[wrapper][snapshot] Snapper busy; skipped pre-cleanup snapshot"
        else
            local SNAP_DESC="zypper-auto: duplicate RPM cleanup (thirdparty)"
            log_duplicate_audit "[wrapper][snapshot] Creating snapper single snapshot: '$SNAP_DESC'"
            if sudo snapper create -t single -p -d "$SNAP_DESC" >/dev/null 2>&1; then
                SNAPSHOT_DONE=1
                printf '%b\n' "${GREEN}   Created snapper snapshot before third-party duplicate cleanup.${RESET}"
                log_duplicate_audit "[wrapper][snapshot] Snapshot created successfully"
            else
                printf '%b\n' "${YELLOW}   WARNING: Failed to create snapper snapshot; proceeding without snapshot.${RESET}"
                log_duplicate_audit "[wrapper][snapshot] FAILED to create snapshot; proceeding without snapshot"
            fi
        fi
    else
        # Snapper not installed; just log for reference.
        log_duplicate_audit "[wrapper][snapshot] snapper not installed; skipping snapshot creation"
    fi

    # 2. Analyse each duplicate (name + arch) and decide whether it's safe
    #    to clean. We only remove extra versions within the same arch.
    local PKG ARCH VENDOR ALL_VERSIONS REMOVE_LIST OLD_PKG
    echo "$DUPLICATE_PAIRS" | while read -r PKG ARCH; do
        [ -z "$PKG" ] && continue

        # GUARD RAIL 1: Critical Package Protection (by name)
        if echo "$PKG" | grep -qE "$CRITICAL_PKGS"; then
            echo "   Skipping CRITICAL package: $PKG.$ARCH (safety override)"
            log_duplicate_audit "[wrapper][thirdparty] Skipping CRITICAL package: $PKG.$ARCH"
            continue
        fi

        # Extra safety: never touch GPG pubkey packages.
        if echo "$PKG" | grep -qi '^gpg-pubkey'; then
            echo "   Skipping GPG key package: $PKG.$ARCH"
            log_duplicate_audit "[wrapper][thirdparty] Skipping GPG key package: $PKG.$ARCH"
            continue
        fi

        # Get Vendor for this name+arch; default to a non-empty placeholder so
        # logic remains robust even for badly built RPMs with missing vendor.
        VENDOR=$(rpm -q --qf '%{VENDOR}\\n' "${PKG}.${ARCH}" 2>/dev/null | head -n 1)
        VENDOR=${VENDOR:-UnknownVendor}

        # GUARD RAIL 2: Trusted Vendor Whitelist (case-insensitive)
        if echo "$VENDOR" | grep -qiE "$SAFE_VENDORS"; then
            echo "   Skipping trusted-vendor package: $PKG.$ARCH (Vendor: $VENDOR)"
            log_duplicate_audit "[wrapper][thirdparty] Skipping trusted-vendor package: $PKG.$ARCH (Vendor: $VENDOR)"
            continue
        fi

        # KILL ZONE: duplicated (same name+arch) + not critical + not from
        # trusted vendor.
        printf '%b\n' "${RED}   Found third-party duplicate: $PKG.$ARCH (Vendor: $VENDOR)${RESET}"
        log_duplicate_audit "[wrapper][thirdparty] Found third-party duplicate: $PKG.$ARCH (Vendor: $VENDOR)"

        # Get all installed versions for this name+arch, newest first; keep
        # the top (newest) and mark the rest for removal.
        ALL_VERSIONS=$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n' --last "${PKG}.${ARCH}" 2>/dev/null)
        REMOVE_LIST=$(echo "$ALL_VERSIONS" | tail -n +2 | awk '{print $1}')

        if [ -z "$REMOVE_LIST" ]; then
            echo "      (Duplicate reported but no removable versions found; skipping.)"
            continue
        fi

        for OLD_PKG in $REMOVE_LIST; do
            [ -z "$OLD_PKG" ] && continue
            printf '%b\n' "${RED}      Removing old/broken version: $OLD_PKG${RESET}"
            log_duplicate_audit "[wrapper][thirdparty] Removing old/broken version: $OLD_PKG (from $PKG.$ARCH; vendor=$VENDOR)"

            # GUARD RAIL 3: Dependency pre-flight; only erase if --test passes.
            if sudo rpm -e --test --noscripts "$OLD_PKG" >/dev/null 2>&1; then
                if sudo rpm -e --noscripts "$OLD_PKG"; then
                    printf '%b\n' "${GREEN}         Cleaned successfully.${RESET}"
                    log_duplicate_audit "[wrapper][thirdparty] Cleaned $OLD_PKG successfully"
                else
                    printf '%b\n' "${YELLOW}         Failed to clean $OLD_PKG (possibly RPM lock or manual intervention needed).${RESET}"
                    log_duplicate_audit "[wrapper][thirdparty] FAILED to clean $OLD_PKG (rpm -e --noscripts error)"
                fi
            else
                printf '%b\n' "${YELLOW}         Skipping $OLD_PKG: rpm -e --test reported dependency failures${RESET}"
                log_duplicate_audit "[wrapper][thirdparty] Skipping $OLD_PKG: rpm -e --test reported dependency failures"
            fi
        done
    done
}

# One-shot conflict-cleanup mode: when invoked as
#   zypper --rm-conflict [optional zypper-args...]
# we run duplicate-RPM cleanup first, then (if additional
# arguments are present) fall through to normal zypper
# handling.
if [[ "${1:-}" == "--rm-conflict" ]]; then
    echo "Running duplicate RPM conflict cleanup (--rm-conflict)..."
    # Drop the flag from the argument list before continuing
    shift
    cleanup_duplicate_rpms
    # If no further args, exit after cleanup
    if [ "$#" -eq 0 ]; then
        exit 0
    fi
fi

# Check if we're running 'dup', 'dist-upgrade' or 'update'
STATUS_DIR="/var/log/zypper-auto"
STATUS_FILE="$STATUS_DIR/download-status.txt"

if [[ "$*" == *"dup"* ]] || [[ "$*" == *"dist-upgrade"* ]] || [[ "$*" == *"update"* ]] ; then
    # For interactive runs, publish a best-effort "downloading" status so the
    # desktop notifier can show a progress bar while the user is running
    # zypper manually. We don't know the package count in advance here, so we
    # mark the total as 0 and treat that as "unknown" on the notifier side.
    sudo mkdir -p "$STATUS_DIR" >/dev/null 2>&1 || true
    sudo bash -c "echo 'downloading:0:manual:0:0' > '$STATUS_FILE'" >/dev/null 2>&1 || true

    # Before running zypper, respect the global system management lock and
    # retry a few times with increasing delays so the user can see that we
    # are waiting instead of failing immediately.
    max_attempts=${LOCK_RETRY_MAX_ATTEMPTS:-10}
    base_delay=${LOCK_RETRY_INITIAL_DELAY_SECONDS:-1}
    attempt=1
    while has_zypp_lock && [ "$attempt" -le "$max_attempts" ]; do
        delay=$((base_delay * attempt))
        echo ""
        echo "System management is currently locked by another update tool (zypper/YaST/PackageKit)."
        echo "Retry $attempt/$max_attempts: waiting $delay second(s) for the other updater to finish..."
        sleep "$delay"
        attempt=$((attempt + 1))
    done

    # After retries, if a lock is still present, show a clear message and exit
    # cleanly instead of letting zypper print the raw lock error.
    if has_zypp_lock; then
        echo ""
        echo "System management is still locked by another update tool."
        echo "Close that other update tool (or wait for it to finish), then run this zypper command again."
        echo ""
        # Clear the manual downloading state so the notifier does not show a
        # stuck progress bar when we never actually ran zypper.
        sudo bash -c "echo 'idle' > '$STATUS_FILE'" >/dev/null 2>&1 || true
        exit 1
    fi

    # Pre-update hooks (best-effort)
    run_hooks "pre" || true

    # Clean up duplicate RPMs before running zypper, according to
    # AUTO_DUPLICATE_RPM_CLEANUP_PACKAGES / AUTO_DUPLICATE_RPM_MODE.
    cleanup_duplicate_rpms

    # Run the actual zypper command. If it fails specifically due to the
    # system management lock (exit code 7), we will show a clearer message
    # afterwards instead of leaving only the raw zypper error.
    sudo /usr/bin/zypper "$@"
    EXIT_CODE=$?

    if [ "$EXIT_CODE" -eq 0 ]; then
        run_hooks "post" || true
    fi

    if [ "$EXIT_CODE" -eq 7 ]; then
        echo ""
        echo "System management is locked by another update tool (zypper/YaST/PackageKit)."
        echo "Close that other update tool (or wait for it to finish), then run this zypper command again."
        echo ""
    fi

    # Clear the manual downloading state so the notifier stops showing
    # a progress bar once the interactive session has finished.
    sudo bash -c "echo 'idle' > '$STATUS_FILE'" >/dev/null 2>&1 || true

    # Update helper status + remote monitoring (best-effort)
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    if [ "$EXIT_CODE" -eq 0 ]; then
        echo "[$ts] SUCCESS: Manual zypper update completed (wrapper)" | sudo tee "$HELPER_STATUS_FILE" >/dev/null 2>&1 || true
        send_webhook "Zypper update successful" "Manual update (wrapper) completed successfully." "65280"
    else
        echo "[$ts] FAILED: Manual zypper update failed (wrapper rc=$EXIT_CODE)" | sudo tee "$HELPER_STATUS_FILE" >/dev/null 2>&1 || true
        send_webhook "Zypper update FAILED" "Manual update (wrapper) failed (rc=$EXIT_CODE)." "16711680"
    fi

    generate_dashboard || true

    # Always run Flatpak and Snap updates after dup, even if dup had no updates or failed
    echo ""
    echo "=========================================="
    echo "  Flatpak Updates"
    echo "=========================================="
    echo ""
    
    if [[ "${ENABLE_FLATPAK_UPDATES,,}" == "true" ]]; then
        if command -v flatpak >/dev/null 2>&1; then
            if sudo flatpak update -y; then
                echo "✅ Flatpak updates completed."
            else
                echo "⚠️  Flatpak update failed (continuing)."
            fi
        else
            echo "⚠️  Flatpak is not installed - skipping Flatpak updates."
            echo "   To install: sudo zypper install flatpak"
        fi
    else
        echo "ℹ️  Flatpak updates are disabled in /etc/zypper-auto.conf (ENABLE_FLATPAK_UPDATES=false)."
    fi

    echo ""
    echo "=========================================="
    echo "  Snap Updates"
    echo "=========================================="
    echo ""
    
    if [[ "${ENABLE_SNAP_UPDATES,,}" == "true" ]]; then
        if command -v snap >/dev/null 2>&1; then
            # Best-effort: ensure snapd services/sockets are enabled so
            # "snap refresh" can talk to the daemon. We keep failures
            # non-fatal and fall back to the existing error message.
            echo "Ensuring snapd services are enabled (snapd.apparmor, snapd.seeded, snapd, snapd.socket)..."
            if systemctl list-unit-files snapd.service >/dev/null 2>&1; then
                # Prefer sudo if available, otherwise fall back to pkexec.
                if command -v sudo >/dev/null 2>&1; then
                    sudo systemctl enable snapd.apparmor.service snapd.seeded.service snapd.service snapd.socket >/dev/null 2>&1 || \
                    pkexec systemctl enable snapd.apparmor.service snapd.seeded.service snapd.service snapd.socket >/dev/null 2>&1 || true
                else
                    pkexec systemctl enable snapd.apparmor.service snapd.seeded.service snapd.service snapd.socket >/dev/null 2>&1 || true
                fi
            fi

            if pkexec snap refresh; then
                echo "✅ Snap updates completed."
            else
                echo "⚠️  Snap refresh failed (continuing)."
            fi
        else
            echo "⚠️  Snapd is not installed - skipping Snap updates."
            echo "   Install (zypper): sudo zypper install snapd"
            echo "   Install (opi)   : sudo opi snapd" 
            echo "   Then enable     : sudo systemctl enable --now snapd.apparmor.service snapd.seeded.service snapd.service snapd.socket"
        fi
    else
        echo "ℹ️  Snap updates are disabled in /etc/zypper-auto.conf (ENABLE_SNAP_UPDATES=false)."
    fi
    echo "  Soar (stable) Update & Sync (optional)"
    echo "=========================================="
    echo ""

    if command -v soar >/dev/null 2>&1; then
        # Run the Soar installer/updater in a subshell with set +e to ensure
        # that any errors cannot kill the interactive zypper session.
        (
            set +e

            # First, check if a newer *stable* Soar release exists on GitHub.
            # We compare the local "soar --version" against
            # https://api.github.com/repos/pkgforge/soar/releases/latest (stable only).
            if command -v curl >/dev/null 2>&1; then
                echo "Checking for newer stable Soar release from GitHub..."

                LOCAL_VER_RAW=$(soar --version 2>/dev/null | head -n1)
                LOCAL_VER=$(echo "$LOCAL_VER_RAW" | grep -oE 'v?[0-9]+(\\.[0-9]+)*' | head -n1 || true)
                LOCAL_BASE=${LOCAL_VER#v}

                REMOTE_JSON=$(curl -fsSL "https://api.github.com/repos/pkgforge/soar/releases/latest" 2>/dev/null || true)
                # Extract the tag_name value in a simple, portable way to avoid sed backref issues
                REMOTE_VER=$(printf '%s\\n' "$REMOTE_JSON" | grep -m1 '"tag_name"' | cut -d '"' -f4 || true)
                REMOTE_BASE=${REMOTE_VER#v}

                if [ -n "$LOCAL_BASE" ] && [ -n "$REMOTE_BASE" ]; then
                    LATEST=$(printf '%s\\n%s\\n' "$LOCAL_BASE" "$REMOTE_BASE" | sort -V | tail -n1)
                    if [ "$LATEST" = "$REMOTE_BASE" ] && [ "$LOCAL_BASE" != "$REMOTE_BASE" ]; then
                        echo "New stable Soar available ($LOCAL_VER -> $REMOTE_VER), updating..."
                        if ! curl -fsSL "https://raw.githubusercontent.com/pkgforge/soar/main/install.sh" | sh; then
                            echo "⚠️  Soar update from GitHub failed (continuing)."
                        fi
                    else
                        echo "Soar is already up to date (local: ${LOCAL_VER:-unknown}, latest stable: ${REMOTE_VER:-unknown})."
                    fi
                else
                    echo "Could not determine Soar versions; running installer to ensure latest stable."
                    if ! curl -fsSL "https://raw.githubusercontent.com/pkgforge/soar/main/install.sh" | sh; then
                        echo "⚠️  Soar installer from GitHub failed (continuing)."
                    fi
                fi
            else
                echo "⚠️  curl is not installed; skipping automatic Soar update from GitHub."
                echo "    You can update Soar manually from: https://github.com/pkgforge/soar/releases"
            fi

            # Then run the usual metadata sync.
            if soar sync; then
                echo "✅ Soar sync completed."
                # Optionally refresh Soar-managed apps that support "soar update".
                if soar update; then
                    echo "✅ Soar update completed."
                else
                    echo "⚠️  Soar update failed (continuing)."
                fi
            else
                echo "⚠️  Soar sync failed (continuing)."
            fi
        )
    else
        echo "ℹ️  Soar is not installed - skipping Soar update/sync."
        echo "    Install from: https://github.com/pkgforge/soar/releases"
        if [ -x /usr/local/bin/zypper-auto-helper ]; then
            echo "    Or via helper: zypper-auto-helper --soar"
        fi
    fi

    echo ""
    echo "=========================================="
    echo "  Homebrew (brew) Updates (optional)"
    echo "=========================================="
    echo ""

    if [[ "${ENABLE_BREW_UPDATES,,}" != "true" ]]; then
        echo "ℹ️  Homebrew updates are disabled in /etc/zypper-auto.conf (ENABLE_BREW_UPDATES=false)."
        echo "    You can still run 'brew update' / 'brew upgrade' manually."
        echo ""
    else
        # Try to detect Homebrew in PATH or the default Linuxbrew prefix
        if command -v brew >/dev/null 2>&1 || [ -x "/home/linuxbrew/.linuxbrew/bin/brew" ]; then
            # Normalise brew command path
            if command -v brew >/dev/null 2>&1; then
                BREW_BIN="brew"
            else
                BREW_BIN="/home/linuxbrew/.linuxbrew/bin/brew"
            fi

            echo "Checking for Homebrew updates from GitHub (brew update)..."
            if ! $BREW_BIN update; then
                echo "⚠️  Homebrew 'brew update' failed (continuing without brew upgrade)."
            else
                # After syncing with GitHub, see if anything needs upgrading
                OUTDATED=$($BREW_BIN outdated --quiet 2>/dev/null || true)
                OUTDATED_COUNT=$(printf '%s\n' "$OUTDATED" | sed '/^$/d' | wc -l | tr -d ' ')

                if [ "${OUTDATED_COUNT:-0}" -eq 0 ]; then
                    echo "Homebrew is already up to date (no formulae to upgrade)."
                else
                    echo "Homebrew has ${OUTDATED_COUNT} outdated formulae; running 'brew upgrade'..."
                    if $BREW_BIN upgrade; then
                        echo "✅ Homebrew upgrade completed (upgraded ${OUTDATED_COUNT} formulae)."
                    else
                        echo "⚠️  Homebrew 'brew upgrade' failed (continuing)."
                    fi
                fi
            fi
        else
            echo "ℹ️  Homebrew (brew) is not installed - skipping brew update/upgrade."
            echo "    To install via helper: sudo zypper-auto-helper --brew"
        fi
    fi

    echo ""
    echo "=========================================="
    echo "  Python (pipx) Updates (optional)"
    echo "=========================================="
    echo ""

    if [[ "${ENABLE_PIPX_UPDATES,,}" != "true" ]]; then
        echo "ℹ️  pipx updates are disabled in /etc/zypper-auto.conf (ENABLE_PIPX_UPDATES=false)."
        echo "    You can still manage Python CLI tools manually with pipx."
        echo ""
    else
        if command -v pipx >/dev/null 2>&1; then
            echo "Upgrading all pipx-managed Python command-line tools (pipx upgrade-all)..."
            if pipx upgrade-all; then
                echo "✅ pipx upgrade-all completed."
            else
                echo "⚠️  pipx upgrade-all failed (continuing)."
            fi
        else
            echo "ℹ️  pipx is not installed - skipping Python CLI (pipx) updates."
            echo "    Recommended: zypper-auto-helper --pip-package (run without sudo)"
        fi
    fi

    echo ""

    # Always show service restart info, even if zypper reported errors
    echo "=========================================="
    echo "  Post-Update Service Check"
    echo "=========================================="
    echo ""
    echo "Checking which services need to be restarted..."
    echo ""
    
    # Run zypper ps -s to show services using old libraries
    ZYPPER_PS_OUTPUT=$(sudo /usr/bin/zypper ps -s 2>/dev/null || true)
    echo "$ZYPPER_PS_OUTPUT"
    
    # Check if there are any running processes
    if echo "$ZYPPER_PS_OUTPUT" | grep -q "running processes"; then
        echo ""
        echo "ℹ️  Services listed above are using old library versions."
        echo ""
        echo "What this means:"
        echo "  • These services/processes are still running old code in memory"
        echo "  • They should be restarted to use the updated libraries"
        echo ""
        echo "Options:"
        echo "  1. Restart individual services: systemctl restart <service>"
        echo "  2. Reboot your system (recommended for kernel/system updates)"
        echo ""
    else
        echo "✅ No services require restart. You're all set!"
        echo ""
    fi

    echo ""
    echo "=========================================="
    echo "  System Status Check"
    echo "=========================================="
    echo ""

    # zypper needs-reboot returns exit code 1 if a reboot is required.
    if zypper needs-reboot >/dev/null 2>&1; then
        echo "🔴 SYSTEM REBOOT IS REQUIRED"
        echo "   Core libraries or the kernel have been updated."
        echo "   Please reboot as soon as possible."
        if command -v notify-send >/dev/null 2>&1; then
             notify-send -u critical -i system-reboot "Restart Required" "System updates require a reboot."
        fi
    else
        echo "🟢 No system reboot required."
    fi
    
    exit $EXIT_CODE
else
    # Not a dup command, just run zypper normally
    sudo /usr/bin/zypper "$@"
fi
EOF
chown "$SUDO_USER:$SUDO_USER" "$ZYPPER_WRAPPER_PATH"
chmod +x "$ZYPPER_WRAPPER_PATH"
log_success "Zypper wrapper script created and made executable"

# Add shell alias/function to user's shell config
log_info ">>> Adding zypper alias to shell configurations..."
update_status "Configuring shell aliases..."

# Bash configuration
if [ -f "$SUDO_USER_HOME/.bashrc" ]; then
    log_debug "Adding zypper alias to .bashrc"
    # Remove old alias if it exists
    sed -i '/# Zypper wrapper for auto service check/d' "$SUDO_USER_HOME/.bashrc"
    sed -i '/alias zypper=/d' "$SUDO_USER_HOME/.bashrc"
    # Add new alias
    {
        echo ""
        echo "# Zypper wrapper for auto service check (added by zypper-auto-helper)"
        echo "alias zypper='$ZYPPER_WRAPPER_PATH'"
    } >> "$SUDO_USER_HOME/.bashrc"
    chown "$SUDO_USER:$SUDO_USER" "$SUDO_USER_HOME/.bashrc"
    log_success "Added zypper alias to .bashrc"
fi

# Fish configuration
if [ -d "$SUDO_USER_HOME/.config/fish" ]; then
    log_debug "Adding zypper wrapper to fish config"
    FISH_CONFIG_DIR="$SUDO_USER_HOME/.config/fish/conf.d"
    mkdir -p "$FISH_CONFIG_DIR"
    FISH_ALIAS_FILE="$FISH_CONFIG_DIR/zypper-wrapper.fish"
    cat > "$FISH_ALIAS_FILE" << 'FISHEOF'
# Zypper wrapper for auto service check (added by zypper-auto-helper)

# Wrap zypper command
function zypper --wraps zypper --description "Wrapper for zypper with post-update checks"
    # Call the wrapper script (which handles sudo and locking internally)
    ~/.local/bin/zypper-with-ps $argv
end
FISHEOF

    # NEW: Install sudo wrapper for Fish to catch 'sudo zypper'
    FISH_SUDO_FILE="$FISH_CONFIG_DIR/sudo-handler.fish"
    log_debug "Creating sudo wrapper for Fish at $FISH_SUDO_FILE"
    cat > "$FISH_SUDO_FILE" << 'FISHEOF'
# Wrapper to catch 'sudo zypper' and redirect it to the safe helper
function sudo --description "Wrapper to handle sudo aliases"
    if test (count $argv) -ge 1
        # If the user runs 'sudo zypper ...', run 'zypper ...' directly.
        # This triggers the 'zypper' function defined in zypper-wrapper.fish,
        # which runs zypper-with-ps (the safe helper).
        if test "$argv[1]" = "zypper"
            zypper $argv[2..-1]
            return $status
        end
    end
    # For everything else, run real sudo
    command sudo $argv
end
FISHEOF

    chown -R "$SUDO_USER:$SUDO_USER" "$SUDO_USER_HOME/.config/fish"
    log_success "Added zypper wrapper functions to fish config"
    log_success "Added sudo wrapper to fish config (catches 'sudo zypper')"
fi

# Zsh configuration
if [ -f "$SUDO_USER_HOME/.zshrc" ]; then
    log_debug "Adding zypper alias to .zshrc"
    # Remove old alias if it exists
    sed -i '/# Zypper wrapper for auto service check/d' "$SUDO_USER_HOME/.zshrc"
    sed -i '/alias zypper=/d' "$SUDO_USER_HOME/.zshrc"
    # Add new alias
    {
        echo ""
        echo "# Zypper wrapper for auto service check (added by zypper-auto-helper)"
        echo "alias zypper='$ZYPPER_WRAPPER_PATH'"
    } >> "$SUDO_USER_HOME/.zshrc"
    chown "$SUDO_USER:$SUDO_USER" "$SUDO_USER_HOME/.zshrc"
    log_success "Added zypper alias to .zshrc"
fi

log_success "Shell aliases configured. Restart your shell or run 'source ~/.bashrc' (or equivalent) to activate."

# --- 7c. Add zypper-auto-helper command alias to shells ---
log_info ">>> Adding zypper-auto-helper command alias to shell configurations..."
update_status "Configuring zypper-auto-helper aliases..."

# Bash configuration for zypper-auto-helper
if [ -f "$SUDO_USER_HOME/.bashrc" ]; then
    log_debug "Adding zypper-auto-helper wrapper to .bashrc"
    # Remove old alias/function block if it exists
    sed -i '/# zypper-auto-helper command alias/d' "$SUDO_USER_HOME/.bashrc"
    sed -i '/alias zypper-auto-helper=/d' "$SUDO_USER_HOME/.bashrc"
    sed -i '/# zypper-auto-helper command wrapper (added by zypper-auto-helper)/,/^}$/d' "$SUDO_USER_HOME/.bashrc" 2>/dev/null || true

    {
        echo ""
        echo "# zypper-auto-helper command wrapper (added by zypper-auto-helper)"
        echo "zypper-auto-helper() {"
        echo "  if [ \\\"\\\${1:-}\\\" = \\\"--dash-open\\\" ]; then"
        echo "    /usr/local/bin/zypper-auto-helper \\\"\\\$@\\\""
        echo "  else"
        echo "    sudo /usr/local/bin/zypper-auto-helper \\\"\\\$@\\\""
        echo "  fi"
        echo "}"
    } >> "$SUDO_USER_HOME/.bashrc"

    chown "$SUDO_USER:$SUDO_USER" "$SUDO_USER_HOME/.bashrc"
    log_success "Added zypper-auto-helper wrapper to .bashrc"
fi

# Fish configuration for zypper-auto-helper
if [ -d "$SUDO_USER_HOME/.config/fish" ]; then
    log_debug "Adding zypper-auto-helper wrapper to fish config"
    FISH_HELPER_FILE="$SUDO_USER_HOME/.config/fish/conf.d/zypper-auto-helper-alias.fish"
    cat > "$FISH_HELPER_FILE" << 'FISHHELPER'
# zypper-auto-helper command wrapper (added by zypper-auto-helper)
#
# Most helper commands need root.
# But dashboard opening should run as the desktop user so it can launch
# the browser with the correct GUI environment.
function zypper-auto-helper --wraps /usr/local/bin/zypper-auto-helper --description "zypper-auto-helper wrapper"
    if test (count $argv) -ge 1
        if test "$argv[1]" = "--dash-open"
            command /usr/local/bin/zypper-auto-helper $argv
            return $status
        end
    end

    command sudo /usr/local/bin/zypper-auto-helper $argv
end
FISHHELPER
    chown "$SUDO_USER:$SUDO_USER" "$FISH_HELPER_FILE"
    log_success "Added zypper-auto-helper wrapper to fish config"
fi

# Zsh configuration for zypper-auto-helper
if [ -f "$SUDO_USER_HOME/.zshrc" ]; then
    log_debug "Adding zypper-auto-helper wrapper to .zshrc"
    # Remove old alias/function block if it exists
    sed -i '/# zypper-auto-helper command alias/d' "$SUDO_USER_HOME/.zshrc"
    sed -i '/alias zypper-auto-helper=/d' "$SUDO_USER_HOME/.zshrc"
    sed -i '/# zypper-auto-helper command wrapper (added by zypper-auto-helper)/,/^}/d' "$SUDO_USER_HOME/.zshrc" 2>/dev/null || true

    {
        echo ""
        echo "# zypper-auto-helper command wrapper (added by zypper-auto-helper)"
        echo "zypper-auto-helper() {"
        echo "  if [ \\\"\\\${1:-}\\\" = \\\"--dash-open\\\" ]; then"
        echo "    /usr/local/bin/zypper-auto-helper \\\"\\\$@\\\""
        echo "  else"
        echo "    sudo /usr/local/bin/zypper-auto-helper \\\"\\\$@\\\""
        echo "  fi"
        echo "}"
    } >> "$SUDO_USER_HOME/.zshrc"

    chown "$SUDO_USER:$SUDO_USER" "$SUDO_USER_HOME/.zshrc"
    log_success "Added zypper-auto-helper wrapper to .zshrc"
fi

log_success "zypper-auto-helper command aliases configured for all shells."

# --- 7d. Install shell completions (bash/zsh/fish) ---
install_shell_completions() {
    log_info ">>> Installing shell completion scripts for zypper-auto-helper (bash/zsh/fish)..."

    # Top-level commands/options (first word after 'zypper-auto-helper')
    local ZNH_CLI_WORDS
    # Keep this as a single line so the generated completion scripts are
    # syntactically robust across distros/shells.
    ZNH_CLI_WORDS="install debug snapper --verify --repair --diagnose --check --self-check --soar --brew --pip-package --pipx --setup-SF --reset-config --reset-downloads --reset-state --rm-conflict --logs --log --live-logs --analyze --health --test-notify --status --dashboard --generate-dashboard --dash-open --dash-stop --dash-install --dash-api-on --dash-api-off --dash-api-status --send-webhook --webhook --diag-logs-on --diag-logs-off --snapshot-state --diag-bundle --diag-logs-runner --show-logs --show-loggs --uninstall-zypper --uninstall-zypper-helper --debug --help -h help"

    # Snapper submenu
    local ZNH_SNAPPER_SUB
    ZNH_SNAPPER_SUB="status list create cleanup auto auto-off"
        local ZNH_SNAPPER_CLEANUP_ALGOS
        ZNH_SNAPPER_CLEANUP_ALGOS="all number timeline empty-pre-post"

    # --- bash completion (system-wide) ---
    local bash_dir bash_file
    bash_dir=""
    if [ -d "/etc/bash_completion.d" ]; then
        bash_dir="/etc/bash_completion.d"
    elif [ -d "/usr/share/bash-completion/completions" ]; then
        bash_dir="/usr/share/bash-completion/completions"
    fi

    if [ -n "${bash_dir}" ]; then
        bash_file="${bash_dir}/zypper-auto-helper"
        log_debug "Writing bash completion file: ${bash_file}"
        write_atomic "${bash_file}" <<EOF
# bash completion for zypper-auto-helper (installed by zypper-auto-helper)

_znh_zypper_auto_helper() {
    local cur prev cword words
    cur="\${COMP_WORDS[COMP_CWORD]}"
    prev="\${COMP_WORDS[COMP_CWORD-1]}"
    cword=\${COMP_CWORD}
    words=("\${COMP_WORDS[@]}")

    # Complete first argument
    if [ \${cword} -eq 1 ]; then
        COMPREPLY=( \$(compgen -W "${ZNH_CLI_WORDS}" -- "\${cur}") )
        return 0
    fi

    # Snapper submenu
    if [ "\${words[1]}" = "snapper" ]; then
        if [ \${cword} -eq 2 ]; then
            COMPREPLY=( \$(compgen -W "${ZNH_SNAPPER_SUB}" -- "\${cur}") )
            return 0
        fi
        if [ "\${words[2]}" = "cleanup" ] && [ \${cword} -eq 3 ]; then
            COMPREPLY=( \$(compgen -W "${ZNH_SNAPPER_CLEANUP_ALGOS}" -- "\${cur}") )
            return 0
        fi
    fi

    COMPREPLY=()
    return 0
}

complete -F _znh_zypper_auto_helper zypper-auto-helper 2>/dev/null || true
EOF
        chmod 644 "${bash_file}" 2>/dev/null || true
        log_success "Installed bash completion: ${bash_file}"
    else
        log_debug "Bash completion directory not found; skipping bash completion install"
    fi

    # --- zsh completion (system-wide when possible) ---
    local zsh_dir zsh_file
    zsh_dir=""
    if [ -d "/usr/share/zsh/site-functions" ]; then
        zsh_dir="/usr/share/zsh/site-functions"
    elif [ -d "/usr/local/share/zsh/site-functions" ]; then
        zsh_dir="/usr/local/share/zsh/site-functions"
    fi

    if [ -n "${zsh_dir}" ]; then
        zsh_file="${zsh_dir}/_zypper-auto-helper"
        log_debug "Writing zsh completion file: ${zsh_file}"
        write_atomic "${zsh_file}" <<'EOF'
#compdef zypper-auto-helper

# zsh completion for zypper-auto-helper (installed by zypper-auto-helper)

local -a _znh_cmds
_znh_cmds=(
  install debug snapper
  --verify --repair --diagnose --check --self-check
  --soar --brew --pip-package --pipx --setup-SF
  --reset-config --reset-downloads --reset-state --rm-conflict
  --logs --log --live-logs --analyze --health
  --test-notify --status
  --dashboard --generate-dashboard --dash-open --dash-stop --dash-install
  --send-webhook --webhook
  --diag-logs-on --diag-logs-off --snapshot-state --diag-bundle --diag-logs-runner
  --show-logs --show-loggs
  --uninstall-zypper --uninstall-zypper-helper
  --debug
  --help -h help
)

local -a _znh_snapper_sub
_znh_snapper_sub=(status list create cleanup auto auto-off)

local -a _znh_snapper_cleanup
_znh_snapper_cleanup=(all number timeline empty-pre-post)

_arguments -C \
  '1:command:->cmds' \
  '*::arg:->args'

case $state in
  cmds)
    _values 'zypper-auto-helper command' $_znh_cmds
    ;;
  args)
    if [[ ${words[2]} == snapper ]]; then
      if (( CURRENT == 3 )); then
        _values 'snapper subcommand' $_znh_snapper_sub
        return
      fi
      if [[ ${words[3]} == cleanup && $CURRENT == 4 ]]; then
        _values 'cleanup algorithm' $_znh_snapper_cleanup
        return
      fi
    fi
    ;;
esac
EOF
        chmod 644 "${zsh_file}" 2>/dev/null || true
        log_success "Installed zsh completion: ${zsh_file}"
    else
        log_debug "Zsh site-functions directory not found; skipping zsh completion install"
    fi

    # --- fish completion (per-user) ---
    if [ -n "${SUDO_USER_HOME:-}" ] && [ -d "${SUDO_USER_HOME}/.config/fish" ]; then
        local fish_comp_dir fish_comp_file
        fish_comp_dir="${SUDO_USER_HOME}/.config/fish/completions"
        fish_comp_file="${fish_comp_dir}/zypper-auto-helper.fish"

        mkdir -p "${fish_comp_dir}" 2>/dev/null || true

        log_debug "Writing fish completion file: ${fish_comp_file}"
        write_atomic "${fish_comp_file}" <<EOF
# fish completion for zypper-auto-helper (installed by zypper-auto-helper)

# top-level
complete -c zypper-auto-helper -f -a "install debug snapper"

# common option-like commands
complete -c zypper-auto-helper -f -a "--verify --repair --diagnose --check --self-check --debug"
complete -c zypper-auto-helper -f -a "--soar --brew --pip-package --pipx --setup-SF"
complete -c zypper-auto-helper -f -a "--reset-config --reset-downloads --reset-state --rm-conflict"
complete -c zypper-auto-helper -f -a "--logs --log --live-logs --analyze --health"
complete -c zypper-auto-helper -f -a "--test-notify --status"
complete -c zypper-auto-helper -f -a "--dashboard --generate-dashboard --dash-open --dash-stop --dash-install"
complete -c zypper-auto-helper -f -a "--send-webhook --webhook"
complete -c zypper-auto-helper -f -a "--diag-logs-on --diag-logs-off --snapshot-state --diag-bundle --diag-logs-runner"
complete -c zypper-auto-helper -f -a "--show-logs --show-loggs"
complete -c zypper-auto-helper -f -a "--uninstall-zypper --uninstall-zypper-helper"
complete -c zypper-auto-helper -f -a "--help -h help"

# snapper submenu
complete -c zypper-auto-helper -n '__fish_seen_subcommand_from snapper' -f -a "status list create cleanup auto auto-off"
complete -c zypper-auto-helper -n '__fish_seen_subcommand_from snapper; and __fish_seen_subcommand_from cleanup' -f -a "all number timeline empty-pre-post"
EOF
        chown "$SUDO_USER:$SUDO_USER" "${fish_comp_file}" 2>/dev/null || true
        chmod 644 "${fish_comp_file}" 2>/dev/null || true
        log_success "Installed fish completion: ${fish_comp_file}"
    else
        log_debug "Fish config directory not present for user; skipping fish completion install"
    fi

    log_success "Shell completions installed (where supported). Restart your shell to activate."
    return 0
}

install_shell_completions || true

# --- 8. Create/Update NOTIFIER (User Service) ---
log_info ">>> Creating (user) notifier service: ${NT_SERVICE_FILE}"
update_status "Creating user notifier service..."
log_debug "Writing user service file: ${NT_SERVICE_FILE}"
write_atomic "${NT_SERVICE_FILE}" << EOF
[Unit]
Description=Notify user of pending Tumbleweed updates
Wants=network-online.target
After=network-online.target nss-lookup.target

[Service]
Type=oneshot
StandardOutput=append:${USER_LOG_DIR}/notifier.log
StandardError=append:${USER_LOG_DIR}/notifier-error.log
Environment=ZNH_CACHE_EXPIRY_MINUTES=${CACHE_EXPIRY_MINUTES}
Environment=ZNH_SNOOZE_SHORT_HOURS=${SNOOZE_SHORT_HOURS}
Environment=ZNH_SNOOZE_MEDIUM_HOURS=${SNOOZE_MEDIUM_HOURS}
Environment=ZNH_SNOOZE_LONG_HOURS=${SNOOZE_LONG_HOURS}
ExecStart=/usr/bin/python3 ${NOTIFY_SCRIPT_PATH}
EOF
chown "$SUDO_USER:$SUDO_USER" "${NT_SERVICE_FILE}"
chmod 644 "${NT_SERVICE_FILE}" 2>/dev/null || true
log_success "User notifier service file created"

# --- 9. Create/Update NOTIFIER (User Timer) ---
log_info ">>> Creating (user) notifier timer: ${NT_TIMER_FILE}"
log_debug "Writing user timer file: ${NT_TIMER_FILE}"

# Derive schedule from NT_TIMER_INTERVAL_MINUTES (validated in load_config).
NT_ONCALENDAR="minutely"
if [ "${NT_TIMER_INTERVAL_MINUTES}" -eq 60 ]; then
    NT_ONCALENDAR="hourly"
elif [ "${NT_TIMER_INTERVAL_MINUTES}" -ne 1 ]; then
    NT_ONCALENDAR="*:0/${NT_TIMER_INTERVAL_MINUTES}"
fi

write_atomic "${NT_TIMER_FILE}" << EOF
[Unit]
Description=Run ${NT_SERVICE_NAME} periodically to check for updates

[Timer]
# First run a few seconds after the user manager starts,
# then re-run on a simple calendar schedule.
OnBootSec=5sec
OnCalendar=${NT_ONCALENDAR}
Persistent=true

[Install]
WantedBy=timers.target
EOF
chown "$SUDO_USER:$SUDO_USER" "${NT_TIMER_FILE}"
chmod 644 "${NT_TIMER_FILE}" 2>/dev/null || true
log_success "User notifier timer file created"

# --- 10. Create/Update Notification Script (v47 Python with logging) ---
log_info ">>> Creating (user) Python notification script: ${NOTIFY_SCRIPT_PATH}"
update_status "Creating Python notifier script..."
log_debug "Writing Python script to: ${NOTIFY_SCRIPT_PATH}"
write_atomic "${NOTIFY_SCRIPT_PATH}" << 'EOF'
#!/usr/bin/env python3
#
# zypper-notify-updater.py (v53 with snooze controls and safety preflight)
#
# This script is run as the USER. It uses PyGObject (gi)
# to create a robust, clickable notification.

import sys
import subprocess
import os
import re
import time
import shlex
import shutil
from datetime import datetime, timedelta
from pathlib import Path

DEBUG = os.getenv("ZNH_DEBUG", "").lower() in ("1", "true", "yes", "debug")

# Correlation ID:
# - When invoked from the bash helper/debug menu we pass ZNH_RUN_ID so Python
#   logs can be linked back to install/verify runs.
# - Under systemd, INVOCATION_ID provides a unique ID per service start.
RUN_ID = (
    os.getenv("ZNH_RUN_ID")
    or os.getenv("INVOCATION_ID")
    or f"PY-{datetime.now().strftime('%Y%m%dT%H%M%S')}-{os.getpid()}"
)

# Logging setup
LOG_DIR = Path.home() / ".local" / "share" / "zypper-notify"
LOG_FILE = LOG_DIR / "notifier-detailed.log"
STATUS_FILE = LOG_DIR / "last-run-status.txt"
HISTORY_FILE = LOG_DIR / "update-history.log"
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5MB
MAX_HISTORY_SIZE = 1 * 1024 * 1024  # 1MB

# Path where the root downloader stores the last zypper dup --dry-run
# output for the notifier to consume (written atomically by the
# zypper-download-with-progress helper).
DRYRUN_OUTPUT_FILE = "/var/log/zypper-auto/dry-run-last.txt"

# Cache directory
CACHE_DIR = Path.home() / ".cache" / "zypper-notify"
CACHE_FILE = CACHE_DIR / "last_check.txt"
SNOOZE_FILE = CACHE_DIR / "snooze_until.txt"
# Marker file used to suppress duplicate popups while an interactive install
# is running (created by the notifier and the Ready-to-Install helper).
INSTALL_MARKER_FILE = CACHE_DIR / "install_in_progress.txt"
CACHE_EXPIRY_MINUTES = 10

# Global config path for zypper-auto-helper
CONFIG_FILE = "/etc/zypper-auto.conf"
# Cache and snooze configuration (overridable via environment, see systemd unit)
def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        value = int(raw)
        if value <= 0:
            return default
        return value
    except ValueError:
        return default

CACHE_EXPIRY_MINUTES = _int_env("ZNH_CACHE_EXPIRY_MINUTES", 10)
SNOOZE_SHORT_HOURS = _int_env("ZNH_SNOOZE_SHORT_HOURS", 1)
SNOOZE_MEDIUM_HOURS = _int_env("ZNH_SNOOZE_MEDIUM_HOURS", 4)
SNOOZE_LONG_HOURS = _int_env("ZNH_SNOOZE_LONG_HOURS", 24)

# Ensure directories exist
LOG_DIR.mkdir(parents=True, exist_ok=True)
CACHE_DIR.mkdir(parents=True, exist_ok=True)

def rotate_log_if_needed():
    """Rotate log file if it exceeds MAX_LOG_SIZE."""
    try:
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > MAX_LOG_SIZE:
            backup = LOG_FILE.with_suffix(".log.old")
            if backup.exists():
                backup.unlink()
            LOG_FILE.rename(backup)
    except Exception as e:
        print(f"Failed to rotate log: {e}", file=sys.stderr)

def log_to_file(level: str, msg: str) -> None:
    """Write log message to file with timestamp.

    Also emits ERROR-level lines to the system journal (best-effort) so you can
    correlate notifier crashes via:
        journalctl -t zypper-auto-helper

    Journal logging defaults to errors-only to avoid spamming the journal.
    Controls:
      - ZNH_JOURNAL_LOGGING=0 disables all journal emission
      - ZNH_JOURNAL_ERRORS_ONLY=0 emits INFO/DEBUG as well
    """
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{timestamp}] [{level}] [RUN={RUN_ID}] {msg}"

        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")

        # Best-effort journald/syslog integration (errors-only by default)
        try:
            journal_enabled = os.getenv("ZNH_JOURNAL_LOGGING", "1").lower() in (
                "1",
                "true",
                "yes",
                "on",
                "enabled",
            )
            errors_only = os.getenv("ZNH_JOURNAL_ERRORS_ONLY", "1").lower() in (
                "1",
                "true",
                "yes",
                "on",
                "enabled",
            )
            if journal_enabled and (not errors_only or level == "ERROR") and shutil.which("logger"):
                prio = "user.err" if level == "ERROR" else "user.info"
                subprocess.run(
                    ["logger", "-t", "zypper-auto-helper", "-p", prio, "--", line],
                    check=False,
                )
        except Exception:
            pass

    except Exception as e:
        print(f"Failed to write log: {e}", file=sys.stderr)

def log_info(msg: str) -> None:
    """Log info message."""
    log_to_file("INFO", msg)
    print(f"[INFO] {msg}")

def log_error(msg: str) -> None:
    """Log error message."""
    log_to_file("ERROR", msg)
    print(f"[ERROR] {msg}", file=sys.stderr)

def log_debug(msg: str) -> None:
    """Log debug message."""
    if DEBUG:
        log_to_file("DEBUG", msg)
        print(f"[DEBUG] {msg}", file=sys.stderr)

def update_status(status: str) -> None:
    """Update the status file with current state."""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(STATUS_FILE, "w", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {status}\n")
    except Exception as e:
        log_error(f"Failed to update status file: {e}")

# --- Helper: read extra dup flags from /etc/zypper-auto.conf ---

def _read_dup_extra_flags() -> list[str]:
    """Read DUP_EXTRA_FLAGS from /etc/zypper-auto.conf, if set.

    The value is split using shell-like rules so users can write e.g.:
        DUP_EXTRA_FLAGS="--allow-vendor-change --from my-repo"
    """
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if not stripped.startswith("DUP_EXTRA_FLAGS"):
                    continue
                # Expect shell-style "NAME=VALUE"
                parts = stripped.split("=", 1)
                if len(parts) != 2:
                    continue
                raw = parts[1].strip()
                # Remove optional surrounding quotes
                if (raw.startswith("\"") and raw.endswith("\"")) or (
                    raw.startswith("'") and raw.endswith("'")
                ):
                    raw = raw[1:-1]
                try:
                    return shlex.split(raw)
                except Exception as e:
                    log_debug(f"Failed to parse DUP_EXTRA_FLAGS='{raw}': {e}")
                    return []
    except FileNotFoundError:
        return []
    except Exception as e:
        log_debug(f"Failed to read {CONFIG_FILE} for DUP_EXTRA_FLAGS: {e}")
        return []


def _read_bool_from_config(name: str, default: bool) -> bool:
    """Best-effort boolean reader for /etc/zypper-auto.conf.

    Accepts typical shell-style booleans such as true/false, yes/no,
    on/off, 1/0 (case-insensitive after stripping quotes and spaces).
    """
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if not stripped.startswith(name + "="):
                    continue
                parts = stripped.split("=", 1)
                if len(parts) != 2:
                    continue
                raw = parts[1].strip().strip("'\"").strip()
                value = raw.lower()
                if value in ("1", "true", "yes", "on", "enabled"):
                    return True
                if value in ("0", "false", "no", "off", "disabled"):
                    return False
        return default
    except FileNotFoundError:
        return default
    except Exception as e:
        log_debug(f"Failed to read {CONFIG_FILE} for {name}: {e}")
        return default


def _read_int_from_config(
    name: str,
    default: int,
    *,
    min_value: int = 0,
    max_value: int | None = None,
) -> int:
    """Best-effort integer reader for /etc/zypper-auto.conf.

    Returns default on errors/out-of-range values.
    """
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if not stripped.startswith(name + "="):
                    continue
                parts = stripped.split("=", 1)
                if len(parts) != 2:
                    continue
                raw = parts[1].strip().strip("'\"").strip()
                try:
                    value = int(raw)
                except ValueError:
                    return default

                if value < min_value:
                    return default
                if max_value is not None and value > max_value:
                    return default
                return value
        return default
    except FileNotFoundError:
        return default
    except Exception as e:
        log_debug(f"Failed to read {CONFIG_FILE} for {name}: {e}")
        return default


DUP_EXTRA_FLAGS = _read_dup_extra_flags()
LOCK_REMINDER_ENABLED = _read_bool_from_config("LOCK_REMINDER_ENABLED", True)
NO_UPDATES_REMINDER_REPEAT_ENABLED = _read_bool_from_config("NO_UPDATES_REMINDER_REPEAT_ENABLED", True)
UPDATES_READY_REMINDER_REPEAT_ENABLED = _read_bool_from_config("UPDATES_READY_REMINDER_REPEAT_ENABLED", True)
INSTALL_CLICK_SUPPRESS_MINUTES = _read_int_from_config(
    "INSTALL_CLICK_SUPPRESS_MINUTES",
    120,
    min_value=0,
    max_value=24 * 60,
)

# --- Caching Functions ---
def read_cache():
    """Read cached update check results.
    Returns: (timestamp, package_count, snapshot) or None if cache invalid/missing.
    """
    try:
        if not CACHE_FILE.exists():
            return None
        
        with open(CACHE_FILE, 'r') as f:
            line = f.read().strip()
            parts = line.split('|')
            if len(parts) != 3:
                return None
            
            timestamp_str, pkg_count, snapshot = parts
            cache_time = datetime.fromisoformat(timestamp_str)
            
            # Check if cache is still valid
            age_minutes = (datetime.now() - cache_time).total_seconds() / 60
            if age_minutes > CACHE_EXPIRY_MINUTES:
                log_debug(f"Cache expired (age: {age_minutes:.1f} minutes)")
                return None
            
            log_debug(f"Cache hit (age: {age_minutes:.1f} minutes)")
            return cache_time, int(pkg_count), snapshot
    except Exception as e:
        log_debug(f"Failed to read cache: {e}")
        return None

def write_cache(package_count: int, snapshot: str) -> None:
    """Write update check results to cache."""
    try:
        timestamp = datetime.now().isoformat()
        with open(CACHE_FILE, 'w') as f:
            f.write(f"{timestamp}|{package_count}|{snapshot}")
        log_debug(f"Cache written: {package_count} packages, snapshot {snapshot}")
    except Exception as e:
        log_debug(f"Failed to write cache: {e}")

# --- Snooze Functions ---
def check_snoozed() -> bool:
    """Check if updates are currently snoozed.
    Returns True if snoozed, False otherwise.
    """
    try:
        if not SNOOZE_FILE.exists():
            return False
        
        with open(SNOOZE_FILE, 'r') as f:
            snooze_until_str = f.read().strip()
            snooze_until = datetime.fromisoformat(snooze_until_str)
            
            if datetime.now() < snooze_until:
                remaining = snooze_until - datetime.now()
                hours = remaining.total_seconds() / 3600
                log_info(f"Updates snoozed for {hours:.1f} more hours")
                return True
            else:
                # Snooze expired, remove file
                SNOOZE_FILE.unlink()
                log_info("Snooze expired, removing snooze file")
                return False
    except Exception as e:
        log_debug(f"Failed to check snooze: {e}")
        return False

def set_snooze(hours: int) -> None:
    """Set snooze for specified number of hours."""
    try:
        snooze_until = datetime.now() + timedelta(hours=hours)
        with open(SNOOZE_FILE, 'w') as f:
            f.write(snooze_until.isoformat())
        log_info(f"Updates snoozed for {hours} hours until {snooze_until.strftime('%Y-%m-%d %H:%M')}")
    except Exception as e:
        log_error(f"Failed to set snooze: {e}")


# --- Install suppression (avoid duplicate popups while installing) ---

def _read_install_marker_time() -> datetime | None:
    """Read install marker timestamp.

    Prefers parsing file content as an ISO timestamp. Falls back to mtime.
    """
    try:
        if not INSTALL_MARKER_FILE.exists():
            return None

        raw = ""
        try:
            raw = INSTALL_MARKER_FILE.read_text(encoding="utf-8", errors="ignore").strip()
        except Exception:
            raw = ""

        if raw:
            # Allow optional metadata after the timestamp.
            first = raw.split("|", 1)[0].strip()
            try:
                return datetime.fromisoformat(first)
            except Exception:
                pass

        # Fallback: file mtime
        return datetime.fromtimestamp(INSTALL_MARKER_FILE.stat().st_mtime)
    except Exception as e:
        log_debug(f"Failed to read install marker time: {e}")
        return None


def is_install_suppressed() -> bool:
    """Return True when an interactive install is in progress."""
    try:
        if INSTALL_CLICK_SUPPRESS_MINUTES <= 0:
            return False

        t = _read_install_marker_time()
        if t is None:
            return False

        age_minutes = (datetime.now() - t).total_seconds() / 60.0
        if age_minutes < float(INSTALL_CLICK_SUPPRESS_MINUTES):
            remaining = max(0, int(INSTALL_CLICK_SUPPRESS_MINUTES - age_minutes))
            log_info(f"Install marker active; suppressing notifications for ~{remaining} more minute(s)")
            update_status("SKIPPED: Install in progress (notification suppressed)")
            return True

        # Stale marker; remove it so we don't suppress forever.
        try:
            INSTALL_MARKER_FILE.unlink()
        except Exception:
            pass
        return False

    except Exception as e:
        log_debug(f"Install suppression check failed: {e}")
        return False


# --- History Logging ---
def log_update_history(snapshot: str, package_count: int) -> None:
    """Log update installation to history file."""
    try:
        # Rotate history if needed
        if HISTORY_FILE.exists() and HISTORY_FILE.stat().st_size > MAX_HISTORY_SIZE:
            backup = HISTORY_FILE.with_suffix(".log.old")
            if backup.exists():
                backup.unlink()
            HISTORY_FILE.rename(backup)
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(HISTORY_FILE, 'a') as f:
            f.write(f"[{timestamp}] Installed snapshot {snapshot} with {package_count} packages\n")
        log_info(f"Update history logged: {snapshot}")
    except Exception as e:
        log_error(f"Failed to log update history: {e}")

# --- Safety Checks ---
def check_disk_space() -> tuple[bool, str]:
    """Check if there's enough disk space for updates.
    Returns: (has_space, message)
    """
    try:
        result = subprocess.run(
            ['df', '-BG', '/'],
            capture_output=True,
            text=True,
            check=True
        )
        lines = result.stdout.strip().split('\n')
        if len(lines) < 2:
            return True, "Could not determine disk space"
        
        # Parse df output: Filesystem 1G-blocks Used Available Use% Mounted
        fields = lines[1].split()
        if len(fields) < 4:
            return True, "Could not parse disk space"
        
        available_str = fields[3].rstrip('G')
        available_gb = int(available_str)
        
        if available_gb < 5:
            msg = f"Only {available_gb}GB free. 5GB required for updates."
            log_info(msg)
            return False, msg
        
        log_debug(f"Disk space check passed: {available_gb}GB available")
        return True, f"{available_gb}GB available"
    except Exception as e:
        log_debug(f"Disk space check failed: {e}")
        return True, "Could not check disk space"

def check_snapshots() -> tuple[bool, str]:
    """Check if snapper is installed and whether configs/snapshots exist.

    Returns: (has_snapshots, message)
    - has_snapshots=True  => at least one snapshot exists
    - has_snapshots=False => snapper not installed, not configured, or zero snapshots
    """
    # First, see if snapper is installed and if there is a root config
    try:
        cfg_result = subprocess.run(
            ['snapper', 'list-configs'],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except FileNotFoundError:
        msg = "Snapper not installed"
        log_info(msg)
        return False, msg
    except Exception as e:
        log_debug(f"Snapshot config check failed: {e}")
        return False, "Could not check snapshots"

    has_config = False
    root_config = False
    if cfg_result.returncode == 0 and cfg_result.stdout.strip():
        for line in cfg_result.stdout.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('Config'):
                continue
            parts = [p.strip() for p in line.split('|')]
            if len(parts) < 2:
                continue
            name = parts[1]
            if not name:
                continue
            has_config = True
            if name == 'root':
                root_config = True

    # Now check the actual snapshots
    try:
        result = subprocess.run(
            ['snapper', 'list'],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception as e:
        log_debug(f"Snapshot list check failed: {e}")
        if root_config or has_config:
            msg = "Snapper configured (root) but snapshot list not available"
            log_info(msg)
            return False, msg
        return False, "Could not check snapshots"

    # Combine stdout/stderr for permission checks
    out_all = (result.stdout or "") + "\n" + (result.stderr or "")
    if "No permissions" in out_all:
        # On openSUSE Tumbleweed with Btrfs, this usually means snapshots
        # exist but are only visible to root. Treat this as "snapshots
        # present" but explain the limitation.
        if root_config or has_config:
            msg = "Snapper snapshots exist (root-only; run as root to view)"
        else:
            msg = "Snapper present but requires root to view snapshots"
        log_info(msg)
        return True, msg

    if result.returncode == 0:
        lines = [ln for ln in result.stdout.split('\n') if ln.strip()]

        # snapper list normally has 2 header lines; anything beyond that is a snapshot
        if len(lines) > 2:
            snapshot_count = len(lines) - 2
            log_debug(f"Snapper is working, {snapshot_count} snapshots available")
            return True, f"{snapshot_count} snapshots available"
        if root_config or has_config:
            msg = "Snapper configured (root) but no snapshots yet"
            log_info(msg)
            return False, msg
        msg = "Snapper not configured or no snapshots"
        log_info(msg)
        return False, msg

    # Non-zero return code from snapper list (and no explicit "No permissions")
    if root_config or has_config:
        msg = "Snapper configured (root) but snapshot list failed"
        log_info(msg)
        return False, msg

    msg = "Snapper not configured or no snapshots"
    log_info(msg)
    return False, msg
def check_network_quality() -> tuple[bool, str]:
    """Check network latency to ensure stable connection.
    Returns: (is_good, message)
    """
    try:
        result = subprocess.run(
            ['ping', '-c', '3', '-W', '2', '1.1.1.1'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            msg = "Network unreachable"
            log_info(msg)
            return False, msg
        
        # Parse ping output for average latency
        # Example: rtt min/avg/max/mdev = 10.1/15.2/20.3/5.1 ms
        match = re.search(r'rtt min/avg/max/mdev = [\\d.]+/([\\d.]+)/', result.stdout)
        if match:
            avg_latency = float(match.group(1))
            if avg_latency > 200:
                msg = f"High latency: {avg_latency:.0f}ms"
                log_info(msg)
                return False, msg
            log_debug(f"Network quality good: {avg_latency:.0f}ms latency")
            return True, f"{avg_latency:.0f}ms latency"
        
        log_debug("Network quality check passed (couldn't parse latency)")
        return True, "Network OK"
    except Exception as e:
        log_debug(f"Network quality check failed: {e}")
        return True, "Could not check network"


# Rotate log at startup if needed
rotate_log_if_needed()
log_info("=" * 60)
log_info("Zypper Notify Updater started")
update_status("Starting update check...")

try:
    import gi
    gi.require_version("Notify", "0.7")
    from gi.repository import Notify, GLib
    log_debug("PyGObject imported successfully")
except ImportError as e:
    log_error(f"PyGObject (gi) not found: {e}")
    update_status("FAILED: PyGObject not available")
    sys.exit(1)

def has_battery_via_sys() -> bool:
    """Detect presence of a real battery via /sys/class/power_supply.

    This avoids depending on external tools like inxi and works on
    modern kernels across desktops and laptops.
    """
    power_supply = Path("/sys/class/power_supply")
    if not power_supply.is_dir():
        log_debug("/sys/class/power_supply not present; assuming no battery")
        return False

    try:
        for dev in power_supply.iterdir():
            type_file = dev / "type"
            if not type_file.is_file():
                continue
            try:
                t = type_file.read_text(encoding="utf-8", errors="ignore").strip().lower()
            except OSError as e:
                log_debug(f"Failed to read {type_file}: {e}")
                continue
            if t == "battery":
                log_debug(f"Battery detected via /sys on device {dev.name}")
                return True
    except Exception as e:
        log_debug(f"Battery detection via /sys failed: {e}")
        return False

    log_debug("No battery detected via /sys")
    return False


def _get_forced_form_factor() -> str | None:
    """Return a forced form-factor override from CONFIG_FILE if set.

    Looks for a FORCE_FORM_FACTOR= line in /etc/zypper-auto.conf and
    accepts one of: laptop, desktop, unknown. Any other value is ignored.
    """
    try:
        path = Path(CONFIG_FILE)
        if not path.is_file():
            return None
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if not line.startswith("FORCE_FORM_FACTOR="):
                continue
            value = line.split("=", 1)[1].strip().strip('"').strip("'").lower()
            if value in ("laptop", "desktop", "unknown"):
                log_info(f"Config override: FORCE_FORM_FACTOR={value}; skipping automatic form-factor detection")
                return value
            if value:
                log_debug(f"Ignoring invalid FORCE_FORM_FACTOR value '{value}' in {CONFIG_FILE}")
            return None
    except Exception as e:
        log_debug(f"Failed to read FORCE_FORM_FACTOR from {CONFIG_FILE}: {e}")
    return None


def detect_form_factor():
    """Detect whether this machine is a laptop or a desktop.

    Prefer kernel-exposed /sys power information and fall back to
    upower/battery heuristics. Returns "laptop", "desktop", or "unknown".
    """
    # 0. Honor explicit override from configuration, if any.
    forced = _get_forced_form_factor()
    if forced:
        log_debug(f"Using forced form factor from config: {forced}")
        return forced

    log_debug("Detecting form factor...")

    # 1. If /sys reports a real battery, treat as laptop immediately.
    try:
        if has_battery_via_sys():
            log_info("Form factor detected: laptop (via /sys battery)")
            return "laptop"
    except Exception as e:
        log_debug(f"has_battery_via_sys failed in detect_form_factor: {e}")

    # 2. Fall back to the previous upower + battery-based heuristic.
    devices: list[str] = []
    try:
        devices = subprocess.check_output(["upower", "-e"], text=True).strip().splitlines()
    except Exception as e:
        log_debug(f"upower -e failed in detect_form_factor: {e}")
        devices = []

    has_battery = False
    has_line_power = False

    if devices:
        try:
            for dev in devices:
                if not dev:
                    continue
                info = subprocess.check_output(
                    ["upower", "-i", dev], text=True, errors="ignore"
                ).lower()

                if "line_power" in dev:
                    has_line_power = True

                if "battery" in info:
                    # Heuristic: real laptop batteries usually have power supply yes
                    if "power supply: yes" in info or "power-supply: yes" in info:
                        has_battery = True
        except Exception as e:
            log_debug(f"upower inspection failed in detect_form_factor: {e}")

    # If upower clearly indicates laptop
    if has_battery and has_line_power:
        log_info("Form factor detected: laptop (via upower battery+line_power)")
        return "laptop"

    # If upower sees a battery but no line_power, treat as laptop as well.
    # Some laptops expose only a battery device without a separate line_power
    # entry; in that case, we must *not* classify as desktop or we will
    # incorrectly assume always-on AC power.
    if has_battery and not has_line_power:
        log_info("Form factor detected: laptop (via upower battery only)")
        return "laptop"

    # No battery seen by either /sys or upower; treat as desktop.
    if not has_battery:
        log_info("Form factor detected: desktop (no battery found)")
        return "desktop"

    # Last resort
    log_info("Form factor detected: unknown")
    return "unknown"


def on_ac_power(form_factor: str) -> bool:
    """Check if the system is on AC power.

    On true desktops we treat AC as always on; on laptops and unknown
    form factors we consult /sys power_supply first, then upower.
    """
    log_debug(f"Checking AC power status (form_factor: {form_factor})")
    if form_factor == "desktop":
        log_debug("Desktop detected, assuming AC power always available")
        return True

    def _ac_via_sys() -> bool | None:
        """Return True/False when /sys exposes a mains/AC adapter, else None."""
        try:
            ps = Path("/sys/class/power_supply")
            if not ps.is_dir():
                return None

            ac_found = False
            ac_online_any = False
            ac_offline_any = False

            for dev in ps.iterdir():
                tf = dev / "type"
                of = dev / "online"
                if not tf.is_file() or not of.is_file():
                    continue

                t = tf.read_text(encoding="utf-8", errors="ignore").strip().lower()
                if t not in ("mains", "ac"):
                    continue

                ac_found = True
                raw = of.read_text(encoding="utf-8", errors="ignore").strip()
                if raw == "1":
                    ac_online_any = True
                elif raw == "0":
                    ac_offline_any = True

            if not ac_found:
                return None

            if ac_online_any:
                log_info("AC power detected: plugged in (via /sys)")
                return True
            if ac_offline_any:
                log_info("AC power detected: on battery (via /sys)")
                return False

            return None
        except Exception as e:
            log_debug(f"/sys AC power detection failed: {e}")
            return None

    def _battery_state_via_sys() -> str | None:
        """Return a best-effort battery status (charging/discharging/full/unknown) via /sys."""
        try:
            ps = Path("/sys/class/power_supply")
            if not ps.is_dir():
                return None
            for dev in ps.iterdir():
                tf = dev / "type"
                sf = dev / "status"
                if not tf.is_file() or not sf.is_file():
                    continue
                t = tf.read_text(encoding="utf-8", errors="ignore").strip().lower()
                if t != "battery":
                    continue
                return sf.read_text(encoding="utf-8", errors="ignore").strip().lower() or None
            return None
        except Exception as e:
            log_debug(f"/sys battery status detection failed: {e}")
            return None

    sys_ac = _ac_via_sys()
    if sys_ac is not None:
        return sys_ac

    # /sys did not expose a mains device; attempt upower.
    try:
        devices = subprocess.check_output(["upower", "-e"], text=True).strip().splitlines()
        line_power_devices = [d for d in devices if "line_power" in d]

        if not line_power_devices:
            # Some systems expose battery info but no line_power device in upower.
            # Fall back to battery state via /sys as a best-effort heuristic.
            bstate = _battery_state_via_sys() or ""
            if "discharging" in bstate:
                log_info("AC power inferred: on battery (battery is discharging; via /sys)")
                return False
            if "charging" in bstate:
                log_info("AC power inferred: plugged in (battery is charging; via /sys)")
                return True

            log_error("No line_power device found; treating as battery (unsafe)")
            return False

        for dev in line_power_devices:
            info = subprocess.check_output(["upower", "-i", dev], text=True, errors="ignore")
            for line in info.splitlines():
                line = line.strip().lower()
                if line.startswith("online:"):
                    value = line.split(":", 1)[1].strip()
                    if value in ("yes", "true"):
                        log_info("AC power detected: plugged in")
                        return True
                    if value in ("no", "false"):
                        log_info("AC power detected: on battery")
                        return False

        # Could not parse any 'online' line; be conservative for laptops
        log_error("Could not parse AC status; treating as battery (unsafe)")
        return False

    except Exception as e:
        # On a laptop and we truly cannot determine AC: be safe and treat as battery
        log_error(f"AC power check failed: {e}")
        return False


def is_metered() -> bool:
    """Check if any active connection is metered using nmcli.

    Uses GENERAL.METERED per active connection.
    Treats values like 'yes', 'guess-yes', 'payg' as metered.
    """
    log_debug("Checking if connection is metered...")
    try:
        # List all connections with ACTIVE flag
        output = subprocess.check_output(
            ["nmcli", "-t", "-f", "NAME,UUID,DEVICE,ACTIVE", "connection", "show"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        log_debug(f"nmcli connection list failed for metered check: {e}")
        return False

    active_ids = []
    for line in output.strip().splitlines():
        if not line:
            continue
        parts = line.split(":")
        if len(parts) < 4:
            continue
        name, uuid, device, active = parts[:4]
        if active.strip().lower() == "yes":
            # Prefer UUID (stable), but fall back to name if missing
            ident = uuid.strip() or name.strip()
            if ident:
                active_ids.append(ident)

    if not active_ids:
        return False

    for ident in active_ids:
        m = ""
        try:
            m = subprocess.check_output(
                ["nmcli", "-g", "GENERAL.METERED", "connection", "show", ident],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip().lower()
        except subprocess.CalledProcessError as e:
            # Some nmcli versions don't support -g GENERAL.METERED; fall back
            # to parsing the full "connection show" output.
            log_debug(f"nmcli GENERAL.METERED failed for {ident}: {e}; trying full show")
            try:
                full = subprocess.check_output(
                    ["nmcli", "connection", "show", ident],
                    text=True,
                    stderr=subprocess.DEVNULL,
                )
            except subprocess.CalledProcessError as e2:
                log_debug(f"nmcli full show failed for {ident}: {e2}")
                continue

            for line in full.splitlines():
                line = line.strip()
                if line.lower().startswith("general.metered:"):
                    m = line.split(":", 1)[1].strip().lower()
                    break

        if m in ("yes", "guess-yes", "payg", "guess-payg"):
            log_info(f"Metered connection detected: {ident} is {m}")
            return True

    # All active connections are explicitly unmetered/unknown
    log_debug("No metered connections detected")
    return False


# --- Environment change tracking ---
ENV_STATE_DIR = os.path.expanduser("~/.cache/zypper-notify")
ENV_STATE_FILE = os.path.join(ENV_STATE_DIR, "env_state.txt")
LAST_NOTIFICATION_FILE = os.path.join(ENV_STATE_DIR, "last_notification.txt")


def _read_last_env_state() -> str:
    try:
        with open(ENV_STATE_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def _write_env_state(state: str) -> None:
    try:
        os.makedirs(ENV_STATE_DIR, exist_ok=True)
        with open(ENV_STATE_FILE, "w", encoding="utf-8") as f:
            f.write(state)
    except OSError as e:
        log_debug(f"Failed to write env state: {e}")


def _read_last_notification() -> str:
    """Read the last notification state (title+message)."""
    try:
        with open(LAST_NOTIFICATION_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def _write_last_notification(title: str, message: str) -> None:
    """Write the last notification state."""
    try:
        os.makedirs(ENV_STATE_DIR, exist_ok=True)
        notification_key = f"{title}|{message}"
        with open(LAST_NOTIFICATION_FILE, "w", encoding="utf-8") as f:
            f.write(notification_key)
    except OSError as e:
        log_debug(f"Failed to write last notification: {e}")


def _notify_env_change(prev_state: str, form_factor: str, on_ac: bool, metered: bool, safe: bool) -> None:
    """Track environment changes and notify once per change.

    - When conditions become *unsafe* (battery or metered), show a
      "paused" notification explaining why.
    - When they become *safe* again (AC + unmetered), show a
      "now safe" notification.
    """
    current_state = f"form_factor={form_factor}, on_ac={on_ac}, metered={metered}, safe={safe}"

    if prev_state == current_state:
        log_debug("Environment state unchanged, no notification needed")
        return  # no change

    log_info(f"Environment state changed from [{prev_state}] to [{current_state}]")
    # Always record the new state
    _write_env_state(current_state)

    # Decide a short human‑readable message
    if safe:
        title = "Update conditions now safe"
        if metered:
            # logically shouldn't happen (safe implies not metered), but guard anyway
            body = "Updates may proceed, but connection is marked metered."
        elif form_factor == "laptop" and on_ac:
            body = "Laptop is on AC power and network is unmetered. Updates can be downloaded."
        else:
            body = "Conditions are okay to download updates."
    else:
        title = "Updates paused due to conditions"
        if metered:
            body = "Active connection is metered. Background update downloads are skipped."
        elif form_factor == "laptop" and not on_ac:
            body = "Laptop is running on battery. Background update downloads are skipped."
        else:
            body = "Current conditions are not safe for background update downloads."

    log_info(f"Showing environment change notification: {title}")
    try:
        n = Notify.Notification.new(title, body, "dialog-information")
        n.set_timeout(8000)
        n.show()
    except Exception as e:
        log_error(f"Failed to show environment change notification: {e}")


def is_safe() -> bool:
    """Combined safety check.

    - desktops: don't block on AC; only check metered.
    - laptops/unknown: require AC and not metered.

    Returns True if it's safe to run a full refresh, False otherwise.
    """
    log_info("Performing safety check...")
    update_status("Checking environment conditions...")
    
    form_factor = detect_form_factor()

    # Pre-compute AC and metered status for clearer logging
    metered = is_metered()
    if form_factor == "desktop":
        on_ac = True  # desktops are treated as effectively always on AC
    else:
        on_ac = on_ac_power(form_factor)

    # Decide safety based on current conditions
    safe = (not metered) and (form_factor == "desktop" or on_ac)

    # Log environment and safety
    log_info(f"Environment: form_factor={form_factor}, on_ac={on_ac}, metered={metered}, safe={safe}")

    # Notify user if conditions changed since last run
    prev_state = _read_last_env_state()
    _notify_env_change(prev_state, form_factor, on_ac, metered, safe)

    # Apply safety policy
    if metered:
        log_info("Metered connection detected. Skipping refresh.")
        update_status("SKIPPED: Metered connection detected")
        return False

    if form_factor == "laptop":
        if not on_ac:
            log_info("Running on battery (or AC unknown). Skipping refresh.")
            update_status("SKIPPED: Running on battery")
            return False
        else:
            log_info("Laptop on AC power.")

    # Desktop or unknown: no AC restriction (already checked metered above)
    log_info("Environment is safe for updates")
    return True


def get_updates():
    """Return the last dry-run output generated by the root downloader.

    The root systemd service (zypper-download-with-progress) runs
    "zypper dup --dry-run" as root and writes the full output to
    DRYRUN_OUTPUT_FILE. The notifier only needs to read and parse that
    file; it should not invoke zypper or pkexec itself.

    Returns:
        - stdout string from the last dry-run when environment is safe
        - "" (empty string) if environment is not safe or no data is available
    """
    log_info("Starting update check (no pkexec; using cached dry-run output)...")

    # Respect environment safety (metered/battery) for *notifications*,
    # even though we no longer run zypper here.
    safe = is_safe()
    if not safe:
        log_info("Environment not safe for background updates; skipping notification.")
        return ""

    try:
        if not os.path.exists(DRYRUN_OUTPUT_FILE):
            log_info(f"Dry-run output file not found: {DRYRUN_OUTPUT_FILE}")
            update_status("SKIPPED: No dry-run data from downloader yet")
            return ""

        try:
            with open(DRYRUN_OUTPUT_FILE, "r", encoding="utf-8") as f:
                output = f.read()
        except Exception as e:
            log_error(f"Failed to read dry-run output file {DRYRUN_OUTPUT_FILE}: {e}")
            update_status("FAILED: Could not read dry-run data from downloader")
            return ""

        if not output.strip():
            log_info("Dry-run output file is empty; treating as no updates.")
            update_status("SKIPPED: Empty dry-run data from downloader")
            return ""

        log_info("Loaded dry-run output from downloader successfully")
        return output

    except Exception as e:
        log_error(f"Unexpected error while loading dry-run data: {e}")
        update_status("FAILED: Unexpected error while loading dry-run data")
        return ""

def extract_package_preview(output: str, max_packages: int = 5) -> list:
    """Extract a preview of packages being updated.
    Returns list of package names.
    """
    packages = []
    try:
        # Look for lines that show package upgrades
        # Format: package-name | version | arch | repository
        in_upgrade_section = False
        for line in output.splitlines():
            line = line.strip()
            
            if "packages to upgrade" in line.lower():
                in_upgrade_section = True
                continue
            
            # Skip non-package summary lines that can appear in the table,
            # such as the "Package download size" section or "0 B | ... already in cache".
            lower = line.lower()
            if any(tok in lower for tok in ["package download size", "overall package size", "already in cache"]):
                continue
            
            if in_upgrade_section and "|" in line:
                # Parse package line
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 1 and parts[0] and not parts[0].startswith("-"):
                    pkg_name = parts[0]
                    # Skip header lines and size-like pseudo "names" such as "0 B" or "12.3 MiB"
                    if pkg_name not in ["Name", "Status", "#"] and not re.match(r"^[0-9].*", pkg_name):
                        packages.append(pkg_name)
                        if len(packages) >= max_packages:
                            break
            
            # Stop if we hit another section
            if in_upgrade_section and line and not line.startswith("|") and "|" not in line:
                if packages:  # Only break if we found some packages
                    break
    except Exception as e:
        log_debug(f"Failed to extract package preview: {e}")
    
    return packages


def parse_output(output: str, include_preview: bool = True):
    """Parse zypper's output for info.

    Returns: (title, message, snapshot, package_count)
             or (None, None, None, 0).
    """
    log_debug("Parsing zypper output...")
    
    if "Nothing to do." in output:
        log_info("No updates found in zypper output")
        return None, None, None, 0

    # Count Packages
    count_match = re.search(r"(\d+) packages to upgrade", output)
    package_count = int(count_match.group(1)) if count_match else 0
    
    # If no packages found or count is 0, return None
    if package_count == 0:
        log_info("No packages to upgrade (count is 0)")
        return None, None, None, 0

    # Find Snapshot
    snapshot_match = None
    # Preferred: product line such as
    #   openSUSE Tumbleweed  20251227-0 -> 20251228-0
    product_match = re.search(r"openSUSE Tumbleweed\s+\S+\s*->\s*([0-9T\-]+)", output)
    if product_match:
        snapshot_match = product_match
    else:
        # Fallback: older tumbleweed-release pattern
        snapshot_match = re.search(r"tumbleweed-release.*->\s*([\dTb\-]+)", output)
    snapshot = snapshot_match.group(1) if snapshot_match else ""

    log_info(
        f"Found {package_count} packages to upgrade"
        + (f" (snapshot: {snapshot})" if snapshot else "")
    )

    # Build strings
    title = f"Snapshot {snapshot} Ready" if snapshot else "Updates Ready to Install"

    if package_count == 1:
        message = "1 update is pending."
    else:
        message = f"{package_count} updates are pending."
    
    # Add package preview if requested
    if include_preview and package_count > 0:
        preview_packages = extract_package_preview(output, max_packages=3)
        if preview_packages:
            preview_str = ", ".join(preview_packages)
            if len(preview_packages) < package_count:
                preview_str += f", and {package_count - len(preview_packages)} more"
            message += f"\n\nIncluding: {preview_str}"

    return title, message, snapshot, package_count

def on_action(notification, action_id, user_data):
    """Callback to run when an action button is clicked."""
    log_info(f"User clicked action: {action_id}")
    
    if action_id == "install":
        update_status("User initiated update installation")

        # Create an "install in progress" marker so the next timer tick does not
        # re-show the exact same "Updates Ready" notification while the user is
        # already installing updates.
        try:
            with open(INSTALL_MARKER_FILE, "w", encoding="utf-8") as f:
                f.write(datetime.now().isoformat())
        except Exception as e:
            log_debug(f"Failed to write install marker file: {e}")

        action_script = user_data
        try:
            # Prefer to launch via systemd-run so the process is clearly
            # associated with the user session and not tied to this script.
            # Explicitly propagate key environment variables (DISPLAY, DBUS, etc.)
            # so GUI terminals like konsole/gnome-terminal can start even when
            # the user systemd manager has a minimal environment.
            env = os.environ.copy()

            # Generate a short trace identifier so we can correlate this GUI
            # click with backend installer logs. This is exported via
            # ZYPPER_TRACE_ID and picked up by the bash helper.
            import uuid
            trace_id = f"GUI-{uuid.uuid4().hex[:8]}"
            env["ZYPPER_TRACE_ID"] = trace_id
            # Also propagate the notifier's own RUN id so action scripts can be
            # correlated back to this notifier run.
            env["ZNH_RUN_ID"] = RUN_ID
            log_info(f"Generated Trace ID for install action: {trace_id}")

            try:
                cmd = [
                    "systemd-run",
                    "--user",
                    "--scope",
                ]
                for key in (
                    "DISPLAY",
                    "WAYLAND_DISPLAY",
                    "XDG_SESSION_TYPE",
                    "DBUS_SESSION_BUS_ADDRESS",
                    "XAUTHORITY",
                    "ZYPPER_TRACE_ID",
                    "ZNH_RUN_ID",
                ):
                    val = env.get(key)
                    if val:
                        cmd.append(f"--setenv={key}={val}")
                cmd.append(action_script)
                log_debug(
                    "Launching install script via systemd-run: "
                    + " ".join(shlex.quote(part) for part in cmd)
                )
                subprocess.Popen(cmd, env=env)
            except FileNotFoundError:
                # Fallback: run the script directly if systemd-run is not available.
                log_debug(f"Launching install script directly: {action_script}")
                subprocess.Popen([action_script], env=env)
            log_info("Install script launched successfully")
        except Exception as e:
            log_error(f"Failed to launch action script: {e}")
    
    elif action_id == "snooze-1h":
        set_snooze(SNOOZE_SHORT_HOURS)
        update_status(f"Updates snoozed for {SNOOZE_SHORT_HOURS} hour(s)")
    
    elif action_id == "snooze-4h":
        set_snooze(SNOOZE_MEDIUM_HOURS)
        update_status(f"Updates snoozed for {SNOOZE_MEDIUM_HOURS} hour(s)")
    
    elif action_id == "snooze-1d":
        set_snooze(SNOOZE_LONG_HOURS)
        update_status(f"Updates snoozed for {SNOOZE_LONG_HOURS} hour(s)")
    
    elif action_id == "view-changes":
        log_info("User clicked View Changes button")
        update_status("User viewing update details")
        view_script = os.path.expanduser("~/.local/bin/zypper-view-changes")
        try:
            # Make sure the script is executable
            import stat
            if os.path.exists(view_script):
                os.chmod(view_script, os.stat(view_script).st_mode | stat.S_IEXEC)
                log_debug(f"Launching view changes script via systemd-run: {view_script}")
                try:
                    subprocess.Popen([
                        "systemd-run",
                        "--user",
                        "--scope",
                        view_script,
                    ])
                except FileNotFoundError:
                    log_debug("systemd-run not found, launching directly")
                    subprocess.Popen([view_script], start_new_session=True)
                log_info("View changes script launched successfully")
            else:
                log_error(f"View changes script not found: {view_script}")
        except Exception as e:
            log_error(f"Failed to launch view changes script: {e}")
            import traceback
            log_debug(f"Traceback: {traceback.format_exc()}")
        # Don't close notification or quit loop for view changes
        return
    
    notification.close()
    GLib.MainLoop().quit()

def main():
    try:
        log_debug("Initializing notification system...")
        Notify.init("zypper-updater")
        
        # Check if updates are snoozed FIRST - skip all notifications if snoozed
        if check_snoozed():
            log_info("Updates are currently snoozed, skipping all notifications")
            return

        # If an interactive install is already running (user clicked "Install Now"),
        # suppress all notifier popups until the helper clears the marker.
        if is_install_suppressed():
            return

        # If the background downloader just finished, we'll attach a short
        # "downloads complete" note to the main "Updates Ready" notification.
        # This avoids showing two notifications back-to-back.
        completion_note = ""
        
        # Check if downloader is actively downloading updates
        download_status_file = "/var/log/zypper-auto/download-status.txt"
        if os.path.exists(download_status_file):
            try:
                # Treat very old statuses as stale so we don't get stuck forever
                try:
                    mtime = os.path.getmtime(download_status_file)
                    age_seconds = time.time() - mtime
                except Exception as e:
                    log_debug(f"Could not stat download status file: {e}")
                    age_seconds = 0

                with open(download_status_file, 'r') as f:
                    status = f.read().strip()

                # If status looks like an in‑progress state but is stale, ignore it
                if status in ("refreshing",) or status.startswith("downloading:"):
                    if age_seconds > 300:  # older than 5 minutes
                        log_info(f"Stale download status '{status}' (age {age_seconds:.0f}s) - ignoring and continuing to full check")
                    else:
                        # Handle stage-based status for fresh operations
                        if status == "refreshing":
                            # IMPORTANT: when the downloader is actively refreshing, do not fall
                            # through into the normal dry-run parsing logic. Otherwise, if showing
                            # the progress notification fails for any reason, we may incorrectly
                            # emit an "Updates Ready" notification while refresh is still running.
                            log_info("Stage: Refreshing repositories")
                            try:
                                n = Notify.Notification.new(
                                    "Checking for updates...",
                                    "Refreshing repositories...",
                                    "emblem-synchronizing"
                                )
                                n.set_timeout(5000)  # 5 seconds
                                # Set hint to replace previous download status notifications
                                n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "zypper-download-status"))
                                n.show()
                                time.sleep(0.1)
                            except Exception as e:
                                log_debug(f"Failed to show 'refreshing' notification: {e}")
                            return  # Exit: refresh in progress; check again on next timer tick

                        elif status.startswith("downloading:"):
                            # Extract from "downloading:TOTAL:SIZE:DOWNLOADED:PERCENT" format
                            try:
                                parts = status.split(":")
                                pkg_total = parts[1] if len(parts) > 1 else "0"
                                download_size = parts[2] if len(parts) > 2 else "unknown size"
                                pkg_downloaded = parts[3] if len(parts) > 3 else "0"
                                percent = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0

                                # Manual interactive zypper runs mark the size as "manual"
                                # via the wrapper script. In that case we avoid showing an
                                # extra desktop progress popup and let the terminal output
                                # act as the primary indicator.
                                if download_size == "manual":
                                    log_info("Download status indicates manual zypper run; skipping download popup")
                                    return

                                log_info(
                                    f"Stage: Downloading {pkg_downloaded} of {pkg_total} packages ({download_size})"
                                )

                                # Build progress bar visual
                                if 0 <= percent <= 100:
                                    bar_length = 20
                                    filled = int(bar_length * percent / 100)
                                    bar = "█" * filled + "░" * (bar_length - filled)
                                    progress_text = f"[{bar}] {percent}%"
                                else:
                                    progress_text = "Processing..."

                                # Build message with progress
                                total_int = int(pkg_total) if pkg_total.isdigit() else 0
                                if total_int > 0:
                                    if download_size and download_size not in ("unknown", "manual"):
                                        msg = (
                                            f"Downloading {pkg_downloaded} of {pkg_total} packages\n"
                                            f"{progress_text}\n"
                                            f"{download_size} total • background priority"
                                        )
                                    else:
                                        msg = (
                                            f"Downloading {pkg_downloaded} of {pkg_total} packages\n"
                                            f"{progress_text}\n"
                                            "background priority"
                                        )
                                else:
                                    # Manual or unknown total: avoid misleading "0 of 0" text
                                    if download_size and download_size not in ("unknown", "manual"):
                                        msg = (
                                            "Downloading updates\n"
                                            f"{progress_text}\n"
                                            f"{download_size} total • background priority"
                                        )
                                    else:
                                        msg = (
                                            "Downloading updates\n"
                                            f"{progress_text}\n"
                                            "background priority"
                                        )

                                n = Notify.Notification.new(
                                    "Downloading updates...",
                                    msg,
                                    "emblem-downloads"
                                )

                                # Add progress bar hint (0-100) for notification daemons that support it
                                if 0 <= percent <= 100:
                                    n.set_hint("value", GLib.Variant("i", percent))
                                    n.set_category("transfer.progress")  # Category hint for progress notifications
                                else:
                                    # Indeterminate progress (pulsing animation)
                                    n.set_hint("value", GLib.Variant("i", 0))
                                    n.set_category("transfer")
                            except Exception as e:
                                log_debug(f"Error parsing download status: {e}")
                                log_info("Stage: Downloading packages")
                                n = Notify.Notification.new(
                                    "Downloading updates...",
                                    "Background download is in progress (background priority).",
                                    "emblem-downloads"
                                )
                                n.set_hint("value", GLib.Variant("i", 50))

                            # Common settings for the progress notification
                            n.set_timeout(5000)  # 5 seconds
                            # Set hint to replace previous download status notifications
                            n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "zypper-download-status"))
                            n.show()

                            # Keep updating the same notification until the downloader
                            # finishes (status changes away from "downloading:").
                            while True:
                                time.sleep(2)
                                try:
                                    with open(download_status_file, 'r') as f2:
                                        new_status = f2.read().strip()
                                except Exception as e:
                                    log_debug(f"Error reading download status during progress loop: {e}")
                                    break

                                if not new_status.startswith("downloading:"):
                                    # Status changed (likely to complete: or idle) –
                                    # update our local variable so the logic below
                                    # can handle completion.
                                    status = new_status
                                    log_debug(f"Download status changed to '{status}', leaving progress loop")
                                    break

                                try:
                                    parts = new_status.split(":")
                                    pkg_total = parts[1] if len(parts) > 1 else "?"
                                    download_size = parts[2] if len(parts) > 2 else "unknown size"
                                    pkg_downloaded = parts[3] if len(parts) > 3 else "0"
                                    percent = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0

                                    log_info(f"Stage: Downloading {pkg_downloaded} of {pkg_total} packages ({download_size})")

                                    # Rebuild progress bar
                                    if 0 <= percent <= 100:
                                        bar_length = 20
                                        filled = int(bar_length * percent / 100)
                                        bar = "█" * filled + "░" * (bar_length - filled)
                                        progress_text = f"[{bar}] {percent}%"
                                    else:
                                        progress_text = "Processing..."

                                    total_int = int(pkg_total) if pkg_total.isdigit() else 0

                                    if total_int > 0:
                                        if download_size and download_size not in ("unknown", "manual"):
                                            msg = (
                                                f"Downloading {pkg_downloaded} of {pkg_total} packages\n"
                                                f"{progress_text}\n"
                                                f"{download_size} total • background priority"
                                            )
                                        else:
                                            msg = (
                                                f"Downloading {pkg_downloaded} of {pkg_total} packages\n"
                                                f"{progress_text}\n"
                                                "background priority"
                                            )
                                    else:
                                        if download_size and download_size not in ("unknown", "manual"):
                                            msg = (
                                                "Downloading updates\n"
                                                f"{progress_text}\n"
                                                f"{download_size} total • background priority"
                                            )
                                        else:
                                            msg = (
                                                "Downloading updates\n"
                                                f"{progress_text}\n"
                                                "background priority"
                                            )

                                    # Update the existing notification in place
                                    n.update("Downloading updates...", msg, "emblem-downloads")

                                    if 0 <= percent <= 100:
                                        n.set_hint("value", GLib.Variant("i", percent))
                                        n.set_category("transfer.progress")
                                    else:
                                        n.set_hint("value", GLib.Variant("i", 0))
                                        n.set_category("transfer")

                                    n.show()
                                except Exception as e:
                                    log_debug(f"Error updating download progress notification: {e}")
                                    # If something goes wrong, just break out and
                                    # let the rest of main() continue.
                                    break

                            # Do not return here – fall through so that a
                            # subsequent 'complete:' status is handled by the
                            # code below.

                # Fresh 'complete:' or 'idle' status fall through to the normal logic below
                if status.startswith("complete:"):
                    # Extract from "complete:DURATION:ACTUAL_DOWNLOADED" format (seconds)
                    try:
                        parts = status.split(":")
                        duration = int(parts[1]) if len(parts) > 1 else 0
                        actual_downloaded = int(parts[2]) if len(parts) > 2 else 0
                        
                        minutes = duration // 60
                        seconds = duration % 60
                        
                        if minutes > 0:
                            time_str = f"{minutes}m {seconds}s"
                        else:
                            time_str = f"{seconds}s"
                        
                        # Before we show any "Downloads Complete" message, double‑check that
                        # there are still updates pending. If zypper dup --dry-run reports
                        # nothing to do, this completion status is stale (the user probably
                        # installed updates manually) and we should skip the download
                        # notification entirely so it doesn't appear after everything
                        # is already installed.
                        dry_output = ""
                        pending_count = None
                        try:
                            log_debug("Verifying pending updates for downloads-complete status...")
                            preview_cmd = [
                                "pkexec",
                                "zypper",
                                "--non-interactive",
                                "dup",
                                "--dry-run",
                                *DUP_EXTRA_FLAGS,
                            ]
                            result = subprocess.run(
                                preview_cmd,
                                capture_output=True,
                                text=True,
                                timeout=30,
                            )
                            if result.returncode == 0:
                                dry_output = result.stdout or ""
                                _, _, _, pending_count = parse_output(dry_output, include_preview=False)
                                pending_count = pending_count or 0
                        except Exception as e:
                            log_debug(f"Verification dry-run for downloads-complete status failed: {e}")
                            dry_output = ""
                            pending_count = None
                        
                        if pending_count == 0:
                            log_info("Download status was 'complete' but zypper reports no pending updates; treating completion as stale and skipping 'Downloads Complete' notification.")
                            try:
                                with open(download_status_file, "w") as f:
                                    f.write("idle")
                            except Exception as e2:
                                log_debug(f"Failed to reset download status after stale completion: {e2}")
                            # Skip the downloads-complete popup; normal update check below
                            # will show the usual 'system up to date' message instead.
                        else:
                            # There are still updates pending. We'll show the main
                            # "Updates Ready" notification below.
                            #
                            # IMPORTANT: do NOT show a separate "✅ Downloads Complete!"
                            # popup here, because it often results in two back-to-back
                            # notifications (Downloads Complete + Updates Ready), which
                            # feels like duplicates.
                            if actual_downloaded == 0:
                                log_info("All packages were already cached; marking downloads complete (no separate popup)")
                                completion_note = "✅ Downloads complete (all packages already in cache)."
                            else:
                                log_info(f"Downloaded {actual_downloaded} packages in {time_str}")
                                completion_note = f"✅ Downloads complete: downloaded {actual_downloaded} package(s) in {time_str}."

                                # If we have fresh dry-run output, attach a short preview
                                if dry_output:
                                    try:
                                        preview_packages = extract_package_preview(dry_output, max_packages=5)
                                        if preview_packages:
                                            preview_str = ", ".join(preview_packages)
                                            completion_note += f" Including: {preview_str}"
                                            log_info(f"Added download completion preview: {preview_str}")
                                    except Exception as e:
                                        log_debug(f"Could not build download completion preview: {e}")

                            # Clear the complete status so it doesn't show again
                            try:
                                with open(download_status_file, "w") as f:
                                    f.write("idle")
                            except Exception as e2:
                                log_debug(f"Failed to reset download status after completion: {e2}")
                        # Continue to show install notification below
                    except Exception:
                        log_debug("Could not process completion status")
                        # Continue to show install notification below
                
                elif status == "idle":
                    log_debug("Status is idle (no updates to download)")
                    # Continue to normal check below

                elif status.startswith("error:network"):
                    # Downloader could not talk to the repositories (DNS or
                    # similar network problem). Surface a clear error to the
                    # user instead of silently failing.
                    log_error("Background downloader reported a network error while checking for updates")
                    msg = (
                        "The background updater could not reach the openSUSE repositories.\n\n"
                        "This is usually a temporary network or DNS problem.\n\n"
                        "Check your connection and DNS settings, then try again."
                    )
                    n = Notify.Notification.new(
                        "Update check failed (network)",
                        msg,
                        "network-error",
                    )
                    n.set_timeout(30000)
                    n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "zypper-network-error"))
                    n.set_urgency(Notify.Urgency.NORMAL)
                    n.show()

                    # Reset status to idle so we do not spam the same
                    # notification on every timer tick.
                    try:
                        with open(download_status_file, "w") as f:
                            f.write("idle")
                    except Exception as e2:
                        log_debug(f"Failed to reset download status after network error: {e2}")

                    return

                elif status.startswith("error:repo"):
                    # Repositories themselves reported an error (e.g. invalid
                    # metadata). Treat similarly to network errors but use a
                    # slightly different message.
                    log_error("Background downloader reported a repository error while checking for updates")
                    msg = (
                        "The background updater hit an error while talking to configured repositories.\n\n"
                        "Zypper reported repository failures or invalid metadata.\n\n"
                        "Run 'sudo zypper refresh' in a terminal for full details."
                    )
                    n = Notify.Notification.new(
                        "Update check failed (repositories)",
                        msg,
                        "dialog-warning",
                    )
                    n.set_timeout(30000)
                    n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "zypper-repo-error"))
                    n.set_urgency(Notify.Urgency.NORMAL)
                    n.show()

                    try:
                        with open(download_status_file, "w") as f:
                            f.write("idle")
                    except Exception as e2:
                        log_debug(f"Failed to reset download status after repo error: {e2}")

                    return

                elif status.startswith("error:solver:"):
                    # Background downloader hit a solver/non-interactive error.
                    # Show a persistent notification that both:
                    #   - explains the conflict, and
                    #   - summarises how many updates are available (if possible),
                    # with an "Install Now" action that runs the helper.
                    try:
                        parts = status.split(":")
                        exit_code = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None
                    except Exception:
                        exit_code = None

                    if exit_code is not None:
                        log_info(f"Background downloader encountered a zypper solver/error exit code {exit_code}")
                    else:
                        log_info("Background downloader reported a solver error (unknown exit code)")

                    # Try to run a dry-run to get a summary of pending updates, even if
                    # zypper still exits non-zero due to conflicts.
                    dry_output = ""
                    try:
                        log_debug("Running zypper dup --dry-run to summarise solver-conflict state...")
                        conflict_cmd = [
                            "pkexec",
                            "zypper",
                            "--non-interactive",
                            "dup",
                            "--dry-run",
                            *DUP_EXTRA_FLAGS,
                        ]
                        result = subprocess.run(
                            conflict_cmd,
                            capture_output=True,
                            text=True,
                            timeout=60,
                        )
                        dry_output = result.stdout or ""
                    except Exception as e2:
                        log_debug(f"Failed to run zypper dry-run for solver summary: {e2}")
                        dry_output = ""

                    title = "Updates require your decision"
                    message = ""

                    # If we got useful output, reuse the normal parser to describe
                    # how many updates are pending and a short preview.
                    parsed_title = None
                    parsed_message = None
                    pkg_count = 0
                    if dry_output:
                        try:
                            parsed_title, parsed_message, snapshot, pkg_count = parse_output(dry_output, include_preview=True)
                        except Exception as e3:
                            log_debug(f"parse_output failed for solver summary: {e3}")
                            parsed_title, parsed_message, pkg_count = None, None, 0

                    if parsed_title:
                        title = f"{parsed_title} (manual decision needed)"
                        message = parsed_message + "\\n\\nZypper needs your decision to resolve conflicts before these updates can be installed."
                    else:
                        # Fallback generic explanation
                        if exit_code is not None:
                            message = (
                                f"Background download of updates hit a zypper solver error (exit code {exit_code}).\\n\\n"
                                "Some packages may already be cached, but zypper needs your decision to continue."
                            )
                        else:
                            message = (
                                "Background download of updates hit a zypper solver error.\\n\\n"
                                "Some packages may already be cached, but zypper needs your decision to continue."
                            )

                    # Always give clear instructions on what to do next.
                    message += (
                        "\\n\\nOpen a terminal and run:\n"
                        "  sudo zypper dup\n"
                        "or click 'Install Now' to open the helper, then follow zypper's prompts to resolve the conflicts."
                    )

                    action_script = os.path.expanduser("~/.local/bin/zypper-run-install")

                    n = Notify.Notification.new(
                        title,
                        message,
                        "system-software-update",
                    )
                    # Persistent notification, high urgency.
                    n.set_timeout(0)
                    n.set_urgency(Notify.Urgency.CRITICAL)
                    n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "zypper-updates-conflict"))

                    # Add the same actions as the normal "updates ready" notification.
                    n.add_action("install", "Install Now", on_action, action_script)
                    n.add_action("view-changes", "View Changes", on_action, None)
                    n.add_action("snooze-1h", "1h", on_action, None)
                    n.add_action("snooze-4h", "4h", on_action, None)
                    n.add_action("snooze-1d", "1d", on_action, None)

                    # Reset the status to idle so we don't spam the same notification forever.
                    try:
                        with open(download_status_file, "w") as f:
                            f.write("idle")
                    except Exception as e2:
                        log_debug(f"Failed to reset download status after solver error: {e2}")

                    # Run a short main loop so actions work, then exit this cycle.
                    loop = GLib.MainLoop()
                    n.connect("closed", lambda *args: loop.quit())
                    n.show()
                    try:
                        loop.run()
                    except KeyboardInterrupt:
                        log_info("Solver-conflict notification main loop interrupted")

                    # Do not run another zypper dry-run in this cycle; wait for user action.
                    return
                    
            except Exception as e:
                log_debug(f"Could not read download status: {e}")

        # Run safety checks before proceeding
        has_space, space_msg = check_disk_space()
        has_snapshots, snapshot_msg = check_snapshots()
        net_ok, net_msg = check_network_quality()
        
        # Log safety check results
        log_info(f"Safety checks: disk={space_msg}, snapshots={snapshot_msg}, network={net_msg}")
        
        output = get_updates()

        # If get_updates() failed with a real error (not just zypper lock), show error notification
        if output is None:
            log_error("Update check failed due to PolicyKit/authentication error")
            update_status("FAILED: Update check failed")
            err_title = "Update check failed"
            err_message = (
                "The updater could not authenticate with PolicyKit.\n"
                "This may be a configuration issue.\n\n"
                "Try running 'pkexec zypper dup --dry-run' manually to test."
            )
            n = Notify.Notification.new(err_title, err_message, "dialog-error")
            n.set_timeout(30000)  # 30 seconds
            n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "zypper-error"))
            n.show()
            log_info("Error notification displayed")
            return

        # Empty string means environment was unsafe and zypper was skipped.
        if not output or not output.strip():
            log_info("No zypper run performed (environment not safe). Exiting.")
            return

        title, message, snapshot, package_count = parse_output(output)
        if not title:
            # No updates available: check if we already showed this
            log_info("System is up-to-date.")
            update_status("SUCCESS: System up-to-date")
            
            # Check if we already showed "no updates" notification
            last_notification = _read_last_notification()
            no_updates_key = "No updates found|Your system is already up to date."
            
            if (not NO_UPDATES_REMINDER_REPEAT_ENABLED) and last_notification == no_updates_key:
                log_info("'No updates' notification already shown, skipping duplicate (NO_UPDATES_REMINDER_REPEAT_ENABLED=false)")
                return
            
            # First time or repeat - show notification and remember it
            log_info("Showing 'no updates found' notification")
            _write_last_notification("No updates found", "Your system is already up to date.")
            
            n = Notify.Notification.new(
                "No updates found",
                "Your system is already up to date.",
                "dialog-information",
            )
            n.set_timeout(10000)  # 10 seconds
            n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "zypper-no-updates"))
            n.show()
            return
        
        # Write cache for future checks
        write_cache(package_count, snapshot)

        # If downloads just completed, attach that info to the updates-ready message
        # so the user sees only one notification.
        if completion_note:
            message = completion_note + "\n\n" + message

        log_info("Updates are pending. Sending 'updates ready' reminder.")
        update_status(f"Updates available: {title}")
        
        # Add safety warnings / info lines to message
        warnings = []
        if not has_space:
            warnings.append(f"⚠️ {space_msg}")
        # Always show Snapper state; use ℹ️ when snapshots exist, ⚠️ when they don't
        if snapshot_msg:
            icon = "ℹ️" if has_snapshots else "⚠️"
            warnings.append(f"{icon} {snapshot_msg}")
        if not net_ok:
            warnings.append(f"⚠️ {net_msg}")
        
        if warnings:
            message += "\n\n" + "\n".join(warnings)

        # Check if this notification is different from the last one
        last_notification = _read_last_notification()
        current_notification = f"{title}|{message}"
        
        if (not UPDATES_READY_REMINDER_REPEAT_ENABLED) and last_notification == current_notification:
            log_info("'Updates ready' notification already shown, skipping duplicate (UPDATES_READY_REMINDER_REPEAT_ENABLED=false)")
            return
        
        if last_notification == current_notification:
            log_debug("Notification unchanged, re-showing to keep it visible")
        else:
            log_info(f"Notification changed from [{last_notification}] to [{current_notification}]")
        
        _write_last_notification(title, message)

        # Get the path to the action script
        action_script = os.path.expanduser("~/.local/bin/zypper-run-install")

        # Create the notification with a stable ID so it replaces the previous one
        log_debug(f"Creating notification: {title}")
        n = Notify.Notification.new(title, message, "system-software-update")
        n.set_timeout(0) # 0 = persistent notification (no timeout)
        n.set_urgency(Notify.Urgency.CRITICAL) # Make it more noticeable
        
        # Set a consistent ID so notifications replace each other
        n.set_hint("desktop-entry", GLib.Variant("s", "zypper-updater"))
        n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "zypper-updates"))

        # Add action buttons with shorter labels
        n.add_action("install", "Install Now", on_action, action_script)
        n.add_action("view-changes", "View Changes", on_action, None)
        n.add_action("snooze-1h", "1h", on_action, None)
        n.add_action("snooze-4h", "4h", on_action, None)
        n.add_action("snooze-1d", "1d", on_action, None)

        log_info("Displaying persistent update notification with Install and Snooze buttons")
        n.show()
        
        # Run main loop indefinitely - only exit when user interacts with notification
        # This keeps the notification visible until user takes action
        log_info("Running GLib main loop indefinitely - waiting for user action...")
        loop = GLib.MainLoop()
        n.connect("closed", lambda *args: loop.quit())
        
        try:
            loop.run()
        except KeyboardInterrupt:
            log_info("Main loop interrupted")
        
        log_info("Main loop finished - user interacted with notification or it was dismissed")

    except Exception as e:
        log_error(f"An error occurred in main: {e}")
        update_status(f"FAILED: {str(e)}")
        import traceback
        log_error(f"Traceback: {traceback.format_exc()}")
    finally:
        log_info("Shutting down notification system")
        Notify.uninit()
        log_info("Zypper Notify Updater finished")
        log_info("=" * 60)

if __name__ == "__main__":
    main()
EOF

chown "$SUDO_USER:$SUDO_USER" "${NOTIFY_SCRIPT_PATH}"
chmod +x "${NOTIFY_SCRIPT_PATH}"
log_success "Python notifier script created and made executable"

# Hard fail early if the generated notifier script is syntactically invalid.
# This avoids later noisy verification failures in diagnostics logs.
log_debug "Validating generated notifier script syntax via py_compile"
if ! execute_guarded "Python syntax check for generated notifier" python3 -B -m py_compile "${NOTIFY_SCRIPT_PATH}"; then
    log_error "Generated notifier script failed syntax validation: ${NOTIFY_SCRIPT_PATH}"
    update_status "FAILED: Generated notifier Python syntax check failed"
    exit 1
fi

# If there were any configuration warnings collected during load_config,
# surface them clearly in the status/log so the user can fix them.
if [ "${#CONFIG_WARNINGS[@]}" -gt 0 ]; then
    echo "" | tee -a "${LOG_FILE}"
    echo "Configuration warnings (from ${CONFIG_FILE}):" | tee -a "${LOG_FILE}"
    for w in "${CONFIG_WARNINGS[@]}"; do
        echo "  - $w" | tee -a "${LOG_FILE}"
    done
    echo "" | tee -a "${LOG_FILE}"
    update_status "WARNING: One or more settings in ${CONFIG_FILE} were invalid and reset to defaults"

    # Try to send a desktop notification to the target user so they
    # notice the config issue and can fix or reset it.
    if command -v sudo >/dev/null 2>&1; then
        USER_BUS_PATH="$(get_user_bus "$SUDO_USER")"
        sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" \
            notify-send "Zypper Auto-Helper config warnings" \
            "Some settings in ${CONFIG_FILE} were invalid and reset to safe defaults.\n\nCheck the install log or run: zypper-auto-helper --reset-config" \
            >/dev/null 2>&1 || true
    fi
fi

# --- 11. Create/Update Install Script (user) ---
log_info ">>> Creating (user) install script: ${INSTALL_SCRIPT_PATH}"
update_status "Creating install helper script..."
log_debug "Writing install script to: ${INSTALL_SCRIPT_PATH}"
write_atomic "${INSTALL_SCRIPT_PATH}" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

# Simple logging helper so we can debug why the install window may be
# opening and closing immediately.
LOG_FILE="$HOME/.local/share/zypper-notify/run-install.log"
LOG_DIR="$(dirname "$LOG_FILE")"
mkdir -p "$LOG_DIR" 2>/dev/null || true

# Suppress duplicate "Updates Ready" popups while this interactive install
# window is running.
INSTALL_MARKER_FILE="$HOME/.cache/zypper-notify/install_in_progress.txt"
mkdir -p "$(dirname "$INSTALL_MARKER_FILE")" 2>/dev/null || true
MARKER_TS="$(date -Iseconds 2>/dev/null || date +%s)"
printf '%s\n' "${MARKER_TS}" >"${INSTALL_MARKER_FILE}" 2>/dev/null || true
cleanup_install_marker() {
    rm -f -- "${INSTALL_MARKER_FILE}" 2>/dev/null || true
}
trap cleanup_install_marker EXIT

# Correlation IDs propagated from the notifier (when available)
ZNH_RUN_ID="${ZNH_RUN_ID:-}"
ZYPPER_TRACE_ID="${ZYPPER_TRACE_ID:-}"
if [ -z "${ZNH_RUN_ID}" ]; then
    ZNH_RUN_ID="RUN-$(date +%Y%m%dT%H%M%S)-$$"
fi

log() {
    # Best-effort logging; never fail the script because of logging issues.
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    {
        printf '[%s] [RUN=%s]%s %s\n' "$ts" "$ZNH_RUN_ID" "${ZYPPER_TRACE_ID:+ [TID=${ZYPPER_TRACE_ID}]}" "$*" >>"$LOG_FILE" 2>/dev/null || true
    } || true
}

execute_guarded() {
    local desc="$1"; shift
    local tmp
    tmp="$(mktemp)"
    log "EXEC: ${desc} -> $*"
    if "$@" >"$tmp" 2>&1; then
        # Always append captured output to the log (best-effort)
        if [ -s "$tmp" ] 2>/dev/null; then
            cat "$tmp" >>"$LOG_FILE" 2>/dev/null || true
        fi
        rm -f "$tmp" 2>/dev/null || true
        return 0
    else
        local rc=$?
        log "FAILED: ${desc} (rc=${rc})"
        cat "$tmp" | tee -a "$LOG_FILE" >&2
        rm -f "$tmp" 2>/dev/null || true
        return $rc
    fi
}

log "===== zypper-run-install started (PID $$) ====="
log "ENV: TERM=${TERM:-} DISPLAY=${DISPLAY:-} WAYLAND_DISPLAY=${WAYLAND_DISPLAY:-} XDG_SESSION_TYPE=${XDG_SESSION_TYPE:-}"
log "ENV: SHELL=${SHELL:-} USER=${USER:-} PWD=${PWD:-}"

# Load feature toggles from the same config used by the installer.
CONFIG_FILE="/etc/zypper-auto.conf"

# Default feature toggles (can be overridden by CONFIG_FILE)
ENABLE_FLATPAK_UPDATES="true"
ENABLE_SNAP_UPDATES="true"
ENABLE_SOAR_UPDATES="true"
ENABLE_BREW_UPDATES="true"
ENABLE_PIPX_UPDATES="true"

# Enterprise extensions (can be overridden by CONFIG_FILE)
HOOKS_ENABLED="true"
HOOKS_BASE_DIR="/etc/zypper-auto/hooks"

if [ -r "$CONFIG_FILE" ]; then
    # shellcheck disable=SC1090
    . "$CONFIG_FILE"
fi

run_hooks() {
    local stage="$1"
    local base hook_dir hook

    if [[ "${HOOKS_ENABLED,,}" != "true" ]]; then
        log "Hooks disabled (HOOKS_ENABLED=${HOOKS_ENABLED}); skipping ${stage} hooks"
        return 0
    fi

    base="${HOOKS_BASE_DIR:-/etc/zypper-auto/hooks}"
    hook_dir="${base}/${stage}.d"

    if [ ! -d "$hook_dir" ]; then
        log "Hook directory not present: $hook_dir (skipping)"
        return 0
    fi

    log "Running ${stage}-update hooks from $hook_dir..."

    for hook in "$hook_dir"/*; do
        [ -e "$hook" ] || continue
        if [ -f "$hook" ] && [ -x "$hook" ]; then
            log "  -> Hook: $(basename "$hook")"
            set +e
            execute_guarded "Hook (${stage}): $(basename "$hook")" \
                pkexec env \
                ZNH_RUN_ID="$ZNH_RUN_ID" \
                ZYPPER_TRACE_ID="${ZYPPER_TRACE_ID:-}" \
                HOOK_STAGE="$stage" \
                "$hook" || true
            set -e
        fi
    done

    return 0
}

helper_send_webhook() {
    local title="$1" message="$2" color="$3"
    if [ -x /usr/local/bin/zypper-auto-helper ]; then
        set +e
        pkexec env \
            ZNH_RUN_ID="$ZNH_RUN_ID" \
            ZYPPER_TRACE_ID="${ZYPPER_TRACE_ID:-}" \
            WEBHOOK_TITLE="$title" \
            WEBHOOK_MESSAGE="$message" \
            WEBHOOK_COLOR="$color" \
            /usr/local/bin/zypper-auto-helper --send-webhook >/dev/null 2>&1 || true
        set -e
    fi
}

helper_generate_dashboard() {
    if [ -x /usr/local/bin/zypper-auto-helper ]; then
        set +e
        pkexec env \
            ZNH_RUN_ID="$ZNH_RUN_ID" \
            ZYPPER_TRACE_ID="${ZYPPER_TRACE_ID:-}" \
            /usr/local/bin/zypper-auto-helper --generate-dashboard >/dev/null 2>&1 || true
        set -e
    fi
}

# Enhanced install script with post-update service check
TERMINALS=("konsole" "gnome-terminal" "kitty" "alacritty" "xterm")

# Helper to detect whether system management is currently locked by
# zypp/zypper (e.g. YaST, another zypper, systemd-zypp-refresh, etc.).
ZYPP_LOCK_FILE="/run/zypp.pid"

has_zypp_lock() {
    # Prefer the zypp.pid lock file, which is what YaST/zypper use.
    if [ -f "$ZYPP_LOCK_FILE" ]; then
        local pid
        pid=$(cat "$ZYPP_LOCK_FILE" 2>/dev/null || echo "")
        if [ -n "$pid" ]; then
            if kill -0 "$pid" 2>/dev/null; then
                # Double-check that this PID really looks like a zypper/YaST
                # style process so we don't treat a reused PID as a live lock.
                local comm cmd
                comm=$(ps -p "$pid" -o comm= 2>/dev/null || echo "")
                cmd=$(ps -p "$pid" -o args= 2>/dev/null || echo "")
                if printf '%s\n%s\n' "$comm" "$cmd" | grep -qiE 'zypper|yast|y2base|zypp|packagekitd'; then
                    log "has_zypp_lock: zypp lock file $ZYPP_LOCK_FILE exists with live pid $pid (comm='$comm')"
                    return 0
                fi
                log "has_zypp_lock: ignoring non-zypp-looking process for lock file $ZYPP_LOCK_FILE (pid $pid, comm='$comm')"
            else
                log "has_zypp_lock: ignoring stale zypp lock file $ZYPP_LOCK_FILE with pid $pid"
            fi
        else
            log "has_zypp_lock: zypp lock file $ZYPP_LOCK_FILE present but empty"
        fi
    fi

    # Fallback: any obviously zypper/YaST/zypp-related process. This is a
    # broader net than just "zypper" so we also catch YaST and zypp-refresh.
    if pgrep -x zypper >/dev/null 2>&1; then
        local zpid
        zpid=$(pgrep -x zypper | head -n1 || true)
        log "has_zypp_lock: detected running zypper process pid ${zpid:-unknown}"
        return 0
    fi
    if pgrep -f -i 'yast' >/dev/null 2>&1; then
        local ypid
        ypid=$(pgrep -f -i 'yast' | head -n1 || true)
        log "has_zypp_lock: detected running YaST process pid ${ypid:-unknown}"
        return 0
    fi
    if pgrep -f 'zypp.*refresh' >/dev/null 2>&1; then
        local rpid
        rpid=$(pgrep -f 'zypp.*refresh' | head -n1 || true)
        log "has_zypp_lock: detected running zypp-refresh process pid ${rpid:-unknown}"
        return 0
    fi

    return 1
}

# Create a wrapper script that will run in the terminal
RUN_UPDATE() {
    echo ""
    echo "=========================================="
    echo "  Running System Update"
    echo "=========================================="
    echo ""
    
    # Track whether zypper failed specifically because of a lock so we can
    # show a clearer message later.
    LOCKED_DURING_UPDATE=0
    
    # Best-effort: stop the background downloader so it doesn't compete
    # for the zypper lock while we're doing an interactive update.
    log "RUN_UPDATE: stopping zypper-autodownload.service/timer to avoid lock conflicts"
    set +e
    execute_guarded "Stop background downloader (avoid lock conflicts)" pkexec systemctl stop zypper-autodownload.service zypper-autodownload.timer || true
    set -e

    # If any other zypper process is still running at this point (for example
    # an open YaST or another terminal zypper), retry a few times with
    # increasing delays (1, 2, 3, ... seconds) before giving up and telling
    # the user what to do. The number of attempts and base delay are
    # controlled from /etc/zypper-auto.conf.
    max_attempts=${LOCK_RETRY_MAX_ATTEMPTS:-10}
    base_delay=${LOCK_RETRY_INITIAL_DELAY_SECONDS:-1}
    attempt=1
    while has_zypp_lock && [ "$attempt" -le "$max_attempts" ]; do
        delay=$((base_delay * attempt))
        echo ""
        echo "System management is currently locked by another update tool (zypper/YaST/PackageKit)."
        echo "Retry $attempt/$max_attempts: waiting $delay second(s) for the other updater to finish..."
        log "RUN_UPDATE: lock still active before attempt $attempt/$max_attempts; sleeping ${delay}s"
        sleep "$delay"
        attempt=$((attempt + 1))
    done

    # After retries, if a lock is still present, show a clear message and exit
    # cleanly instead of letting pkexec/zypper print the raw lock error.
    if has_zypp_lock; then
        echo ""
        echo "System management is still locked by another update tool."
        echo "Close that other update tool (or wait for it to finish), then run"
        echo "this 'Ready to Install' action again."
        echo ""
        log "RUN_UPDATE: aborting after $max_attempts lock retries because another updater is still holding the lock"
        echo "Press Enter to close this window..."
        set +e
        if ! read -r _ </dev/tty 2>/dev/null; then
            # If /dev/tty is not available (or read fails instantly), pause briefly
            # so the user still has a chance to see the message.
            sleep 5
        fi
        set -e
        return 0
    fi

    # Pre-update hooks (best-effort)
    run_hooks "pre" || true

    # Capture package state before running the update so we can compute a
    # precise delta of what changed when the run succeeds.
    local PKG_DELTA_DIR PKG_PRE_FILE PKG_POST_FILE DELTA_FILE
    PKG_DELTA_DIR="$HOME/.local/share/zypper-notify/pkg-deltas"
    mkdir -p "$PKG_DELTA_DIR" 2>/dev/null || true
    PKG_PRE_FILE="${PKG_DELTA_DIR}/pkg-pre-$$.txt"
    PKG_POST_FILE="${PKG_DELTA_DIR}/pkg-post-$$.txt"
    DELTA_FILE="${PKG_DELTA_DIR}/update-delta-$(date +%Y%m%d-%H%M%S).log"

    log "RUN_UPDATE: Capturing pre-update package state into ${PKG_PRE_FILE}..."
    if ! execute_guarded "Capture pre-update package snapshot" bash -lc "rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}\\n' | sort >\"${PKG_PRE_FILE}\""; then
        log "RUN_UPDATE: WARNING: failed to capture pre-update package snapshot (see log)"
    fi

    log "RUN_UPDATE: starting pkexec zypper dup..."
    # Run the update, capturing stderr so we can detect a lock even if it
    # appears after our pre-check.
    set +e
    ZYPPER_ERR_FILE=$(mktemp)
    pkexec zypper dup 2> >(tee "$ZYPPER_ERR_FILE" | sed -E '/System management is locked/d;/Close this application before trying again/d' >&2)
    rc=$?
    set -e

    if [ "$rc" -eq 0 ]; then
        # Post-update hooks (best-effort)
        run_hooks "post" || true
    fi

    # Auto-snapshot system state on any non-zero exit so diagnostics have
    # rich context without requiring the user to manually open the debug menu.
    if [ "$rc" -ne 0 ]; then
        log "RUN_UPDATE: Failure detected (rc=$rc). Triggering auto-snapshot via helper..."
        echo ""
        echo "⚠️  Update failed. Capturing system state for diagnostics..."

        # On failure, print the log destination clearly so terminals can
        # hyperlink it (file://...). This makes it easy for users to click
        # straight into the folder and attach the right logs to bug reports.
        echo ""
        echo "Logs saved to:"
        echo "  - Ready-to-Install log: ${LOG_FILE}"
        echo "  - Ready-to-Install log folder: ${LOG_DIR}"
        echo "    Clickable: file://${LOG_DIR}"
        echo "  - System helper logs (root): /var/log/zypper-auto"
        echo "    Clickable: file:///var/log/zypper-auto"
        echo ""
        echo "Tip: you can also open the diagnostics folder via: zypper-auto-helper --show-logs"

        set +e
        # Best-effort: propagate correlation IDs into the helper snapshot.
        sudo env ZYPPER_TRACE_ID="${ZYPPER_TRACE_ID:-}" ZNH_RUN_ID="${ZNH_RUN_ID:-}" \
            /usr/local/bin/zypper-auto-helper --snapshot-state >/dev/null 2>&1 &
        set -e
        log "RUN_UPDATE: Auto-snapshot helper invoked in background."
    fi

    if [ "$rc" -ne 0 ] && grep -q "System management is locked" "$ZYPPER_ERR_FILE" 2>/dev/null; then
        LOCKED_DURING_UPDATE=1
    fi
    rm -f "$ZYPPER_ERR_FILE"

    # When the update completes successfully, capture a post-update snapshot
    # and compute a delta file describing exactly which packages changed.
    if [ "$rc" -eq 0 ]; then
        log "RUN_UPDATE: Capturing post-update package state into ${PKG_POST_FILE}..."
        if execute_guarded "Capture post-update package snapshot" bash -lc "rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}\\n' | sort >\"${PKG_POST_FILE}\""; then
            log "RUN_UPDATE: Computing package delta into ${DELTA_FILE}..."
            execute_guarded "Write package delta file" bash -lc "{
                echo '=== Package Changes (post - pre) ==='
                if [ -s \"${PKG_PRE_FILE}\" ] && [ -s \"${PKG_POST_FILE}\" ]; then
                    comm -13 \"${PKG_PRE_FILE}\" \"${PKG_POST_FILE}\" || true
                else
                    echo '(one or both snapshot files were empty; delta may be incomplete)'
                fi
            } >\"${DELTA_FILE}\"" || true
            local change_count
            change_count=$(wc -l <"${DELTA_FILE}" 2>/dev/null || echo 0)
            log "RUN_UPDATE: Delta calculation complete; ${change_count} lines written to ${DELTA_FILE}"
        else
            log "RUN_UPDATE: WARNING: failed to capture post-update package snapshot (see log); skipping delta"
        fi
        rm -f "${PKG_PRE_FILE}" "${PKG_POST_FILE}" 2>/dev/null || true
    fi

    if [ "$rc" -eq 0 ]; then
        UPDATE_SUCCESS=true
        log "RUN_UPDATE: pkexec zypper dup completed successfully (rc=$rc)"
        helper_send_webhook "Zypper update successful" "Interactive update completed successfully." "65280"
    else
        UPDATE_SUCCESS=false
        if [ "$LOCKED_DURING_UPDATE" -eq 1 ]; then
            log "RUN_UPDATE: pkexec zypper dup failed due to existing zypper lock (rc=$rc)"
            helper_send_webhook "Zypper update blocked (lock)" "Interactive update could not run because system management was locked (rc=$rc)." "16760576"
        else
            log "RUN_UPDATE: pkexec zypper dup FAILED (rc=$rc)"
            helper_send_webhook "Zypper update FAILED" "Interactive update failed (rc=$rc). See run-install.log for details." "16711680"
        fi
    fi

    # Refresh dashboard after the attempt (best-effort)
    helper_generate_dashboard
    
    echo ""
    echo "=========================================="
    echo "  Update Complete - Post-Update Check"
    echo "=========================================="
    echo ""
    
    # Post-update integrations (Flatpak, Snap, Soar, Homebrew) are controlled
    # by flags in /etc/zypper-auto.conf.
    echo "=========================================="
    echo "  Flatpak Updates"
    echo "=========================================="
    echo ""
    
    if [[ "${ENABLE_FLATPAK_UPDATES,,}" == "true" ]]; then
        if command -v flatpak >/dev/null 2>&1; then
            if pkexec flatpak update -y; then
                echo "✅ Flatpak updates completed."
            else
                echo "⚠️  Flatpak update failed (continuing)."
            fi
        else
            echo "⚠️  Flatpak is not installed - skipping Flatpak updates."
            echo "   To install: sudo zypper install flatpak"
        fi
    else
        echo "ℹ️  Flatpak updates are disabled in /etc/zypper-auto.conf (ENABLE_FLATPAK_UPDATES=false)."
    fi

    echo ""
    echo "=========================================="
    echo "  Snap Updates"
    echo "=========================================="
    echo ""

    if [[ "${ENABLE_SNAP_UPDATES,,}" == "true" ]]; then
        if command -v snap >/dev/null 2>&1; then
            if pkexec snap refresh; then
                echo "✅ Snap updates completed."
            else
                echo "⚠️  Snap refresh failed (continuing)."
            fi
        else
            echo "⚠️  Snapd is not installed - skipping Snap updates."
            echo "   To install: sudo zypper install snapd"
            echo "   Then enable: sudo systemctl enable --now snapd"
        fi
    else
        echo "ℹ️  Snap updates are disabled in /etc/zypper-auto.conf (ENABLE_SNAP_UPDATES=false)."
    fi

    echo ""
    echo "=========================================="
    echo "  Soar (stable) Update & Sync"
    echo "=========================================="
    echo ""

    # Detect Soar in common per-user locations so we don't offer to install
    # it when it's already present but not yet on PATH for non-interactive
    # shells.
    SOAR_BIN=""
    if command -v soar >/dev/null 2>&1; then
        SOAR_BIN=$(command -v soar)
    elif [ -x "$HOME/.local/bin/soar" ]; then
        SOAR_BIN="$HOME/.local/bin/soar"
    elif [ -d "$HOME/pkgforge" ] && \
         find "$HOME/pkgforge" -maxdepth 1 -type f -name 'soar*' -perm -u+x 2>/dev/null | grep -q .; then
        SOAR_BIN=$(find "$HOME/pkgforge" -maxdepth 1 -type f -name 'soar*' -perm -u+x 2>/dev/null | head -n1)
    fi

    if [[ "${ENABLE_SOAR_UPDATES,,}" != "true" ]]; then
        echo "ℹ️  Soar updates are disabled in /etc/zypper-auto.conf (ENABLE_SOAR_UPDATES=false)."
    elif [ -n "$SOAR_BIN" ]; then
        # First, check if a newer *stable* Soar release exists on GitHub.
        # We compare the local "soar --version" against
        # https://api.github.com/repos/pkgforge/soar/releases/latest (stable only).
        if command -v curl >/dev/null 2>&1; then
            echo "Checking for newer stable Soar release from GitHub..."

            LOCAL_VER_RAW=$("$SOAR_BIN" --version 2>/dev/null | head -n1)
            LOCAL_VER=$(echo "$LOCAL_VER_RAW" | grep -oE 'v?[0-9]+(\.[0-9]+)*' | head -n1 || true)
            LOCAL_BASE=${LOCAL_VER#v}

            REMOTE_JSON=$(curl -fsSL "https://api.github.com/repos/pkgforge/soar/releases/latest" 2>/dev/null || true)
            REMOTE_VER=$(printf '%s\n' "$REMOTE_JSON" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name" *: *"([^"]+)".*/\1/' || true)
            REMOTE_BASE=${REMOTE_VER#v}

            if [ -n "$LOCAL_BASE" ] && [ -n "$REMOTE_BASE" ]; then
                LATEST=$(printf '%s\n%s\n' "$LOCAL_BASE" "$REMOTE_BASE" | sort -V | tail -n1)
                if [ "$LATEST" = "$REMOTE_BASE" ] && [ "$LOCAL_BASE" != "$REMOTE_BASE" ]; then
                    echo "New stable Soar available ($LOCAL_VER -> $REMOTE_VER), updating..."
                    if curl -fsSL "https://raw.githubusercontent.com/pkgforge/soar/main/install.sh" | sh; then
                        echo "✅ Soar updated to latest stable release."
                    else
                        echo "⚠️  Failed to update Soar from GitHub (continuing with existing version)."
                    fi
                else
                    echo "Soar is already up to date (local: ${LOCAL_VER:-unknown}, latest stable: ${REMOTE_VER:-unknown})."
                fi
            else
                echo "Could not determine Soar versions; running installer to ensure latest stable."
                if curl -fsSL "https://raw.githubusercontent.com/pkgforge/soar/main/install.sh" | sh; then
                    echo "✅ Soar updated to latest stable release."
                else
                    echo "⚠️  Failed to update Soar from GitHub (continuing with existing version)."
                fi
            fi
        else
            echo "⚠️  curl is not installed; skipping automatic Soar update from GitHub."
            echo "    You can update Soar manually from: https://github.com/pkgforge/soar/releases"
            if [ -x /usr/local/bin/zypper-auto-helper ]; then
                echo "    Or via helper: zypper-auto-helper --soar"
            fi
        fi

        # Then run the usual metadata sync.
        if "$SOAR_BIN" sync; then
            echo "✅ Soar sync completed."
            # Optionally refresh Soar-managed apps that support "soar update".
            if "$SOAR_BIN" update; then
                echo "✅ Soar update completed."
            else
                echo "⚠️  Soar update failed (continuing)."
            fi
        else
            echo "⚠️  Soar sync failed (continuing)."
        fi
    else
        echo "ℹ️  Soar is not installed."
        if command -v curl >/dev/null 2>&1; then
            echo "    Soar can be installed from the official GitHub installer."
            read -rp "    Do you want to install Soar (stable) from GitHub now? [y/N]: " SOAR_INSTALL_REPLY
            if [[ "$SOAR_INSTALL_REPLY" =~ ^[Yy]$ ]]; then
                echo "Installing Soar from GitHub..."
                if curl -fsSL "https://raw.githubusercontent.com/pkgforge/soar/main/install.sh" | sh; then
                    echo "✅ Soar installed successfully."
                    # Optionally run initial sync if the binary is now available
                    if command -v soar >/dev/null 2>&1; then
                        if soar sync; then
                            echo "✅ Soar sync completed."
                        else
                            echo "⚠️  Soar sync failed after install (continuing)."
                        fi
                    fi
                else
                    echo "⚠️  Failed to install Soar from GitHub. You can install it manually from:"
                    echo "    https://github.com/pkgforge/soar/releases"
                fi
            else
                echo "Skipping Soar installation. You can install it later from:"
                echo "    https://github.com/pkgforge/soar/releases"
                if [ -x /usr/local/bin/zypper-auto-helper ]; then
                    echo "    Or via helper: zypper-auto-helper --soar"
                fi
            fi
        else
            echo "⚠️  curl is not installed; cannot automatically install Soar."
            echo "    Please install curl or install Soar manually from: https://github.com/pkgforge/soar/releases"
            if [ -x /usr/local/bin/zypper-auto-helper ]; then
                echo "    Or via helper: zypper-auto-helper --soar"
            fi
        fi
    fi

    echo ""

    echo "=========================================="
    echo "  Homebrew (brew) Updates (optional)"
    echo "=========================================="
    echo ""

    if [[ "${ENABLE_BREW_UPDATES,,}" != "true" ]]; then
        echo "ℹ️  Homebrew updates are disabled in /etc/zypper-auto.conf (ENABLE_BREW_UPDATES=false)."
        echo "    You can still run 'brew update' / 'brew upgrade' manually."
        echo ""
        return
    fi

    # Try to detect Homebrew in PATH or the default Linuxbrew prefix
    if command -v brew >/dev/null 2>&1 || [ -x "/home/linuxbrew/.linuxbrew/bin/brew" ]; then
        # Normalise brew command path
        if command -v brew >/dev/null 2>&1; then
            BREW_BIN="brew"
        else
            BREW_BIN="/home/linuxbrew/.linuxbrew/bin/brew"
        fi

        echo "Checking for Homebrew updates from GitHub (brew update)..."
        if ! $BREW_BIN update; then
            echo "⚠️  Homebrew 'brew update' failed (continuing without brew upgrade)."
        else
            # After syncing with GitHub, see if anything needs upgrading
            OUTDATED=$($BREW_BIN outdated --quiet 2>/dev/null || true)
            OUTDATED_COUNT=$(printf '%s\n' "$OUTDATED" | sed '/^$/d' | wc -l | tr -d ' ')

            if [ "${OUTDATED_COUNT:-0}" -eq 0 ]; then
                echo "Homebrew is already up to date (no formulae to upgrade)."
            else
                echo "Homebrew has ${OUTDATED_COUNT} outdated formulae; running 'brew upgrade'..."
                if $BREW_BIN upgrade; then
                    echo "✅ Homebrew upgrade completed (upgraded ${OUTDATED_COUNT} formulae)."
                else
                    echo "⚠️  Homebrew 'brew upgrade' failed (continuing)."
                fi
            fi
        fi
    else
        echo "ℹ️  Homebrew (brew) is not installed - skipping brew update/upgrade."
        if [ -x /usr/local/bin/zypper-auto-helper ]; then
            echo "    To install via helper: zypper-auto-helper --brew"
        fi
    fi

    echo ""
    echo "=========================================="
    echo "  Python (pipx) Updates (optional)"
    echo "=========================================="
    echo ""

    if [[ "${ENABLE_PIPX_UPDATES,,}" != "true" ]]; then
        echo "ℹ️  pipx updates are disabled in /etc/zypper-auto.conf (ENABLE_PIPX_UPDATES=false)."
        echo "    You can still manage Python CLI tools manually with pipx."
        echo ""
    else
        if command -v pipx >/dev/null 2>&1; then
            echo "Upgrading all pipx-managed Python command-line tools (pipx upgrade-all)..."
            if pipx upgrade-all; then
                echo "✅ pipx upgrade-all completed."
            else
                echo "⚠️  pipx upgrade-all failed (continuing)."
            fi
        else
            echo "ℹ️  pipx is not installed - skipping Python CLI (pipx) updates."
            echo "    Recommended: zypper-auto-helper --pip-package (run without sudo)"
        fi
    fi

    echo ""
    echo "Checking which services need to be restarted..."
    echo ""
    
    # Run zypper ps -s and capture output (even if dup had errors)
    ZYPPER_PS_OUTPUT=$(pkexec zypper ps -s 2>/dev/null || true)
    echo "$ZYPPER_PS_OUTPUT"
    
    # Check if there are any running processes in the output
    if echo "$ZYPPER_PS_OUTPUT" | grep -q "running processes"; then
        echo ""
        echo "ℹ️  Services listed above are using old library versions."
        echo ""
        echo "What this means:"
        echo "  • These services/processes are still running old code in memory"
        echo "  • They should be restarted to use the updated libraries"
        echo ""
        echo "Options:"
        echo "  1. Restart individual services: systemctl restart <service>"
        echo "  2. Reboot your system (recommended for kernel/system updates)"
        echo ""
    else
        echo "✅ No services require restart. You're all set!"
        echo ""
    fi

    if [ "$UPDATE_SUCCESS" = false ]; then
        if [ "$LOCKED_DURING_UPDATE" -eq 1 ]; then
            echo "⚠  Zypper could not run because system management is locked by another tool. No system packages were changed."
        else
            echo "⚠️  Zypper dup reported errors (see above), but Flatpak/Snap updates were attempted."
        fi
        echo ""
    fi

    log "RUN_UPDATE: finished (UPDATE_SUCCESS=$UPDATE_SUCCESS)"

    # After an interactive update, clear cached downloader state so the
    # next background run recomputes everything from scratch. This avoids
    # stale "Ready to install" notifications after you just installed updates.
    log "RUN_UPDATE: clearing downloader cache files after interactive run"
    set +e
    execute_guarded "Clear downloader cache files (pkexec)" pkexec rm -f /var/log/zypper-auto/dry-run-last.txt /var/log/zypper-auto/download-status.txt || \
        execute_guarded "Clear downloader cache files (fallback rm)" rm -f /var/log/zypper-auto/dry-run-last.txt /var/log/zypper-auto/download-status.txt || true

    # Triggered maintenance: request zypper cache cleanup only after a
    # successful interactive update (no independent "clean nothing" scans).
    if [ "${UPDATE_SUCCESS:-false}" = true ]; then
        log "RUN_UPDATE: requesting post-update zypper cache cleanup"
        pkexec touch /var/log/zypper-auto/cleanup-needed.stamp >/dev/null 2>&1 || true
        pkexec systemctl start zypper-cache-cleanup.service >/dev/null 2>&1 || true
    fi

    set -e

    # Keep the terminal open so the user can read the output, even if stdin
    # is not a normal TTY or "read" would normally fail under set -e.
    echo "Press Enter to close this window..."
    set +e
    if ! read -r _ </dev/tty 2>/dev/null; then
        # If /dev/tty is not available (or read fails instantly), pause briefly
        # so the user still has a chance to see the final output.
        sleep 5
    fi
    set -e
}

# Self-test mode: validate that correlation IDs and logging work end-to-end
# without actually running any updates.
if [[ "${1:-}" == "--selftest" ]]; then
    log "Selftest mode (--selftest) invoked; not performing updates"
    log "Selftest: ZNH_RUN_ID=${ZNH_RUN_ID}"
    log "Selftest: ZYPPER_TRACE_ID=${ZYPPER_TRACE_ID:-}"
    echo "zypper-run-install selftest OK (RUN=${ZNH_RUN_ID}${ZYPPER_TRACE_ID:+, TID=${ZYPPER_TRACE_ID}})"
    exit 0
fi

# If invoked with --inner, run the update directly in this process instead of
# spawning another terminal. This avoids relying on exported shell functions
# inside a separate konsole/gnome-terminal bash.
if [[ "${1:-}" == "--inner" ]]; then
    log "Inner mode (--inner) invoked; running RUN_UPDATE directly"
    shift || true
    RUN_UPDATE
    exit $?
fi

# Export the function (harmless, but not relied upon anymore)
export -f RUN_UPDATE || true

# Run the update in a terminal
log "Terminal selection: candidates: ${TERMINALS[*]}"
for term in "${TERMINALS[@]}"; do
    log "Checking terminal: $term"
    if command -v "$term" >/dev/null 2>&1; then
        log "Using terminal '$term' to run inner helper (--inner)"
        case "$term" in
            konsole)
                set +e
                konsole -e bash -lc '"$HOME"/.local/bin/zypper-run-install --inner'
                rc=$?
                set -e
                log "konsole finished with exit code $rc"
                exit 0
                ;;
            gnome-terminal)
                set +e
                gnome-terminal -- bash -lc '"$HOME"/.local/bin/zypper-run-install --inner'
                rc=$?
                set -e
                log "gnome-terminal finished with exit code $rc"
                exit 0
                ;;
            kitty|alacritty|xterm)
                set +e
                "$term" -e bash -lc '"$HOME"/.local/bin/zypper-run-install --inner'
                rc=$?
                set -e
                log "${term} finished with exit code $rc"
                exit 0
                ;;
        esac
    fi
done

log "No GUI terminal found; falling back to running RUN_UPDATE directly"
# Fallback: run directly if no terminal found
RUN_UPDATE
EOF

chown "$SUDO_USER:$SUDO_USER" "${INSTALL_SCRIPT_PATH}"
chmod +x "${INSTALL_SCRIPT_PATH}"
log_success "Install helper script created and made executable"

# --- 11b. Create View Changes Script ---
log_info ">>> Creating (user) view changes script: ${VIEW_CHANGES_SCRIPT_PATH}"
update_status "Creating view changes helper script..."
log_debug "Writing view changes script to: ${VIEW_CHANGES_SCRIPT_PATH}"
write_atomic "${VIEW_CHANGES_SCRIPT_PATH}" << 'EOF'
#!/usr/bin/env bash

# Script to view detailed package changes
# Logging for debugging
LOG_FILE="$HOME/.local/share/zypper-notify/view-changes.log"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] View changes script started" >> "$LOG_FILE"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] DISPLAY=$DISPLAY" >> "$LOG_FILE"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] USER=$USER" >> "$LOG_FILE"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] PWD=$PWD" >> "$LOG_FILE"

# Ensure a usable GUI environment when launched from systemd --user
# Prefer existing vars; only set safe defaults if missing
if [ -z "${XDG_RUNTIME_DIR:-}" ]; then
    export XDG_RUNTIME_DIR="/run/user/$(id -u)"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] XDG_RUNTIME_DIR was empty, set to $XDG_RUNTIME_DIR" >> "$LOG_FILE"
fi
if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]; then
    export DBUS_SESSION_BUS_ADDRESS="unix:path=${XDG_RUNTIME_DIR}/bus"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] DBUS_SESSION_BUS_ADDRESS was empty, set to $DBUS_SESSION_BUS_ADDRESS" >> "$LOG_FILE"
fi
# On Wayland, WAYLAND_DISPLAY is usually set by the session. If both DISPLAY and WAYLAND_DISPLAY
# are empty, fall back to DISPLAY=:0 which works for X11
if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
    export DISPLAY=:0
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Neither DISPLAY nor WAYLAND_DISPLAY set; defaulted DISPLAY to :0" >> "$LOG_FILE"
fi

# Create a temporary script file for the terminal to execute
TMP_SCRIPT=$(mktemp /tmp/zypper-view-changes.XXXXXX.sh)
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Created temp script: $TMP_SCRIPT" >> "$LOG_FILE"

cat > "$TMP_SCRIPT" << 'INNEREOF'
#!/usr/bin/env bash
echo ""
echo "=========================================="
echo "  Package Update Details"
echo "=========================================="
echo ""
echo "Fetching update information..."
echo ""

# Run zypper with details
if pkexec zypper --non-interactive dup --dry-run --details; then
    echo ""
    echo "=========================================="
    echo ""
    echo "This is a preview of what will be updated."
    echo "Click 'Install Now' in the notification to proceed."
    echo ""
else
    echo "⚠️  Could not fetch update details."
    echo ""
fi

echo "Press Enter to close this window..."
read -r

# Clean up temporary script
rm -f "$0"
INNEREOF

chmod +x "$TMP_SCRIPT"

# Try terminals in order  
if command -v konsole >/dev/null 2>&1; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Launching konsole..." >> "$LOG_FILE"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Command: konsole --noclose -e bash $TMP_SCRIPT" >> "$LOG_FILE"
    nohup konsole --noclose -e bash "$TMP_SCRIPT" >> "$LOG_FILE" 2>&1 &
    KONSOLE_PID=$!
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Konsole PID: $KONSOLE_PID" >> "$LOG_FILE"
    sleep 0.5
    if ps -p $KONSOLE_PID > /dev/null 2>&1; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Konsole is running" >> "$LOG_FILE"
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: Konsole exited immediately!" >> "$LOG_FILE"
    fi
elif command -v gnome-terminal >/dev/null 2>&1; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Launching gnome-terminal..." >> "$LOG_FILE"
    gnome-terminal -- "$TMP_SCRIPT" >> "$LOG_FILE" 2>&1 &
    disown
elif command -v kitty >/dev/null 2>&1; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Launching kitty..." >> "$LOG_FILE"
    kitty -e "$TMP_SCRIPT" >> "$LOG_FILE" 2>&1 &
    disown
elif command -v alacritty >/dev/null 2>&1; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Launching alacritty..." >> "$LOG_FILE"
    alacritty -e "$TMP_SCRIPT" >> "$LOG_FILE" 2>&1 &
    disown
elif command -v xterm >/dev/null 2>&1; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Launching xterm..." >> "$LOG_FILE"
    xterm -e "$TMP_SCRIPT" >> "$LOG_FILE" 2>&1 &
    disown
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] No terminal found, running directly" >> "$LOG_FILE"
    "$TMP_SCRIPT" >> "$LOG_FILE" 2>&1
fi
EOF

chown "$SUDO_USER:$SUDO_USER" "${VIEW_CHANGES_SCRIPT_PATH}"
chmod +x "${VIEW_CHANGES_SCRIPT_PATH}"
log_success "View changes helper script created and made executable"

# --- 11c. Create Soar Install Helper (user) ---
SOAR_INSTALL_HELPER_PATH="$USER_BIN_DIR/zypper-soar-install-helper"
log_info ">>> Creating (user) Soar install helper: ${SOAR_INSTALL_HELPER_PATH}"
update_status "Creating Soar install helper script..."
log_debug "Writing Soar helper script to: ${SOAR_INSTALL_HELPER_PATH}"
write_atomic "${SOAR_INSTALL_HELPER_PATH}" << 'EOF'
#!/usr/bin/env python3
"""
Small helper that shows a notification with an "Install Soar" button.
When clicked, it opens a terminal and runs the official Soar install
command:

  curl -fsSL "https://raw.githubusercontent.com/pkgforge/soar/main/install.sh" | sh
"""

import os
import subprocess
import sys
import traceback
import shutil
import time

try:
    import gi
    gi.require_version("Notify", "0.7")
    from gi.repository import Notify, GLib
except Exception:
    # If PyGObject is not available for some reason, just exit quietly.
    sys.exit(0)


# Best-effort fixups for environment when launched from systemd --user or
# via sudo -u from the installer, so that terminals can attach to the
# correct user session.
if "XDG_RUNTIME_DIR" not in os.environ or not os.environ["XDG_RUNTIME_DIR"]:
    os.environ["XDG_RUNTIME_DIR"] = f"/run/user/{os.getuid()}"
if "DBUS_SESSION_BUS_ADDRESS" not in os.environ or not os.environ["DBUS_SESSION_BUS_ADDRESS"]:
    os.environ["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={os.environ['XDG_RUNTIME_DIR']}/bus"
if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
    # Fallback for X11-only sessions
    os.environ["DISPLAY"] = ":0"
if not os.environ.get("PATH"):
    # Minimal sane PATH so we can discover common terminals
    os.environ["PATH"] = "/usr/local/bin:/usr/bin:/bin"


LOG_PATH = os.path.expanduser("~/.local/share/zypper-notify/soar-install-helper.log")
loop = None  # type: ignore[assignment]


def _log(message: str) -> None:
    """Best-effort logging to a user log file for debugging."""
    try:
        log_dir = os.path.dirname(LOG_PATH)
        os.makedirs(log_dir, exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
    except Exception:
        # Never let logging failures break the helper
        pass


def _open_terminal_with_soar_install() -> None:
    # Use the main helper CLI so behavior is consistent with running
    #   sudo zypper-auto-helper --soar
    # from a regular terminal.
    cmd = (
        "sudo zypper-auto-helper --soar; "
        "echo; echo 'Press Enter to close this window...'; read -r"
    )
    terminals = ["konsole", "gnome-terminal", "kitty", "alacritty", "xterm"]

    _log("Install action triggered; attempting to open terminal for Soar install")
    _log(f"Environment DISPLAY={os.environ.get('DISPLAY')} WAYLAND_DISPLAY={os.environ.get('WAYLAND_DISPLAY')} DBUS_SESSION_BUS_ADDRESS={os.environ.get('DBUS_SESSION_BUS_ADDRESS')}")
    _log(f"PATH={os.environ.get('PATH')}")

    for term in terminals:
        term_path = shutil.which(term)
        _log(f"Checking terminal '{term}': path={term_path}")
        # Use shutil.which instead of external 'which' so we don't depend on
        # that binary existing in a restricted PATH.
        if term_path is not None:
            try:
                _log(f"Trying to launch terminal '{term}' with command: {cmd}")
                if term == "konsole":
                    subprocess.Popen([term, "-e", "bash", "-lc", cmd])
                elif term == "gnome-terminal":
                    subprocess.Popen([term, "--", "bash", "-lc", cmd])
                else:
                    subprocess.Popen([term, "-e", "bash", "-lc", cmd])
                _log(f"Successfully launched terminal '{term}'")
                return
            except Exception as e:
                _log(f"Failed to launch terminal '{term}': {e}")
                # If launching this terminal fails for any reason, try the next one.
                continue

    # Fallback: run in a plain shell if no terminal was detected or all
    # launches failed. This at least ensures the installer runs, even if it
    # isn't in a separate GUI terminal.
    _log("No GUI terminal found or all launches failed; falling back to 'bash -lc'")
    try:
        subprocess.Popen(["bash", "-lc", cmd])
        _log("Started fallback 'bash -lc' successfully")
    except Exception as e:
        _log(f"Failed to start fallback 'bash -lc': {e}")



def _on_action(notification, action_id, user_data):
    global loop
    _log(f"Notification action received: {action_id}")
    if action_id == "install":
        _open_terminal_with_soar_install()
    try:
        notification.close()
    except Exception as e:
        _log(f"Error while closing notification: {e}")
    if loop is not None:
        try:
            loop.quit()
        except Exception as e:
            _log(f"Error while quitting main loop: {e}")



def main() -> None:
    global loop
    try:
        _log("Soar install helper started")
        _log(f"Initial env DISPLAY={os.environ.get('DISPLAY')} WAYLAND_DISPLAY={os.environ.get('WAYLAND_DISPLAY')} DBUS_SESSION_BUS_ADDRESS={os.environ.get('DBUS_SESSION_BUS_ADDRESS')}")
        _log(f"Initial PATH={os.environ.get('PATH')}")

        Notify.init("zypper-auto-helper")
        body = (
            "Soar (optional CLI helper) is not installed.\n\n"
            "Click 'Install Soar' to open a terminal and run the official "
            "install script, or dismiss this notification to skip."
        )
        n = Notify.Notification.new(
            "Zypper Auto-Helper: Install Soar",
            body,
            "dialog-information",
        )
        n.set_timeout(0)  # persistent until action or close
        n.add_action("install", "Install Soar", _on_action, None)

        loop = GLib.MainLoop()
        n.connect("closed", lambda *args: (_log("Notification closed"), loop.quit()))
        n.show()
        _log("Notification shown; entering GLib main loop")
        try:
            loop.run()
        finally:
            _log("Exiting GLib main loop; calling Notify.uninit()")
            Notify.uninit()
    except Exception:
        tb = traceback.format_exc()
        _log(f"Unhandled exception in helper: {tb}")
        try:
            Notify.uninit()
        except Exception as e:
            _log(f"Error during Notify.uninit after exception: {e}")
if __name__ == "__main__":
    main()
EOF

chown "$SUDO_USER:$SUDO_USER" "${SOAR_INSTALL_HELPER_PATH}"
chmod +x "${SOAR_INSTALL_HELPER_PATH}"
log_success "Soar install helper script created and made executable"

# --- 11d. Install script itself as a command ---
log_info ">>> Installing zypper-auto-helper command..."
update_status "Installing command-line interface..."

COMMAND_PATH="/usr/local/bin/zypper-auto-helper"
INSTALLER_SCRIPT_PATH="$0"

# Get the absolute path of the installer script
if [ ! -f "$INSTALLER_SCRIPT_PATH" ]; then
    INSTALLER_SCRIPT_PATH="$(realpath "$0")"
fi

log_debug "Installer script path: $INSTALLER_SCRIPT_PATH"
log_debug "Command installation path: $COMMAND_PATH"

# Copy the installer script to /usr/local/bin
if execute_guarded "Install command to ${COMMAND_PATH}" cp "$INSTALLER_SCRIPT_PATH" "$COMMAND_PATH"; then
    # NOTE: Because this script uses umask 077, a plain 'chmod +x' would
    # result in 700 (root-only). We want the command to be runnable by the
    # desktop user (wrappers may still use sudo for privileged operations).
    execute_guarded "Set ${COMMAND_PATH} permissions (755)" chmod 755 "$COMMAND_PATH"
    log_success "Command installed: zypper-auto-helper"
    log_info "You can now run: zypper-auto-helper --help"

    # Polkit action (pkexec UX polish for desktop shortcut actions)
    __znh_install_polkit_policy || log_warn "Failed to install Polkit policy (non-fatal)"
else
    log_error "Warning: Could not install command (non-fatal)"
fi

# --- 11e. Install dashboard settings API (localhost) ---
# This provides a small API for the HTML dashboard to read/write
# /etc/zypper-auto.conf settings via localhost.
DASH_API_BIN="/usr/local/bin/zypper-auto-dashboard-api"
DASH_API_UNIT="/etc/systemd/system/zypper-auto-dashboard-api.service"
DASH_API_TOKEN_DIR="/var/lib/zypper-auto"
DASH_API_TOKEN_FILE="${DASH_API_TOKEN_DIR}/dashboard-api.token"

log_info ">>> Installing dashboard settings API (localhost)..."
update_status "Installing dashboard settings API..."

# Install API server script
if write_atomic "${DASH_API_BIN}" <<'PYEOF'
#!/usr/bin/env python3
import argparse
import json
import os
import re
import secrets
import socketserver
import subprocess
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

def _load_schema(schema_file: str) -> dict:
    with open(schema_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    schema = data.get("schema") or {}
    if not isinstance(schema, dict):
        raise ValueError("schema must be an object")
    return schema


def _build_defaults(schema: dict) -> dict:
    out = {}
    for k, meta in (schema or {}).items():
        if not isinstance(meta, dict):
            continue
        d = meta.get("default")
        if d is None:
            continue
        out[k] = str(d)
    return out


DEFAULTS = {}
SCHEMA = {}

MANAGED_BEGIN = "# BEGIN ZNH DASHBOARD MANAGED SETTINGS"
MANAGED_END = "# END ZNH DASHBOARD MANAGED SETTINGS"


def _load_token(token_file: str) -> str:
    with open(token_file, "r", encoding="utf-8") as f:
        return f.read().strip()


def _parse_conf_text(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # basic KEY=VALUE (value may be quoted)
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
        if not m:
            continue
        k = m.group(1)
        v = m.group(2).strip()
        if len(v) >= 2 and ((v[0] == '"' and v[-1] == '"') or (v[0] == "'" and v[-1] == "'")):
            v = v[1:-1]
        out[k] = v
    return out


def _validate(cfg: dict) -> tuple[dict, list[str], list[str]]:
    warnings = []
    invalid = []
    eff = dict(DEFAULTS)
    eff.update({k: str(v) for k, v in cfg.items() if k in SCHEMA})

    def set_default(k: str, why: str):
        invalid.append(k)
        warnings.append(f"Invalid {k}='{eff.get(k)}': {why}. Using default {SCHEMA[k].get('default')}.")
        eff[k] = SCHEMA[k].get("default")

    for k, meta in SCHEMA.items():
        v = eff.get(k, meta.get("default"))
        t = meta["type"]
        if t == "bool":
            vl = str(v).lower()
            if vl not in ("true", "false"):
                set_default(k, "must be true/false")
            else:
                eff[k] = vl
        elif t == "interval":
            if str(v) not in meta.get("allowed", []):
                set_default(k, f"allowed: {','.join(meta.get('allowed', []))}")
        elif t == "enum":
            if str(v) not in meta.get("allowed", []):
                set_default(k, f"allowed: {','.join(meta.get('allowed', []))}")
        elif t == "int":
            s = str(v).strip()
            if not re.fullmatch(r"[0-9]+", s or ""):
                set_default(k, "must be a non-negative integer")
            else:
                n = int(s)
                mn = int(meta.get("min", 0))
                mx = meta.get("max", None)
                if n < mn:
                    set_default(k, f"minimum is {mn}")
                elif mx is not None and n > int(mx):
                    set_default(k, f"maximum is {int(mx)}")
                else:
                    eff[k] = str(n)
        elif t == "string":
            s = str(v)
            s = s.replace("\r", "").strip()
            max_len = int(meta.get("max_len", 200))
            if len(s) == 0:
                eff[k] = meta.get("default", "")
            elif len(s) > max_len:
                set_default(k, f"max length is {max_len}")
            else:
                eff[k] = s
        else:
            # unknown type -> fall back
            set_default(k, "unknown type")

    return eff, warnings, invalid


def _read_conf(conf_path: str) -> tuple[dict, list[str], list[str]]:
    try:
        with open(conf_path, "r", encoding="utf-8") as f:
            txt = f.read()
    except FileNotFoundError:
        txt = ""
    raw = _parse_conf_text(txt)
    eff, warnings, invalid = _validate(raw)
    return eff, warnings, invalid


def _write_managed_block(conf_path: str, values: dict) -> None:
    try:
        with open(conf_path, "r", encoding="utf-8") as f:
            txt = f.read()
    except FileNotFoundError:
        txt = ""

    # Remove existing managed block
    if MANAGED_BEGIN in txt and MANAGED_END in txt:
        pre = txt.split(MANAGED_BEGIN, 1)[0]
        post = txt.split(MANAGED_END, 1)[1]
        txt = pre.rstrip() + "\n\n" + post.lstrip()

    lines = [MANAGED_BEGIN]
    for k in sorted(SCHEMA.keys()):
        v = values.get(k, SCHEMA[k].get("default"))
        # Quote everything for safety
        lines.append(f'{k}="{str(v)}"')
    lines.append(MANAGED_END)

    new_txt = txt.rstrip() + "\n\n" + "\n".join(lines) + "\n"

    # NOTE: We intentionally write directly to conf_path (truncate + rewrite)
    # instead of using os.replace(temp, conf_path) because the systemd unit runs
    # with ProtectSystem=strict and a per-file ReadWritePaths sandbox. Renaming
    # across directory protections can fail even when the target file itself is
    # writable.
    os.makedirs(os.path.dirname(conf_path), exist_ok=True)
    with open(conf_path, "w", encoding="utf-8") as f:
        f.write(new_txt)
    os.chmod(conf_path, 0o600)


def _run_cmd(cmd: list[str], timeout_s: int, *, log=None) -> tuple[int, str]:
    # Returns: (rc, combined_output)
    # Keep it simple and deterministic: merge stderr into stdout.
    env = os.environ.copy()
    env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    try:
        if log:
            log("debug", f"exec: {' '.join(cmd)} timeout={timeout_s}s")
        p = subprocess.run(
            cmd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout_s,
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        out = p.stdout or ""
        # Bound output to keep API responses sane.
        if len(out) > 200_000:
            out = out[:200_000] + "\n\n[... output truncated ...]\n"
        return int(p.returncode), out
    except subprocess.TimeoutExpired:
        return 124, f"Timed out after {timeout_s}s"
    except Exception as e:
        return 1, f"Exception while running command: {e}"


def _json_response(handler: BaseHTTPRequestHandler, code: int, obj: dict, origin: str | None = None):
    data = json.dumps(obj, indent=2).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Cache-Control", "no-store")
    if origin:
        handler.send_header("Access-Control-Allow-Origin", origin)
        handler.send_header("Vary", "Origin")
        handler.send_header("Access-Control-Allow-Headers", "Content-Type, X-ZNH-Token")
        handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.end_headers()
    handler.wfile.write(data)


def _read_json(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length) if length > 0 else b"{}"
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return {}


def _allowed_origin(origin: str | None) -> str | None:
    if not origin:
        return None

    # Allow the local dashboard server (dynamic port range).
    # This prevents CORS lockout when :8765 is busy and the dashboard binds
    # to a nearby free port (e.g. :8766).
    try:
        p = urlparse(origin)
        if p.scheme != "http":
            return None
        host = (p.hostname or "").lower()
        port = p.port
        if host not in ("127.0.0.1", "localhost"):
            return None
        if port is None:
            return None
        if 8765 <= int(port) <= 8790:
            return origin
    except Exception:
        return None

    return None


class Handler(BaseHTTPRequestHandler):
    server_version = "ZNH-Dashboard-API/1.0"

    def do_OPTIONS(self):
        origin = _allowed_origin(self.headers.get("Origin"))
        self.send_response(204)
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-ZNH-Token")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def _auth_ok(self) -> bool:
        token = getattr(self.server, "token", "")
        provided = self.headers.get("X-ZNH-Token", "")
        return bool(token) and provided == token

    def log_message(self, fmt, *args):
        # Quiet default HTTP logs (systemd journal has enough noise already).
        return

    def do_GET(self):
        origin = _allowed_origin(self.headers.get("Origin"))
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query or "")
        try:
            getattr(self.server, "_znh_log", lambda *_: None)("debug", f"GET {path} from {self.client_address[0]}")
        except Exception:
            pass

        # Snapper endpoints always require auth (even for read-only status).
        if path.startswith("/api/snapper/"):
            if not self._auth_ok():
                try:
                    getattr(self.server, "_znh_log", lambda *_: None)("warn", f"Unauthorized GET {path} from {self.client_address[0]}")
                except Exception:
                    pass
                return _json_response(self, 401, {"error": "unauthorized"}, origin)

            if path == "/api/snapper/status":
                cmd = ["/usr/local/bin/zypper-auto-helper", "snapper", "status"]
                rc, out = _run_cmd(cmd, timeout_s=30, log=getattr(self.server, "_znh_log", None))
                return _json_response(self, 200 if rc == 0 else 500, {"rc": rc, "output": out}, origin)

            if path == "/api/snapper/list":
                n = "10"
                try:
                    n = (qs.get("n") or ["10"])[0]
                except Exception:
                    n = "10"
                if not re.fullmatch(r"[0-9]+", str(n)):
                    n = "10"
                # Bound list size
                try:
                    nn = int(n)
                except Exception:
                    nn = 10
                if nn < 1:
                    nn = 1
                if nn > 50:
                    nn = 50
                cmd = ["/usr/local/bin/zypper-auto-helper", "snapper", "list", str(nn)]
                rc, out = _run_cmd(cmd, timeout_s=30, log=getattr(self.server, "_znh_log", None))
                return _json_response(self, 200 if rc == 0 else 500, {"rc": rc, "output": out}, origin)

            return _json_response(self, 404, {"error": "not found"}, origin)

        if path == "/api/ping":
            # Unauthenticated health probe used by auto-repair to detect
            # whether the running service has been restarted after upgrades.
            return _json_response(self, 200, {
                "ok": True,
                "ts": time.time(),
                "features": {
                    "dashboard_refresh": True,
                    "snapper": True,
                    "settings": True,
                },
            }, origin)

        if path == "/api/schema":
            return _json_response(self, 200, {"schema": SCHEMA}, origin)
        if path == "/api/config":
            eff, warnings, invalid = _read_conf(self.server.conf_path)
            return _json_response(self, 200, {"config": eff, "warnings": warnings, "invalid_keys": invalid}, origin)
        return _json_response(self, 404, {"error": "not found"}, origin)

    def do_POST(self):
        origin = _allowed_origin(self.headers.get("Origin"))
        path = urlparse(self.path).path
        try:
            getattr(self.server, "_znh_log", lambda *_: None)("info", f"POST {path} from {self.client_address[0]}")
        except Exception:
            pass
        if not self._auth_ok():
            try:
                getattr(self.server, "_znh_log", lambda *_: None)("warn", f"Unauthorized POST {path} from {self.client_address[0]}")
            except Exception:
                pass
            return _json_response(self, 401, {"error": "unauthorized"}, origin)

        # --- Dashboard maintenance (safe) ---
        if path == "/api/dashboard/refresh":
            # Regenerate the root dashboard artifacts. The user's dashboard copy
            # will be kept in sync by the dashboard sync worker started by --dash-open.
            cmd = ["/usr/local/bin/zypper-auto-helper", "--dashboard"]
            rc, out = _run_cmd(cmd, timeout_s=120, log=getattr(self.server, "_znh_log", None))
            return _json_response(self, 200 if rc == 0 else 500, {"rc": rc, "output": out}, origin)

        # --- Snapper control (dashboard) ---
        def _confirm_purge(now_ts: float):
            try:
                items = getattr(self.server, "confirm_tokens", {})
                dead = []
                for k, v in items.items():
                    if float(v.get("exp", 0)) < now_ts:
                        dead.append(k)
                for k in dead:
                    items.pop(k, None)
            except Exception:
                return

        if path == "/api/snapper/confirm":
            body = _read_json(self)
            action = str(body.get("action", "")).strip()
            params = body.get("params", {})
            if not isinstance(params, dict):
                params = {}

            allowed = {
                "create": "Type SNAPSHOT to confirm snapshot creation.",
                "cleanup": "Type CLEANUP to confirm Snapper cleanup (may delete snapshots).",
                "auto-enable": "Type ENABLE to confirm enabling Snapper timers.",
                "auto-disable": "Type DISABLE to confirm disabling Snapper timers.",
            }
            if action not in allowed:
                return _json_response(self, 400, {"error": f"unsupported confirm action: {action}"}, origin)

            now_ts = time.time()
            _confirm_purge(now_ts)

            token = secrets.token_urlsafe(24)
            exp = now_ts + 120.0
            try:
                if not hasattr(self.server, "confirm_tokens"):
                    self.server.confirm_tokens = {}
                self.server.confirm_tokens[token] = {
                    "action": action,
                    "params": params,
                    "exp": exp,
                }
            except Exception:
                return _json_response(self, 500, {"error": "failed to store confirm token"}, origin)

            phrase = ""
            if action == "create":
                phrase = "SNAPSHOT"
            elif action == "cleanup":
                phrase = "CLEANUP"
            elif action == "auto-enable":
                phrase = "ENABLE"
            elif action == "auto-disable":
                phrase = "DISABLE"

            return _json_response(self, 200, {
                "confirm_token": token,
                "expires_in_seconds": 120,
                "phrase": phrase,
                "hint": allowed[action],
            }, origin)

        if path == "/api/snapper/run":
            body = _read_json(self)
            action = str(body.get("action", "")).strip()
            params = body.get("params", {})
            if not isinstance(params, dict):
                params = {}

            # Determine if action requires confirmation.
            needs_confirm = action in ("create", "cleanup", "auto-enable", "auto-disable")
            if action in ("status", "list"):
                needs_confirm = False

            confirm_token = str(body.get("confirm_token", "")).strip()
            confirm_phrase = str(body.get("confirm_phrase", "")).strip()

            if needs_confirm:
                now_ts = time.time()
                _confirm_purge(now_ts)
                items = getattr(self.server, "confirm_tokens", {})
                meta = items.get(confirm_token)
                if not meta:
                    return _json_response(self, 400, {"error": "missing/expired confirm token"}, origin)
                if meta.get("action") != action:
                    return _json_response(self, 400, {"error": "confirm token does not match action"}, origin)

                required_phrase = {
                    "create": "SNAPSHOT",
                    "cleanup": "CLEANUP",
                    "auto-enable": "ENABLE",
                    "auto-disable": "DISABLE",
                }.get(action, "")

                if required_phrase and confirm_phrase.upper() != required_phrase:
                    return _json_response(self, 400, {"error": f"confirmation phrase mismatch (expected {required_phrase})"}, origin)

                # One-time token.
                try:
                    items.pop(confirm_token, None)
                except Exception:
                    pass

            # Map actions to helper subcommands.
            cmd = None
            timeout_s = 60

            if action == "status":
                cmd = ["/usr/local/bin/zypper-auto-helper", "snapper", "status"]
                timeout_s = 30
            elif action == "list":
                n = str(params.get("n", "10"))
                if not re.fullmatch(r"[0-9]+", n):
                    n = "10"
                nn = 10
                try:
                    nn = int(n)
                except Exception:
                    nn = 10
                if nn < 1:
                    nn = 1
                if nn > 50:
                    nn = 50
                cmd = ["/usr/local/bin/zypper-auto-helper", "snapper", "list", str(nn)]
                timeout_s = 30
            elif action == "create":
                desc = str(params.get("desc", "")).strip()
                # Bound description size.
                if len(desc) > 200:
                    desc = desc[:200]
                cmd = ["/usr/local/bin/zypper-auto-helper", "snapper", "create", desc]
                timeout_s = 90
            elif action == "cleanup":
                mode = str(params.get("mode", "all")).strip()
                if mode not in ("all", "number", "timeline", "empty-pre-post"):
                    mode = "all"
                cmd = ["/usr/local/bin/zypper-auto-helper", "snapper", "cleanup", mode]
                timeout_s = 600
            elif action == "auto-enable":
                cmd = ["/usr/local/bin/zypper-auto-helper", "snapper", "auto"]
                timeout_s = 120
            elif action == "auto-disable":
                cmd = ["/usr/local/bin/zypper-auto-helper", "snapper", "auto-off"]
                timeout_s = 120
            else:
                return _json_response(self, 400, {"error": f"unsupported action: {action}"}, origin)

            # Best-effort "busy" guard: avoid running snapper actions if snapper is active.
            if action in ("cleanup", "create"):
                rc_busy, out_busy = _run_cmd(["/usr/bin/pgrep", "-x", "snapper"], timeout_s=2, log=None)
                if rc_busy == 0:
                    return _json_response(self, 409, {"error": "snapper appears to be running already; try again later"}, origin)

            rc, out = _run_cmd(cmd, timeout_s=timeout_s, log=getattr(self.server, "_znh_log", None))
            code = 200 if rc == 0 else 500
            return _json_response(self, code, {"rc": rc, "output": out, "action": action}, origin)

        if path == "/api/client-log":
            body = _read_json(self)
            level = str(body.get("level", "info")).lower()
            msg = str(body.get("msg", ""))
            ctx = body.get("ctx", {})
            if level not in ("error","warn","info","debug"):
                level = "info"
            try:
                getattr(self.server, "_znh_log", lambda *_: None)(level, f"[UI] {msg} ctx={json.dumps(ctx, ensure_ascii=False)[:400]}")
            except Exception:
                pass
            return _json_response(self, 200, {"ok": True}, origin)

        if path == "/api/reset-config":
            # Non-interactive reset via helper so it stays consistent with installer template.
            cmd = ["/usr/local/bin/zypper-auto-helper", "--reset-config", "--yes"]
            try:
                subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
            eff, warnings, invalid = _read_conf(self.server.conf_path)
            # Ensure managed block matches the validated effective config.
            _write_managed_block(self.server.conf_path, eff)
            eff2, warnings2, invalid2 = _read_conf(self.server.conf_path)
            return _json_response(self, 200, {"config": eff2, "warnings": warnings2, "invalid_keys": invalid2}, origin)

        if path == "/api/config":
            body = _read_json(self)
            patch = body.get("patch", body)
            if not isinstance(patch, dict):
                patch = {}
            eff, warnings, invalid = _read_conf(self.server.conf_path)

            # Apply patch to effective config (only known keys)
            applied = {}
            for k, v in patch.items():
                if k not in SCHEMA:
                    continue
                applied[k] = str(v)
                eff[k] = str(v)

            try:
                getattr(self.server, "_znh_log", lambda *_: None)("debug", f"Patch keys={list(applied.keys())} values={json.dumps(applied, ensure_ascii=False)[:400]}")
            except Exception:
                pass

            eff2, warnings2, invalid2 = _validate(eff)
            if invalid2:
                try:
                    getattr(self.server, "_znh_log", lambda *_: None)("warn", f"Invalid keys auto-healed: {invalid2}")
                except Exception:
                    pass

            # Write corrected values back so invalid inputs auto-heal to defaults.
            try:
                _write_managed_block(self.server.conf_path, eff2)
            except Exception as e:
                try:
                    getattr(self.server, "_znh_log", lambda *_: None)("error", f"Write failed for {self.server.conf_path}: {e}")
                except Exception:
                    pass
                return _json_response(self, 500, {"error": f"write failed: {e}"}, origin)

            eff3, warnings3, invalid3 = _read_conf(self.server.conf_path)
            return _json_response(self, 200, {"config": eff3, "warnings": warnings2 + warnings3, "invalid_keys": invalid2 + invalid3}, origin)

        return _json_response(self, 404, {"error": "not found"}, origin)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8766)
    ap.add_argument("--token-file", required=True)
    ap.add_argument("--config", default="/etc/zypper-auto.conf")
    ap.add_argument("--schema-file", default="/var/lib/zypper-auto/dashboard-schema.json")
    ap.add_argument("--log-file", default="/var/log/zypper-auto/service-logs/dashboard-api.log")
    ap.add_argument("--mirror-file", default="")
    ap.add_argument("--log-level", default="info", choices=["error","warn","info","debug"])
    args = ap.parse_args()

    global SCHEMA, DEFAULTS
    SCHEMA = _load_schema(args.schema_file)
    DEFAULTS = _build_defaults(SCHEMA)

    # Structured logging similar to the bash helper
    run_id = f"API-{os.getpid()}"

    def _ts():
        # millisecond timestamp
        import datetime
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    def _write_line(path: str, line: str):
        if not path:
            return
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            return

    LEVEL_ORDER = {"error": 0, "warn": 1, "info": 2, "debug": 3}
    LOG_LEVEL = args.log_level

    def log(level: str, msg: str):
        if LEVEL_ORDER.get(level, 2) > LEVEL_ORDER.get(LOG_LEVEL, 2):
            return
        line = f"[{level.upper()}] {_ts()} [RUN={run_id}] {msg}"
        _write_line(args.log_file, line)
        # Mirror into user dashboard dir so the HTML can display it.
        if args.mirror_file:
            _write_line(args.mirror_file, line)
            try:
                os.chmod(args.mirror_file, 0o644)
            except Exception:
                pass

    # Log startup
    log("info", f"Starting dashboard API on {args.listen}:{args.port} (config={args.config})")

    # API FIX: Use a multi-threaded HTTP server so slow requests (large logs,
    # snapper commands, etc.) don't freeze the entire dashboard.
    class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    token = _load_token(args.token_file)

    try:
        httpd = ThreadingHTTPServer((args.listen, args.port), Handler)
    except OSError as e:
        log("error", f"FATAL: Could not bind dashboard API to {args.listen}:{args.port}: {e}")
        raise SystemExit(1)

    httpd.token = token
    httpd.conf_path = args.config
    httpd._znh_log = log
    httpd.confirm_tokens = {}

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log("info", "Stopping dashboard API (KeyboardInterrupt)")
    finally:
        try:
            httpd.server_close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
PYEOF
then
    execute_guarded "Set API server permissions (755)" chmod 755 "${DASH_API_BIN}" || true
    log_success "Dashboard API server installed: ${DASH_API_BIN}"
else
    log_warn "Failed to install dashboard API server (non-fatal)"
fi

# Install systemd unit
if write_atomic "${DASH_API_UNIT}" <<EOF
[Unit]
Description=Zypper Auto Dashboard Settings API (localhost)
After=network.target

[Service]
Type=simple
EnvironmentFile=-/var/lib/zypper-auto/dashboard-api.env
ExecStart=${DASH_API_BIN} --listen 127.0.0.1 --port 8766 --token-file ${DASH_API_TOKEN_FILE} --config ${CONFIG_FILE} --schema-file /var/lib/zypper-auto/dashboard-schema.json --log-file /var/log/zypper-auto/service-logs/dashboard-api.log --mirror-file=${DASH_API_MIRROR_FILE:-} --log-level ${DASH_API_LOG_LEVEL:-info}
Restart=on-failure
RestartSec=2

# Background priority + caps (best-effort; ignored on older systemd / cgroup setups)
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
CPUWeight=20
IOWeight=20
MemoryHigh=250M
MemoryMax=400M

# Basic hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${CONFIG_FILE} ${DASH_API_TOKEN_DIR} /var/log/zypper-auto /var/log/zypper-auto/service-logs

[Install]
WantedBy=multi-user.target
EOF
then
    chmod 644 "${DASH_API_UNIT}" 2>/dev/null || true
    execute_guarded "systemd daemon-reload (dashboard api unit)" systemctl daemon-reload || true
    log_success "Dashboard API systemd unit installed: ${DASH_API_UNIT}"
else
    log_warn "Failed to write dashboard API unit file (non-fatal): ${DASH_API_UNIT}"
fi

# Ensure token directory exists with strict perms
mkdir -p "${DASH_API_TOKEN_DIR}" 2>/dev/null || true
chown root:root "${DASH_API_TOKEN_DIR}" 2>/dev/null || true
chmod 700 "${DASH_API_TOKEN_DIR}" 2>/dev/null || true

# Write dashboard schema used by the Settings API/UI
__znh_write_dashboard_schema_json "${DASH_API_TOKEN_DIR}/dashboard-schema.json" || true

# Create an initial token if missing (will be replaced by --dash-open as needed)
if [ ! -f "${DASH_API_TOKEN_FILE}" ]; then
    if command -v python3 >/dev/null 2>&1; then
        python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(24))
PY
    else
        date +%s%N
    fi | tr -d '\n' >"${DASH_API_TOKEN_FILE}" 2>/dev/null || true
    chmod 600 "${DASH_API_TOKEN_FILE}" 2>/dev/null || true
fi

# --- 11f. Install dashboard performance worker (user-space) ---
# This worker writes perf-data.json into the user's dashboard directory so
# status.html can show realtime service CPU/memory/IO charts when opened via
# --dash-open.
DASH_PERF_BIN="/usr/local/bin/zypper-auto-dashboard-perf-worker"

log_info ">>> Installing dashboard performance worker (service perf charts)..."
update_status "Installing dashboard performance worker..."

if write_atomic "${DASH_PERF_BIN}" <<'PYEOF'
#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
import time
from collections import deque
from datetime import datetime, timezone

def _iso_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

def _to_int(v, default=0):
    try:
        if v is None:
            return default
        s = str(v).strip()
        if s == "":
            return default
        return int(s)
    except Exception:
        return default

def _systemctl_show(unit: str) -> dict:
    # Keep the set small + stable; only what we need for charts.
    props = [
        "CPUUsageNSec",
        "MemoryCurrent",
        "IOReadBytes",
        "IOWriteBytes",
        "ActiveState",
        "SubState",
        "ExecMainPID",
        "ExecMainStatus",
    ]
    cmd = ["systemctl", "show", unit]
    for p in props:
        cmd.extend(["-p", p])

    try:
        p = subprocess.run(
            cmd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=2,
        )
    except Exception as e:
        return {"error": f"exec failed: {e}"}

    if p.returncode != 0:
        err = (p.stderr or "").strip()
        out = (p.stdout or "").strip()
        msg = err or out or f"systemctl show failed rc={p.returncode}"
        return {"error": msg}

    out = {}
    for line in (p.stdout or "").splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out

def _atomic_write(path: str, data: dict):
    tmp = f"{path}.tmp.{os.getpid()}"
    s = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(s)
        f.write("\n")
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o644)
    except Exception:
        pass

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--max-samples", type=int, default=180)
    ap.add_argument(
        "--units",
        default="zypper-autodownload.service,zypper-auto-verify.service,zypper-auto-dashboard-api.service",
    )
    args = ap.parse_args()

    out_dir = os.path.abspath(os.path.expanduser(args.out_dir))
    out_file = os.path.join(out_dir, "perf-data.json")

    units = [u.strip() for u in str(args.units).split(",") if u.strip()]
    if not units:
        return 0

    max_samples = max(10, int(args.max_samples))
    interval = float(args.interval)
    if interval < 0.5:
        interval = 0.5

    hist = {u: deque(maxlen=max_samples) for u in units}
    prev_cpu = {u: None for u in units}
    prev_t = {u: None for u in units}

    while True:
        now = time.time()
        now_ms = int(now * 1000)

        payload_units = {}
        for u in units:
            show = _systemctl_show(u)
            if "error" in show:
                # Still emit a point so the UI can show that collection failed.
                hist[u].append({"t": now_ms, "cpu": 0.0, "mem": 0, "r": 0, "w": 0, "err": show.get("error")})
                payload_units[u] = {"samples": list(hist[u])}
                continue

            cpu_ns = _to_int(show.get("CPUUsageNSec"), 0)
            mem_b = _to_int(show.get("MemoryCurrent"), 0)
            r_b = _to_int(show.get("IOReadBytes"), 0)
            w_b = _to_int(show.get("IOWriteBytes"), 0)

            cpu_pct = 0.0
            if prev_cpu[u] is not None and prev_t[u] is not None:
                dcpu = cpu_ns - int(prev_cpu[u])
                dt = now - float(prev_t[u])
                if dcpu < 0:
                    dcpu = 0
                if dt > 0:
                    cpu_pct = (dcpu / (dt * 1e9)) * 100.0
            prev_cpu[u] = cpu_ns
            prev_t[u] = now

            # Bound extreme spikes (multi-core can exceed 100; keep it sane for charts).
            if cpu_pct < 0:
                cpu_pct = 0.0
            if cpu_pct > 4000:
                cpu_pct = 4000.0

            hist[u].append({
                "t": now_ms,
                "cpu": round(cpu_pct, 2),
                "mem": mem_b,
                "r": r_b,
                "w": w_b,
                "active": show.get("ActiveState", ""),
                "sub": show.get("SubState", ""),
                "pid": _to_int(show.get("ExecMainPID"), 0),
                "status": _to_int(show.get("ExecMainStatus"), 0),
            })
            payload_units[u] = {"samples": list(hist[u])}

        payload = {
            "generated_iso": _iso_now(),
            "interval_sec": interval,
            "units": payload_units,
        }

        try:
            _atomic_write(out_file, payload)
        except Exception:
            # Don't die just because the filesystem had a transient error.
            pass

        time.sleep(interval)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(0)
PYEOF
then
    execute_guarded "Set perf worker permissions (755)" chmod 755 "${DASH_PERF_BIN}" || true
    log_success "Dashboard perf worker installed: ${DASH_PERF_BIN}"
else
    log_warn "Failed to install dashboard perf worker (non-fatal)"
fi

# --- 12. Final self-check ---
log_info ">>> Final syntax self-check..."
update_status "Running final syntax checks..."
run_self_check

# --- 13. Reload user systemd daemon and ensure notifier timer is active ---
USER_BUS_PATH="unix:path=/run/user/$(id -u "$SUDO_USER")/bus"

log_info ">>> Reloading user systemd daemon and (re)starting ${NT_SERVICE_NAME}.timer..."
update_status "Enabling user services..."
log_debug "User bus path: $USER_BUS_PATH"

if execute_guarded "systemctl --user daemon-reload" \
    sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user daemon-reload; then
    log_success "User systemd daemon reloaded"
    
    log_debug "Enabling user timer: ${NT_SERVICE_NAME}.timer"
    if execute_guarded "Enable + start user timer ${NT_SERVICE_NAME}.timer" \
        sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user enable --now "${NT_SERVICE_NAME}.timer"; then
        log_success "User notifier timer enabled and started"
        # Some systemd versions can leave the timer in an 'elapsed' state
        # with no NEXT trigger after unit changes. Force a restart so it
        # gets a fresh schedule and actually fires again for this user.
        log_debug "Restarting user timer to ensure it is scheduled"
        execute_guarded "Restart user timer ${NT_SERVICE_NAME}.timer" \
            sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user restart "${NT_SERVICE_NAME}.timer" || true
    else
        log_error "Failed to enable user timer (non-fatal)"
        log_info "You may need to run manually as the target user:"
        log_info "  systemctl --user enable --now ${NT_SERVICE_NAME}.timer"
    fi
else
    log_error "Warning: Could not talk to user systemd (no session bus?)"
    log_info "You may need to run manually as the target user:"
    log_info "  systemctl --user daemon-reload"
    log_info "  systemctl --user enable --now ${NT_SERVICE_NAME}.timer"
fi


# --- 14. Installation Verification (called during install) ---
if [ "${VERIFICATION_ONLY_MODE:-0}" -ne 1 ]; then
    # Only run verification during installation, not in verify-only mode
    # (verify-only mode calls the function directly and exits)
    run_smart_verification_with_safety_net 1
fi

# --- 14b. Check for Optional Packages ---
log_info ">>> Checking for optional package managers..."
MISSING_PACKAGES=()

if ! command -v flatpak >/dev/null 2>&1; then
    log_info "Flatpak is not installed (optional)"
    MISSING_PACKAGES+=("flatpak")
fi

if ! command -v snap >/dev/null 2>&1; then
    log_info "Snapd is not installed (optional)"
    MISSING_PACKAGES+=("snapd")
fi

# Optional: Soar CLI helper (used to sync metadata after updates)
# Soar is typically installed per-user (for example under ~/.local/bin or
# ~/pkgforge). Detect it using the user's PATH and common install dirs so
# we don't warn when it is already present.
SOAR_PRESENT=0

# Optional: pipx helper (for Python CLI tools). Only warn when
# ENABLE_PIPX_UPDATES=true and pipx is missing for the target user.
PIPX_MISSING_FOR_UPDATES=0
if [[ "${ENABLE_PIPX_UPDATES,,}" == "true" ]]; then
    if ! sudo -u "$SUDO_USER" command -v pipx >/dev/null 2>&1; then
        PIPX_MISSING_FOR_UPDATES=1
        log_info "pipx is not installed for user $SUDO_USER but ENABLE_PIPX_UPDATES=true (optional)"
    fi
fi

# 1) Check via the user's PATH
if sudo -u "$SUDO_USER" command -v soar >/dev/null 2>&1; then
    SOAR_PRESENT=1
# 2) Check common per-user install locations
elif [ -x "$SUDO_USER_HOME/.local/bin/soar" ]; then
    SOAR_PRESENT=1
elif [ -d "$SUDO_USER_HOME/pkgforge" ] && \
     find "$SUDO_USER_HOME/pkgforge" -maxdepth 1 -type f -name 'soar*' -perm -u+x 2>/dev/null | grep -q .; then
    SOAR_PRESENT=1
fi

if [ "$SOAR_PRESENT" -eq 0 ]; then
    log_info "Soar CLI is not installed for user $SUDO_USER (optional)"
    MISSING_PACKAGES+=("soar")
fi

if [ "$PIPX_MISSING_FOR_UPDATES" -eq 1 ]; then
    MISSING_PACKAGES+=("pipx")
fi

# Notify user about missing packages if any
if [ "${#MISSING_PACKAGES[@]}" -gt 0 ]; then
    log_info "Optional package managers missing: ${MISSING_PACKAGES[*]}"
    
    # Create notification for user
    MISSING_MSG="The following optional package managers are not installed:\n\n"
    for pkg in "${MISSING_PACKAGES[@]}"; do
        if [ "$pkg" = "flatpak" ]; then
            MISSING_MSG+="• Flatpak - for Flatpak app updates\n  Install: sudo zypper install flatpak\n\n"
        elif [ "$pkg" = "snapd" ]; then
            MISSING_MSG+="• Snapd - for Snap package updates\n  Install: sudo zypper install snapd\n  Enable: sudo systemctl enable --now snapd\n\n"
        fi
    done
    MISSING_MSG+="These are optional. System updates will work without them."
    
    # Send desktop notification to user
    if command -v notify-send >/dev/null 2>&1; then
        sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" notify-send \
            -u normal \
            -t 15000 \
            -i "dialog-information" \
            "Zypper Auto-Helper: Optional Packages" \
            "${MISSING_MSG}" 2>/dev/null || true
    fi

    # If Soar is missing and the helper exists, also show a richer
    # notification with an "Install Soar" button that opens a terminal
    # running the official install script.
    if printf '%s
' "${MISSING_PACKAGES[@]}" | grep -qx 'soar'; then
        # Propagate DISPLAY from the current environment so the helper
        # can open a terminal on the correct graphical session. Without
        # this, the helper fell back to DISPLAY=:0 which may not match
        # the user's real display.
        if sudo -u "$SUDO_USER" DISPLAY="$DISPLAY" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" \
            "$USER_BIN_DIR/zypper-soar-install-helper" >/dev/null 2>&1 & then
            log_debug "Launched Soar install helper notification for user $SUDO_USER"
        fi
    fi
    
    echo "" | tee -a "${LOG_FILE}"
    echo "============================" | tee -a "${LOG_FILE}"
    echo "⚠️  Optional Packages Missing" | tee -a "${LOG_FILE}"
    echo "============================" | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"
    for pkg in "${MISSING_PACKAGES[@]}"; do
        if [ "$pkg" = "flatpak" ]; then
            echo "Flatpak:" | tee -a "${LOG_FILE}"
            echo "  Purpose: Update Flatpak applications" | tee -a "${LOG_FILE}"
            echo "  Install: sudo zypper install flatpak" | tee -a "${LOG_FILE}"
            echo "" | tee -a "${LOG_FILE}"
        elif [ "$pkg" = "snapd" ]; then
            echo "Snapd:" | tee -a "${LOG_FILE}"
            echo "  Purpose: Update Snap packages" | tee -a "${LOG_FILE}"
            echo "  Install (zypper): sudo zypper install snapd" | tee -a "${LOG_FILE}"
            echo "  Install (opi)   : sudo opi snapd" | tee -a "${LOG_FILE}"
            echo "  Enable services : sudo systemctl enable --now snapd.apparmor.service snapd.seeded.service snapd.service snapd.socket" | tee -a "${LOG_FILE}"
            echo "" | tee -a "${LOG_FILE}"
        elif [ "$pkg" = "soar" ]; then
            echo "Soar:" | tee -a "${LOG_FILE}"
            echo "  Purpose: Optional CLI helper for keeping metadata in sync after updates" | tee -a "${LOG_FILE}"
            echo "  Install: curl -fsSL \"https://raw.githubusercontent.com/pkgforge/soar/main/install.sh\" | sh" | tee -a "${LOG_FILE}"
            echo "  Usage after install: soar sync" | tee -a "${LOG_FILE}"
            echo "" | tee -a "${LOG_FILE}"
        elif [ "$pkg" = "pipx" ]; then
            echo "pipx:" | tee -a "${LOG_FILE}"
            echo "  Purpose: Manage standalone Python CLI tools (yt-dlp, black, ansible, httpie, etc.)" | tee -a "${LOG_FILE}"
            echo "  Install: sudo zypper install python3-pipx" | tee -a "${LOG_FILE}"
            echo "  Helper:  zypper-auto-helper --pip-package  (run without sudo)" | tee -a "${LOG_FILE}"
            echo "" | tee -a "${LOG_FILE}"
        fi
    done
    echo "Note: These are optional. System updates will work without them." | tee -a "${LOG_FILE}"
    echo "============================" | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"
fi

# --- 15. Final Summary ---
log_success ">>> Installation completed successfully!"
update_status "SUCCESS: Installation completed"

# Update the static HTML dashboard (best-effort)
generate_dashboard || true

# Ensure dashboard desktop shortcut exists for the primary user (best-effort)
if [ -n "${SUDO_USER:-}" ] && [ -n "${SUDO_USER_HOME:-}" ]; then
    __znh_ensure_dash_desktop_shortcut "${SUDO_USER}" "${SUDO_USER_HOME}" || true
fi

# Remote monitoring: notify success (best-effort)
send_webhook "zypper-auto-helper: Installation successful" \
    "Installation completed successfully.\nInstall log: ${LOG_FILE}" \
    "65280" || true

echo "" | tee -a "${LOG_FILE}"
echo "==============================================" | tee -a "${LOG_FILE}"
echo "Installation Summary:" | tee -a "${LOG_FILE}"
echo "  - Command: zypper-auto-helper (installed to /usr/local/bin)" | tee -a "${LOG_FILE}"
echo "  - System service: ${DL_SERVICE_NAME}.timer (enabled)" | tee -a "${LOG_FILE}"
echo "  - User service: ${NT_SERVICE_NAME}.timer (enabled)" | tee -a "${LOG_FILE}"
echo "  - Install logs: ${LOG_DIR}/install-*.log" | tee -a "${LOG_FILE}"
echo "  - Service logs: ${LOG_DIR}/service-logs/" | tee -a "${LOG_FILE}"
echo "  - User logs: ${USER_LOG_DIR}/" | tee -a "${LOG_FILE}"
echo "  - Status file: ${STATUS_FILE}" | tee -a "${LOG_FILE}"
echo "" | tee -a "${LOG_FILE}"
echo "Quick Commands:" | tee -a "${LOG_FILE}"
echo "  sudo zypper-auto-helper --verify        # Check system health" | tee -a "${LOG_FILE}"
echo "  sudo zypper-auto-helper --help          # Show help" | tee -a "${LOG_FILE}"
echo "  cat ${STATUS_FILE}                      # View current status" | tee -a "${LOG_FILE}"
echo "" | tee -a "${LOG_FILE}"

echo "Enterprise Quickstart (optional):" | tee -a "${LOG_FILE}"
echo "  Fastest: sudo zypper-auto-helper --dash-install" | tee -a "${LOG_FILE}"
echo "  (enables example hooks + generates/opens dashboard)" | tee -a "${LOG_FILE}"
echo "" | tee -a "${LOG_FILE}"
echo "  Manual steps:" | tee -a "${LOG_FILE}"
echo "  1) Edit ${CONFIG_FILE} and set WEBHOOK_URL=\"...\" (leave empty to disable webhooks)" | tee -a "${LOG_FILE}"
echo "  2) Enable hooks by copying templates and making them executable:" | tee -a "${LOG_FILE}"
echo "     - ${HOOKS_BASE_DIR:-/etc/zypper-auto/hooks}/pre.d/00-example-pre.sh.example" | tee -a "${LOG_FILE}"
echo "     - ${HOOKS_BASE_DIR:-/etc/zypper-auto/hooks}/post.d/00-example-post.sh.example" | tee -a "${LOG_FILE}"
echo "  3) Open the dashboard: ${SUDO_USER_HOME}/.local/share/zypper-notify/status.html" | tee -a "${LOG_FILE}"
echo "" | tee -a "${LOG_FILE}"
echo "Service Status:" | tee -a "${LOG_FILE}"
echo "  systemctl status ${DL_SERVICE_NAME}.timer" | tee -a "${LOG_FILE}"
echo "  systemctl --user status ${NT_SERVICE_NAME}.timer" | tee -a "${LOG_FILE}"
echo "" | tee -a "${LOG_FILE}"
echo "View Logs:" | tee -a "${LOG_FILE}"
echo "  journalctl -u ${DL_SERVICE_NAME}.service" | tee -a "${LOG_FILE}"
echo "  journalctl --user -u ${NT_SERVICE_NAME}.service" | tee -a "${LOG_FILE}"
echo "  cat ${LOG_FILE}" | tee -a "${LOG_FILE}"
echo "==============================================" | tee -a "${LOG_FILE}"
echo "Completed: $(date)" | tee -a "${LOG_FILE}"
