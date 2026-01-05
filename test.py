#!/usr/bin/env python3
#
# test-notification.py
#
# This script sends a fake "Updates Ready" notification
# using the Python (gi) library and logs its actions
# to 'zypper-test.log' in the *same folder as this script*.
#
# Run it directly from your terminal as your user.

import sys
import subprocess
import os
import logging
import traceback
import time

# --- Setup Logging (v2 - Log to script directory) ---
try:
    # Get the directory where this script is located (normally the repo root)
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    # Create the log file in that same directory, named test.log so other
    # developers can easily grab it from the repository folder.
    LOG_FILE = os.path.join(SCRIPT_DIR, "test.log")

    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        filemode='a'  # Append new runs to a shared test.log
    )
except Exception as e:
    print(f"Error setting up logging: {e}")
    sys.exit(1)
# ---------------------

try:
    import gi
    gi.require_version("Notify", "0.7")
    from gi.repository import Notify, GLib
    logging.info("PyGObject (gi) imported successfully.")
except ImportError:
    error_msg = "Error: PyGObject (gi) not found. This is a problem."
    logging.error(error_msg)
    logging.error("Please install 'python3-gobject' and try again.")
    print(error_msg) # Also print to terminal
    sys.exit(1)

def on_action(notification, action_id, user_data_script):
    """Callback to run when a notification action button is clicked.

    Logs detailed diagnostic information about the chosen action,
    the resolved script path, and any launcher process that is started.
    """
    logging.info("on_action: action_id=%r raw_user_data_script=%r", action_id, user_data_script)
    try:
        # We try to find the v33 script, but fall back to a generic one
        # for this test.
        if not os.path.exists(user_data_script):
            resolved = os.path.expanduser("~/.local/bin/zypper-run-install")
            logging.info("on_action: primary script missing, falling back to %r", resolved)
            user_data_script = resolved

        if not os.path.exists(user_data_script):
            logging.warning(
                "on_action: action=%r, no runnable script at %r. Did you run the installer?",
                action_id,
                user_data_script,
            )
            # Fallback: just open a terminal to give the user some context
            logging.info("on_action: falling back to launching 'konsole'")
            try:
                proc = subprocess.Popen(["konsole"])  # type: ignore[arg-type]
                logging.info("on_action: launched konsole, pid=%s", getattr(proc, "pid", "unknown"))
            except Exception:
                logging.error("on_action: failed to launch konsole")
                logging.error(traceback.format_exc())
        else:
            is_exec = os.access(user_data_script, os.X_OK)
            logging.info(
                "on_action: executing script=%r exists=%s executable=%s",
                user_data_script,
                True,
                is_exec,
            )
            try:
                proc = subprocess.Popen([user_data_script])  # type: ignore[arg-type]
                logging.info(
                    "on_action: launched helper script pid=%s cmd=%r",
                    getattr(proc, "pid", "unknown"),
                    [user_data_script],
                )
            except Exception:
                logging.error("on_action: failed to spawn helper script %r", user_data_script)
                logging.error(traceback.format_exc())

    except Exception as e:
        logging.error("on_action: unexpected failure: %s", e)
        logging.error(traceback.format_exc())

    try:
        notification.close()
    except Exception:
        logging.error("on_action: failed to close notification")
        logging.error(traceback.format_exc())
    # The real notifier uses a GLib main loop; simulate a clean exit here.
    GLib.MainLoop().quit()

def _show_checking_stage():
    """Simulate the "refreshing" stage (checking for updates)."""
    title = "Checking for updates... (Test)"
    body = "Refreshing repositories..."
    icon = "emblem-synchronizing"
    logging.info(
        "CHECKING: title=%r body=%r icon=%r timeout_ms=%d", title, body, icon, 2000
    )
    n = Notify.Notification.new(title, body, icon)
    # Use same synchronous ID as real downloader so notifications replace each other
    n.set_timeout(2000)
    n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "zypper-download-status"))
    n.show()
    time.sleep(2)


def _show_downloading_stage():
    """Simulate the "downloading" stage with a progress bar."""
    total_pkgs = 10
    download_size = "120 MiB"
    logging.info(
        "DOWNLOADING: total_pkgs=%d download_size=%r bar_len=%d step_delay=%.2fs",
        total_pkgs,
        download_size,
        20,
        0.7,
    )

    for downloaded in range(0, total_pkgs + 1):
        percent = int(downloaded * 100 / total_pkgs)
        bar_len = 20
        filled = int(bar_len * percent / 100)
        bar = "█" * filled + "░" * (bar_len - filled)
        progress_text = f"[{bar}] {percent}%"

        msg_lines = [
            f"Downloading {downloaded} of {total_pkgs} packages",
            progress_text,
            f"{download_size} total • HIGH priority",
        ]
        msg = "\n".join(msg_lines)

        n = Notify.Notification.new(
            "Downloading updates... (Test)",
            msg,
            "emblem-downloads",
        )
        # Progress hint + category like the real notifier
        n.set_hint("value", GLib.Variant("i", percent))
        n.set_category("transfer.progress")
        n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "zypper-download-status"))
        n.set_timeout(1200)
        n.show()
        time.sleep(0.7)


def _show_complete_stage():
    """Simulate the "downloads complete" summary notification."""
    msg = (
        "Downloaded 10 packages in 1m 23s.\n\n"
        "Including: kernel-default, zypper, glibc, and more.\n\n"
        "Ready to install."
    )
    logging.info(
        "COMPLETE: title=%r body_preview=%r icon=%r timeout_ms=%d",
        "✅ Downloads Complete! (Test)",
        msg.replace("\n", " ")[:160],
        "emblem-default",
        4000,
    )
    n = Notify.Notification.new(
        "✅ Downloads Complete! (Test)",
        msg,
        "emblem-default",
    )
    n.set_timeout(4000)
    n.set_urgency(Notify.Urgency.NORMAL)
    n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "zypper-download-complete"))
    n.show()
    time.sleep(4)


def _show_updates_ready_stage():
    """Final persistent "Updates Ready" notification with buttons, like real flow."""
    title = "Snapshot 20251112-0 Ready (Test)"
    message = (
        "10 updates are pending. Click 'Install' to begin.\n\n"
        "Including: kernel-default, zypper, glibc, and more."
    )

    action_script = os.path.expanduser("~/.local/bin/zypper-run-install")
    logging.info(
        "UPDATES_READY: title=%r body_preview=%r icon=%r script=%r",
        title,
        message.replace("\n", " ")[:160],
        "system-software-update",
        action_script,
    )

    n = Notify.Notification.new(title, message, "system-software-update")
    # Persistent: keep until user interacts
    n.set_timeout(0)
    n.set_urgency(Notify.Urgency.CRITICAL)
    n.set_hint("desktop-entry", GLib.Variant("s", "zypper-updater"))
    n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "zypper-updates"))

    # Buttons similar to real notifier
    n.add_action("install", "Install Now", on_action, action_script)
    n.add_action("view-changes", "View Changes", on_action, None)
    n.add_action("snooze-1h", "1h", on_action, None)
    n.add_action("snooze-4h", "4h", on_action, None)
    n.add_action("snooze-1d", "1d", on_action, None)

    # Main loop so the notification stays until user acts
    loop = GLib.MainLoop()
    n.connect("closed", lambda *args: loop.quit())

    n.show()
    logging.info("Updates Ready notification sent. Waiting for user interaction...")
    loop.run()
    logging.info("Updates Ready stage finished (user interacted or closed notification)")


def _show_solver_error_notification():
    """Simulate the solver/conflict error notification from the real helper."""
    title = "Updates require your decision (Test)"
    message = (
        "Background download of updates hit a zypper solver error.\n\n"
        "Some packages may already be cached, but zypper needs your decision to continue.\n\n"
        "Open a terminal and run:\n"
        "  sudo zypper dup\n"
        "or click 'Install Now' to open the helper, then follow zypper's prompts to resolve the conflicts."
    )

    action_script = os.path.expanduser("~/.local/bin/zypper-run-install")
    logging.info(
        "SOLVER_ERROR: title=%r body_preview=%r icon=%r script=%r",
        title,
        message.replace("\n", " ")[:200],
        "system-software-update",
        action_script,
    )

    n = Notify.Notification.new(
        title,
        message,
        "system-software-update",
    )
    n.set_timeout(0)
    n.set_urgency(Notify.Urgency.CRITICAL)
    n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "zypper-updates-conflict"))

    n.add_action("install", "Install Now", on_action, action_script)
    n.add_action("view-changes", "View Changes", on_action, None)
    n.add_action("snooze-1h", "1h", on_action, None)
    n.add_action("snooze-4h", "4h", on_action, None)
    n.add_action("snooze-1d", "1d", on_action, None)

    loop = GLib.MainLoop()
    n.connect("closed", lambda *args: loop.quit())

    n.show()
    logging.info("Solver-error notification sent. Waiting for user interaction...")
    loop.run()
    logging.info("Solver-error test notification finished")


def _show_policykit_error_notification():
    """Simulate the PolicyKit/auth failure notification used by the helper."""

    title = "Update check failed (Test)"
    message = (
        "The updater could not authenticate with PolicyKit.\n"
        "This may be a configuration issue.\n\n"
        "Try running 'pkexec zypper dup --dry-run' manually to test."
    )

    logging.info(
        "POLKIT_ERROR: title=%r body_preview=%r icon=%r timeout_ms=%d",
        title,
        message.replace("\n", " ")[:160],
        "dialog-error",
        30000,
    )

    n = Notify.Notification.new(title, message, "dialog-error")
    n.set_timeout(30000)  # 30 seconds
    n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "zypper-error"))
    n.set_urgency(Notify.Urgency.CRITICAL)
    n.show()

    logging.info("PolicyKit-error notification sent (30s timeout)")
    time.sleep(3)


def _show_config_warning_notification():
    """Simulate the config-warning notification from zypper-auto-helper."""

    title = "Zypper Auto-Helper config warnings (Test)"
    message = (
        "Some settings in /etc/zypper-auto.conf were invalid and reset to safe defaults.\n\n"
        "Check the install log or run: zypper-auto-helper --reset-config"
    )

    logging.info(
        "CONFIG_WARNING: title=%r body_preview=%r icon=%r timeout_ms=%d",
        title,
        message.replace("\n", " ")[:160],
        "dialog-warning",
        20000,
    )

    n = Notify.Notification.new(title, message, "dialog-warning")
    n.set_timeout(20000)
    n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "zypper-config-warning"))
    n.set_urgency(Notify.Urgency.NORMAL)
    n.show()

    logging.info("Config-warning notification sent (20s timeout)")
    time.sleep(2)


def main():
    run_id = time.strftime("%Y%m%d-%H%M%S")
    logging.info("================ RUN %s START ================", run_id)
    logging.info("Python version: %s", sys.version.replace("\n", " "))
    logging.info("ENV DISPLAY=%s WAYLAND_DISPLAY=%s XDG_SESSION_TYPE=%s", os.environ.get("DISPLAY"), os.environ.get("WAYLAND_DISPLAY"), os.environ.get("XDG_SESSION_TYPE"))
    logging.info("User: %s, HOME=%s, PWD=%s", os.environ.get("USER"), os.environ.get("HOME"), os.getcwd())
    print(f"Sending staged test notifications... Log file at: {LOG_FILE}")
    try:
        Notify.init("zypper-updater-test")

        # Simulate the main happy-path stages the real system uses
        _show_checking_stage()
        _show_downloading_stage()
        _show_complete_stage()
        _show_updates_ready_stage()

        # Simulate the main error / edge-case notifications used by the
        # real notifier and installer so we can visually verify them.
        _show_solver_error_notification()
        _show_policykit_error_notification()
        _show_config_warning_notification()

        logging.info("Test finished.")
        print("Test finished.")

    except Exception as e:
        logging.error(f"An error occurred in main: {e}")
        logging.error(traceback.format_exc())
    finally:
        Notify.uninit()
        logging.info("================ RUN %s END ==================", run_id)

if __name__ == "__main__":
    main()
