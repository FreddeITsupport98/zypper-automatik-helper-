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
    # Get the directory where this script is located
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    # Create the log file in that same directory
    LOG_FILE = os.path.join(SCRIPT_DIR, "zypper-test.log")

    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        filemode='w'  # Overwrite log each time
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
    """Callback to run when the button is clicked."""
    logging.info(f"Action '{action_id}' clicked. Running install script at: {user_data_script}")
    try:
        # We try to find the v33 script, but fall back to a generic one
        # for this test.
        if not os.path.exists(user_data_script):
             user_data_script = os.path.expanduser("~/.local/bin/zypper-run-install")

        if not os.path.exists(user_data_script):
            logging.warning(f"Could not find the action script at {user_data_script}. Did you run the v33 installer?")
            # Fallback: just open a terminal
            logging.info("Falling back to opening 'konsole'.")
            subprocess.Popen(["konsole"])
        else:
            logging.info(f"Executing: {user_data_script}")
            subprocess.Popen([user_data_script])

    except Exception as e:
        logging.error(f"Failed to launch action script: {e}")
        logging.error(traceback.format_exc())

    notification.close()
    GLib.MainLoop().quit()

def _show_checking_stage():
    """Simulate the "refreshing" stage (checking for updates)."""
    logging.info("Showing CHECKING stage test notification")
    n = Notify.Notification.new(
        "Checking for updates... (Test)",
        "Refreshing repositories...",
        "emblem-synchronizing",
    )
    # Use same synchronous ID as real downloader so notifications replace each other
    n.set_timeout(2000)
    n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "zypper-download-status"))
    n.show()
    time.sleep(2)


def _show_downloading_stage():
    """Simulate the "downloading" stage with a progress bar."""
    total_pkgs = 10
    download_size = "120 MiB"
    logging.info("Showing DOWNLOADING stage test notifications with progress bar")

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
    logging.info("Showing COMPLETE stage test notification")
    msg = (
        "Downloaded 10 packages in 1m 23s.\n\n"
        "Including: kernel-default, zypper, glibc, and more.\n\n"
        "Ready to install."
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
    logging.info("Showing UPDATES READY stage test notification")

    title = "Snapshot 20251112-0 Ready (Test)"
    message = (
        "10 updates are pending. Click 'Install' to begin.\n\n"
        "Including: kernel-default, zypper, glibc, and more."
    )

    action_script = os.path.expanduser("~/.local/bin/zypper-run-install")

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


def main():
    logging.info("--- TEST SCRIPT STARTED ---")
    print(f"Sending staged test notifications... Log file at: {LOG_FILE}")
    try:
        Notify.init("zypper-updater-test")

        # Simulate the same stages the real system uses
        _show_checking_stage()
        _show_downloading_stage()
        _show_complete_stage()
        _show_updates_ready_stage()

        logging.info("Test finished.")
        print("Test finished.")

    except Exception as e:
        logging.error(f"An error occurred in main: {e}")
        logging.error(traceback.format_exc())
    finally:
        Notify.uninit()
        logging.info("--- TEST SCRIPT FINISHED ---")

if __name__ == "__main__":
    main()
