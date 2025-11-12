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

def main():
    logging.info("--- TEST SCRIPT STARTED ---")
    print(f"Sending fake notification... Log file at: {LOG_FILE}")
    try:
        Notify.init("zypper-updater-test")

        title = "Snapshot 20251112-0 Ready (Test)"
        message = "10 updates are pending. Click 'Install' to begin."

        # Get the path to the action script
        # This is a test, so we just point to where v33 *will* put it
        action_script = os.path.expanduser("~/.local/bin/zypper-run-install")

        # Create the notification
        n = Notify.Notification.new(title, message, "system-software-update")
        n.set_timeout(30000) # 30 seconds
        logging.info("Notification object created.")

        # Add the button
        n.add_action("default", "Install", on_action, action_script)
        logging.info("Action button added.")

        # We need a main loop to keep the script alive for the button
        loop = GLib.MainLoop()
        n.connect("closed", lambda *args: loop.quit())

        n.show()
        logging.info("Notification sent. Waiting for it to be clicked or closed...")
        loop.run() # Wait for the notification to be closed or clicked
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
