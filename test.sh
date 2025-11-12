#!/bin/bash
#
# test-notification.sh
#
# This script sends a fake "Updates Ready" notification
# to test that the desktop popups are working.
#
# Run it directly from your terminal as your user.

echo "Sending fake notification..."

notify-send \
    -u normal \
    -i "system-software-update" \
    -t 30000 \
    "Snapshot 20251112-0 Ready" \
    "10 updates are pending. Run 'sudo zypper dup' to install."

echo "Done."
