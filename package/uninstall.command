#!/bin/bash
# ============================================================================
#  iStat Menus — full uninstall
#
#  Removes everything this build puts on your Mac:
#    * stops the app, menu bar host, helper and fan-control daemon
#    * removes the menu bar login agent
#    * unregisters the app's background items
#    * deletes the app and its support data
#
#  Usage:
#    ./uninstall.command            normal uninstall
#    ./uninstall.command --purge    also remove preferences + signing keychain
#    ./uninstall.command --no-sudo  skip the admin step (daemon may keep
#                                   running until you log out)
#
#  Double-click friendly. Safe to run twice.
# ============================================================================
set -u

log() { printf '%s\n' "$*"; }
OPTS="${1:-}"

log "== iStat Menus uninstaller =="

# 1) stop everything user-owned
log "Stopping iStat Menus processes..."
osascript -e 'tell application id "com.bjango.istatmenus" to quit' >/dev/null 2>&1 || true
sleep 1
pkill -f "iStat Menus Menubar.app/Contents/MacOS/iStat Menus Menubar" >/dev/null 2>&1 || true
pkill -f "iStat Menus Helper.app/Contents/MacOS/iStat Menus helper" >/dev/null 2>&1 || true
pkill -x "iStat Menus" >/dev/null 2>&1 || true
sleep 1

# 2) remove the menu bar login agent
log "Removing the menu bar login agent..."
launchctl bootout "gui/$(id -u)/local.istat-menus.menubar" >/dev/null 2>&1 || true
rm -f "$HOME/Library/LaunchAgents/local.istat-menus.menubar.plist"

# 3) unregister the app's own background items (best effort)
for j in com.bjango.istatmenus.status.sm com.bjango.istatmenus.agent.sm; do
  launchctl bootout "gui/$(id -u)/$j" >/dev/null 2>&1 || true
  launchctl disable "gui/$(id -u)/$j" >/dev/null 2>&1 || true
done

# 4) the fan-control daemon is root-owned; stop it if we may
if [ "$OPTS" != "--no-sudo" ]; then
  log "Stopping the fan-control daemon (may ask for your password)..."
  sudo launchctl bootout system/com.bjango.istatmenus.daemon.sm >/dev/null 2>&1 || true
  sudo launchctl disable system/com.bjango.istatmenus.daemon.sm >/dev/null 2>&1 || true
fi

# 5) remove the app + its support data
log "Deleting the application and support data..."
rm -rf "/Applications/iStat Menus.app" "$HOME/Applications/iStat Menus.app"
rm -rf "$HOME/Library/Application Support/iStat Menus 7"

# 6) optional full purge
if [ "$OPTS" = "--purge" ]; then
  log "Purging preferences and the local signing keychain..."
  defaults delete com.bjango.istatmenus >/dev/null 2>&1 || true
  defaults delete com.bjango.istatmenus.status >/dev/null 2>&1 || true
  security delete-keychain "$HOME/Library/Keychains/istat-crack.keychain-db" >/dev/null 2>&1 || true
fi

# 7) report
sleep 1
LEFT="$(ps aux | grep -i 'iStat Menus' | grep -v grep || true)"
if [ -n "$LEFT" ]; then
  log ""
  log "Some processes could not be stopped (log out and back in):"
  printf '%s\n' "$LEFT"
else
  log ""
  log "Done: iStat Menus is removed and no related processes are running."
fi
