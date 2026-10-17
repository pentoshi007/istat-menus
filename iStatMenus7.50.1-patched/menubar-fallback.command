#!/bin/bash
# ============================================================================
#  iStat Menus — menu bar login-agent fallback
#
#  Some Macs refuse the app's own background-item registration for a
#  locally-signed build (launchd "spawn failed / Launch Constraint
#  Violation"), so the menu bar host never starts. This script installs a
#  per-user login agent that starts the menu bar host at login — only when
#  the app's own host is NOT already running.
#
#  Normal behaviour: stopping the menu bar items (quit from the iStat menu,
#  or kill the host) keeps them hidden until the next login. Use
#  uninstall.command to remove everything.
#
#  Usage:
#    ./menubar-fallback.command            install fallback if needed
#    ./menubar-fallback.command --remove   remove the fallback agent
#                                          (fixes duplicated menu bar items)
#
#  It only touches your own LaunchAgents folder. No admin password needed.
# ============================================================================
set -u

OPTS="${1:-}"
LABEL="local.istat-menus.menubar"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
HOST_PATTERN="iStat Menus Menubar.app/Contents/MacOS/iStat Menus Menubar"

if [ "$OPTS" = "--remove" ]; then
  echo "== removing menu bar login agent =="
  launchctl bootout "gui/$UID/$LABEL" >/dev/null 2>&1 || true
  rm -f "$PLIST"
  pkill -f "$HOST_PATTERN" >/dev/null 2>&1 || true
  sleep 4
  n="$(pgrep -f "$HOST_PATTERN" 2>/dev/null | wc -l | tr -d ' ')"
  echo "Done. Menu bar host instances now: $n (the app's own service keeps one)."
  echo "If the count is 0, open iStat Menus once to start it."
  exit 0
fi

APP="/Applications/iStat Menus.app"
[ -d "$APP" ] || APP="$HOME/Applications/iStat Menus.app"
[ -d "$APP" ] || { echo "[!] iStat Menus.app not found in /Applications or ~/Applications."; exit 1; }

BIN="$APP/Contents/Resources/iStat Menus Menubar.app/Contents/MacOS/iStat Menus Menubar"
[ -x "$BIN" ] || { echo "[!] Menu bar executable missing inside the app."; exit 1; }

MENUBAR_APP="$APP/Contents/Resources/iStat Menus Menubar.app"

# If the app's own host is already running, installing the fallback would
# create a SECOND host (duplicated menu bar items). Never do that.
if pgrep -f "$HOST_PATTERN" >/dev/null 2>&1; then
  echo "OK: the menu bar host is already running — the app manages it itself."
  echo "    No login-agent fallback needed."
  echo "    (If you ever see duplicated menu bar items, run:"
  echo "     \"$0\" --remove )"
  exit 0
fi

mkdir -p "$HOME/Library/LaunchAgents" || exit 1
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>$LABEL</string>
	<key>ProgramArguments</key>
	<array>
		<string>/usr/bin/open</string>
		<string>-g</string>
		<string>$MENUBAR_APP</string>
	</array>
	<key>RunAtLoad</key><true/>
	<key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
EOF

echo "== installing menu bar login agent =="
launchctl bootout "gui/$UID/$LABEL" >/dev/null 2>&1 || true
if ! launchctl bootstrap "gui/$UID" "$PLIST" 2>/dev/null; then
  echo "[!] launchctl bootstrap failed."
  exit 1
fi
# Start it now unless something already starts a host ("open" re-uses a
# running host, so this can never create a duplicate menu bar).
if ! pgrep -f "$HOST_PATTERN" >/dev/null 2>&1; then
  open -g "$MENUBAR_APP"
fi
sleep 3
if pgrep -f "$HOST_PATTERN" >/dev/null 2>&1; then
  echo "OK: menu bar host running (starts automatically at login)."
  echo "    Stop it anytime (quit from the iStat menu, or kill the process);"
  echo "    it returns at your next login."
  echo "    Undo: \"$0\" --remove"
  exit 0
fi
echo "[!] The menu bar host did not start. Open the app once, then retry."
exit 1
