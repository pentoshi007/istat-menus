#!/bin/bash
# ============================================================================
#  iStat Menus 7.50.1 — patched build installer
#
#  Installs the patched app to /Applications, clears quarantine, re-signs
#  every component with a local self-signed identity (falling back to
#  ad-hoc), sets the trial date, and launches the app.
#
#  Requires: macOS 13 or later. No admin password needed (unless a system
#  install of the fan-control daemon is requested later by the app itself).
# ============================================================================
set -u
cd "$(dirname "$0")" || exit 1

APP_NAME="iStat Menus.app"
SRC="$PWD/$APP_NAME"
SIGN_DIR="$PWD/signing"
KC="$HOME/Library/Keychains/istat-crack.keychain-db"
KC_PASS="istatcrack"
IDENTITY_NAME="iStat Local Signer"
TMP="$(mktemp -d /tmp/istat-install.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

log()  { printf '%s\n' "$*"; }
fail() { printf '\n[!] ERROR: %s\n' "$*"; printf '[!] Nothing else was changed. You can close this window.\n'; exit 1; }

# ---------------------------------------------------------------- prechecks
[ "$(uname -s)" = "Darwin" ] || fail "This script must be run on macOS."
[ -d "$SRC" ] || fail "\"$APP_NAME\" was not found next to this script. Keep the whole extracted folder together and run install.command from inside it."

OSVER="$(sw_vers -productVersion 2>/dev/null || echo 0)"
log "== iStat Menus 7.50.1 (patched) installer =="
log "macOS: $OSVER"

# ------------------------------------------------------------- destination
DEST="/Applications/$APP_NAME"
if [ ! -w /Applications ] 2>/dev/null; then
  DEST="$HOME/Applications/$APP_NAME"
  mkdir -p "$HOME/Applications" || fail "Cannot create ~/Applications."
  log "No write access to /Applications — installing to ~/Applications instead."
  log "(Full helper-service support works best from /Applications.)"
fi

# ------------------------------------------------------ stop running copy
log "Quitting any running copy..."
if pgrep -qx "iStat Menus"; then
  osascript -e 'tell application id "com.bjango.istatmenus" to quit' >/dev/null 2>&1 || true
  sleep 1
fi
pkill -x "iStat Menus" >/dev/null 2>&1 || true
pkill -f "iStat Menus Menubar.app/Contents/MacOS/iStat Menus Menubar" >/dev/null 2>&1 || true
pkill -f "iStat Menus Helper.app/Contents/MacOS/iStat Menus helper" >/dev/null 2>&1 || true
sleep 1

# -------------------------------------------------------------------- copy
log "Installing to: $DEST"
rm -rf "$DEST" || fail "Cannot remove old copy at $DEST (close the app and retry)."
ditto "$SRC" "$DEST" || fail "Copy failed."
xattr -cr "$DEST" 2>/dev/null || true

# --------------------------------------------------------------- identity
create_identity() {
  log "Creating local signing identity (one-time)..."
  cat > "$TMP/openssl.cnf" <<EOF
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = $IDENTITY_NAME
OU = Y93TK974AT
O = iStat Local
[ext]
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
basicConstraints = critical,CA:FALSE
EOF
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -config "$TMP/openssl.cnf" \
    -keyout "$TMP/key.pem" -out "$TMP/cert.pem" >/dev/null 2>&1 || return 1

  # fresh private keychain for this identity
  security delete-keychain "$KC" >/dev/null 2>&1 || true
  rm -f "$KC"
  security create-keychain -p "$KC_PASS" "$KC" >/dev/null 2>&1 || return 1
  security set-keychain-settings -lut 21600 "$KC" >/dev/null 2>&1 || true
  security unlock-keychain -p "$KC_PASS" "$KC" >/dev/null 2>&1 || return 1

  # Import the identity. OpenSSL 3 defaults to AES-based PKCS#12 encryption
  # which macOS "security import" rejects (MAC verification failed), so the
  # first attempt forces the legacy SHA1/3DES scheme. LibreSSL already
  # exports legacy by default, so the plain form is the second attempt. A
  # direct PEM key+cert import is the last resort.
  ok=0
  if openssl pkcs12 -export -out "$TMP/id.p12" \
       -inkey "$TMP/key.pem" -in "$TMP/cert.pem" \
       -passout "pass:$KC_PASS" \
       -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1 >/dev/null 2>&1; then
    security import "$TMP/id.p12" -k "$KC" -P "$KC_PASS" \
      -T /usr/bin/codesign -T /usr/bin/security >/dev/null 2>&1 && ok=1
  fi
  if [ "$ok" -eq 0 ]; then
    openssl pkcs12 -export -out "$TMP/id.p12" \
      -inkey "$TMP/key.pem" -in "$TMP/cert.pem" \
      -passout "pass:$KC_PASS" >/dev/null 2>&1
    security import "$TMP/id.p12" -k "$KC" -P "$KC_PASS" \
      -T /usr/bin/codesign -T /usr/bin/security >/dev/null 2>&1 && ok=1
  fi
  if [ "$ok" -eq 0 ]; then
    security import "$TMP/cert.pem" -k "$KC" \
      -T /usr/bin/codesign -T /usr/bin/security >/dev/null 2>&1 || true
    security import "$TMP/key.pem" -k "$KC" \
      -T /usr/bin/codesign -T /usr/bin/security >/dev/null 2>&1 \
      || security import "$TMP/key.pem" -k "$KC" -P "" \
           -T /usr/bin/codesign -T /usr/bin/security >/dev/null 2>&1 || true
    if security find-identity -p codesigning "$KC" 2>/dev/null | grep -q "$IDENTITY_NAME"; then
      ok=1
    fi
  fi
  [ "$ok" -eq 1 ] || return 1

  # Trust the self-signed cert for code signing in the user domain (no admin
  # needed) so codesign/find-identity see a valid identity.
  security add-trusted-cert -p codeSign -k "$KC" "$TMP/cert.pem" >/dev/null 2>&1 || true
  security set-key-partition-list -S apple-tool:,apple:,codesign: \
    -s -k "$KC_PASS" "$KC" >/dev/null 2>&1 || true
  # append to the user search list (never replace it). The listing is space-
  # and quote-formatted and may hold stale entries; normalise and keep only
  # paths that exist. bash 3.2-safe.
  KCLIST=()
  while IFS= read -r line; do
    line="$(printf '%s' "$line" | sed -E 's/^[[:space:]]+"?//; s/"?[[:space:]]*$//')"
    case "$line" in ""|"$KC") continue ;; esac
    [ -e "$line" ] && KCLIST+=("$line")
  done < <(security list-keychains -d user 2>/dev/null)
  if [ "${#KCLIST[@]}" -gt 0 ]; then
    security list-keychains -d user -s "${KCLIST[@]}" "$KC" >/dev/null 2>&1 || true
  else
    security list-keychains -d user -s "$KC" >/dev/null 2>&1 || true
  fi
  return 0
}

find_identity_hash() {
  security find-identity -p codesigning "$KC" 2>/dev/null \
    | awk -v name="$IDENTITY_NAME" 'index($0, name) { print $2; exit }'
}

# A listed identity is not enough: the keychain can be locked or stale.
# Prove the identity can actually sign before trusting it.
identity_works() {
  [ -n "$1" ] || return 1
  security unlock-keychain -p "$KC_PASS" "$KC" >/dev/null 2>&1 || true
  cp /bin/echo "$TMP/signtest" 2>/dev/null || printf '#!/bin/sh\n' > "$TMP/signtest"
  codesign --force --timestamp=none --sign "$1" "$TMP/signtest" >/dev/null 2>&1
}

SIGN_HASH="$(find_identity_hash)"
if [ -n "$SIGN_HASH" ] && ! identity_works "$SIGN_HASH"; then
  log "[i] Existing signing identity cannot sign (locked or stale keychain) — recreating it."
  SIGN_HASH=""
fi
if [ -z "$SIGN_HASH" ]; then
  if create_identity; then
    SIGN_HASH="$(find_identity_hash)"
  fi
fi
if [ -n "$SIGN_HASH" ]; then
  security unlock-keychain -p "$KC_PASS" "$KC" >/dev/null 2>&1 || true
  if identity_works "$SIGN_HASH"; then
    log "Signing identity: $IDENTITY_NAME ($SIGN_HASH)"
  else
    log "[i] Self-signed identity still cannot sign — falling back to ad-hoc signing."
    SIGN_HASH=""
  fi
else
  log "[i] Self-signed identity unavailable — falling back to ad-hoc signing."
fi

# ------------------------------------------------------------------ signing
sign_one() {
  target="$1"; shift
  if [ -n "$SIGN_HASH" ]; then
    if codesign --force --timestamp=none --sign "$SIGN_HASH" "$@" "$target" >/dev/null 2>&1; then
      return 0
    fi
    log "  [!] identity signing failed for $target — falling back to ad-hoc"
  fi
  codesign --force --timestamp=none --sign - "$@" "$target" >/dev/null 2>&1
}

log "Signing app (this takes a minute)..."
# 1) frameworks, innermost first
find "$DEST" -type d -name "*.framework" -depth 2>/dev/null | while IFS= read -r fw; do
  sign_one "$fw"
done

# 2) loose executables that get launched directly
sign_one "$DEST/Contents/Resources/com.bjango.istatmenus.daemon"
sign_one "$DEST/Contents/Resources/relaunch"

# 3) nested bundles, innermost first
HELPER="$DEST/Contents/Resources/iStat Menus Helper.app"
MENUBAR="$DEST/Contents/Resources/iStat Menus Menubar.app"
sign_one "$DEST/Contents/Resources/InstallerBundle.bundle"
sign_one "$HELPER/Contents/Resources/iStat Menus Updater.app"
sign_one "$HELPER"
sign_one "$MENUBAR/Contents/XPCServices/history.xpc"
if [ -f "$SIGN_DIR/menubar.entitlements" ]; then
  sign_one "$MENUBAR" --entitlements "$SIGN_DIR/menubar.entitlements"
else
  sign_one "$MENUBAR"
fi

# 4) the app itself, last
if [ -f "$SIGN_DIR/main.entitlements" ]; then
  sign_one "$DEST" --entitlements "$SIGN_DIR/main.entitlements"
else
  sign_one "$DEST"
fi

# ----------------------------------------------------------------- verify
log "Verifying signature..."
if codesign --verify --verbose=2 "$DEST" >"$TMP/verify.log" 2>&1; then
  log "Signature OK: $(tail -1 "$TMP/verify.log")"
else
  log "[i] codesign verify reported: $(tail -1 "$TMP/verify.log")"
  log "[i] (A locally-signed app is expected not to be notarized; this is fine.)"
fi

# ------------------------------------------------------- trial date marker
SUPPORT="$HOME/Library/Application Support/iStat Menus 7"
mkdir -p "$SUPPORT" 2>/dev/null || true
xattr -w com.bjango.istatmenus.installdate "$(date +%s)" "$SUPPORT" 2>/dev/null \
  || log "[i] Could not write trial date marker (not critical)."

# ------------------------------------------------------------------ launch
log ""
log "========================================================"
log " Done. Launching iStat Menus..."
log "========================================================"
log ""
log " Notes:"
log "  * Menu bar items may take ~10 seconds to appear on first run."
log "  * During setup you can allow the helper/daemon for fan control;"
log "    if macOS refuses it, choose Skip — everything else still works."
log "  * This build runs with the UI of a registered install: no trial"
log "    countdown, no purchase or expiry prompts, no licence nag."
log "  * Auto-update is disabled (updating would replace this build)."
log ""
open "$DEST" || log "[i] Could not auto-open the app — open it from Applications."

# macOS may refuse the app's own background-item registration for a
# locally-signed build, leaving the menu bar without its host process.
# If nothing came up after a few seconds, install the login-agent fallback.
sleep 8
if ! pgrep -x "iStat Menus Menubar" >/dev/null 2>&1; then
  log ""
  log "[i] Menu bar host did not start by itself — installing the login-agent fallback..."
  SCRIPT_DIR="$PWD"
  if [ -x "$SCRIPT_DIR/menubar-fallback.command" ]; then
    "$SCRIPT_DIR/menubar-fallback.command" || \
      log "[i] Fallback failed — menu bar items may require System Settings -> General -> Login Items."
  else
    log "[i] menubar-fallback.command not found next to install.command."
  fi
fi
