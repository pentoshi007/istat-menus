# iStat Menus 7.50.1 — patched build

This is a patched copy of iStat Menus 7.50.1 (build 2356, universal x86_64 +
arm64). The licence checks and trial UI are removed: the app runs with every
feature enabled and behaves like a registered install — no trial countdown,
no expiry nag, no purchase window, no serial, no account.

## Install

1. Keep this whole folder together and **double-click `install.command`**.
   - If macOS refuses to open it: right-click → **Open** → **Open**.
   - If Finder says it “cannot be executed”: open Terminal in this folder and
     run `chmod +x install.command` first.
2. Wait ~30–60 seconds while it installs and signs the app, then it opens by
   itself.

No admin password is required for the normal install.

### What `install.command` does

- Copies **iStat Menus.app** to `/Applications` (falls back to
  `~/Applications` when needed) and removes the quarantine flag.
- Creates a one-time local signing identity in a dedicated keychain
  (`~/Library/Keychains/istat-crack.keychain-db`) and re-signs every
  component bottom-up. An existing identity is self-tested first and
  recreated automatically if it can no longer sign; only if no identity can
  be made does it fall back to ad-hoc signing.
- Writes a fresh trial-date marker for the app.
- Launches iStat Menus.
- If the menu bar host does not come up (macOS can refuse the app's own
  background-item registration for locally-signed builds), it installs a
  per-user login agent that starts it instead. The same thing is available
  any time as `menubar-fallback.command`.

### First launch

- Allow the Calendar / weather / location prompts as you like — the app
  works either way.
- During setup iStat Menus asks to install its helper service (used for fan
  control). You can allow it; if macOS refuses it, choose **Skip**.
  Monitoring of CPU, memory, network, disks, battery, time and sensors does
  not need it and keeps working.
- Menu bar items are hosted by the menu bar process, which starts
  automatically at login (see above).

### What was changed in the app

- Trial/expiry checks are neutralised in the main app and the menu bar
  helper: every feature stays enabled and the app never expires.
- The licence UI is normalised to a registered install: the trial countdown
  label is cleared and the expiry nag / purchase window can never appear —
  on every Mac, whatever dates or settings it finds.
- Auto-update is disabled, so nothing can replace this build with a stock
  (locked) copy.

### Things you may notice (by design)

- The purchase and registration screens still exist in the menus, but no
  trial or purchase prompt ever appears on its own.
- The app is signed locally, not notarized by Apple. It runs fine; do not
  run `spctl` checks (they are meant for notarized apps).

### Verify (optional)

```sh
codesign -dv --verbose=4 "/Applications/iStat Menus.app" | head
codesign --verify --verbose=2 "/Applications/iStat Menus.app"
# expected: Authority=iStat Local Signer; "valid on disk";
#           "satisfies its Designated Requirement"
```

### Stopping / Uninstalling

- Quitting the menu bar items (from the iStat menu) or killing the menu bar
  host hides them until the next login.
- To remove everything: double-click **`uninstall.command`** (or run it in
  Terminal). It stops the app, the menu bar host, the helper and the
  fan-control daemon, removes the login agent and deletes the app and its
  support data. Add `--purge` to also remove preferences and the local
  signing keychain:

  ```sh
  ./uninstall.command --purge
  ```

### Troubleshooting

- **“iStat Menus is damaged / cannot be opened”** — run `install.command`
  again (it clears quarantine and re-signs), or run manually:
  `xattr -cr "/Applications/iStat Menus.app"`.
- **No menu bar items appear** — run `menubar-fallback.command`; it starts
  the menu bar host and makes it start automatically at login. You can also
  launch it once directly:
  `open "/Applications/iStat Menus.app/Contents/Resources/iStat Menus Menubar.app"`.
  If macOS still refuses it, enable iStat Menus under System Settings →
  General → Login Items.
- **Menu bar items appear twice** — the login-agent fallback and the app's
  own service are both running (this happens if the fallback was installed
  and the app's own registration later started working). Fix:
  `./menubar-fallback.command --remove` — it removes the agent and leaves a
  single, app-managed host.
- **Fan control unavailable** — the root daemon could not be registered by
  macOS (it is stricter about locally-signed helpers). Use Skip in setup;
  everything else works.

*Use at your own risk. Keep the original download if you want to restore the
stock app later.*
