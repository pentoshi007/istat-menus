# iStat Menus 7.50.1 — patched macOS build

Locally patched **iStat Menus 7.50.1** (build 2356; universal — Apple Silicon
and Intel):

* 61 byte patches: trial/expiry logic neutralized, licensed-mode UI forced,
  update checkers stubbed to no-ops,
* privileged-helper plists relaxed so the app can be locally re-signed,
* re-signed with a one-time local identity and installed to `/Applications`;
  menu-bar items are hosted by a per-user login agent.

Verified on macOS 26 — install steps and technical details are in
`package/README.md`.

> **Read first**
> * For personal use. **Do not update iStat Menus afterwards** — updating
>   reinstalls the trial version; re-run the installer instead.
> * Normal install needs **no admin password** and touches nothing outside your
>   user account except `/Applications` (or `~/Applications` as a fallback).

## What you get

* `iStatMenus7.50.1-patched.zip` — the finished build: the app **plus** its
  installer, uninstaller and signing assets, all inside the zip.
* `bootstrap.command` — one-step install: extracts the zip and runs its installer.
* After install: every feature unlocked — no trial countdown, no expiry nag, no
  purchase window, no serial or account.

## Requirements

* macOS 13 (Ventura) or newer — Apple Silicon or Intel.
* A couple hundred MB of free disk space.
* Internet only to download this repo; the install itself is fully offline.

## Step-by-step install

**1. Get the repo**

```bash
git clone https://github.com/pentoshi007/istat-menus.git
cd istat-menus
```

(or the green **Code** button → *Download ZIP*)

**2. Run the bootstrap**

```bash
bash bootstrap.command
```

It extracts `iStatMenus7.50.1-patched.zip` and runs the installer inside, which:

* copies **iStat Menus.app** to `/Applications` (falls back to
  `~/Applications` if that isn't writable) and clears the quarantine flag;
* creates a one-time local signing identity in a dedicated keychain
  (`~/Library/Keychains/istat-crack.keychain-db`) and re-signs every component
  bottom-up — an existing identity is self-tested first and recreated
  automatically if it went stale; if no identity can be made it falls back to
  ad-hoc signing;
* writes a fresh trial-date marker and launches the app;
* installs a per-user login agent to host the menu-bar items (macOS sometimes
  refuses the app's own background-item registration for locally-signed builds).

*Manual alternative:* unzip `iStatMenus7.50.1-patched.zip` in Finder and
double-click `install.command` inside it (right-click → **Open** if macOS
complains).

**3. First launch** — allow the Calendar / weather / location prompts as you
like; the app works either way. When it offers to install its fan-control helper
service you can allow it; if macOS refuses, choose **Skip** — CPU, memory,
network, disks, battery, time and sensors all keep working without it.

## Troubleshooting — issues you might face

**"Apple cannot check it for malicious software" / "unidentified developer"** —
normal for locally signed apps on first run: right-click the app (or
`install.command`) → **Open** → **Open** again. Terminal alternative:
`xattr -d com.apple.quarantine <path>`.

**Finder says `install.command` "cannot be executed"** — run
`chmod +x install.command` in that folder, or just use `bash bootstrap.command`.

**Nothing appears in the menu bar** — the login agent didn't come up. Restart it:

```bash
bash package/menubar-fallback.command
```

(then log out and back in if it still doesn't appear).

**A keychain prompt appears while installing** — allow it; the identity lives in
the dedicated `istat-crack` keychain with password `istatcrack` and never touches
your login keychain items.

**Trial counter / purchase window / "expired" appears again** — the patched
files were replaced by an app update. Do not update; unzip the patched zip again
and re-run `install.command`.

**The app won't launch after a macOS update** — re-run the installer; it
recreates the signing identity if it went stale and re-signs everything.

**Fan control says the helper isn't available** — the privileged helper didn't
get installed (usually macOS refusing a locally-signed helper). Monitoring is
unaffected; if you want fan control, re-run the app and accept the helper
prompt — it works on most systems.

**It installed to `~/Applications` instead of `/Applications`** — your user
can't write `/Applications`; that's fine (everything works), though
helper-service support is best from `/Applications`.

## Uninstall

```bash
bash package/uninstall.command            # remove app + menu-bar login agent
bash package/uninstall.command --purge    # also preferences + signing keychain
```

Stops everything, removes the app, the menu-bar agent and its support data.

## Layout

    iStatMenus7.50.1-patched.zip   finished, installable build (app + installer + signing)
    bootstrap.command              one step: extract the zip + install
    package/                       installer/uninstaller + signing assets (package/README.md)
    iStatMenus7.50.1.zip           original unpatched download (provenance)
    work/                          scratch copies used while developing the patches
