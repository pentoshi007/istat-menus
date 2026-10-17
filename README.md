# iStat Menus 7.50.1 — patched macOS build

Locally patched iStat Menus 7.50.1 (universal: arm64 + x86_64):

* 61 byte patches: trial/expiry logic neutralized, licensed-mode UI forced,
  update checkers stubbed to no-ops,
* privileged-helper plists relaxed for local signing,
* re-signed with a local identity and installed at `/Applications`; menu-bar
  items hosted by a login agent, fan-control daemon running.

Verified on macOS 26 — install steps and technical details are in
`package/README.md`.

## Deliverable

`iStatMenus7.50.1-patched.zip` — the finished, installable build (contains the
app plus its installer and signing assets).
`bootstrap.command` — one-step install: extracts the zip and runs its
installer (or unzip manually and double-click `install.command`).
`package/` — installer/uninstaller and signing assets used to produce it
(`package/README.md`).
`iStatMenus7.50.1.zip` — the original unpatched download (provenance).
`work/` — scratch copies used while developing the patches.
