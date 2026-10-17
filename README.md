# iStat Menus 7.50.1 — patched macOS build

Locally patched iStat Menus 7.50.1 (universal: arm64 + x86_64):

* 61 byte patches: trial/expiry logic neutralized, licensed-mode UI forced,
  update checkers stubbed to no-ops,
* privileged-helper plists relaxed for local signing,
* re-signed with a local identity and installed at `/Applications`; menu-bar
  items hosted by a login agent, fan-control daemon running.

Verified on macOS 26 — the full patch table, crash-fix notes and verification
details are in `NEXT_STEPS.md` (read it first).

## Deliverable

`iStatMenus7.50.1-patched.zip` — the finished, installable build.
`package/` — installer/uninstaller and signing assets used to produce it
(`package/README.md`).
`iStatMenus7.50.1.zip` — the original unpatched download (provenance).
`work/` — scratch copies used while developing the patches.
