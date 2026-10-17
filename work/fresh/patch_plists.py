#!/usr/bin/env python3
"""t4: relax SMJobBless-style code-signing requirement strings so the
re-signed build (no Apple anchor) can still use the legacy installer path.

SMAppService (macOS 13+ daemon/agent registration) does not read these keys;
they are only used by the legacy SMJobBless flow. Rewriting them to an
identifier-only requirement keeps that path usable after re-signing.
"""
import plistlib, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(HERE, "iStat Menus.app")

TARGETS = [
    "Contents/Info.plist",
    "Contents/Resources/iStat Menus Helper.app/Contents/Info.plist",
]
NEW_REQ = 'identifier "com.bjango.istatmenus.installer"'


def main():
    for rel in TARGETS:
        path = os.path.join(APP, rel)
        with open(path, "rb") as fh:
            pl = plistlib.load(fh)
        changed = False
        spe = pl.get("SMPrivilegedExecutables")
        if isinstance(spe, dict):
            for key in list(spe):
                if spe[key] != NEW_REQ:
                    print(f"  [plist] {rel}: SMPrivilegedExecutables[{key}] relaxed")
                    spe[key] = NEW_REQ
                    changed = True
        if changed:
            with open(path, "wb") as fh:
                plistlib.dump(pl, fh)  # default FMT_XML matches original
        else:
            print(f"  [plist] {rel}: already relaxed")
        # verify round-trip
        with open(path, "rb") as fh:
            check = plistlib.load(fh)
        val = check.get("SMPrivilegedExecutables", {}).get("com.bjango.istatmenus.installer")
        assert val == NEW_REQ, f"{rel}: verification failed: {val!r}"
        print(f"  [plist] {rel}: verified -> {val!r}")


if __name__ == "__main__":
    main()
