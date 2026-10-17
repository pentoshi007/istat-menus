#!/usr/bin/env python3
"""Read-only verification that the iStat Menus 7.50.1 patches are present.

Nothing is ever modified. Run it on any copy of the patched app, e.g. after
installing on the Mac:

    python3 verify_patches.py                          # checks "iStat Menus.app" next to this file
    python3 verify_patches.py "/Applications/iStat Menus.app"

Checks:
  * main app (x86_64 + arm64):      trial-days computation forced to 30
  * main app (x86_64 + arm64):      licensed-mode UI normalization (trial
                                    label cleared, expiry nag + purchase
                                    window disabled)
  * menubar app (x86_64 + arm64):   trial-active flag forced true
  * every BBRUpdater copy:          6 update methods stubbed to no-op
  * main + helper Info.plist:       SMPrivilegedExecutables relaxed (no
                                    "anchor apple generic" requirement)

Exit status: 0 = all patches present, 1 = something is missing, 2 = error
(app/binary not found or unreadable).
"""
import os
import plistlib
import struct
import sys

ARM64 = 0x100000c
X86_64 = 0x1000007

MAIN = "Contents/MacOS/iStat Menus"
MENUBAR = "Contents/Resources/iStat Menus Menubar.app/Contents/MacOS/iStat Menus Menubar"
HELPER_PLIST = "Contents/Resources/iStat Menus Helper.app/Contents/Info.plist"

# (slice_cputype, vaddr, expected_original_hex, patched_hex, description)
# Same table as patch_istat.py.
FIXED_SITES = {
    MAIN: [
        (ARM64, 0x10006c220, "0c030054", "0840601e",
         "trial days = 30 (fmov d8, d0)"),
        (X86_64, 0x10009645d, "f20f5e0d2bac0a00", "f20f100d33ac0a00",
         "trial days = 30 (movsd xmm1, [30.0])"),
        (ARM64, 0x10006c06c, "a8050054", "1f2003d5",
         "licensed UI: updateLicensingState label-clear path (b.hi -> nop)"),
        (ARM64, 0x10006b5ec, "23140054", "a1000014",
         "licensed UI: showExpiryIfNeeded early return (b.lo -> b ret)"),
        (ARM64, 0x10006bad8, "f657bda9", "c0035fd6",
         "licensed UI: showPurchase no-op (ret)"),
        (ARM64, 0x1000a2664, "ff8301d1", "c0035fd6",
         "licensed UI: showExpired no-op (ret)"),
        (X86_64, 0x100096211, "0f8716010000", "909090909090",
         "licensed UI: updateLicensingState label-clear path (ja -> nop)"),
        (X86_64, 0x10009549e, "0f820b030000", "e90b03000090",
         "licensed UI: showExpiryIfNeeded early return (jb -> jmp ret)"),
        (X86_64, 0x100095a66, "55", "c3",
         "licensed UI: showPurchase no-op (ret)"),
        (X86_64, 0x1000dfe85, "55", "c3",
         "licensed UI: showExpired no-op (ret)"),
    ],
    MENUBAR: [
        (ARM64, 0x100027760, "f343881a", "33008052",
         "trial-active bool = 1 (movz w19, #1)"),
        (ARM64, 0x100027768, "130080d2", "330080d2",
         "trial-active odd-path fixup (movz x19, #1)"),
        (X86_64, 0x100035b71, "660f54d1", "660f76d2",
         "trial-active bool = 1 (pcmpeqd xmm2, xmm2)"),
    ],
}

# movz x0, #0 = word 0xd2800000, ret = word 0xd65f03c0.
# File bytes are little-endian, so the byte order is reversed per instruction.
NOP_RET_A64 = bytes.fromhex("000080d2c0035fd6")  # mov x0, #0 ; ret
NOP_RET_X64 = bytes.fromhex("31c0c3")            # xor eax, eax ; ret

UPDATER_METHODS_INST = (
    "checkForUpdates:",
    "downloadUpdate:",
    "downloadFullUpdate:",
    "handleUpdate:completion:",
    "handlePatch:completion:",
)
UPDATER_METHODS_META = ("checkForUpdates:completion:",)

RESULTS = []  # (label, status, detail)


def report(label, status, detail=""):
    RESULTS.append((label, status, detail))
    line = f"  {label:<66} {status}"
    if detail:
        line += f"  [{detail}]"
    print(line)


# ---------------------------------------------------------------- Mach-O utils
# (same parsing as patch_istat.py)
def parse_fat(data):
    magic = struct.unpack(">I", data[:4])[0]
    if magic not in (0xcafebabe, 0xcafebabf):
        cputype = struct.unpack("<i", data[4:8])[0] & 0xFFFFFFFF
        return [(cputype, 0, len(data))]
    n = struct.unpack(">I", data[4:8])[0]
    wide = magic == 0xcafebabf
    out = []
    for i in range(n):
        if wide:
            ct, cs, off, size = struct.unpack(">iiQQ", data[8 + i * 32: 8 + i * 32 + 24])
        else:
            ct, cs, off, size = struct.unpack(">iiII", data[8 + i * 20: 8 + i * 20 + 16])
        out.append((ct & 0xFFFFFFFF, off, size))
    return out


def segments(data):
    ncmds = struct.unpack("<I", data[16:20])[0]
    p = 32
    segs = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack("<II", data[p:p + 8])
        if cmd == 0x19:
            name = data[p + 8:p + 24].split(b"\0")[0].decode()
            vm, vs, fo, fs = struct.unpack("<QQQQ", data[p + 24:p + 56])
            segs.append((name, vm, vs, fo, fs))
        p += cmdsize
    return segs


def sections(data):
    ncmds = struct.unpack("<I", data[16:20])[0]
    p = 32
    out = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack("<II", data[p:p + 8])
        if cmd == 0x19:
            segname = data[p + 8:p + 24].split(b"\0")[0].decode()
            nsects = struct.unpack("<I", data[p + 64:p + 68])[0]
            sp = p + 72
            for _ in range(nsects):
                sectname = data[sp:sp + 16].split(b"\0")[0].decode()
                addr, size = struct.unpack("<QQ", data[sp + 32:sp + 48])
                off = struct.unpack("<I", data[sp + 48:sp + 52])[0]
                out.append((segname, sectname, addr, size, off))
                sp += 80
        p += cmdsize
    return out


def v2o(segs, v):
    for name, vm, vs, fo, fs in segs:
        if vm <= v < vm + vs:
            return fo + (v - vm)
    return None


def image_base(segs):
    return next(s for s in segs if s[0] == "__TEXT")[1]


def chained_ptr(data, segs, v):
    o = v2o(segs, v)
    if o is None:
        return None
    raw = struct.unpack("<Q", data[o:o + 8])[0]
    if raw == 0:
        return 0
    if raw >> 63:
        return None
    return image_base(segs) + (raw & 0xFFFFFFFFF)


def cstr(data, segs, v, n=256):
    if not v:
        return None
    o = v2o(segs, v)
    if o is None:
        return None
    return data[o:o + n].split(b"\0")[0].decode("utf8", "replace")


def find_objc_class(data, segs, want):
    cl = next((s for s in sections(data) if s[1] == "__objc_classlist"), None)
    if not cl:
        return None
    addr, size = cl[2], cl[3]
    for i in range(size // 8):
        cls = chained_ptr(data, segs, addr + i * 8)
        if not cls or cls == 0:
            continue
        ro = chained_ptr(data, segs, cls + 32)
        if not ro:
            continue
        ro &= ~0x7
        if cstr(data, segs, chained_ptr(data, segs, ro + 24)) == want:
            return cls
    return None


def rel_method_list(data, segs, addr):
    o = v2o(segs, addr)
    ent = struct.unpack("<I", data[o:o + 4])[0]
    n = struct.unpack("<I", data[o + 4:o + 8])[0]
    if n > 4096:
        return []
    rel = bool(ent & 0x80000000)
    stride = 12 if rel else 24
    out = []
    for i in range(n):
        e = addr + 8 + i * stride
        eo = v2o(segs, e)
        if rel:
            d0 = struct.unpack("<i", data[eo:eo + 4])[0]
            d2 = struct.unpack("<i", data[eo + 8:eo + 12])[0]
            name = cstr(data, segs, chained_ptr(data, segs, e + d0) or 0)
            imp = e + 8 + d2
        else:
            name = cstr(data, segs, chained_ptr(data, segs, e) or 0)
            imp = chained_ptr(data, segs, e + 16)
        out.append((name, imp))
    return out


def class_methods(data, segs, cls):
    ro = chained_ptr(data, segs, cls + 32)
    if not ro:
        return {}
    ml = chained_ptr(data, segs, (ro & ~0x7) + 32)
    return {n: i for n, i in rel_method_list(data, segs, ml) if n} if ml else {}


def meta_methods(data, segs, cls):
    meta = chained_ptr(data, segs, cls)
    if not meta:
        return {}
    ro = chained_ptr(data, segs, meta + 32)
    if not ro:
        return {}
    ml = chained_ptr(data, segs, (ro & ~0x7) + 32)
    return {n: i for n, i in rel_method_list(data, segs, ml) if n} if ml else {}


def arch_name(ct):
    return {ARM64: "arm64", X86_64: "x86_64"}.get(ct, hex(ct))


# ------------------------------------------------------------------- checks
def check_fixed(app, rel):
    path = os.path.join(app, rel)
    label = rel.split("/")[-1]
    try:
        data = open(path, "rb").read()
    except OSError as e:
        report(f"{label}: file", "ERROR", str(e))
        return
    for ct, off, size in parse_fat(data):
        sd = data[off:off + size]
        segs = segments(sd)
        for sct, vaddr, exp, new, desc in FIXED_SITES[rel]:
            if sct != ct:
                continue
            tag = f"{label} {arch_name(ct)} {vaddr:#x} {desc}"
            o = v2o(segs, vaddr)
            newb, expb = bytes.fromhex(new), bytes.fromhex(exp)
            if o is None:
                report(tag, "ERROR", "vaddr unmapped")
                continue
            cur = data[off + o: off + o + len(newb)]
            if cur == newb:
                report(tag, "PATCHED")
            elif cur == expb:
                report(tag, "NOT PATCHED", "original bytes still present")
            else:
                report(tag, "UNEXPECTED", f"got {cur.hex()}")


def find_updaters(app):
    out = []
    for root, dirs, files in os.walk(app):
        if root.endswith("BBRUpdater.framework/Versions/A") and "BBRUpdater" in files:
            out.append(os.path.join(root, "BBRUpdater"))
    return sorted(out)


def check_updater(app, path):
    rel = os.path.relpath(path, app)
    try:
        data = open(path, "rb").read()
    except OSError as e:
        report(f"{rel}: file", "ERROR", str(e))
        return
    for ct, off, size in parse_fat(data):
        sd = data[off:off + size]
        segs = segments(sd)
        arch = arch_name(ct)
        cls = find_objc_class(sd, segs, "BBRUpdater")
        if cls is None:
            report(f"{rel} {arch}: BBRUpdater class", "ERROR", "class not found")
            continue
        inst = class_methods(sd, segs, cls)
        meta = meta_methods(sd, segs, cls)
        targets = []
        for sel in UPDATER_METHODS_INST:
            if sel in inst:
                targets.append((sel, inst[sel]))
            else:
                report(f"{rel} {arch} {sel}", "ERROR", "method not found")
        for sel in UPDATER_METHODS_META:
            if sel in meta:
                targets.append((sel, meta[sel]))
            else:
                report(f"{rel} {arch} {sel}", "ERROR", "method not found")
        for sel, imp in targets:
            patch = NOP_RET_A64 if ct == ARM64 else NOP_RET_X64
            o = v2o(segs, imp)
            tag = f"{rel} {arch} {sel}"
            if o is None or not (0 < o < size - 8):
                report(tag, "ERROR", f"bad imp {imp:#x}")
                continue
            cur = data[off + o: off + o + len(patch)]
            if cur == patch:
                report(tag, "PATCHED")
            else:
                report(tag, "NOT PATCHED", f"got {cur.hex()}")


def check_plists(app):
    for rel in ("Contents/Info.plist", HELPER_PLIST):
        key = "SMPrivilegedExecutables"
        tag = f"{rel} {key}"
        try:
            with open(os.path.join(app, rel), "rb") as f:
                pl = plistlib.load(f)
        except Exception as e:  # plistlib raises several types
            report(tag, "ERROR", str(e))
            continue
        val = pl.get(key)
        if not val:
            report(tag, "MISSING", "key absent")
        elif "anchor apple generic" in str(val):
            report(tag, "NOT RELAXED", "still requires Apple-signed anchor")
        else:
            report(tag, "RELAXED")


def main():
    app = (sys.argv[1] if len(sys.argv) > 1
           else os.path.join(os.path.dirname(os.path.abspath(__file__)), "iStat Menus.app"))
    if not os.path.isdir(app):
        sys.exit(f"app not found: {app}")
    print(f"app: {app}")
    print("== main app:")
    check_fixed(app, MAIN)
    print("== menubar app:")
    check_fixed(app, MENUBAR)
    ups = find_updaters(app)
    print(f"== updater copies ({len(ups)} found):")
    for up in ups:
        check_updater(app, up)
    print("== helper-registration plists:")
    check_plists(app)

    good = [r for r in RESULTS if r[1] in ("PATCHED", "RELAXED")]
    bad = [r for r in RESULTS if r[1] not in ("PATCHED", "RELAXED")]
    byte_sites = [r for r in RESULTS if "Info.plist" not in r[0]]
    print()
    print(f"summary: {len(byte_sites)} byte sites checked, "
          f"{len(byte_sites) - len([r for r in bad if 'Info.plist' not in r[0]])} patched; "
          f"{len(RESULTS) - len(byte_sites)} plist checks, "
          f"{len([r for r in good if 'Info.plist' in r[0]])} relaxed")
    if bad:
        print("RESULT: PROBLEMS FOUND:")
        for label, status, detail in bad:
            print(f"  - {label}: {status}" + (f" [{detail}]" if detail else ""))
        sys.exit(1)
    print("RESULT: ALL PATCHES PRESENT")
    sys.exit(0)


if __name__ == "__main__":
    main()
