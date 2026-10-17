#!/usr/bin/env python3
"""Apply iStat Menus 7.50.1 license/trial/updater patches in-place.

Patches (same-size, in-place; signature becomes invalid by design and is
re-created on macOS by install/install.command):

  main app (both slices):
    * trial days computation -> constant "30 days remaining", never expired
    * licensed-mode UI normalization: the trial label is always cleared and
      the expiry nag / purchase window can never appear (the UI behaves like
      a registered install on every Mac, whatever dates it computes)
  menubar app (both slices):
    * trial-active boolean -> always true (lstate stays 1 = full features)
  every BBRUpdater.framework copy (both slices):
    * checkForUpdates:/+checkForUpdates:completion:, downloadUpdate:,
      downloadFullUpdate:, handleUpdate:completion:, handlePatch:completion:
      -> immediate return (updates can no longer replace the patched app)

Idempotent: a second run reports "already patched" instead of rewriting.
"""
import struct, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(HERE, "iStat Menus.app")

ARM64 = 0x100000c
X86_64 = 0x1000007

MAIN = "Contents/MacOS/iStat Menus"
MENUBAR = "Contents/Resources/iStat Menus Menubar.app/Contents/MacOS/iStat Menus Menubar"

# (slice_cputype, vaddr, expect_hex, new_hex, description)
FIXED_SITES = {
    MAIN: [
        (ARM64, 0x10006c220, "0c030054", "0840601e",
         "trial display: force 30 days remaining (fmov d8, d0)"),
        (X86_64, 0x10009645d, "f20f5e0d2bac0a00", "f20f100d33ac0a00",
         "trial display: force 30 days remaining (movsd xmm1, [30.0])"),
        # licensed-mode UI normalization: make the UI behave exactly like a
        # registered install (state 1/2 goes down the "clear the label"
        # branch) no matter what licence state the app computes.
        (ARM64, 0x10006c06c, "a8050054", "1f2003d5",
         "licensed UI: updateLicensingState always clears the trial label (b.hi -> nop)"),
        (ARM64, 0x10006b5ec, "23140054", "a1000014",
         "licensed UI: showExpiryIfNeeded always returns early (b.lo -> b ret)"),
        (ARM64, 0x10006bad8, "f657bda9", "c0035fd6",
         "licensed UI: showPurchase is a no-op (ret)"),
        (ARM64, 0x1000a2664, "ff8301d1", "c0035fd6",
         "licensed UI: SettingsInstaller.showExpired is a no-op (ret)"),
        (X86_64, 0x100096211, "0f8716010000", "909090909090",
         "licensed UI: updateLicensingState always clears the trial label (ja -> nop)"),
        (X86_64, 0x10009549e, "0f820b030000", "e90b03000090",
         "licensed UI: showExpiryIfNeeded always returns early (jb -> jmp ret)"),
        (X86_64, 0x100095a66, "55", "c3",
         "licensed UI: showPurchase is a no-op (ret)"),
        (X86_64, 0x1000dfe85, "55", "c3",
         "licensed UI: SettingsInstaller.showExpired is a no-op (ret)"),
    ],
    MENUBAR: [
        (ARM64, 0x100027760, "f343881a", "33008052",
         "trial-active bool = 1 (movz w19, #1)"),
        (ARM64, 0x100027768, "130080d2", "330080d2",
         "trial-active when xattr absent (movz x19, #1)"),
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


def apply_fixed(fatpath):
    path = os.path.join(APP, fatpath)
    data = bytearray(open(path, "rb").read())
    sites = FIXED_SITES[fatpath]
    applied = already = 0
    for ct, off, size in parse_fat(bytes(data)):
        sd = bytes(data[off:off + size])
        segs = segments(sd)
        for sct, vaddr, exp, new, desc in sites:
            if sct != ct:
                continue
            o = v2o(segs, vaddr)
            if o is None:
                sys.exit(f"FAIL {fatpath} cpu={ct:#x}: unmapped vaddr {vaddr:#x}")
            newb = bytes.fromhex(new)
            expb = bytes.fromhex(exp)
            cur = bytes(data[off + o: off + o + len(newb)])
            if cur == newb:
                already += 1
                continue
            if cur != expb:
                sys.exit(f"FAIL {fatpath} cpu={ct:#x} @ {vaddr:#x} ({desc}): "
                         f"unexpected bytes {cur.hex()}")
            data[off + o: off + o + len(newb)] = newb
            applied += 1
            print(f"  [main] {fatpath} cpu={ct:#x} {vaddr:#x}: {desc}")
    open(path, "wb").write(bytes(data))
    return applied, already


def apply_updater(fatpath):
    data = bytearray(open(fatpath, "rb").read())
    applied = already = 0
    for ct, off, size in parse_fat(bytes(data)):
        sd = bytes(data[off:off + size])
        segs = segments(sd)
        cls = find_objc_class(sd, segs, "BBRUpdater")
        if cls is None:
            sys.exit(f"FAIL {fatpath} cpu={ct:#x}: BBRUpdater class not found")
        targets = []
        inst = class_methods(sd, segs, cls)
        for sel in UPDATER_METHODS_INST:
            if sel in inst:
                targets.append((sel, inst[sel]))
        meta = meta_methods(sd, segs, cls)
        for sel in UPDATER_METHODS_META:
            if sel in meta:
                targets.append((sel, meta[sel]))
        if not targets:
            sys.exit(f"FAIL {fatpath} cpu={ct:#x}: no updater methods resolved")
        for sel, imp in targets:
            o = v2o(segs, imp)
            if o is None or not (0 < o < size - 8):
                sys.exit(f"FAIL {fatpath} cpu={ct:#x}: bad imp {imp:#x} for {sel}")
            patch = NOP_RET_A64 if ct == ARM64 else NOP_RET_X64
            cur = bytes(data[off + o: off + o + len(patch)])
            if cur == patch:
                already += 1
                continue
            data[off + o: off + o + len(patch)] = patch
            applied += 1
            print(f"  [updater] {os.path.relpath(fatpath, APP)} cpu={ct:#x} {sel} @ {imp:#x}")
    open(fatpath, "wb").write(bytes(data))
    return applied, already


def find_updaters():
    out = []
    for root, dirs, files in os.walk(APP):
        if root.endswith("BBRUpdater.framework/Versions/A") and "BBRUpdater" in files:
            out.append(os.path.join(root, "BBRUpdater"))
    return sorted(out)


def main():
    if not os.path.isdir(APP):
        sys.exit(f"app not found: {APP}")

    total_applied = total_already = 0
    print("== main app + menubar:")
    for p in (MAIN, MENUBAR):
        a, b = apply_fixed(p)
        total_applied += a
        total_already += b
    print(f"== updater copies ({len(find_updaters())} found):")
    for up in find_updaters():
        a, b = apply_updater(up)
        total_applied += a
        total_already += b
    print(f"\nDONE: {total_applied} patch(es) applied, {total_already} already patched.")


if __name__ == "__main__":
    main()
