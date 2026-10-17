#!/usr/bin/env python3
"""Find code xrefs to an ObjC selector in a thin Mach-O (arm64).
Usage: selrefs.py <macho> <selector> [<selector>...]
Locates the selector cstring, its __objc_selrefs slot, then adrp+ldr x1 refs."""
import struct, sys


def parse_segments(data):
    ncmds = struct.unpack('<I', data[16:20])[0]
    p = 32
    segs = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack('<II', data[p:p + 8])
        if cmd == 0x19:
            name = data[p + 8:p + 24].split(b'\0')[0].decode()
            vm, vs, fo, fs = struct.unpack('<QQQQ', data[p + 24:p + 56])
            segs.append((name, vm, vs, fo, fs))
        p += cmdsize
    return segs


def main():
    path = sys.argv[1]
    data = open(path, 'rb').read()
    segs = parse_segments(data)
    txt = next(s for s in segs if s[0] == '__TEXT')
    base = txt[1]

    def v2o(v):
        for name, vm, vs, fo, fs in segs:
            if vm <= v < vm + vs:
                return fo + (v - vm)
        return None

    def o2v(o):
        for name, vm, vs, fo, fs in segs:
            if fo <= o < fo + fs:
                return vm + (o - fo)
        return None

    def rd64(v):
        o = v2o(v)
        return struct.unpack('<Q', data[o:o + 8])[0] if o is not None else None

    def decode(raw):
        if raw == 0:
            return 0
        if raw >> 63:
            return None
        return base + (raw & 0xFFFFFFFFF)

    for sel in sys.argv[2:]:
        b = sel.encode()
        # selector cstring (first exact NUL-terminated match)
        so = None
        i = data.find(b + b'\0')
        so = i if i != -1 else None
        if so is None:
            print(f"{sel}: cstring not found")
            continue
        sv = o2v(so)
        # objc_selrefs slot pointing at sv
        selrefs = []
        dcs = [s for s in segs if s[0] in ('__DATA_CONST', '__DATA')]
        for name, vm, vs, fo, fs in dcs:
            for fo2 in range(fo, fo + fs - 8, 8):
                raw = struct.unpack('<Q', data[fo2:fo2 + 8])[0]
                if raw == 0:
                    continue
                t = decode(raw)
                if t == sv:
                    selrefs.append(o2v(fo2))
        print(f"{sel}: cstring {sv:#x}, selrefs {[hex(x) for x in selrefs]}")
        # code refs: adrp x1, page; ldr x1, [x1, #off]
        for sr in selrefs:
            page = sr & ~0xFFF
            offin = sr & 0xFFF
            i = 0
            tsize = txt[4]
            while i < tsize - 8:
                w = struct.unpack('<I', data[txt[3] + i:txt[3] + i + 4])[0]
                if (w & 0x9F000000) == 0x90000000 and (w & 0x1F) == 1:  # adrp x1
                    immhi = (w >> 5) & 0x7FFFF
                    immlo = (w >> 29) & 0x3
                    imm = ((immhi << 2) | immlo) << 12
                    if imm & (1 << 32):
                        imm -= 1 << 33
                    if ((txt[1] + i) & ~0xFFF) + imm == page:
                        for j in range(1, 4):
                            w2 = struct.unpack('<I', data[txt[3] + i + 4 * j:txt[3] + i + 4 * j + 4])[0]
                            if (w2 & 0xFFC00000) == 0xF9400000 and ((w2 >> 5) & 0x1F) == 1:
                                if ((w2 >> 10) & 0xFFF) * 8 == offin:
                                    print(f"   ref @ {txt[1] + i:#x}")
                                break
                            if (w2 & 0x9F000000) == 0x90000000:
                                break
                i += 4
        print()


if __name__ == '__main__':
    main()
