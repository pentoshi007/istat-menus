#!/usr/bin/env python3
"""Find BL call sites (arm64) to given target vaddrs in a thin Mach-O.
Usage: calls.py <macho> <target_hex> [<target_hex>...]
Prints each call site and the nearest preceding function start if known via
--funcs <file> (objdump-style labels)."""
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
    targets = [int(a, 16) for a in sys.argv[2:]]
    data = open(path, 'rb').read()
    segs = parse_segments(data)
    txt = next(s for s in segs if s[0] == '__TEXT')
    lo, hi, fo = txt[1], txt[1] + txt[4], txt[3]
    for t in targets:
        print(f"== callers of {t:#x} ==")
        hits = []
        i = 0
        while i < hi - lo - 4:
            w = struct.unpack('<I', data[fo + i:fo + i + 4])[0]
            if (w & 0xFC000000) == 0x94000000:
                off = w & 0x3FFFFFF
                if off & (1 << 25):
                    off -= 1 << 26
                if lo + i + off * 4 == t:
                    hits.append(lo + i)
            i += 4
        for h in hits:
            print(f"   bl @ {h:#x}")
        if not hits:
            print("   (none)")


if __name__ == '__main__':
    main()
