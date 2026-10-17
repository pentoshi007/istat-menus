#!/usr/bin/env python3
"""Find code refs to CFString-wrapped cstrings in a thin arm64 Mach-O.
Usage: cfrefs.py <binary> <string> [<string>...]"""
import struct, sys

def segments(data):
    ncmds = struct.unpack('<I', data[16:20])[0]
    p = 32
    segs = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack('<II', data[p:p+8])
        if cmd == 0x19:
            name = data[p+8:p+24].split(b'\0')[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack('<QQQQ', data[p+24:p+56])
            segs.append((name, vmaddr, vmsize, fileoff, filesize))
        p += cmdsize
    return segs

def v2o(segs, vaddr):
    for name, vm, vs, fo, fs in segs:
        if vm <= vaddr < vm + vs:
            return fo + (vaddr - vm)
    return None

def o2v(segs, off):
    for name, vm, vs, fo, fs in segs:
        if fo <= off < fo + fs:
            return vm + (off - fo)
    return None

def decode_chained(raw, base):
    if raw == 0:
        return 0
    if raw >> 63:
        return None
    return base + (raw & 0xFFFFFFFFF)

def main():
    path = sys.argv[1]
    wanted = sys.argv[2:]
    data = open(path, 'rb').read()
    BASE = 0x100000000
    segs = segments(data)
    tx = next(s for s in segs if s[0] == '__TEXT')
    dc = next(s for s in segs if s[0] == '__DATA_CONST')
    # 1) locate exact NUL-terminated cstrings
    taddrs = {}
    for cs in wanted:
        b = cs.encode()
        i = data.find(b)
        while i != -1:
            if data[i + len(b)] == 0:
                taddrs[BASE + i] = cs
                break
            i = data.find(b, i + 1)
    # 2) CFString objects in __DATA_CONST (iterate file offsets, translate to vmaddrs)
    cf = {}
    for fo in range(dc[3], dc[3] + dc[4] - 32, 8):
        raw = struct.unpack('<Q', data[fo + 16:fo + 24])[0]
        if raw and not (raw >> 63):
            t = decode_chained(raw, BASE)
            if t in taddrs:
                cf[o2v(segs, fo)] = taddrs[t]
    print(f"CFString objects: {{ {', '.join(f'{hex(k)}: {v!r}' for k, v in cf.items())} }}")
    # 3) scan __TEXT for adrp+add / adrp+ldr refs
    tsize = min(tx[4], 0x200000)
    for obj, name in cf.items():
        page = obj & ~0xFFF
        offin = obj & 0xFFF
        found = []
        i = 0
        while i < tsize - 8:
            w = struct.unpack('<I', data[tx[3] + i:tx[3] + i + 4])[0]
            if (w & 0x9F000000) == 0x90000000:
                rd = w & 0x1F
                immhi = (w >> 5) & 0x7FFFF
                immlo = (w >> 29) & 0x3
                imm = ((immhi << 2) | immlo) << 12
                if imm & (1 << 32):
                    imm -= 1 << 33
                if ((tx[1] + i) & ~0xFFF) + imm == page:
                    for j in range(1, 8):
                        w2 = struct.unpack('<I', data[tx[3] + i + 4 * j:tx[3] + i + 4 * j + 4])[0]
                        if (w2 & 0xFF800000) == 0x91000000 and ((w2 >> 5) & 0x1F) == rd:
                            if ((w2 >> 10) & 0xFFF) == offin:
                                found.append(tx[1] + i)
                            break
                        if (w2 & 0xFFC00000) == 0xF9400000 and ((w2 >> 5) & 0x1F) == rd:
                            if ((w2 >> 10) & 0xFFF) * 8 == offin:
                                found.append(tx[1] + i)
                            break
                        if (w2 & 0x9F000000) == 0x90000000 and (w2 & 0x1F) == rd:
                            break
            i += 4
        print(f"  {name!r}: refs {[hex(r) for r in found]}")

if __name__ == '__main__':
    main()
