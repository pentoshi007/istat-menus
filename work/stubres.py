#!/usr/bin/env python3
"""Resolve ObjC stub targets (selector names) in a thin arm64 Mach-O.
Usage: stubres.py <binary> <addr> [<addr>...]"""
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

def rd32(data, segs, vaddr):
    o = v2o(segs, vaddr)
    return struct.unpack('<I', data[o:o+4])[0] if o is not None else 0

def rd64(data, segs, vaddr):
    o = v2o(segs, vaddr)
    return struct.unpack('<Q', data[o:o+8])[0] if o is not None else 0

def decode_chained(raw, base):
    if raw == 0:
        return 0
    if raw >> 63:
        return None
    return base + (raw & 0xFFFFFFFFF)

def cstr_at(data, segs, vaddr):
    o = v2o(segs, vaddr)
    if o is None:
        return None
    return data[o:o+200].split(b'\0')[0].decode('utf8', 'replace')

def resolve_stub(data, segs, base, stub):
    """Follow a __objc_stubs entry: adrp x1, page; ldr x1, [x1, #off]; adrp x16..; ldr x16...; br"""
    pc = stub
    reg_val = {}
    for k in range(8):
        w = rd32(data, segs, pc)
        if (w & 0x9F000000) == 0x90000000:  # adrp
            rd = w & 0x1F
            immhi = (w >> 5) & 0x7FFFF
            immlo = (w >> 29) & 0x3
            imm = ((immhi << 2) | immlo) << 12
            if imm & (1 << 32):
                imm -= 1 << 33
            reg_val[rd] = ((pc & ~0xFFF) + imm)
        elif (w & 0xFFC00000) == 0xF9400000:  # ldr Xt, [Xn, #imm*8]
            rn = (w >> 5) & 0x1F
            rd = w & 0x1F
            if rn in reg_val:
                slot = reg_val[rn] + (((w >> 10) & 0xFFF) * 8)
                raw = rd64(data, segs, slot)
                t = decode_chained(raw, base)
                if t:
                    name = cstr_at(data, segs, t)
                    return name
            return None
        elif (w & 0xFF800000) == 0x91000000:  # add
            rd = w & 0x1F
            rn = (w >> 5) & 0x1F
            if rn in reg_val:
                reg_val[rd] = reg_val[rn] + ((w >> 10) & 0xFFF)
        elif w == 0xD61F0080:  # br x16 — selector load missed
            return None
        pc += 4
    return None

def main():
    path = sys.argv[1]
    data = open(path, 'rb').read()
    BASE = 0x100000000
    segs = segments(data)
    for a in sys.argv[2:]:
        addr = int(a, 16)
        name = resolve_stub(data, segs, BASE, addr)
        print(f"{addr:#x} -> {name!r}")

if __name__ == '__main__':
    main()
