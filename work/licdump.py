#!/usr/bin/env python3
"""Dump ObjC classes + methods (with IMP vaddrs) from a thin Mach-O slice.
Usage: licdump.py <macho> [name_filter ...]
Filters match case-insensitively as substrings of the class name."""
import struct, sys


def parse_segments(data):
    magic = struct.unpack('<I', data[:4])[0]
    if magic not in (0xfeedfacf, 0xfeedface):
        raise SystemExit('not thin macho')
    ncmds = struct.unpack('<I', data[16:20])[0]
    p = 32
    segs = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack('<II', data[p:p + 8])
        if cmd == 0x19:
            segname = data[p + 8:p + 24].split(b'\0')[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack('<QQQQ', data[p + 24:p + 56])
            segs.append((segname, vmaddr, vmsize, fileoff, filesize))
        p += cmdsize
    return segs


def parse_sections(data):
    ncmds = struct.unpack('<I', data[16:20])[0]
    p = 32
    out = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack('<II', data[p:p + 8])
        if cmd == 0x19:
            segname = data[p + 8:p + 24].split(b'\0')[0].decode()
            nsects = struct.unpack('<I', data[p + 64:p + 68])[0]
            sp = p + 72
            for _ in range(nsects):
                sectname = data[sp:sp + 16].split(b'\0')[0].decode()
                addr, size = struct.unpack('<QQ', data[sp + 32:sp + 48])
                off = struct.unpack('<I', data[sp + 48:sp + 52])[0]
                out.append((segname, sectname, addr, size, off))
                sp += 80
        p += cmdsize
    return out


class Image:
    def __init__(self, path):
        self.data = open(path, 'rb').read()
        self.segs = parse_segments(self.data)
        self.sections = parse_sections(self.data)
        text = next(s for s in self.segs if s[0] == '__TEXT')
        self.base = text[1]

    def off(self, vaddr):
        for name, vmaddr, vmsize, fileoff, filesize in self.segs:
            if vmaddr <= vaddr < vmaddr + vmsize:
                return fileoff + (vaddr - vmaddr)
        return None

    def read(self, vaddr, n):
        o = self.off(vaddr)
        return None if o is None else self.data[o:o + n]

    def u32(self, vaddr):
        b = self.read(vaddr, 4)
        return struct.unpack('<I', b)[0] if b and len(b) == 4 else None

    def s32(self, vaddr):
        b = self.read(vaddr, 4)
        return struct.unpack('<i', b)[0] if b and len(b) == 4 else None

    def u64(self, vaddr):
        b = self.read(vaddr, 8)
        return struct.unpack('<Q', b)[0] if b and len(b) == 8 else None

    def ptr(self, vaddr):
        raw = self.u64(vaddr)
        if raw is None:
            return None
        if raw == 0:
            return 0
        if raw >> 63:
            return ('bind', raw & 0xFFFFFF)
        return self.base + (raw & 0xFFFFFFFFF)

    def cstr(self, vaddr, maxlen=512):
        if not vaddr or vaddr >= self.base + 0x100000000:
            return None
        b = self.read(vaddr, maxlen)
        if b is None:
            return None
        return b.split(b'\0')[0].decode('utf8', 'replace')

    def rel_chain_list(self, addr):
        ent = self.u32(addr)
        if ent is None:
            return []
        n = self.u32(addr + 4)
        if n is None or n > 8192:
            return []
        out = []
        rel = bool(ent & 0x80000000)
        stride = 12 if rel else 24
        for i in range(n):
            e = addr + 8 + i * stride
            if rel:
                d0 = self.s32(e)
                d2 = self.s32(e + 8)
                if d0 is None or d2 is None:
                    break
                name = self.cstr(self.ptr(e + d0) or 0)
                imp = e + 8 + d2
            else:
                np = self.ptr(e)
                name = self.cstr(np) if np else None
                imp = self.ptr(e + 16)
            out.append((name, imp))
        return out

    def class_methods(self, class_ptr):
        ro = self.ptr(class_ptr + 32)
        if not ro or isinstance(ro, tuple):
            return None, [], []
        ro &= ~0x7
        name = self.cstr(self.ptr(ro + 24))
        meths = self.rel_chain_list(self.ptr(ro + 32) or 0)
        metacls = self.ptr(class_ptr)
        plus = []
        if metacls and not isinstance(metacls, tuple):
            mro = self.ptr(metacls + 32)
            if mro and not isinstance(mro, tuple):
                mro &= ~0x7
                plus = self.rel_chain_list(self.ptr(mro + 32) or 0)
        return name, meths, plus


def main():
    path = sys.argv[1]
    filters = [f.lower() for f in sys.argv[2:]]
    img = Image(path)
    cl = next((s for s in img.sections if s[1] == '__objc_classlist'), None)
    if not cl:
        raise SystemExit('no __objc_classlist')
    addr, size = cl[2], cl[3]
    dumped = 0
    for i in range(size // 8):
        cp = img.ptr(addr + i * 8)
        if not cp or isinstance(cp, tuple):
            continue
        name, meths, plus = img.class_methods(cp)
        if name is None:
            continue
        if filters and not any(f in name.lower() for f in filters):
            continue
        dumped += 1
        print(f"@@ {name} @ {cp:#x} ({len(meths)} inst, {len(plus)} cls)")
        for sel, imp in meths:
            print(f"  - [{sel}] @ {imp:#x}")
        for sel, imp in plus:
            print(f"  + [{sel}] @ {imp:#x}")
    print(f"== {dumped} classes matched", file=sys.stderr)


if __name__ == '__main__':
    main()
