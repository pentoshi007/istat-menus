#!/usr/bin/env python3
"""Dump ObjC classes/methods from a Mach-O with chained fixups (arm64/x86_64).
Usage: objc_dump.py <macho> [name_filter]
Decodes DYLD_CHAINED_PTR_64_OFFSET rebases in __DATA*/__objc sections."""
import struct, sys

def parse_segments(data):
    magic = struct.unpack('<I', data[:4])[0]
    if magic not in (0xfeedfacf, 0xfeedface):
        raise SystemExit('not thin macho')
    is64 = magic == 0xfeedfacf
    ncmds = struct.unpack('<I', data[16:20])[0]
    p = 32 if is64 else 28
    segs = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack('<II', data[p:p+8])
        if cmd == 0x19:  # LC_SEGMENT_64
            segname = data[p+8:p+24].split(b'\0')[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack('<QQQQ', data[p+24:p+56])
            segs.append((segname, vmaddr, vmsize, fileoff, filesize))
        p += cmdsize
    return segs

class Image:
    def __init__(self, path):
        self.data = open(path, 'rb').read()
        self.segs = parse_segments(self.data)
        text = next(s for s in self.segs if s[0] == '__TEXT')
        self.base = text[1]
        self.text_lo = text[1]
        self.text_hi = text[1] + text[2]

    def off(self, vaddr):
        for name, vmaddr, vmsize, fileoff, filesize in self.segs:
            if vmaddr <= vaddr < vmaddr + vmsize:
                return fileoff + (vaddr - vmaddr)
        return None

    def read(self, vaddr, n):
        o = self.off(vaddr)
        if o is None:
            return None
        return self.data[o:o+n]

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
        """Decode a chained dyld pointer (DYLD_CHAINED_PTR_64_OFFSET layout)."""
        raw = self.u64(vaddr)
        if raw is None:
            return None
        if raw == 0:
            return 0
        if raw >> 63:  # bind (external symbol)
            return ('bind', raw & 0xFFFFFF)
        target = raw & 0xFFFFFFFFF  # 36-bit
        return self.base + target

    def cstr(self, vaddr, maxlen=256):
        if not vaddr or vaddr >= self.base + 0x100000000:
            return None
        b = self.read(vaddr, maxlen)
        if b is None:
            return None
        return b.split(b'\0')[0].decode('utf8', 'replace')

    def rel_chain_list(self, addr):
        """Parse a relative method list at addr → list of (sel, imp).
        Note: on this build name offsets point to a chained-pointer slot whose
        target is the selector cstring (indirection through __objc_selrefs-like table)."""
        ent = self.u32(addr)
        if ent is None:
            return []
        n = self.u32(addr + 4)
        if n is None or n > 4096:
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
                # imp delta is relative to the imp field itself (entry + 8)
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
            return None, []
        ro &= ~0x7
        name = self.cstr(self.ptr(ro + 24))
        meths = self.rel_chain_list(self.ptr(ro + 32) or 0)
        # metaclass methods (+)
        metacls = self.ptr(class_ptr)
        plus = []
        if metacls and not isinstance(metacls, tuple):
            mro = self.ptr(metacls + 32)
            if mro:
                mro &= ~0x7
                plus = self.rel_chain_list(self.ptr(mro + 32) or 0)
        return name, meths, plus

def main():
    path = sys.argv[1]
    filt = sys.argv[2].lower() if len(sys.argv) > 2 else None
    img = Image(path)
    clsp = next(s for s in img.segs if s[0] == '__DATA_CONST' and False) if False else None
    # find __objc_classlist section inside __DATA_CONST
    classlist_v, classlist_n = None, 0
    for name, vmaddr, vmsize, fileoff, filesize in img.segs:
        if name == '__DATA_CONST':
            classlist_v = vmaddr + 0x4500 % 0x100000  # replaced below
    # simpler: rescan via sections using known paddr 0x154500 / size 0x618 passed in env
    import os
    clv = int(os.environ.get('CLASSLIST_V', '0x100154500'), 16)
    cln = int(os.environ.get('CLASSLIST_N', '195'), 10)
    found = 0
    for i in range(cln):
        cp = img.ptr(clv + i * 8)
        if not cp or isinstance(cp, tuple):
            continue
        r = img.class_methods(cp)
        if not r:
            continue
        name, meths, plus = r
        if name is None:
            continue
        if filt and filt not in name.lower():
            continue
        found += 1
        print(f"@@ {name} @ {cp:#x}")
        for sel, imp in meths:
            print(f"   - [{sel}] @ {imp:#x}")
        for sel, imp in plus:
            print(f"   + [{sel}] @ {imp:#x}")
    print(f"== {found} classes dumped", file=sys.stderr)

if __name__ == '__main__':
    main()
