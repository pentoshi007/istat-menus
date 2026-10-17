#!/usr/bin/env python3
"""Split a universal Mach-O into thin slice files: split_slices.py <in> <out_prefix>
Writes <out_prefix>.<cputype> and a JSON manifest with offsets/sizes/aligns."""
import struct, sys, json, os

def main():
    src, prefix = sys.argv[1], sys.argv[2]
    data = open(src, 'rb').read()
    magic = struct.unpack('>I', data[:4])[0]
    if magic not in (0xcafebabe, 0xcafebabf):
        print("not fat")
        sys.exit(1)
    n = struct.unpack('>I', data[4:8])[0]
    wide = magic == 0xcafebabf
    entries = []
    for i in range(n):
        if wide:
            cputype, cpusub, off, size, align = struct.unpack('>iiQQQ', data[8+i*32: 8+(i+1)*32])[:5]
        else:
            cputype, cpusub, off, size, align = struct.unpack('>iiIII', data[8+i*20: 8+(i+1)*20])[:5]
        name = {0x1000007: 'x86_64', 0x100000c: 'arm64'}.get(cputype & 0xffffffff, hex(cputype))
        out = f"{prefix}.{name}"
        open(out, 'wb').write(data[off:off+size])
        entries.append({'name': name, 'cputype': cputype, 'cpusubtype': cpusub, 'offset': off, 'size': size, 'align': align, 'file': out})
        print(f"wrote {out} offset={off:#x} size={size:#x} align={align:#x}")
    json.dump({'wide': wide, 'entries': entries}, open(prefix + '.manifest.json', 'w'), indent=1)

if __name__ == '__main__':
    main()
