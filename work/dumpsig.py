#!/usr/bin/env python3
"""Dump code signature metadata (identifier, entitlements, requirements) from Mach-O files."""
import struct, sys, plistlib

CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0
CSMAGIC_CODEDIRECTORY = 0xfade0c02
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171
CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xfade7172
CSMAGIC_REQUIREMENT = 0xfade0c00
CSMAGIC_REQUIREMENTS = 0xfade0c01
CSMAGIC_BLOBWRAPPER = 0xfade0b01

SLOT_NAMES = {1: 'Requirements', 2: 'Entitlements', 3: 'DER-Entitlements', 4: 'CodeResources', 5: 'App-specific'}

def slices(data):
    magic = struct.unpack('>I', data[:4])[0]
    if magic in (0xcafebabe, 0xcafebabf):
        n = struct.unpack('>I', data[4:8])[0]
        wide = magic == 0xcafebabf
        out = []
        for i in range(n):
            if wide:
                e = data[8 + i*32: 8 + (i+1)*32]
                cputype, cpusub, off, size, align = struct.unpack('>iiQQQ', e[:32])[:5]
            else:
                e = data[8 + i*20: 8 + (i+1)*20]
                cputype, cpusub, off, size, align = struct.unpack('>iiIII', e[:20])[:5]
            out.append((cputype, cpusub, off, size))
        return out
    return [(struct.unpack('<i', data[4:8])[0], struct.unpack('<i', data[8:12])[0], 0, len(data))]

def parse_blob(data, off, depth=0):
    magic, length = struct.unpack('>II', data[off:off+8])
    return magic, length, data[off:off+length]

def dump_slice(data, base, size, label):
    mh = base
    magic = struct.unpack('<I', data[mh:mh+4])[0]
    if magic not in (0xfeedfacf, 0xfeedface):
        print(f"[{label}] not thin mach-o at {mh}")
        return
    ncmds = struct.unpack('<I', data[mh+16:mh+20])[0]
    p = mh + 32
    sig = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack('<II', data[p:p+8])
        if cmd == 0x1d:  # LC_CODE_SIGNATURE
            dataoff, datasize = struct.unpack('<II', data[p+8:p+16])
            sig = (mh + dataoff, datasize)
        p += cmdsize
    if not sig:
        print(f"[{label}] no signature")
        return
    off, sz = sig
    magic, length, blob = parse_blob(data, off)
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        print(f"[{label}] bad sig magic {magic:#x}")
        return
    count = struct.unpack('>I', blob[8:12])[0]
    print(f"[{label}] SUPERBLOB blobs={count}")
    for i in range(count):
        ty, boff = struct.unpack('>II', blob[12 + i*8: 20 + i*8])
        if boff == 0:
            continue
        bmagic, blength, bdata = parse_blob(blob, boff)
        print(f"  index[{i}] type={ty} {SLOT_NAMES.get(ty, '')} magic={bmagic:#x} len={blength}")
        if bmagic == CSMAGIC_CODEDIRECTORY:
            version, flags, hashOffset, identOffset, nSpecialSlots, nCodeSlots = struct.unpack('>IIIIII', bdata[8:32])
            ident = bdata[identOffset:bdata.index(b'\0', identOffset)].decode('utf8', 'replace')
            team = None
            if version >= 0x20200:
                teamOff = struct.unpack('>I', bdata[48:52])[0]
                if teamOff:
                    team = bdata[teamOff:bdata.index(b'\0', teamOff)].decode('utf8', 'replace')
            print(f"  CodeDirectory v{version:#x} ident='{ident}' team='{team}' flags={flags:#x}")
        elif bmagic == CSMAGIC_EMBEDDED_ENTITLEMENTS:
            try:
                pl = plistlib.loads(bdata[8:blength])
                print(f"  Entitlements: {pl}")
            except Exception as e:
                print(f"  Entitlements parse error: {e}")
        elif bmagic == CSMAGIC_EMBEDDED_DER_ENTITLEMENTS:
            print(f"  DER entitlements: {blength-8} bytes")
        elif bmagic == CSMAGIC_REQUIREMENTS:
            n = struct.unpack('>I', bdata[8:12])[0]
            print(f"  Requirements blob with {n} entries")
            for j in range(n):
                ty, roff = struct.unpack('>iI', bdata[12 + j*8: 20 + j*8])
                if roff == 0:
                    continue
                rmagic, rlen, rdata = parse_blob(bdata, roff)
                s = rdata[12:].split(b'\0')[0].decode('utf8', 'replace')
                print(f"    [{ty}] {s}")
        elif bmagic == CSMAGIC_BLOBWRAPPER:
            print(f"  CMS signature: {blength} bytes")
        else:
            print(f"  blob magic={bmagic:#x} len={blength}")

def main():
    path = sys.argv[1]
    data = open(path, 'rb').read()
    for cputype, cpusub, off, size in slices(data):
        label = f"{path} cpu={cputype:#x} sub={cpusub:#x}"
        dump_slice(data, off, size, label)
        print()

if __name__ == '__main__':
    main()
