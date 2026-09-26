"""Compare a local build against the published binary.

A rebuild is never hash-identical to dist/RtWorkQ.dll: the linker writes the
build time into the COFF header and again into the IMAGE_DEBUG_TYPE_REPRO
entry of the debug directory, so those two 4-byte fields differ between any
two builds. This zeroes both fields in each file and then compares what is
left, which is everything that actually comes from the source.

Usage:
    python verify-build.py src/AutoOffline.dll dist/RtWorkQ.dll
"""
import hashlib
import struct
import sys


def rva_to_offset(d, pe, rva):
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    optsz = struct.unpack_from("<H", d, pe + 20)[0]
    for i in range(nsec):
        s = pe + 24 + optsz + i * 40
        vsz, va, rsz, ra = struct.unpack_from("<IIII", d, s + 8)
        if va <= rva < va + max(vsz, rsz):
            return ra + (rva - va)
    raise ValueError("RVA 0x%X is not inside any section" % rva)


def normalise(path):
    d = bytearray(open(path, "rb").read())
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    struct.pack_into("<I", d, pe + 8, 0)                    # COFF TimeDateStamp
    dbg_rva, dbg_size = struct.unpack_from("<II", d, pe + 0x18 + 0xA0)
    off = rva_to_offset(d, pe, dbg_rva)
    for e in range(0, dbg_size, 28):                        # IMAGE_DEBUG_DIRECTORY[]
        struct.pack_into("<I", d, off + e + 4, 0)           # TimeDateStamp
    return bytes(d)


if len(sys.argv) != 3:
    sys.exit(__doc__)

first, second = (normalise(p) for p in sys.argv[1:3])

print("%s   %s" % (sys.argv[1], hashlib.sha256(first).hexdigest()))
print("%s   %s" % (sys.argv[2], hashlib.sha256(second).hexdigest()))
print()
print("identical (build timestamps ignored)" if first == second else "DIFFERENT")
sys.exit(0 if first == second else 1)
