"""Patch version numbers in a version-X-Y-Z-W.bin file.
Usage: python patch_version_bin.py <input.bin> <output.bin> <major> <minor> <build> <sub> <name>
"""
import struct, sys

def main():
    if len(sys.argv) != 8:
        print(f"usage: {sys.argv[0]} <input.bin> <output.bin> <major> <minor> <build> <sub> <name>")
        return 2
    with open(sys.argv[1], "rb") as f:
        data = bytearray(f.read())
    major, minor, build, sub = int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6])
    name = sys.argv[7].encode("utf-8")
    # Format 1: format(4) + version(4x4=16) + name_len(4) + name + NUL + ...
    # version starts at offset 4
    struct.pack_into("<4I", data, 4, major, minor, build, sub)
    # name_len at offset 20
    old_name_len = struct.unpack_from("<I", data, 20)[0]
    # Check if name fits
    if len(name) + 1 > old_name_len:
        print(f"FAIL: new name ({len(name)+1} bytes) > old name space ({old_name_len} bytes)")
        return 1
    # Write name at offset 24
    data[24:24+len(name)] = name
    data[24+len(name)] = 0  # NUL terminator
    with open(sys.argv[2], "wb") as f:
        f.write(data)
    print(f"patched version {major}.{minor}.{build}.{sub} name={sys.argv[7]} -> {sys.argv[2]}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
