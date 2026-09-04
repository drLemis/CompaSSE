"""Generate version-X-Y-Z-W.bin (format 1) from versionlib-X-Y-Z-W.bin (format 5).
Usage: python gen_version_bin.py <versionlib_path> <output_path>
"""
import struct, sys

def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <versionlib-X-Y-Z-W.bin> <output_version-X-Y-Z-W.bin>")
        return 2
    with open(sys.argv[1], "rb") as f:
        data = f.read()
    if len(data) < 96:
        print("FAIL: file too small"); return 1
    fmt = struct.unpack_from("<I", data, 0)[0]
    if fmt != 5:
        print(f"FAIL: expected format 5, got {fmt}"); return 1
    version = struct.unpack_from("<4I", data, 4)
    name = data[20:84].split(b'\x00')[0]
    ptr_size = struct.unpack_from("<I", data, 84)[0]
    data_fmt = struct.unpack_from("<I", data, 88)[0]
    count = struct.unpack_from("<I", data, 92)[0]
    # Read dense u32 entries
    entries = []
    for i in range(count):
        off = 96 + i * 4
        v = struct.unpack_from("<I", data, off)[0]
        if v != 0:
            entries.append((i, v))
    print(f"read {len(entries)} non-zero entries from {count} total")
    # Encode as format 1 (same as format 2 but with format byte = 1)
    # Header: format(4) + version(16) + name_len(4) + name + NUL + ptr_size(4) + count(4)
    # Entries: delta-encoded with type bytes
    out = bytearray()
    out += struct.pack("<I", 1)  # format = 1
    out += struct.pack("<4I", *version)
    name_bytes = name if isinstance(name, bytes) else name.encode("utf-8")
    out += struct.pack("<I", len(name_bytes) + 1)
    out += name_bytes + b'\x00'
    out += struct.pack("<I", ptr_size)
    out += struct.pack("<I", len(entries))
    prev_id = 0
    prev_offset = 0
    for id_, offset in entries:
        id_delta = id_ - prev_id
        off_delta = offset - prev_offset
        if id_delta == 0 and off_delta == 0:
            type_byte = 0x00  # absolute id, absolute offset
            out += bytes([type_byte])
            out += struct.pack("<Q", id_)
            out += struct.pack("<Q", offset)
        elif id_delta == 1 and off_delta == 0:
            type_byte = 0x10  # +1 id, absolute offset
            out += bytes([type_byte])
            out += struct.pack("<Q", offset)
        elif id_delta == 1 and 0 < off_delta < 256:
            type_byte = 0x12  # +1 id, +u8 offset
            out += bytes([type_byte, off_delta])
        elif id_delta == 1 and -256 < off_delta < 0:
            type_byte = 0x13  # +1 id, -u8 offset
            out += bytes([type_byte, -off_delta])
        else:
            # Fallback: absolute encoding
            lo = 0x00  # absolute u64 id
            hi = 0x00  # absolute u64 offset
            type_byte = (hi << 4) | lo
            out += bytes([type_byte])
            out += struct.pack("<Q", id_)
            out += struct.pack("<Q", offset)
        prev_id = id_
        prev_offset = offset
    with open(sys.argv[2], "wb") as f:
        f.write(out)
    print(f"wrote {len(entries)} entries to {sys.argv[2]} ({len(out)} bytes)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
