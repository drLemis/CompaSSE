"""
gen_translation_bin.py - Generate binary translation table for the C++ shim.
"""
import argparse
import json
import struct
import sys
from pathlib import Path

def parse_version(s):
    parts = s.split(".")
    return (int(parts[0]), int(parts[1]), int(parts[2]))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", required=True)
    parser.add_argument("--libs", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    with open(args.json) as f:
        data = json.load(f)

    libs_dir = Path(args.libs)

    # Load current runtime library for offset lookups
    latest = data["latest_version"]
    latest_lib = None
    for p in libs_dir.glob("version*"):
        if latest.replace(".", "-") in p.name:
            sys.path.insert(0, str(Path(__file__).parent))
            from build_translation_table import parse_library
            latest_lib = dict(parse_library(str(p)))
            break
    if latest_lib is None:
        print("ERROR: cannot find latest version library", file=sys.stderr)
        sys.exit(1)
    print("Loaded %d entries from %s library" % (len(latest_lib), latest))

    # Build binary output
    out = bytearray()
    out += b"TRTL"
    ver_count = 0
    ver_offset_pos = len(out)
    out += struct.pack("<I", 0)  # placeholder

    for ver_str, chain in sorted(data["full_chain_map"].items()):
        if not chain:
            continue

        ver = parse_version(ver_str.split("->")[0])
        entries = []
        for old_id_str, info in chain.items():
            old_id = int(old_id_str)
            new_id = info["new_id"]
            if new_id in latest_lib:
                offset = latest_lib[new_id]
            elif old_id in latest_lib:
                offset = latest_lib[old_id]
            else:
                offset = 0
            entries.append((old_id, offset))

        entries.sort(key=lambda x: x[0])

        ver_bytes = ("%d.%d.%d" % (ver[0], ver[1], ver[2])).encode("ascii")
        ver_len = len(ver_bytes)
        padded_len = (ver_len + 3) & ~3
        out += struct.pack("<I", ver_len)
        out += ver_bytes
        out += b"\x00" * (padded_len - ver_len)
        out += struct.pack("<I", len(entries))
        for old_id, offset in entries:
            out += struct.pack("<QI", old_id, offset)
        ver_count += 1
        print("  %s: %d entries" % (ver_str, len(entries)))

    struct.pack_into("<I", out, ver_offset_pos, ver_count)

    with open(args.out, "wb") as f:
        f.write(out)
    print("\nWrote %d bytes to %s (%d versions)" % (len(out), args.out, ver_count))

if __name__ == "__main__":
    main()
