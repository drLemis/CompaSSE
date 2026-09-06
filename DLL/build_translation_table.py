"""
build_translation_table.py - Build ID translation tables across Skyrim SE address library versions.

Usage:
    python build_translation_table.py --bins <dir> --libs <dir> --out <file.json>

--bins: directory containing version subdirs, each with SkyrimSE.exe
        e.g. bins/1.6.640/SkyrimSE.exe, bins/1.6.1130/SkyrimSE.exe
--libs: directory containing versionlib-*.bin and version-*.bin files
--out:  output JSON translation table
"""
import argparse, json, os, re, struct, sys
from pathlib import Path
from collections import defaultdict

# ---------------------------------------------------------------------------
# PE helpers
# ---------------------------------------------------------------------------
def load_pe(path):
    data = open(path, "rb").read()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    optsz = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sec = e_lfanew + 24 + optsz
    secs = []
    for i in range(nsec):
        o = sec + i * 40
        name = data[o:o+8].rstrip(b"\0").decode()
        vaddr = struct.unpack_from("<I", data, o + 12)[0]
        vsz = struct.unpack_from("<I", data, o + 8)[0]
        rptr = struct.unpack_from("<I", data, o + 20)[0]
        secs.append((name, vaddr, vsz, rptr))
    return data, secs

def rva2off(rva, secs):
    for name, vaddr, vsz, rptr in secs:
        if vaddr <= rva < vaddr + vsz:
            return rptr + (rva - vaddr)
    return None

def read_u32(data, off):
    return struct.unpack_from("<I", data, off)[0]

def read_u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]

# ---------------------------------------------------------------------------
# Address library parser - faithful port of C++ parse_format2
# ---------------------------------------------------------------------------
class Reader:
    def __init__(self, data):
        self.data = data
        self.size = len(data)
        self.off = 0

    def u8(self):
        if self.off + 1 > self.size: return None
        v = self.data[self.off]; self.off += 1; return v

    def u16(self):
        if self.off + 2 > self.size: return None
        v = self.data[self.off] | (self.data[self.off+1] << 8); self.off += 2; return v

    def u32(self):
        if self.off + 4 > self.size: return None
        v = (self.data[self.off] | (self.data[self.off+1] << 8) |
             (self.data[self.off+2] << 16) | (self.data[self.off+3] << 24)); self.off += 4; return v

    def u64(self):
        if self.off + 8 > self.size: return None
        v = 0
        for i in range(8): v |= self.data[self.off+i] << (8*i)
        self.off += 8; return v

def parse_format2(data):
    """Parse fmt1/fmt2. Returns list of (id, offset) or None on failure."""
    r = Reader(data)
    fmt = r.u32()
    if fmt not in (1, 2): return None

    version = [r.u32() for _ in range(4)]
    name_len = r.u32()
    if name_len == 0 or r.off + name_len > r.size: return None
    name = data[r.off:r.off+name_len].split(b"\0")[0].decode(errors="replace")
    r.off += name_len

    ptr_size = r.u32()
    if ptr_size == 0: return None

    count = r.u32()

    entries = []
    prev_id = 0
    prev_offset = 0

    for _ in range(count):
        type_byte = r.u8()
        if type_byte is None: return None

        lo = type_byte & 0x0F
        hi = type_byte >> 4

        # Decode ID from low nibble
        if lo == 0:
            id_val = r.u64()
        elif lo == 1:
            id_val = prev_id + 1
        elif lo == 2:
            d = r.u8(); id_val = prev_id + d
        elif lo == 3:
            d = r.u8(); id_val = prev_id - d
        elif lo == 4:
            d = r.u16(); id_val = prev_id + d
        elif lo == 5:
            d = r.u16(); id_val = prev_id - d
        elif lo == 6:
            id_val = r.u16()
        elif lo == 7:
            id_val = r.u32()
        else:
            return None

        # Decode offset from high nibble
        tmp = (prev_offset // ptr_size) if (hi & 8) else prev_offset
        hi_off = hi & 7

        if hi_off == 0:
            offset = r.u64()
        elif hi_off == 1:
            offset = tmp + 1
        elif hi_off == 2:
            d = r.u8(); offset = tmp + d
        elif hi_off == 3:
            d = r.u8(); offset = tmp - d
        elif hi_off == 4:
            d = r.u16(); offset = tmp + d
        elif hi_off == 5:
            d = r.u16(); offset = tmp - d
        elif hi_off == 6:
            offset = r.u16()
        elif hi_off == 7:
            offset = r.u32()
        else:
            return None

        if hi & 8: offset *= ptr_size

        entries.append((id_val, offset))
        prev_id = id_val
        prev_offset = offset

    entries.sort(key=lambda x: x[0])
    return entries

def parse_format5(data):
    """Parse fmt5: dense u32 array. Returns list of (id, offset) or None."""
    if len(data) < 96: return None
    if read_u32(data, 0) != 5: return None
    count = read_u32(data, 92)
    entries = []
    for i in range(count):
        off = read_u32(data, 96 + i * 4)
        if off != 0:
            entries.append((i, off))
    return entries

def parse_library(path):
    """Parse any versionlib/version-*.bin file."""
    data = open(path, "rb").read()
    fmt = read_u32(data, 0) if len(data) >= 4 else 0
    if fmt == 5: return parse_format5(data)
    elif fmt in (1, 2): return parse_format2(data)
    return None

# ---------------------------------------------------------------------------
# Version extraction
# ---------------------------------------------------------------------------
def extract_version_from_filename(fn):
    m = re.search(r'(\d+)-(\d+)-(\d+)', fn)
    if m: return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    m = re.search(r'(\d+)\.(\d+)\.(\d+)', fn)
    if m: return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return None

def extract_pointer_at(exe_data, secs, rva):
    off = rva2off(rva, secs)
    if off is None or off + 8 > len(exe_data): return None
    return read_u64(exe_data, off)

def read_string_at(exe_data, secs, rva, max_len=256):
    off = rva2off(rva, secs)
    if off is None: return None
    end = exe_data.find(b"\0", off, off + max_len)
    if end < 0: return None
    raw = exe_data[off:end]
    try: return raw.decode("ascii")
    except: return None

def read_code_sig(exe_data, secs, rva, length=64):
    off = rva2off(rva, secs)
    if off is None or off + length > len(exe_data): return None
    return bytes(exe_data[off:off+length])

def collect_version_data(binary_path, library_path):
    exe_data, secs = load_pe(binary_path)
    entries = parse_library(library_path)
    if entries is None: return None

    result = {}
    imagebase = 0x140000000
    for id_val, offset in entries:
        ptr = extract_pointer_at(exe_data, secs, offset)
        info = {"offset": offset}
        if ptr is not None:
            info["pointer"] = ptr
            if ptr >= imagebase:
                str_rva = ptr - imagebase
                s = read_string_at(exe_data, secs, str_rva)
                if s and len(s) >= 3:
                    info["string"] = s
            sig = read_code_sig(exe_data, secs, offset)
            if sig: info["code_sig"] = sig.hex()
        result[id_val] = info
    return result

# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------
def match_versions(data_a, data_b):
    b_string_to_ids = defaultdict(list)
    b_code_to_ids = defaultdict(list)
    for id_val, info in data_b.items():
        if "string" in info: b_string_to_ids[info["string"]].append(id_val)
        if "code_sig" in info: b_code_to_ids[info["code_sig"]].append(id_val)

    renames = {}
    for id_a, info_a in data_a.items():
        if id_a in data_b: continue

        if "string" in info_a:
            candidates = b_string_to_ids.get(info_a["string"], [])
            if len(candidates) == 1:
                renames[id_a] = candidates[0]
            elif len(candidates) > 1:
                best = min(candidates, key=lambda c: abs(data_b[c]["offset"] - info_a["offset"]))
                renames[id_a] = best

        if id_a not in renames and "code_sig" in info_a:
            candidates = b_code_to_ids.get(info_a["code_sig"], [])
            if len(candidates) == 1:
                renames[id_a] = candidates[0]
            # Multiple candidates = ambiguous, skip (leave as absent)

    return renames

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Build address library ID translation tables")
    parser.add_argument("--bins", required=True, help="Directory with version subdirs containing SkyrimSE.exe")
    parser.add_argument("--libs", required=True, help="Directory with versionlib-*.bin and version-*.bin files")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    lib_dir = Path(args.libs)
    lib_files = sorted(lib_dir.glob("version*.bin"))
    print(f"Found {len(lib_files)} library files")

    bin_dir = Path(args.bins)
    bin_versions = {}
    for p in bin_dir.iterdir():
        exe = p / "SkyrimSE.exe"
        if exe.exists():
            ver = extract_version_from_filename(p.name)
            if ver: bin_versions[ver] = str(exe)
    print(f"Found {len(bin_versions)} binary versions: {sorted(bin_versions.keys())}")

    all_versions = {}
    for lib_file in lib_files:
        ver = extract_version_from_filename(lib_file.name)
        if ver is None:
            print(f"  SKIP (no version): {lib_file.name}")
            continue
        if ver not in bin_versions:
            print(f"  SKIP (no binary): {lib_file.name}")
            continue
        print(f"  Collecting {lib_file.name} ...", end=" ", flush=True)
        data = collect_version_data(bin_versions[ver], str(lib_file))
        if data:
            all_versions[ver] = data
            print(f"{len(data)} entries")
        else:
            print("PARSE FAIL")

    sorted_versions = sorted(all_versions.keys())
    print(f"\nCollected {len(sorted_versions)} versions: {sorted_versions}")

    # Pair-wise matching (all pairs, not just adjacent)
    translation_tables = {}
    for i in range(len(sorted_versions)):
        for j in range(i + 1, len(sorted_versions)):
            va, vb = sorted_versions[i], sorted_versions[j]
            key = f"{va[0]}.{va[1]}.{va[2]}->{vb[0]}.{vb[1]}.{vb[2]}"
            renames = match_versions(all_versions[va], all_versions[vb])
            if renames:
                translation_tables[key] = {str(k): v for k, v in renames.items()}
                print(f"  {key}: {len(renames)} renames")

    # Build full chain to latest: for each source version, find direct pair to latest
    latest = sorted_versions[-1]
    full_map = {}
    for va in sorted_versions[:-1]:
        key = f"{va[0]}.{va[1]}.{va[2]}->{latest[0]}.{latest[1]}.{latest[2]}"
        direct_key = f"{va[0]}.{va[1]}.{va[2]}->{latest[0]}.{latest[1]}.{latest[2]}"
        if direct_key in translation_tables:
            chain = {int(k): v for k, v in translation_tables[direct_key].items()}
        else:
            # No direct pair - fall back to greedy chain
            chain = {}
            current = va
            while current != latest:
                best_jump = None
                best_renames = {}
                for vk, vr in translation_tables.items():
                    src = tuple(int(x) for x in vk.split("->")[0].split("."))
                    if src != current:
                        continue
                    dst = tuple(int(x) for x in vk.split("->")[1].split("."))
                    if dst <= current:
                        continue
                    if best_jump is None or dst > best_jump:
                        best_jump = dst
                        best_renames = vr
                if best_jump is None:
                    break
                new_chain = {}
                for old_id, cur_id in chain.items():
                    new_chain[old_id] = best_renames.get(str(cur_id), cur_id)
                for old_id, new_id in best_renames.items():
                    if int(old_id) not in chain:
                        new_chain[int(old_id)] = new_id
                chain = new_chain
                current = best_jump
        full_map[key] = {}
        for old_id, new_id in chain.items():
            info = {"new_id": new_id}
            if new_id in all_versions[latest]:
                info["offset"] = all_versions[latest][new_id]["offset"]
                if "string" in all_versions[latest][new_id]:
                    info["string"] = all_versions[latest][new_id]["string"]
            full_map[key][str(old_id)] = info

    output = {
        "latest_version": f"{latest[0]}.{latest[1]}.{latest[2]}",
        "versions_collected": [f"{v[0]}.{v[1]}.{v[2]}" for v in sorted_versions],
        "pair_renames": translation_tables,
        "full_chain_map": full_map,
    }
    with open(args.out, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved to {args.out}")

if __name__ == "__main__":
    main()
