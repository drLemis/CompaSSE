"""Address library file formats and lookup."""
from pathlib import Path
import struct
from core.pe import find_export_rva, find_pe_sections

# V5 reader markers. Must match DLL/decoder_detect.cpp.
FMT5_MARKERS = (
    b"AddressLibraryV5",
    b"Address Library V5",
    b"not an Address Library V5 file",
    b"AddressLibV2",
)

def module_supports_fmt5_bytes(data):
    """True if the bytes carry a V5 reader marker."""
    if not data:
        return False
    return any(m in data for m in FMT5_MARKERS)

# Legacy reader markers. Must match DLL/decoder_detect.cpp.
FMT2_ONLY_MARKERS = (
    b"CommonLibSSEOffsets",
    b"Unsupported address library format",
    b"within the address library",
    b"failed to create shared mapping",
)

def module_is_legacy_reader_bytes(data):
    """True if the bytes carry a legacy reader marker."""
    if not data:
        return False
    return any(m in data for m in FMT2_ONLY_MARKERS)

def module_has_version_export_bytes(data):
    """True if the bytes export SKSEPlugin_Version."""
    if not data:
        return False
    sections = find_pe_sections(data)
    if not sections:
        return False
    rva = find_export_rva(data, sections, b"SKSEPlugin_Version")
    return rva is not None

# ---------------------------------------------------------------------------
# Address library parsers: one entry point takes any versionlib or
# version bin and returns {id: offset}.
# ---------------------------------------------------------------------------
def parse_format5(bin_data):
    """Parse fmt5 bytes to {id: offset}. None if invalid."""
    if len(bin_data) < 96: return None
    if struct.unpack_from("<I", bin_data, 0)[0] != 5: return None
    count = struct.unpack_from("<I", bin_data, 92)[0]
    entries = {}
    for i in range(count):
        off = struct.unpack_from("<I", bin_data, 96 + i * 4)[0]
        if off != 0:
            entries[i] = off
    return entries

def parse_library_any(bin_path):
    """Parse any library bin to {id: offset}."""
    with open(bin_path, "rb") as f:
        data = f.read()
    fmt = struct.unpack_from("<I", data, 0)[0] if len(data) >= 4 else 0
    if fmt == 5: return parse_format5(data)
    elif fmt in (1, 2): return parse_addresslib(bin_path)
    return None

# ---------------------------------------------------------------------------
# Address Library parsing (format 2)
# ---------------------------------------------------------------------------
def parse_addresslib(bin_path):
    """Parse a fmt1/fmt2 bin to {id: offset}."""
    with open(bin_path, "rb") as f:
        data = f.read()
    off = 0
    format_ = struct.unpack_from("<i", data, off)[0]; off += 4
    if format_ not in (1, 2):
        return None
    off += 16  # version[4]
    name_len = struct.unpack_from("<i", data, off)[0]; off += 4
    off += name_len  # name
    pointer_size = struct.unpack_from("<i", data, off)[0]; off += 4
    address_count = struct.unpack_from("<i", data, off)[0]; off += 4

    def read_uint(size):
        nonlocal off
        val = int.from_bytes(data[off:off + size], "little")
        off += size
        return val

    entries = {}
    prev_id = 0
    prev_offset = 0
    for _ in range(address_count):
        type_ = data[off]; off += 1
        lo = type_ & 0xF
        hi = type_ >> 4
        if lo == 0:
            id_ = read_uint(8)
        elif lo == 1:
            id_ = prev_id + 1
        elif lo == 2:
            id_ = prev_id + read_uint(1)
        elif lo == 3:
            id_ = prev_id - read_uint(1)
        elif lo == 4:
            id_ = prev_id + read_uint(2)
        elif lo == 5:
            id_ = prev_id - read_uint(2)
        elif lo == 6:
            id_ = read_uint(2)
        elif lo == 7:
            id_ = read_uint(4)
        else:
            return None
        tmp = (prev_offset // pointer_size) if (hi & 8) else prev_offset
        hi_off = hi & 7
        if hi_off == 0:
            offset = read_uint(8)
        elif hi_off == 1:
            offset = tmp + 1
        elif hi_off == 2:
            offset = tmp + read_uint(1)
        elif hi_off == 3:
            offset = tmp - read_uint(1)
        elif hi_off == 4:
            offset = tmp + read_uint(2)
        elif hi_off == 5:
            offset = tmp - read_uint(2)
        elif hi_off == 6:
            offset = read_uint(2)
        elif hi_off == 7:
            offset = read_uint(4)
        else:
            return None
        if hi & 8:
            offset *= pointer_size
        entries[id_] = offset
        prev_id = id_
        prev_offset = offset
    return entries

# ---------------------------------------------------------------------------
# Format 5 -> 2 bin conversion
# ---------------------------------------------------------------------------
def convert_format5_to_format2(fmt5_path, out_path, fmt=2):
    with open(fmt5_path, "rb") as f:
        raw = f.read()
    name_raw = raw[20:84]
    name = name_raw.split(b"\x00")[0].decode("utf-8", errors="replace")
    ptr_size = struct.unpack_from("<i", raw, 84)[0]
    offset_count = struct.unpack_from("<i", raw, 92)[0]
    dense = struct.unpack_from(f"<{offset_count}I", raw, 96)
    entries = [(i, off) for i, off in enumerate(dense) if off != 0]
    entries.sort(key=lambda x: x[0])

    name_bytes = name.encode("utf-8") + b"\x00"
    header = bytearray()
    header += struct.pack("<4i", 1, 7, 104, 0)
    header += struct.pack("<i", len(name_bytes))
    header += name_bytes
    header += struct.pack("<i", ptr_size)
    header += struct.pack("<i", len(entries))

    body = bytearray()
    prev_id = 0
    prev_offset = 0
    for entry_id, entry_offset in entries:
        id_delta = entry_id - prev_id
        if id_delta == 1:
            id_type, id_extra = 1, None
        elif 0 <= id_delta <= 255:
            id_type, id_extra = 2, struct.pack("<B", id_delta)
        elif -255 <= id_delta < 0:
            id_type, id_extra = 3, struct.pack("<B", -id_delta)
        elif 0 <= id_delta <= 65535:
            id_type, id_extra = 4, struct.pack("<H", id_delta)
        elif -65535 <= id_delta < 0:
            id_type, id_extra = 5, struct.pack("<H", -id_delta)
        elif 0 <= entry_id <= 0xFFFFFFFF:
            id_type, id_extra = 7, struct.pack("<I", entry_id)
        else:
            id_type, id_extra = 0, struct.pack("<Q", entry_id)

        off_delta = entry_offset - prev_offset
        if off_delta == 1:
            off_type, off_extra = 1, None
        elif 0 <= off_delta <= 255:
            off_type, off_extra = 2, struct.pack("<B", off_delta)
        elif -255 <= off_delta < 0:
            off_type, off_extra = 3, struct.pack("<B", -off_delta)
        elif 0 <= off_delta <= 65535:
            off_type, off_extra = 4, struct.pack("<H", off_delta)
        elif -65535 <= off_delta < 0:
            off_type, off_extra = 5, struct.pack("<H", -off_delta)
        elif 0 <= entry_offset <= 0xFFFFFFFF:
            off_type, off_extra = 7, struct.pack("<I", entry_offset)
        else:
            off_type, off_extra = 0, struct.pack("<Q", entry_offset)

        body.append((off_type << 4) | id_type)
        if id_extra:
            body.extend(id_extra)
        if off_extra:
            body.extend(off_extra)
        prev_id, prev_offset = entry_id, entry_offset

    out = struct.pack("<i", fmt) + bytes(header) + bytes(body)
    with open(out_path, "wb") as f:
        f.write(out)
    return len(entries), len(out)

def extract_version_from_filename(fn):
    """Game version from a bin filename. None if missing."""
    import re
    m = re.search(r'(\d+)-(\d+)-(\d+)', fn)
    if m: return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    m = re.search(r'(\d+)\.(\d+)\.(\d+)', fn)
    if m: return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return None

def find_versionlib(plugins_dir, version_tuple):
    """Bin path for this game version. None if missing."""
    if plugins_dir is None or version_tuple is None:
        return None
    try:
        bins = sorted(plugins_dir.glob("versionlib-*.bin"))
    except OSError:
        return None
    want = tuple(version_tuple[:3])
    for b in bins:
        if extract_version_from_filename(b.name) == want:
            return b
    return None

def find_versionlib_in_dirs(dirs, version_tuple):
    """First bin match across folders. None if missing."""
    if version_tuple is None:
        return None
    for d in dirs or []:
        if d is None:
            continue
        match = find_versionlib(Path(d), version_tuple)
        if match is not None:
            return match
    return None

def load_matching_lib(dirs, version):
    """Parsed bin for this version. None if missing."""
    match = find_versionlib_in_dirs(dirs, version)
    if match is None:
        return None
    try:
        return parse_library_any(str(match))
    except (OSError, struct.error, ValueError):
        return None

def collect_lib_bins(dirs):
    """All library bins across folders."""
    out = []
    seen = set()
    for d in dirs or []:
        if d is None:
            continue
        try:
            base = Path(d)
            if not base.is_dir():
                continue
            cands = sorted(base.glob("versionlib-*.bin"))
            cands += sorted(base.glob("version-*.bin"))
        except OSError:
            continue
        for b in cands:
            try:
                key = str(b.resolve()).lower()
            except OSError:
                key = str(b).lower()
            if key not in seen:
                seen.add(key)
                out.append(b)
    return out
