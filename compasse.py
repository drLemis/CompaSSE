#!/usr/bin/env python3
"""CompaSSE - refits old SKSE plugins to run on the current Skyrim SE runtime.

Three fix layers:
1. FLAG PATCH: CommonLibNG plugins get rejected by SKSE because
   versionIndependenceEx=0. Patch to 2 (AddressLibraryV5).
2. VERSION INDEPENDENCE PATCH: plugins with wrong versionIndependence flags
   get rejected ("incompatible with current version of the game"). Patch to
   0x5 (AddressLibraryPostAE | StructsPost629) and set versionIndependenceEx
   |= 0x2 so the build-time check is also skipped.
3. OFFSET/PATTERN FIX: plugins that resolve REL::ID(n) + hardcoded offset,
   then pattern-check. When the game updates the offset goes stale.
   Resolve via Address Library, scan exe, patch displacement.

Usage:
  python compasse.py --audit --plugins-dir <dir>     # compatibility verdicts
  python compasse.py --scan --plugins-dir <dir>      # scan and report
  python compasse.py --fix --plugins-dir <dir> --game <exe> --addresslib <bin>
  python compasse.py --audit --dll <file>            # audit single plugin
  python compasse.py --build-translations            # build translation table
"""

import argparse
import shutil
import struct
import sys
from pathlib import Path

VERSION = "1.2.0"

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, x86
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

FLAG_STRUCT_OFFSET = 0x304  # versionIndependenceEx offset within SKSEPlugin_Version
VERSION_INDEP_OFFSET = 0x308  # versionIndependence offset within SKSEPlugin_Version
PATTERN_SCAN_RANGE = 0x1000  # scan offsets 0..0x1000 for the pattern
SHIM_NAME = "!CompaSSE.dll"

# versionIndependence flags (from SKSE64 PluginManager.cpp)
KVI_ADDR_LIB_POST_AE = 1 << 0
KVI_SIGNATURES = 1 << 1
KVI_STRUCTS_POST629 = 1 << 2
KVI_KNOWN = KVI_ADDR_LIB_POST_AE | KVI_SIGNATURES | KVI_STRUCTS_POST629
KVI_TARGET = KVI_ADDR_LIB_POST_AE | KVI_STRUCTS_POST629  # 0x5

# versionIndependenceEx flags
KVIEX_ADDR_LIB_V5 = 1 << 1  # 0x2

# SKSE build-time rejection window: plugins built in this range get
# "must be recompiled" when they declare AddressLibraryPostAE but lack V5.
_BUILD_TIME_SENTINEL = 520128000      # 1986-06-19 (sentinel "no timestamp")
_BUILD_TIME_CUTOFF = 1748217600       # 2025-05-26


def runtime_version_from_exe(exe_path):
    """Packed runtime version (e.g. 1.7.104.0 -> 0x01076800) from the exe.

    Reads the VS_FIXEDFILEINFO FileVersion of the PE. Returns None if it
    cannot be determined.
    """
    try:
        import ctypes
        from ctypes import wintypes
        ver = ctypes.windll.version
        size = ver.GetFileVersionInfoSizeW(str(exe_path), None)
        if not size:
            return None
        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(str(exe_path), 0, size, buf):
            return None
        vsffi = wintypes.DWORD()
        vslen = wintypes.UINT()
        ptr = ctypes.c_void_p()
        if not ver.VerQueryValueW(buf, "\\", ctypes.byref(ptr), ctypes.byref(vslen)):
            return None
        ffi = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_uint32 * 13)).contents
        # VS_FIXEDFILEINFO: [2]=ffileversionMS (major, minor), [3]=LS (build, rev)
        major = ffi[2] >> 16
        minor = ffi[2] & 0xFFFF
        build = ffi[3] >> 16
        rev = ffi[3] & 0xFFFF
        return (major << 24) | (minor << 16) | (build << 8) | rev
    except Exception:
        return None

def unpack_version(packed):
    """Unpack version integer to (major, minor, patch) tuple."""
    if packed is None: return None
    return (packed >> 24, (packed >> 16) & 0xFF, (packed >> 8) & 0xFF)

def pe_build_dt(dll_path):
    """PE TimeDateStamp as datetime (UTC), or None if missing/unreadable."""
    try:
        from datetime import datetime, timezone
        with open(dll_path, "rb") as f:
            hdr = f.read(0x400)
        pe_off = struct.unpack_from("<I", hdr, 0x3C)[0]
        if pe_off + 8 > len(hdr) or hdr[pe_off:pe_off + 4] != b"PE\x00\x00":
            return None
        ts = struct.unpack_from("<I", hdr, pe_off + 8)[0]
        if not ts:
            return None
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except Exception:
        return None

# ---------------------------------------------------------------------------
# PE helpers
# ---------------------------------------------------------------------------
def find_pe_sections(data):
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return []
    coff = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:
        num_dd = struct.unpack_from("<I", data, opt + 108)[0]
        dd_start = opt + 112
    elif magic == 0x10B:
        num_dd = struct.unpack_from("<I", data, opt + 92)[0]
        dd_start = opt + 96
    else:
        return []
    # Real PEs declare 16 dirs; clamp garbage so one corrupt header
    # can't send the section table into the weeds.
    if not 0 < num_dd <= 32:
        num_dd = 16
    sec_start = dd_start + num_dd * 8
    sections = []
    for i in range(num_sections):
        s = sec_start + i * 40
        name = data[s:s + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize = struct.unpack_from("<I", data, s + 8)[0]
        vaddr = struct.unpack_from("<I", data, s + 12)[0]
        rawoff = struct.unpack_from("<I", data, s + 20)[0]
        rawsize = struct.unpack_from("<I", data, s + 16)[0]
        sections.append((name, vaddr, vsize, rawoff, rawsize))
    return sections

def rva_to_offset(rva, sections):
    for name, vaddr, vsize, rawoff, rawsize in sections:
        # max(vsize, rawsize): .text is often padded on disk (rawsize > vsize);
        # RVAs in the padding still map to file bytes. vsize-only misses them.
        if vaddr <= rva < vaddr + max(vsize, rawsize):
            return rawoff + (rva - vaddr)
    return None

# ---------------------------------------------------------------------------
# Address library parsers (for --build-translations)
# ---------------------------------------------------------------------------
def parse_format5(bin_data):
    """Parse fmt5: dense u32 array. Returns dict {id: offset} or None."""
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
    """Parse any versionlib/version-*.bin file. Returns dict {id: offset}."""
    with open(bin_path, "rb") as f:
        data = f.read()
    fmt = struct.unpack_from("<I", data, 0)[0] if len(data) >= 4 else 0
    if fmt == 5: return parse_format5(data)
    elif fmt in (1, 2): return parse_addresslib(bin_path)
    return None

def read_code_sig(exe_data, sections, rva, length=64):
    """Read code signature (bytes) at RVA from PE data."""
    off = rva_to_offset(rva, sections)
    if off is None or off + length > len(exe_data): return None
    return bytes(exe_data[off:off+length])

def collect_signatures(exe_data, sections, id_offsets):
    """Extract code signatures for each ID. Returns dict {id: sig_bytes}."""
    sigs = {}
    for id_val, offset in id_offsets.items():
        sig = read_code_sig(exe_data, sections, offset)
        if sig:
            sigs[id_val] = sig
    return sigs

def extract_version_from_filename(fn):
    """Extract (major, minor, patch) from filename like 'version-1-6-640-0'."""
    import re
    m = re.search(r'(\d+)-(\d+)-(\d+)', fn)
    if m: return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    m = re.search(r'(\d+)\.(\d+)\.(\d+)', fn)
    if m: return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return None

def build_translations(game_exe, plugins_dir, game_version=None):
    """Build translation_table.bin from old bins + current binary.

    Returns (version_count, total_entries) on success, raises on error.
    """
    exe_data, sections = load_exe_sections(game_exe)
    if not exe_data:
        raise RuntimeError(f"Cannot read PE: {game_exe}")

    game_ver_tuple = unpack_version(game_version)
    current_lib = None
    current_ver = None
    for p in plugins_dir.glob("versionlib-*.bin"):
        ver = extract_version_from_filename(p.name)
        if ver and ver == game_ver_tuple:
            lib = parse_library_any(str(p))
            if lib:
                current_lib = lib
                current_ver = ver
                break
    if current_lib is None:
        for p in plugins_dir.glob("versionlib-*.bin"):
            ver = extract_version_from_filename(p.name)
            if ver:
                lib = parse_library_any(str(p))
                if lib:
                    current_lib = lib
                    current_ver = ver
                    break
    if current_lib is None:
        raise RuntimeError("No versionlib-*.bin found in plugins folder")

    exclude_ver = unpack_version(game_version) if game_version else current_ver

    old_sigs = {}  # {version_tuple: {id: sig_bytes}}
    trans_bin = plugins_dir / "CompaSSE" / "translation_table.bin"
    if trans_bin.exists():
        with open(trans_bin, "rb") as f:
            data = f.read()
        if len(data) >= 8 and data[:4] == b"TRTL":
            fmt_ver = struct.unpack_from("<I", data, 4)[0]
            o = 8
            ver_count = struct.unpack_from("<I", data, o)[0]; o += 4
            for _ in range(ver_count):
                if o + 4 > len(data): break
                ver_len = struct.unpack_from("<I", data, o)[0]; o += 4
                if ver_len > 32 or o + ver_len > len(data): break
                ver_str = data[o:o+ver_len].decode("ascii", errors="replace")
                o += (ver_len + 3) & ~3
                ver = extract_version_from_filename(ver_str.replace(".", "-"))
                if o + 4 > len(data): break
                entry_count = struct.unpack_from("<I", data, o)[0]; o += 4
                sigs = {}
                for _ in range(entry_count):
                    if fmt_ver == 2:
                        if o + 16 > len(data): break
                        old_id = struct.unpack_from("<Q", data, o)[0]; o += 8
                        o += 4  # skip offset
                        sig_size = struct.unpack_from("<I", data, o)[0]; o += 4
                        sig = data[o:o+sig_size]; o += sig_size
                        sigs[old_id] = sig
                    else:
                        if o + 12 > len(data): break
                        o += 12  # skip old_id + offset (v1 has no signatures)
                if ver and sigs:
                    old_sigs[ver] = sigs  # only v2 provides cached signatures

    current_sigs = collect_signatures(exe_data, sections, current_lib)
    print(f"Current binary: {len(current_sigs)} signatures extracted")
    print(f"Current version: {current_ver[0]}.{current_ver[1]}.{current_ver[2]}")

    # Build reverse lookup: signature -> current_id (for O(1) matching)
    sig_to_id = {}
    for cur_id, cur_sig in current_sigs.items():
        if cur_sig not in sig_to_id:
            sig_to_id[cur_sig] = cur_id

    old_bins = {}
    for p in plugins_dir.glob("version-*.bin"):
        ver = extract_version_from_filename(p.name)
        if ver and ver != exclude_ver:
            lib = parse_library_any(str(p))
            if lib:
                old_bins[ver] = lib

    if not old_bins and not old_sigs:
        raise RuntimeError("No old version bins or existing translations found")

    out = bytearray()
    out += b"TRTL"
    out += struct.pack("<I", 1)  # format version 1 (no signatures - DLL doesn't need them)
    ver_count_pos = len(out)
    out += struct.pack("<I", 0)  # placeholder
    ver_count = 0
    total_entries = 0

    for old_ver in sorted(old_bins.keys()):
        old_lib = old_bins[old_ver]
        entries = []
        for old_id, old_offset in old_lib.items():
            # Same ID exists in current library - only translate if offset changed
            if old_id in current_lib:
                cur_offset = current_lib[old_id]
                if cur_offset != old_offset:
                    entries.append((old_id, cur_offset, b""))
                continue
            # ID missing from current library - try to match by signature
            matched_sig = b""
            if old_ver in old_sigs and old_id in old_sigs[old_ver]:
                old_sig = old_sigs[old_ver][old_id]
                cur_id = sig_to_id.get(old_sig)
                if cur_id is not None:
                    matched_sig = old_sig
                    entries.append((old_id, current_lib.get(cur_id, 0), matched_sig))
            else:
                # No old signature - extract at old offset and match
                sig = read_code_sig(exe_data, sections, old_offset)
                if sig:
                    cur_id = sig_to_id.get(sig)
                    if cur_id is not None:
                        matched_sig = sig
                        entries.append((old_id, current_lib.get(cur_id, 0), matched_sig))

        if not entries:
            continue

        entries.sort(key=lambda x: x[0])
        ver_str = f"{old_ver[0]}.{old_ver[1]}.{old_ver[2]}"
        ver_bytes = ver_str.encode("ascii")
        padded_len = (len(ver_bytes) + 3) & ~3
        out += struct.pack("<I", len(ver_bytes))
        out += ver_bytes
        out += b"\x00" * (padded_len - len(ver_bytes))
        out += struct.pack("<I", len(entries))
        for old_id, offset, sig in entries:
            out += struct.pack("<QI", old_id, offset)
        ver_count += 1
        total_entries += len(entries)
        print(f"  {ver_str}: {len(entries)} entries")

    struct.pack_into("<I", out, ver_count_pos, ver_count)

    out_dir = plugins_dir / "CompaSSE"
    out_dir.mkdir(exist_ok=True)
    with open(out_dir / "translation_table.bin", "wb") as f:
        f.write(out)
    print(f"\nWrote {len(out)} bytes to {out_dir / 'translation_table.bin'} ({ver_count} versions, {total_entries} entries)")
    return ver_count, total_entries


def mint_missing_translations(old_exe_data, old_secs, old_lib,
                              new_exe_data, new_secs, new_lib, sig_len=64):
    """Mint entries for old IDs missing from the new library.

    Ground truth comes from the OLD exe bytes: the signature at the old
    offset is searched in the NEW exe .text. Unique hit -> (old_id,
    new_offset). Zero hits -> function removed (unfixable). Several hits
    -> ambiguous (reported, not minted: a wrong entry is worse than none).

    IDs present in both libs need no entry: fresh lookup resolves them.

    Returns (entries, removed_count, ambiguous_ids).
    """
    new_text_va = new_text = None
    for name, vaddr, vsize, rawoff, rawsize in new_secs:
        if name == ".text":
            new_text_va = vaddr
            new_text = bytes(new_exe_data[rawoff:rawoff + rawsize])
            break
    if new_text is None:
        raise RuntimeError("new exe has no .text section")

    def sig_at(exe_data, secs, rva):
        off = rva_to_offset(rva, secs)
        if off is None or off + sig_len > len(exe_data):
            return None
        return bytes(exe_data[off:off + sig_len])

    entries, removed, ambiguous = [], 0, []
    for old_id, old_offset in old_lib.items():
        if old_id in new_lib:
            continue
        sig = sig_at(old_exe_data, old_secs, old_offset)
        if sig is None or len(set(sig)) < 8:
            continue  # unmappable or padding-weak: never mint on weak sigs
        hits = []
        pos = new_text.find(sig)
        while pos != -1 and len(hits) <= 2:
            hits.append(pos)
            pos = new_text.find(sig, pos + 1)
        if len(hits) == 1:
            entries.append((old_id, new_text_va + hits[0]))
        elif len(hits) == 0:
            removed += 1
        else:
            ambiguous.append(old_id)
    entries.sort()
    return entries, removed, ambiguous


def merge_translation_block(plugins_dir, version_str, entries):
    """Append a version block, dropping stale rows verified-wrong.

    Rows for the same old_id from older blocks lose: a byte-verified
    ground-truth entry beats a weak-signature guess. Backs up first.
    Returns (dropped, total_entries).
    """
    trans_bin = plugins_dir / "CompaSSE" / "translation_table.bin"
    if not trans_bin.exists():
        raise RuntimeError(f"no translation table at {trans_bin}")
    bak = trans_bin.parent / (trans_bin.name + ".bak")
    if not bak.exists():
        shutil.copy2(trans_bin, bak)

    raw = bytearray(open(trans_bin, "rb").read())
    if bytes(raw[:4]) != b"TRTL" or struct.unpack_from("<I", raw, 4)[0] != 1:
        raise RuntimeError("unsupported translation table format")
    o = 8
    ver_count = struct.unpack_from("<I", raw, o)[0]; o += 4
    versions = []
    for _ in range(ver_count):
        ver_len = struct.unpack_from("<I", raw, o)[0]; o += 4
        vs = raw[o:o + ver_len].decode("ascii", errors="replace")
        o += (ver_len + 3) & ~3
        ec = struct.unpack_from("<I", raw, o)[0]; o += 4
        ent = []
        for _ in range(ec):
            oid = struct.unpack_from("<Q", raw, o)[0]; o += 8
            off = struct.unpack_from("<I", raw, o)[0]; o += 4
            ent.append((oid, off))
        versions.append((vs, ent))

    new_ids = {i for i, _ in entries}
    dropped = 0
    fixed = []
    for vs, ent in versions:
        if vs == version_str:
            continue
        kept = [(i, x) for i, x in ent if i not in new_ids]
        dropped += len(ent) - len(kept)
        fixed.append((vs, kept))
    fixed.append((version_str, sorted(entries)))

    out = bytearray(b"TRTL" + struct.pack("<I", 1) + struct.pack("<I", len(fixed)))
    for vs, ent in fixed:
        vb = vs.encode("ascii")
        out += struct.pack("<I", len(vb)) + vb + b"\x00" * (((len(vb) + 3) & ~3) - len(vb))
        out += struct.pack("<I", len(ent))
        for i, off in ent:
            out += struct.pack("<QI", i, off)
    with open(trans_bin, "wb") as f:
        f.write(out)
    total = sum(len(e) for _, e in fixed)
    return dropped, total


def find_export_rva(data, sections, export_name_bytes):
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:
        dd_start = opt + 112
    elif magic == 0x10B:
        dd_start = opt + 96
    else:
        return None
    export_rva = struct.unpack_from("<I", data, dd_start)[0]
    if export_rva == 0:
        return None
    export_off = rva_to_offset(export_rva, sections)
    if export_off is None:
        return None
    num_names = struct.unpack_from("<I", data, export_off + 24)[0]
    addr_names = struct.unpack_from("<I", data, export_off + 32)[0]
    addr_ords = struct.unpack_from("<I", data, export_off + 36)[0]
    addr_funcs = struct.unpack_from("<I", data, export_off + 28)[0]
    names_off = rva_to_offset(addr_names, sections)
    ords_off = rva_to_offset(addr_ords, sections)
    funcs_off = rva_to_offset(addr_funcs, sections)
    if not all([names_off, ords_off, funcs_off]):
        return None
    for i in range(num_names):
        name_rva = struct.unpack_from("<I", data, names_off + i * 4)[0]
        name_off = rva_to_offset(name_rva, sections)
        if name_off is None:
            continue
        if data[name_off:name_off + len(export_name_bytes)] == export_name_bytes:
            ord_idx = struct.unpack_from("<H", data, ords_off + i * 2)[0]
            return struct.unpack_from("<I", data, funcs_off + ord_idx * 4)[0]
    return None

# ---------------------------------------------------------------------------
# Layer 1: flag patch
# ---------------------------------------------------------------------------
def check_flag(dll_path):
    """Return dict with flag status, or None if not an SKSE plugin."""
    with open(dll_path, "rb") as f:
        data = bytearray(f.read())
    sections = find_pe_sections(data)
    if not sections:
        return None
    rva = find_export_rva(data, sections, b"SKSEPlugin_Version")
    if rva is None:
        return None
    struct_off = rva_to_offset(rva, sections)
    if struct_off is None:
        return None
    flag_off = struct_off + FLAG_STRUCT_OFFSET
    if flag_off + 4 > len(data):
        return None
    flag_val = struct.unpack_from("<I", data, flag_off)[0]
    return {
        "name": dll_path.name,
        "flag_off": flag_off,
        "flag_val": flag_val,
        "needs_patch": flag_val == 0,
    }

def _backup(src_path):
    """Copy a file to <src_dir>/CompaSSE/backups/ before modification.

    Idempotent: skips if a backup already exists. Returns the backup path.
    Backups live in one subfolder instead of being laying around.
    """
    parent = src_path.parent
    out_dir = parent / "CompaSSE" / "backups"
    out_dir.mkdir(parents=True, exist_ok=True)
    bak = out_dir / (src_path.name + ".bak")
    if not bak.exists():
        shutil.copy2(src_path, bak)
    return bak

def backup_bytes(path, data):
    """Backup a file then atomically overwrite it with the given bytes."""
    _backup(path)
    with open(path, "wb") as f:
        f.write(data)

def patch_flag(dll_path):
    """Patch versionIndependenceEx 0->2 with backup. Returns True if patched."""
    data = bytearray(open(dll_path, "rb").read())
    sections = find_pe_sections(data)
    rva = find_export_rva(data, sections, b"SKSEPlugin_Version")
    struct_off = rva_to_offset(rva, sections)
    flag_off = struct_off + FLAG_STRUCT_OFFSET
    if struct.unpack_from("<I", data, flag_off)[0] != 0:
        return False
    struct.pack_into("<I", data, flag_off, 2)
    backup_bytes(dll_path, bytes(data))
    return True

# ---------------------------------------------------------------------------
# Layer 1b: versionIndependence patch
# ---------------------------------------------------------------------------
def check_version_independence(dll_path, runtime_version=None):
    """Check versionIndependence + versionIndependenceEx fields.

    runtime_version: packed game runtime (1.7.104.0 -> 0x01076800). If None,
    the compatibleVersions membership check is skipped.

    Returns dict with:
        indep_val:     current versionIndependence value
        indep_ex_val:  current versionIndependenceEx value
        needs_indep:   True if versionIndependence lacks required bits
        runtime_ver:   compatibleVersions[0] (first entry) or None
    Returns None if not an SKSE plugin.
    """
    with open(dll_path, "rb") as f:
        data = f.read()
    sections = find_pe_sections(data)
    if not sections:
        return None
    rva = find_export_rva(data, sections, b"SKSEPlugin_Version")
    if rva is None:
        return None
    struct_off = rva_to_offset(rva, sections)
    if struct_off is None:
        return None

    indep_off = struct_off + VERSION_INDEP_OFFSET
    flag_off = struct_off + FLAG_STRUCT_OFFSET
    compat_off = struct_off + 0x30C
    if indep_off + 4 > len(data) or flag_off + 4 > len(data):
        return None

    indep_val = struct.unpack_from("<I", data, indep_off)[0]
    indep_ex_val = struct.unpack_from("<I", data, flag_off)[0]


    runtime_ver = None
    if compat_off + 4 <= len(data):
        first_compat = struct.unpack_from("<I", data, compat_off)[0]
        if first_compat != 0:
            runtime_ver = first_compat

    has_addr = bool(indep_val & KVI_ADDR_LIB_POST_AE)
    has_sigs = bool(indep_val & KVI_SIGNATURES)
    has_structs = bool(indep_val & KVI_STRUCTS_POST629)
    has_ex_v5 = bool(indep_ex_val & KVIEX_ADDR_LIB_V5)
    has_unknown = bool(indep_val & ~KVI_KNOWN)


    build_time = 0
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 8 < len(data):
        build_time = struct.unpack_from("<I", data, pe_off + 8)[0]

    # Mirror SKSE's two rejection paths (PluginManager.cpp):
    # 1. "must be recompiled": declares AddressLibraryPostAE,
    #    built pre-cutoff, lacks AddressLibraryV5 in ex.
    # 2. "incompatible with current version": no AddressLibraryPostAE,
    #    compatibleVersions list non-empty and runtime not in it.
    if has_addr:
        pre_cutoff = _BUILD_TIME_SENTINEL <= build_time < _BUILD_TIME_CUTOFF
        needs_indep = pre_cutoff and not has_ex_v5
    else:
        compat_list = []
        for ci in range(16):
            co = compat_off + ci * 4
            if co + 4 > len(data):
                break
            v = struct.unpack_from("<I", data, co)[0]
            if v == 0:
                break
            compat_list.append(v)
        needs_indep = bool(compat_list) and runtime_version is not None \
            and runtime_version not in compat_list

    return {
        "indep_val": indep_val,
        "indep_ex_val": indep_ex_val,
        "has_addr": has_addr,
        "has_sigs": has_sigs,
        "has_unknown": has_unknown,
        "needs_indep": needs_indep,
        "runtime_ver": runtime_ver,
    }

def _packed_to_ver(packed):
    """Convert packed version uint32 to 'M.m.b.r' string."""
    b = packed.to_bytes(4, "little")
    return f"{b[3]}.{b[2]}.{b[1]}.{b[0]}"

def patch_version_independence(dll_path):
    """Patch versionIndependence to 0x5 and versionIndependenceEx |= 0x2.

    These flags tell SKSE the plugin uses Address Library (post-AE) and
    updated structs (post-1.6.629), making it version-independent so SKSE
    skips the compatibleVersions check.

    Also sets AddressLibraryV5 in versionIndependenceEx so the build-time
    "must be recompiled" check is skipped.

    Returns True if patched.
    """
    with open(dll_path, "rb") as f:
        data = bytearray(f.read())
    sections = find_pe_sections(data)
    rva = find_export_rva(data, sections, b"SKSEPlugin_Version")
    struct_off = rva_to_offset(rva, sections)

    indep_off = struct_off + VERSION_INDEP_OFFSET
    flag_off = struct_off + FLAG_STRUCT_OFFSET

    indep_val = struct.unpack_from("<I", data, indep_off)[0]
    flag_val = struct.unpack_from("<I", data, flag_off)[0]

    needs_indep = not (indep_val & KVI_ADDR_LIB_POST_AE) or not (
        indep_val & KVI_STRUCTS_POST629
    )
    needs_flag = not (flag_val & KVIEX_ADDR_LIB_V5)

    if not needs_indep and not needs_flag:
        return False

    new_indep = indep_val | KVI_TARGET
    new_flag = flag_val | KVIEX_ADDR_LIB_V5
    struct.pack_into("<I", data, indep_off, new_indep)
    struct.pack_into("<I", data, flag_off, new_flag)

    backup_bytes(dll_path, bytes(data))
    return True

def patch_flag_force(dll_path):
    """Unconditionally set versionIndependenceEx to 2 and return True.

    Unsafe-mode force: writes the flag even when it already differs (e.g.
    a plugin carrying extra flag bits). Backs up first.
    """
    with open(dll_path, "rb") as f:
        data = bytearray(f.read())
    sections = find_pe_sections(data)
    rva = find_export_rva(data, sections, b"SKSEPlugin_Version")
    if rva is None:
        return False
    struct_off = rva_to_offset(rva, sections)
    if struct_off is None:
        return False
    flag_off = struct_off + FLAG_STRUCT_OFFSET
    if flag_off + 4 > len(data):
        return False
    old = struct.unpack_from("<I", data, flag_off)[0]
    struct.pack_into("<I", data, flag_off, 2)
    backup_bytes(dll_path, bytes(data))
    return old != 2

def patch_version_independence_force(dll_path):
    """Unconditionally set versionIndependence to 0x5 and Ex |= 0x2. Returns True.

    Unsafe-mode force: writes the target even when the plugin already has
    superset/extra bits (which we clear to the canonical values).
    """
    with open(dll_path, "rb") as f:
        data = bytearray(f.read())
    sections = find_pe_sections(data)
    rva = find_export_rva(data, sections, b"SKSEPlugin_Version")
    if rva is None:
        return False
    struct_off = rva_to_offset(rva, sections)
    if struct_off is None:
        return False
    indep_off = struct_off + VERSION_INDEP_OFFSET
    flag_off = struct_off + FLAG_STRUCT_OFFSET
    if indep_off + 4 > len(data) or flag_off + 4 > len(data):
        return False
    old_indep = struct.unpack_from("<I", data, indep_off)[0]
    old_flag = struct.unpack_from("<I", data, flag_off)[0]
    new_indep = KVI_TARGET            # 0x5
    new_flag = old_flag | KVIEX_ADDR_LIB_V5  # |= 0x2
    struct.pack_into("<I", data, indep_off, new_indep)
    struct.pack_into("<I", data, flag_off, new_flag)
    backup_bytes(dll_path, bytes(data))
    return (old_indep != new_indep) or (old_flag != new_flag)

# ---------------------------------------------------------------------------
# Hook detection (REL::ID + offset + pattern)
# ---------------------------------------------------------------------------
def get_functions_from_pdata(data, sections):
    pdata = None
    for name, vaddr, vsize, rawoff, rawsize in sections:
        if name == ".pdata":
            pdata = (vaddr, rawoff, rawsize)
            break
    if not pdata:
        return []
    pvaddr, prawoff, prawsize = pdata
    funcs = []
    for i in range(0, prawsize, 12):
        begin = struct.unpack_from("<I", data, prawoff + i)[0]
        end = struct.unpack_from("<I", data, prawoff + i + 4)[0]
        if begin and end and end > begin:
            funcs.append((begin, end))
    return funcs

def find_hooks(dll_path):
    """Find auto-portable REL::ID hooks. Returns list of hook dicts."""
    if not HAS_CAPSTONE:
        return []
    with open(dll_path, "rb") as f:
        data = f.read()
    sections = find_pe_sections(data)
    text = None
    for name, vaddr, vsize, rawoff, rawsize in sections:
        if name == ".text":
            text = (vaddr, rawoff, rawsize)
            break
    if not text:
        return []
    tvaddr, trawoff, trawsize = text
    text_data = data[trawoff:trawoff + trawsize]

    funcs = get_functions_from_pdata(data, sections)
    if not funcs:
        return []

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    results = []

    for begin, end in funcs:
        if end - begin > 0x10000:
            continue
        rel_begin = begin - tvaddr
        rel_end = end - tvaddr
        if rel_begin < 0 or rel_end > len(text_data):
            continue
        try:
            insns = list(md.disasm(text_data[rel_begin:rel_end], begin))
        except Exception:
            continue

        for i in range(len(insns) - 1):
            insn = insns[i]
            if insn.mnemonic != "lea":
                continue
            lea_info = None
            for op in insn.operands:
                if op.type == x86.X86_OP_MEM and op.mem.base == x86.X86_REG_RAX and op.mem.index == 0:
                    lea_info = (insn.operands[0].reg, op.mem.disp)
                    break
            if not lea_info:
                continue
            dest_reg, disp = lea_info

            # Backward: mov [mem], imm (REL::ID) + call, within 25 insns.
            # Stop is max(-1, ...) so index 0 is still visited (range stop
            # is exclusive; max(0, ...) silently skipped function starts).
            rel_id = None
            has_call = False
            for k in range(i - 1, max(-1, i - 25), -1):
                prev = insns[k]
                if prev.mnemonic == "call":
                    has_call = True
                    continue
                if prev.mnemonic == "mov":
                    for op in prev.operands:
                        if op.type == x86.X86_OP_IMM and prev.operands[0].type == x86.X86_OP_MEM:
                            rel_id = op.imm
                            break
                    if rel_id is not None:
                        break
                if prev.mnemonic in ("ret", "jmp", "push", "int3"):
                    break
            if rel_id is None or not has_call:
                continue

            # Forward: cmp byte ptr [reg+N], imm pattern check
            pattern = {}
            j = i + 1
            while j < len(insns) and j < i + 30:
                nxt = insns[j]
                if nxt.mnemonic == "cmp":
                    for op2 in nxt.operands:
                        if op2.type == x86.X86_OP_MEM and op2.mem.base == dest_reg:
                            off = op2.mem.disp
                            imm = None
                            for op3 in nxt.operands:
                                if op3.type == x86.X86_OP_IMM:
                                    imm = op3.imm
                            if imm is not None:
                                pattern[off] = imm
                elif nxt.mnemonic in ("call", "ret", "mov", "lea", "test", "add", "sub"):
                    break
                j += 1

            if len(pattern) >= 4:
                results.append({
                    "va": insn.address,
                    "rel_id": rel_id,
                    "offset": disp,
                    "pattern": pattern,
                    "pattern_len": max(pattern.keys()) + 1,
                })
    return results

# ---------------------------------------------------------------------------
# Address Library parsing (format 2)
# ---------------------------------------------------------------------------
def parse_addresslib(bin_path):
    """Parse format-2 Address Library bin. Returns dict {id: offset}."""
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
# Pattern scan in game exe
# ---------------------------------------------------------------------------
def load_exe_sections(exe_path):
    with open(exe_path, "rb") as f:
        exe = f.read()
    sections = find_pe_sections(exe)
    return exe, sections

def find_pattern_offsets(exe, sections, base_offset, pattern, old_offset, window=0x400):
    """Find all offsets in [old_offset-window, old_offset+window] where pattern matches.

    Returns a sorted list of matching offsets. The inlined-cmp pattern is often
    weak (matches at many offsets), so callers must handle ambiguity.
    """
    def rva2off(rva):
        for name, vaddr, vsize, rawoff, rawsize in sections:
            if vaddr <= rva < vaddr + vsize:
                return rawoff + (rva - vaddr)
        return None

    matches = []
    lo = max(0, old_offset - window)
    hi = old_offset + window
    for off in range(lo, hi + 1):
        rva = base_offset + off
        foff = rva2off(rva)
        if foff is None:
            continue
        ok = True
        for i, expected in sorted(pattern.items()):
            if foff + i >= len(exe):
                ok = False
                break
            if exe[foff + i] != expected:
                ok = False
                break
        if ok:
            matches.append(off)
    return matches

def pattern_matches_at(exe, sections, base_offset, offset, pattern):
    """Check if the pattern matches at base_offset + offset."""
    def rva2off(rva):
        for name, vaddr, vsize, rawoff, rawsize in sections:
            if vaddr <= rva < vaddr + vsize:
                return rawoff + (rva - vaddr)
        return None
    foff = rva2off(base_offset + offset)
    if foff is None:
        return False
    for i, expected in sorted(pattern.items()):
        if foff + i >= len(exe) or exe[foff + i] != expected:
            return False
    return True

# ---------------------------------------------------------------------------
# Offset patch
# ---------------------------------------------------------------------------
def patch_hook_offset(dll_path, hook, new_offset):
    """Patch the lea displacement for a hook. Returns True if patched."""
    with open(dll_path, "rb") as f:
        data = bytearray(f.read())
    sections = find_pe_sections(data)
    text = None
    for name, vaddr, vsize, rawoff, rawsize in sections:
        if name == ".text":
            text = (vaddr, rawoff, rawsize)
            break
    if not text:
        return False
    tvaddr, trawoff, trawsize = text
    # Only the disp32 form (48 8D 98 <disp32>) carries its displacement at
    # va+3 with 4-byte width. Anything else (disp8, other regs) and a blind
    # 4-byte write corrupts the following instruction - refuse instead.
    insn_off = trawoff + (hook["va"] - tvaddr)
    if insn_off + 7 > len(data) or bytes(data[insn_off:insn_off + 3]) != b"\x48\x8D\x98":
        return False
    disp_off = insn_off + 3
    cur = struct.unpack_from("<I", data, disp_off)[0]
    if cur != hook["offset"]:
        return False
    struct.pack_into("<I", data, disp_off, new_offset)
    backup_bytes(dll_path, bytes(data))
    return True

# ---------------------------------------------------------------------------
# Format 5 -> 2 bin conversion
# ---------------------------------------------------------------------------
def convert_format5_to_format2(fmt5_path, out_path):
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

    out = struct.pack("<i", 2) + bytes(header) + bytes(body)
    with open(out_path, "wb") as f:
        f.write(out)
    return len(entries), len(out)

# ---------------------------------------------------------------------------
# High-level operations
# ---------------------------------------------------------------------------
def count_xref_ids(dll_path, id_set):
    """Data slots holding known address-library IDs AND read by code.

    A mod our ID machinery can help must resolve game addresses through
    IDs baked into its binary: a rip-relative load from a .data/.rdata
    slot whose value is a known library ID. Returns that count, or None
    when capstone is missing, no ID set was given, or the PE is unreadable.

    Zero (with a real ID set) means: no statically recoverable game
    references. Flags/format/translation fixes cannot help such a mod -
    its game coupling is version-gated logic, hardcoded RVAs, or vtable
    slots, all invisible to the address library.
    """
    if not HAS_CAPSTONE or not id_set:
        return None
    try:
        with open(dll_path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    sections = find_pe_sections(data)
    if not sections:
        return None
    by_name = {n: (v, o, s) for n, v, _, o, s in sections}
    if ".text" not in by_name:
        return None

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    rip_targets = set()
    try:
        for begin, end in get_functions_from_pdata(data, sections):
            if end - begin > 0x10000:
                continue
            off = rva_to_offset(begin, sections)
            if off is None:
                continue
            for ins in md.disasm(data[off:off + (end - begin)], begin):
                for op in ins.operands:
                    if op.type == x86.X86_OP_MEM and op.mem.base == x86.X86_REG_RIP:
                        rip_targets.add(ins.address + ins.size + op.mem.disp)
    except Exception:
        return None
    if not rip_targets:
        return None

    count = 0
    for sname in (".data", ".rdata"):
        if sname not in by_name:
            continue
        vaddr, rawoff, rawsize = by_name[sname]
        for k in range(0, rawsize - 8):
            rva = vaddr + k
            if rva not in rip_targets:
                continue
            for width, fmt in ((8, "<Q"), (4, "<I")):
                if k + width > rawsize:
                    continue
                val = struct.unpack_from(fmt, data, rawoff + k)[0]
                if val in id_set:
                    count += 1
                    break
    return count


def find_version_gates(dll_path):
    """Find game-version gate patterns in an SKSE plugin.

    Three shapes, all read-only reported (never patched here):
    - iface_version_read: SKSEPlugin_Load reads [rcx+4] (runtimeVersion
      from the SKSEInterface* first arg). The seed of every gate.
    - packed_compare: cmp against a packed 1.x runtime constant
      (0x01______). The rungs of the version ladder.
    - version_string_ref: code references a version-gate string
      ("version", "mismatch", ...). File-parse gates never touch packed
      constants; their error strings are the fingerprint.

    Returns list of dicts {kind, rva, func, detail}. Empty (not None)
    when capstone works but nothing found; None when unavailable.
    """
    if not HAS_CAPSTONE:
        return None
    try:
        with open(dll_path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    sections = find_pe_sections(data)
    if not sections:
        return None

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    funcs = get_functions_from_pdata(data, sections)
    if not funcs:
        return None

    load_rva = find_export_rva(data, sections, b"SKSEPlugin_Load")
    load_bounds = None
    if load_rva is not None:
        for b, e in funcs:
            if b <= load_rva < e:
                load_bounds = (b, e)
                break

    # Version-gate strings in .rdata, keyed by RVA (rip targets are RVAs).
    # Two noise guards from corpus calibration:
    # - skip undecodable bytes (wide strings misread as ascii produce
    #   phantom keyword hits like "<unicode conversion error>");
    # - word boundaries ("conversion" is not "version").
    import re as _re
    _gate_pat = _re.compile(
        r"(?<![a-z])(?:load_version|version|mismatch|incompatible|outdated|not supported)(?![a-z])")
    keystrings = {}
    for name, vaddr, vsize, rawoff, rawsize in sections:
        if name not in (".rdata", ".data"):
            continue
        blob = data[rawoff:rawoff + rawsize]
        for m in _re.finditer(rb"[ -~]{4,80}\x00", blob):
            try:
                s = m.group(0)[:-1].decode("ascii")
            except UnicodeDecodeError:
                continue
            if "\ufffd" in s:
                continue
            if _gate_pat.search(s.lower()):
                keystrings[vaddr + m.start()] = s

    gates = []
    for b, e in funcs:
        if e - b > 0x10000:
            continue
        off = rva_to_offset(b, sections)
        if off is None:
            continue
        try:
            block = data[off:off + (e - b)]
        except Exception:
            continue
        try:
            insns = list(md.disasm(block, b))
        except Exception:
            continue
        in_loader = load_bounds is not None and load_bounds[0] <= b < load_bounds[1]
        # SKSEPlugin_Load receives SKSEInterface* in rcx; it is usually
        # copied to a callee-saved reg first. Track one level of aliasing
        # so [rbx+4] reads still match the runtimeVersion field.
        iface_regs = {x86.X86_REG_RCX} if in_loader else set()
        for ins in insns:
            if in_loader and ins.mnemonic == "mov" and len(ins.operands) == 2:
                o0, o1 = ins.operands
                if o0.type == x86.X86_OP_REG and o1.type == x86.X86_OP_REG \
                        and o1.reg in iface_regs:
                    iface_regs.add(o0.reg)
            for op in ins.operands:
                if op.type == x86.X86_OP_MEM and op.mem.base in iface_regs \
                        and op.mem.disp == 4 and in_loader:
                    gates.append({"kind": "iface_version_read",
                                  "rva": ins.address, "func": b,
                                  "detail": f"{ins.mnemonic} {ins.op_str}"})
                if op.type == x86.X86_OP_MEM and op.mem.base == x86.X86_REG_RIP \
                        and ins.mnemonic in ("lea", "mov", "cmp"):
                    tgt = ins.address + ins.size + op.mem.disp
                    if tgt in keystrings:
                        gates.append({"kind": "version_string_ref",
                                      "rva": ins.address, "func": b,
                                      "detail": f"{ins.mnemonic} {ins.op_str} "
                                                f"-> {keystrings[tgt][:60]!r}"})
                if op.type == x86.X86_OP_IMM and ins.mnemonic in (
                        "cmp", "test", "mov", "lea", "sub", "add", "xor"):
                    v = op.imm & 0xFFFFFFFF
                    # Packed runtime: (1<<24)|(minor<<16)|(build<<8)|rev.
                    # Skyrim minors are 5/6/7 - anything else (sizes like
                    # 0x16E3600, type tags like 0x100002D) is noise.
                    if ((v >> 24) == 1 and ((v >> 16) & 0xFF) in (5, 6, 7)
                            and v & 0x00FFFFFF):
                        gates.append({"kind": "packed_compare",
                                      "rva": ins.address, "func": b,
                                      "detail": f"{ins.mnemonic} {ins.op_str}"})
    # deduplicate, keep function attribution
    seen = set()
    uniq = []
    for g in gates:
        key = (g["kind"], g["rva"])
        if key not in seen:
            seen.add(key)
            uniq.append(g)
    return uniq


def analyze_plugin(dll_path, runtime_version=None, include_hooks=True):
    """Analyze a single plugin. Returns dict with flag + versionIndependence + hooks info.

    include_hooks=False skips the capstone disassembly pass (seconds per
    DLL) for fast scans; callers run find_hooks on demand at fix time.
    """
    info = {"name": dll_path.name, "flag": None, "version_indep": None, "hooks": [],
            "hooks_scanned": include_hooks}
    flag = check_flag(dll_path)
    if flag is not None:
        info["flag"] = flag
    vi = check_version_independence(dll_path, runtime_version)
    if vi is not None:
        info["version_indep"] = vi
    if include_hooks:
        info["hooks"] = find_hooks(dll_path)
    return info


# ---------------------------------------------------------------------------
# Audit: definitive compatibility verdict
# ---------------------------------------------------------------------------
def _audit_plugin(dll_path, runtime_version=None, id_set=None):
    """Audit a single plugin against the definitive compatibility rules.

    Returns dict with:
        name:    plugin filename
        verdict: SAFE / NEEDS_FIX / BROKEN / UNKNOWN
        reason:  one-line human-readable explanation
        details: dict of raw analysis data (flag, vi, hooks, build_year)
    """
    info = analyze_plugin(dll_path, runtime_version)
    dt = pe_build_dt(dll_path)
    build_year = dt.year if dt else None

    flag = info["flag"]
    vi = info["version_indep"]
    hooks = info["hooks"]

    # Not an SKSE plugin at all
    if flag is None and vi is None:
        return {
            "name": dll_path.name,
            "verdict": "UNKNOWN",
            "reason": "Not an SKSE plugin (no SKSEPlugin_Version export).",
            "details": {"build_year": build_year},
        }

    has_addr = vi.get("has_addr", False) if vi else False
    flag_patch = flag is not None and flag.get("needs_patch", False)
    indep_patch = vi is not None and vi.get("needs_indep", False)
    has_unknown = vi is not None and vi.get("has_unknown", False)
    needs_fix = flag_patch or indep_patch

    # Rule 1: built with CommonLibSSE? (heuristic: build year + has SKSE export)
    # Rule 2: uses Address Library? (versionIndependence flag bit)
    # Rule 3: has hardcoded offsets? (capstone hook scan finds REL::ID + offset)

    old_build = build_year is not None and build_year < 2025

    # BROKEN: old build, no Address Library, likely hardcoded offsets
    if old_build and not has_addr and not needs_fix:
        return {
            "name": dll_path.name,
            "verdict": "BROKEN",
            "reason": (f"Built {build_year}, no Address Library. "
                       "Likely hardcoded offsets - will crash on current runtime."),
            "details": {"build_year": build_year, "has_addr": has_addr,
                        "hooks": len(hooks)},
        }

    # BROKEN: unknown flags, can't verify
    if has_unknown:
        return {
            "name": dll_path.name,
            "verdict": "BROKEN",
            "reason": (f"Unknown versionIndependence flags (0x{vi['indep_val']:x}). "
                       "Cannot verify compatibility."),
            "details": {"build_year": build_year, "has_addr": has_addr},
        }

    # NEEDS_FIX: flag patches will make it work
    if needs_fix and has_addr:
        reasons = []
        if flag_patch:
            reasons.append("versionIndependenceEx flag is 0 (needs 2)")
        if indep_patch:
            reasons.append(f"versionIndependence is 0x{vi['indep_val']:x} (needs 0x{KVI_TARGET:x})")
        extra = f", {len(hooks)} hook offsets stale" if hooks else ""
        return {
            "name": dll_path.name,
            "verdict": "NEEDS_FIX",
            "reason": "; ".join(reasons) + extra,
            "details": {"build_year": build_year, "has_addr": has_addr,
                        "hooks": len(hooks)},
        }

    # NEEDS_FIX: needs flags but no address library - risky
    if needs_fix and not has_addr:
        return {
            "name": dll_path.name,
            "verdict": "NEEDS_FIX",
            "reason": (f"Built {build_year or '?'}, no Address Library. "
                       "Flag patches applied but hardcoded offsets may still break it."),
            "details": {"build_year": build_year, "has_addr": has_addr,
                        "hooks": len(hooks)},
        }

    # SAFE: flags correct, uses Address Library
    if has_addr and not needs_fix:
        # Triage gate: without statically recoverable game references, ID
        # machinery (flags, formats, translations) cannot help this mod.
        # Seen live: version-gated init logic that crashes past the gate.
        xref = count_xref_ids(dll_path, id_set) if id_set else None
        if xref == 0:
            return {
                "name": dll_path.name,
                "verdict": "MANUAL",
                "reason": ("Flags look right but no game addresses are "
                           "statically recoverable (0 xref'd IDs). Fixes here "
                           "can't help it - likely version-gated logic or "
                           "hardcoded offsets. Needs author or deep RE."),
                "details": {"build_year": build_year, "has_addr": has_addr,
                            "hooks": len(hooks), "xref_ids": 0},
            }
        extra = f", {len(hooks)} hooks verified" if hooks else ""
        if xref:
            extra += f", {xref} xref'd IDs"
        return {
            "name": dll_path.name,
            "verdict": "SAFE",
            "reason": f"Uses Address Library, flags correct{extra}.",
            "details": {"build_year": build_year, "has_addr": has_addr,
                        "hooks": len(hooks)},
        }

    # UNKNOWN: can't determine
    return {
        "name": dll_path.name,
        "verdict": "UNKNOWN",
        "reason": "Cannot determine compatibility. Review manually.",
        "details": {"build_year": build_year, "has_addr": has_addr},
    }


def fix_plugin(dll_path, exe, exe_sections, addresslib, runtime_version=None, dry_run=True):
    """Fix a single plugin. Returns list of action strings."""
    actions = []
    info = analyze_plugin(dll_path, runtime_version)

    # Layer 1: flag patch (runs first so Layer 2's |= 0x2 doesn't shadow it)
    if info["flag"] and info["flag"]["needs_patch"]:
        if dry_run:
            actions.append(f"  flag: needs patch (0 -> 2)")
        else:
            if patch_flag(dll_path):
                actions.append(f"  flag: patched 0 -> 2")
            else:
                actions.append(f"  flag: patch FAILED")

    # Layer 2: versionIndependence patch
    vi = info["version_indep"]
    if vi and vi["needs_indep"]:
        if dry_run:
            actions.append(
                f"  versionIndependence: needs patch "
                f"(0x{vi['indep_val']:x} -> 0x{KVI_TARGET:x})"
            )
        else:
            if patch_version_independence(dll_path):
                actions.append(
                    f"  versionIndependence: patched "
                    f"(0x{vi['indep_val']:x} -> 0x{KVI_TARGET:x}, "
                    f"versionIndependenceEx |= 0x2)"
                )
            else:
                actions.append(f"  versionIndependence: patch FAILED")

    # Offset/pattern fix (only when exe and addresslib are available)
    if addresslib is None or exe is None:
        return actions
    for hook in info["hooks"]:
        rel_id = hook["rel_id"]
        if rel_id not in addresslib:
            actions.append(f"  hook REL::ID {rel_id}: not in address library, skip")
            continue
        base = addresslib[rel_id]
        old_off = hook["offset"]


        if pattern_matches_at(exe, exe_sections, base, old_off, hook["pattern"]):
            actions.append(f"  hook REL::ID {rel_id}: offset 0x{old_off:x} already correct")
            continue

        # Scan a window around the old offset (the new offset is close to the
        # old one; the function layout shifts only slightly between patches).
        matches = find_pattern_offsets(exe, exe_sections, base, hook["pattern"], old_off)
        if not matches:
            actions.append(f"  hook REL::ID {rel_id}: pattern not found near old offset 0x{old_off:x}, skip")
            continue

        # The inlined-cmp pattern is often weak and matches at many offsets.
        # Only auto-patch on a UNIQUE match; otherwise report for manual review
        # (patching the wrong offset silently breaks the plugin).
        if len(matches) > 1:
            cand = ", ".join(f"0x{m:x}" for m in matches)
            actions.append(
                f"  hook REL::ID {rel_id}: offset 0x{old_off:x} stale; "
                f"AMBIGUOUS ({len(matches)} candidates: {cand}) - manual review required"
            )
            continue

        new_off = matches[0]
        if dry_run:
            actions.append(f"  hook REL::ID {rel_id}: offset 0x{old_off:x} -> 0x{new_off:x} (needs patch)")
        else:
            if patch_hook_offset(dll_path, hook, new_off):
                actions.append(f"  hook REL::ID {rel_id}: offset 0x{old_off:x} -> 0x{new_off:x} (patched)")
            else:
                actions.append(f"  hook REL::ID {rel_id}: offset patch FAILED")
    return actions

def main():
    parser = argparse.ArgumentParser(
        description=f"CompaSSE {VERSION} for Skyrim SE 1.7.99+")
    parser.add_argument("--scan", action="store_true",
                        help="Scan plugins and show status (no changes)")
    parser.add_argument("--audit", action="store_true",
                        help="Audit plugins against compatibility rules")
    parser.add_argument("--fix", action="store_true",
                        help="Apply fixes to plugins")
    parser.add_argument("--plugins-dir", type=Path, default=None,
                        help="SKSE plugins directory")
    parser.add_argument("--dll", type=Path, default=None,
                        help="Single DLL to process")
    parser.add_argument("--game", type=Path, default=None,
                        help="SkyrimSE.exe path (required for hook offset fix)")
    parser.add_argument("--addresslib", type=Path, default=None,
                        help="versionlib bin path (required for hook offset fix)")
    parser.add_argument("--build-translations", action="store_true",
                        help="Build translation table from old bins + current binary")
    parser.add_argument("--mint-missing", action="store_true",
                        help="Mint entries for old IDs missing from the new lib, "
                             "using --old-exe bytes as ground truth")
    parser.add_argument("--old-exe", type=Path, default=None,
                        help="Old game exe matching --old-lib (for --mint-missing)")
    parser.add_argument("--old-lib", type=Path, default=None,
                        help="Old versionlib bin (for --mint-missing)")
    parser.add_argument("--find-gates", action="store_true",
                        help="Report game-version gate patterns (read-only, no changes)")
    args = parser.parse_args()

    # -- Mint-missing mode: old-exe ground truth for dropped IDs
    if args.mint_missing:
        if args.old_exe is None or not args.old_exe.exists():
            parser.error("--old-exe is required for --mint-missing")
        if args.old_lib is None or not args.old_lib.exists():
            parser.error("--old-lib is required for --mint-missing")
        game_path = args.game
        if game_path is None:
            game_path = Path(__file__).resolve().parent / "SkyrimSE.exe"
        if not game_path.exists():
            parser.error(f"game exe not found: {game_path}")
        plugins_dir = args.plugins_dir
        if plugins_dir is None:
            plugins_dir = game_path.parent / "Data" / "SKSE" / "Plugins"
        if not plugins_dir.exists():
            parser.error(f"plugins folder not found: {plugins_dir}")
        game_ver = runtime_version_from_exe(game_path)
        new_lib = None
        for p in plugins_dir.glob("versionlib-*.bin"):
            if game_ver and extract_version_from_filename(p.name) == unpack_version(game_ver):
                new_lib = parse_library_any(str(p))
                if new_lib:
                    break
        if new_lib is None:
            parser.error("no versionlib matching the game exe found")
        old_exe_data, old_secs = load_exe_sections(str(args.old_exe))
        new_exe_data, new_secs = load_exe_sections(str(game_path))
        old_lib = parse_library_any(str(args.old_lib))
        if old_lib is None:
            parser.error(f"cannot parse old lib: {args.old_lib}")
        old_ver = extract_version_from_filename(args.old_lib.name) or (0, 0, 0)
        entries, removed, ambig = mint_missing_translations(
            old_exe_data, old_secs, old_lib, new_exe_data, new_secs, new_lib)
        print(f"minted={len(entries)} removed-fn={removed} ambiguous={len(ambig)}")
        if entries:
            ver_str = f"{old_ver[0]}.{old_ver[1]}.{old_ver[2]}"
            dropped, total = merge_translation_block(plugins_dir, ver_str, entries)
            print(f"merged {ver_str}: +{len(entries)} dropped-stale={dropped} total={total}")
        return

    # -- Find-gates mode: read-only version-gate report
    if args.find_gates:
        if args.dll is None and args.plugins_dir is None:
            parser.error("specify --plugins-dir or --dll")
        dlls = []
        if args.dll:
            dlls = [args.dll]
        elif args.plugins_dir and args.plugins_dir.exists():
            dlls = sorted(args.plugins_dir.glob("*.dll"))
        for dll in dlls:
            gates = find_version_gates(dll)
            if gates is None:
                print(f"{dll.name}: gate scan unavailable")
            elif not gates:
                print(f"{dll.name}: no version gates")
            else:
                from collections import Counter as _Counter
                per_func = _Counter(g["func"] for g in gates)
                gates.sort(key=lambda g: (-per_func[g["func"]], g["rva"]))
                print(f"{dll.name}: {len(gates)} gate signal(s)")
                for g in gates[:12]:
                    mark = "*" if per_func[g["func"]] > 1 else " "
                    print(f"   {mark}[{g['kind']}] func {hex(g['func'])} "
                          f"@{hex(g['rva'])}: {g['detail']}")
                if len(gates) > 12:
                    print(f"    ... and {len(gates) - 12} more")
        return

    # -- Build translations mode
    if args.build_translations:

        game_path = args.game
        if game_path is None:
            game_path = Path(__file__).resolve().parent / "SkyrimSE.exe"
        if not game_path.exists():
            parser.error(f"game exe not found: {game_path}")
        plugins_dir = args.plugins_dir
        if plugins_dir is None:
            plugins_dir = game_path.parent / "Data" / "SKSE" / "Plugins"
        if not plugins_dir.exists():
            parser.error(f"plugins folder not found: {plugins_dir}")
        game_ver = runtime_version_from_exe(game_path)
        print(f"Game: {game_path}")
        print(f"Plugins: {plugins_dir}")
        ver_count, total = build_translations(str(game_path), plugins_dir,
                                              game_version=game_ver)
        print(f"\nDone. {ver_count} version(s), {total} total entries.")
        return

    if not HAS_CAPSTONE:
        print("WARNING: capstone not installed - hook detection disabled")

    if args.dll is None and args.plugins_dir is None:
        parser.error("specify --plugins-dir or --dll")


    exe = None
    exe_sections = None
    addresslib = None
    runtime_version = None
    if args.fix and (args.game or args.dll):
        game_path = args.game
        if game_path is None:
            parser.error("--game is required for --fix")
        runtime_version = runtime_version_from_exe(game_path) if game_path.exists() else None
        al_path = args.addresslib
        if al_path is None:
            parser.error("--addresslib is required for --fix")
        if game_path.exists():
            exe, exe_sections = load_exe_sections(game_path)
        else:
            print(f"ERROR: game exe not found: {game_path}")
        if al_path.exists():
            addresslib = parse_addresslib(al_path)
        else:
            print(f"ERROR: address library not found: {al_path}")

    dry_run = not args.fix


    dlls = []
    if args.dll:
        dlls = [args.dll]
    elif args.plugins_dir and args.plugins_dir.exists():
        dlls = sorted(args.plugins_dir.glob("*.dll"))
    else:
        print(f"ERROR: no plugins found at {args.plugins_dir}")
        sys.exit(1)

    # -- Audit mode: definitive compatibility verdicts
    if args.audit:
        print(f"\n=== AUDIT {len(dlls)} plugin(s) ===\n")
        # Triage gate needs the ID set: load it when a lib is provided.
        id_set = None
        if args.addresslib is not None and args.addresslib.exists():
            lib = parse_library_any(str(args.addresslib))
            if lib:
                id_set = set(lib)
        counts = {"SAFE": 0, "NEEDS_FIX": 0, "BROKEN": 0, "UNKNOWN": 0}
        for dll in dlls:
            result = _audit_plugin(dll, runtime_version, id_set)
            v = result["verdict"]
            counts[v] = counts.get(v, 0) + 1
            tag = {"SAFE": "[OK]", "NEEDS_FIX": "[FIX]", "BROKEN": "[!!]", "UNKNOWN": "[??]"}[v]
            print(f"  {tag} {result['name']}: {result['reason']}")
        print(f"\n  {counts['SAFE']} safe, {counts['NEEDS_FIX']} needs fix, "
              f"{counts['BROKEN']} broken, {counts['UNKNOWN']} unknown")
        return

    # -- Scan / Fix mode
    mode = "SCAN" if dry_run else "FIX"
    print(f"\n=== {mode} {len(dlls)} plugin(s) ===")

    for dll in dlls:
        info = analyze_plugin(dll, runtime_version)
        print(f"\n{dll.name}:")

        if info["flag"] is None:
            print("  not an SKSE plugin")
        elif info["flag"]["needs_patch"]:
            print("  flag: NEEDS PATCH")
        else:
            print("  flag: OK")

        vi = info["version_indep"]
        if vi is not None:
            if vi["has_unknown"]:
                print(f"  versionIndependence: UNKNOWN (0x{vi['indep_val']:x})")
            elif vi["needs_indep"]:
                print("  versionIndependence: NEEDS PATCH")
            else:
                print("  versionIndependence: OK")

        if info["hooks"]:
            print(f"  hooks: {len(info['hooks'])} auto-portable")
        else:
            print("  hooks: none")

        if args.fix:
            for action in fix_plugin(dll, exe, exe_sections, addresslib,
                                     runtime_version=runtime_version, dry_run=False):
                print(action)
        elif exe is not None and addresslib is not None:
            for action in fix_plugin(dll, exe, exe_sections, addresslib,
                                     runtime_version=runtime_version, dry_run=True):
                print(action)

    if dry_run:
        print("\n  (scan only - no changes made)")
    print("\nDone.")

if __name__ == "__main__":
    main()
