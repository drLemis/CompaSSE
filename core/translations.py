"""Offset translations across game versions."""
import logging
from pathlib import Path
import shutil
import struct
from core.addresslib import extract_version_from_filename, parse_library_any
from core.pe import load_exe_sections, rva_to_offset
from core.versions import unpack_version

_log = logging.getLogger("compasse")

def _encode_table_header(fmt, stamp=None):
    """Header bytes for a translation table."""
    out = bytearray(b"TRTL" + struct.pack("<I", fmt))
    if fmt == 3:
        sb = (stamp or "").encode("ascii")
        out += struct.pack("<I", len(sb)) + sb
        out += b"\x00" * (((len(sb) + 3) & ~3) - len(sb))
    return bytes(out)

def _table_header(data):
    """Parse table header. None if invalid."""
    if len(data) < 12 or data[:4] != b"TRTL":
        return None
    fmt = struct.unpack_from("<I", data, 4)[0]
    o = 8
    stamp = None
    if fmt == 3:
        if o + 4 > len(data):
            return None
        n = struct.unpack_from("<I", data, o)[0]; o += 4
        if n == 0 or n > 32 or o + n > len(data):
            return None
        try:
            stamp = data[o:o + n].decode("ascii")
        except UnicodeDecodeError:
            return None
        o += (n + 3) & ~3
    elif fmt not in (1, 2):
        return None
    return fmt, stamp, o

def table_header(data):
    """Parse table header. None if invalid."""
    return _table_header(data)

def read_code_sig(exe_data, sections, rva, length=64):
    """Code bytes at RVA. None if unreadable."""
    off = rva_to_offset(rva, sections)
    if off is None or off + length > len(exe_data): return None
    return bytes(exe_data[off:off+length])

def collect_signatures(exe_data, sections, id_offsets):
    """Code bytes for each ID."""
    sigs = {}
    for id_val, offset in id_offsets.items():
        sig = read_code_sig(exe_data, sections, offset)
        if sig:
            sigs[id_val] = sig
    return sigs

def build_translations(game_exe, plugins_dir, game_version=None, extra_lib_dirs=None):
    """Build translation_table.bin for IDs missing from the current bin."""
    exe_data, sections = load_exe_sections(game_exe)
    if not exe_data:
        raise RuntimeError(f"Cannot read PE: {game_exe}")

    game_ver_tuple = unpack_version(game_version)
    search_dirs = [plugins_dir] + list(extra_lib_dirs or [])
    lib_bins = []
    for d in search_dirs:
        try:
            lib_bins.extend(sorted(Path(d).glob("versionlib-*.bin")))
        except OSError:
            continue
    current_lib = None
    current_ver = None
    for p in lib_bins:
        ver = extract_version_from_filename(p.name)
        if ver and ver == game_ver_tuple:
            lib = parse_library_any(str(p))
            if lib:
                current_lib = lib
                current_ver = ver
                break
    if current_lib is None:
        for p in lib_bins:
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
        hdr = _table_header(data)
        if hdr is not None:
            fmt_ver, _, o = hdr
            if o + 4 > len(data):
                fmt_ver = -1
            else:
                ver_count = struct.unpack_from("<I", data, o)[0]; o += 4
            if fmt_ver in (1, 2, 3):
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
                            o += 12  # skip old_id + offset (no signatures)
                    if ver and sigs:
                        old_sigs[ver] = sigs  # only v2 provides cached signatures

    current_sigs = collect_signatures(exe_data, sections, current_lib)
    _log.info("Current binary: %d signatures extracted", len(current_sigs))
    _log.info("Current version: %d.%d.%d", current_ver[0], current_ver[1], current_ver[2])

    # Build reverse lookup: signature -> current_id (for O(1) matching)
    sig_to_id = {}
    for cur_id, cur_sig in current_sigs.items():
        if cur_sig not in sig_to_id:
            sig_to_id[cur_sig] = cur_id

    old_bins = {}
    for d in search_dirs:
        try:
            cands = sorted(Path(d).glob("version-*.bin"))
        except OSError:
            continue
        for p in cands:
            ver = extract_version_from_filename(p.name)
            if ver and ver != exclude_ver and ver not in old_bins:
                lib = parse_library_any(str(p))
                if lib:
                    old_bins[ver] = lib

    if not old_bins and not old_sigs:
        raise RuntimeError("No old version bins or existing translations found")

    out = bytearray()
    stamp_tup = unpack_version(game_version) if game_version else current_ver
    stamp = f"{stamp_tup[0]}.{stamp_tup[1]}.{stamp_tup[2]}"
    out += _encode_table_header(3, stamp)
    ver_count_pos = len(out)
    out += struct.pack("<I", 0)  # placeholder
    ver_count = 0
    total_entries = 0

    for old_ver in sorted(old_bins.keys()):
        old_lib = old_bins[old_ver]
        entries = []
        for old_id, old_offset in old_lib.items():
            # Same ID exists in current library: skip
            if old_id in current_lib:
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
        _log.info("  %s: %d entries", ver_str, len(entries))

    struct.pack_into("<I", out, ver_count_pos, ver_count)

    out_dir = plugins_dir / "CompaSSE"
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "translation_table.bin", "wb") as f:
        f.write(out)
    _log.info("Wrote %d bytes to %s (%d versions, %d entries)",
              len(out), out_dir / "translation_table.bin", ver_count, total_entries)
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

def read_translation_table(data):
    """(header_bytes, fmt, stamp_or_None, [(version, [(old_id, offset)])]).

    Single reader for the table body; None when unparsable. Merge and
    check-up share it instead of walking the format twice.
    """
    hdr = _table_header(bytes(data))
    if hdr is None:
        return None
    fmt, stamp, o = hdr
    if fmt == 2:
        return None  # sig-cached rows carry signatures, not plain pairs
    try:
        header = bytes(data[:o])
        ver_count = struct.unpack_from("<I", data, o)[0]; o += 4
        versions = []
        for _ in range(ver_count):
            ver_len = struct.unpack_from("<I", data, o)[0]; o += 4
            vs = data[o:o + ver_len].decode("ascii", errors="replace")
            o += (ver_len + 3) & ~3
            ec = struct.unpack_from("<I", data, o)[0]; o += 4
            ent = []
            for _ in range(ec):
                oid = struct.unpack_from("<Q", data, o)[0]; o += 8
                off = struct.unpack_from("<I", data, o)[0]; o += 4
                ent.append((oid, off))
            versions.append((vs, ent))
    except (struct.error, IndexError, ValueError):
        return None
    return (header, fmt, stamp, versions)

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
    parsed = read_translation_table(bytes(raw))
    if parsed is None:
        raise RuntimeError("unsupported translation table format")
    header, fmt, _, versions = parsed
    if fmt == 2:
        raise RuntimeError("sig-cached tables cannot be merged")

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

    out = bytearray(header + struct.pack("<I", len(fixed)))
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

def table_build_stamp(plugins_dir):
    """Game version ("M.m.b") the translation table was built for.

    None when the table is missing, legacy (unstamped), or unreadable.
    """
    try:
        data = (Path(plugins_dir) / "CompaSSE"
                / "translation_table.bin").read_bytes()
    except OSError:
        return None
    hdr = _table_header(data)
    if hdr is None:
        return None
    return hdr[1]

def table_state(plugins_dir, game_str):
    """Translation table status for the GUI: ("ok" | "stale" | "legacy"
    | "absent", stamp_or_None). Legacy predates stamps, so the GUI
    offers a rebuild instead of staying silent."""
    try:
        data = (Path(plugins_dir) / "CompaSSE"
                / "translation_table.bin").read_bytes()
    except OSError:
        return ("absent", None)
    hdr = _table_header(data)
    if hdr is None:
        return ("absent", None)
    fmt, stamp, _ = hdr
    if fmt == 3:
        return ("ok", stamp) if stamp == game_str else ("stale", stamp)
    return ("legacy", None)
