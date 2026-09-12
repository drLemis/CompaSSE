#!/usr/bin/env python3
"""SKSE co-save surgeon - list and drop per-plugin data blocks in .skse files.

Layout (SKSE Serialization.cpp): Header {signature 'SKSE', formatVersion,
skseVersion, runtimeVersion, numPlugins}, then per plugin PluginHeader
{uid, numChunks, length} + ChunkHeader {type, version, length} + data.
FourCCs read byte-swapped on disk (file 'NGLP' == logical 'PLGN').

Dropping a block is engine-blessed: SKSE natively skips unknown plugin
UIDs at load, so a dropped block behaves exactly like "plugin not
installed". Refuses inexact parses and uid 0 (SKSE core). `.ess`
orphans are out of scope (ReSaver's job).

Usage:
    python skse_surgeon.py <save.skse>              # list plugin blocks
    python skse_surgeon.py <save.skse> --drop PLGN   # drop one block
"""

import argparse
import json
import re
import shutil
import struct
import sys
from pathlib import Path

SIG_SKS = 0x45534B53  # 'SKSE' on disk
FORMAT_VERSION = 1

# UIDs we can name. Everything else shows as its FourCC (unknown but
# droppable - the format needs no name table to stay byte-exact).
KNOWN_UIDS = {
    0x00000000: "SKSE core",
}


def fcc(value):
    """Logical FourCC string for a raw u32 (file order is byte-swapped)."""
    return bytes(((value >> 24) & 0xFF, (value >> 16) & 0xFF,
                  (value >> 8) & 0xFF, value & 0xFF)).decode("ascii", errors="replace")


def unfcc(name):
    """Raw u32 for a logical FourCC like 'PLGN'."""
    b = name.encode("ascii")
    if len(b) != 4:
        raise ValueError(f"not a FourCC: {name!r}")
    return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]


def parse_uid(text):
    """Accept decimal ('12'), hex ('0x...') or logical FourCC ('PLGN')."""
    text = text.strip()
    try:
        return int(text, 0)
    except ValueError:
        pass
    if len(text) == 4 and text.isascii():
        return unfcc(text)
    raise ValueError(f"not a uid: {text!r}")


def plugin_list_chunk(block, path):
    """Decode a PLGN chunk into [(index, esp_name)] or None.

    SKSE stores the save-time load order here: u16 count, then per mod
    {u8 index, u16 name length, name} - with u8 0xFE marking a light
    plugin, followed by its u16 light index (shown as FE BokJ). Garbage
    in -> None (never guess: callers treat None as unknown).
    """
    for c in block["chunks"]:
        if fcc(c["type"]) != "PLGN":
            continue
        try:
            with open(path, "rb") as f:
                f.seek(c["offset"])
                raw = f.read(c["length"])
        except OSError:
            return None
        try:
            pos = 0
            (n,) = struct.unpack_from("<H", raw, pos)
            pos += 2
            if n > 512:
                return None
            out = []
            for _ in range(n):
                if pos + 3 > len(raw):
                    return None
                idx = raw[pos]
                pos += 1
                if idx == 0xFE:
                    (light,) = struct.unpack_from("<H", raw, pos)
                    pos += 2
                    idx = 0xFE000 + light
                (ln,) = struct.unpack_from("<H", raw, pos)
                pos += 2
                if ln > 256 or pos + ln > len(raw):
                    return None
                name = raw[pos:pos + ln].decode("ascii", errors="strict")
                pos += ln
                out.append((idx, name))
            if pos != len(raw):
                return None
            return sorted(out)
        except (struct.error, ValueError, UnicodeDecodeError):
            return None
    return None


def fmt_index(idx):
    """Load-order index for display: two hex digits, FE-prefixed for ESL."""
    if idx >= 0xFE000:
        return "FE%03X" % (idx - 0xFE000)
    return "%02X" % idx


def missing_mods(plugin_list, data_dir):
    """ESP/ESM/ESL names in the save list but absent from the game Data dir."""
    try:
        present = {p.name.lower() for p in Path(data_dir).glob("*")
                   if p.suffix.lower() in (".esp", ".esm", ".esl")}
    except OSError:
        return None
    return [name for _, name in (plugin_list or [])
            if name.lower() not in present]


def parse_cosave(path):
    """Parse a .skse file. Returns (header, blocks, trailing).

    header: dict with signature/format/skseVersion/runtimeVersion/numPlugins.
    blocks: list of {uid, chunks: [{type, version, length, offset}],
    offset, length}. trailing: leftover byte count (normally 0).
    Raises ValueError on bad signature, bad format, or truncation.
    """
    data = Path(path).read_bytes()
    if len(data) < 20:
        raise ValueError(f"too small for a co-save ({len(data)} bytes)")
    sig, fmt, skse, runt, nplug = struct.unpack_from("<5I", data, 0)
    if sig != SIG_SKS:
        raise ValueError(f"bad signature 0x{sig:08x}, not a co-save")
    if fmt != FORMAT_VERSION:
        raise ValueError(f"unsupported format version {fmt}")
    header = {"signature": sig, "format": fmt, "skseVersion": skse,
              "runtimeVersion": runt, "numPlugins": nplug}
    blocks = []
    pos = 20
    for _ in range(nplug):
        if pos + 12 > len(data):
            raise ValueError("truncated plugin header")
        uid, nch, ln = struct.unpack_from("<III", data, pos)
        start = pos
        pos += 12
        chunks = []
        for _ in range(nch):
            if pos + 12 > len(data):
                raise ValueError("truncated chunk header")
            t, v, ln2 = struct.unpack_from("<III", data, pos)
            pos += 12
            if pos + ln2 > len(data):
                raise ValueError("truncated chunk data")
            chunks.append({"type": t, "version": v, "length": ln2,
                           "offset": pos})
            pos += ln2
        if pos != start + 12 + ln:
            raise ValueError(f"plugin block 0x{uid:08x} over/under-reads "
                             f"its declared length")
        blocks.append({"uid": uid, "chunks": chunks, "offset": start,
                       "length": 12 + ln})
    return header, blocks, len(data) - pos


def uid_name(uid):
    """Human name for a plugin uid: known name, printable FourCC, else hex."""
    if uid in KNOWN_UIDS:
        return KNOWN_UIDS[uid]
    tag = fcc(uid)
    if tag.isprintable():
        return f"plugin {tag}"
    return "unknown plugin"


def parse_save_filename(name):
    """Split an engine save name into parts, or None when foreign.

    <label>_<formid>_<0>_<playerhex>_<location>_<coords>_<YYYYMMDDHHMMSS>
    _<level>_<num>. Label may itself contain underscores, so parse from
    the right and validate the date + hex-decoded character name.
    """
    stem = name[:-5] if name.lower().endswith(".skse") else name
    parts = stem.split("_")
    if len(parts) < 9:
        return None
    label = "_".join(parts[:-8])
    _formid, _zero, playerhex, location, _coords, stamp, level, _num = parts[-8:]
    if len(stamp) != 14 or not stamp.isdigit():
        return None
    try:
        character = bytes.fromhex(playerhex).decode("ascii")
    except ValueError:
        return None
    if not character or not all(32 <= ord(c) < 127 for c in character):
        return None
    try:
        lnum = int(level)
    except ValueError:
        return None
    return {"label": label or "Save", "character": character,
            "location": location,
            "date": f"{stamp[0:4]}-{stamp[4:6]}-{stamp[6:8]} "
                    f"{stamp[8:10]}:{stamp[10:12]}",
            "level": lnum}


def _read_bstring(data, pos):
    """u16-len ASCII string at pos. Returns (str, next_pos)."""
    (ln,) = struct.unpack_from("<H", data, pos)
    pos += 2
    if ln > 256 or pos + ln > len(data):
        raise ValueError("bad string length")
    s = data[pos:pos + ln].decode("ascii", errors="strict")
    return s, pos + ln


def read_ess_info(ess_path):
    """Player/preview info from the .ess companion, or None.

    Reads magic, player name/level/location/race, day-time string and
    the 320x192-style RGB screenshot. Anything off -> None (never guess).
    """
    try:
        data = Path(ess_path).read_bytes()
    except OSError:
        return None
    try:
        if data[:13] != b"TESV_SAVEGAME" or len(data) < 64:
            return None
        pos = 25  # magic(13) + headerSize + version + saveNumber
        player, pos = _read_bstring(data, pos)
        (level,) = struct.unpack_from("<I", data, pos)
        pos += 4
        location, pos = _read_bstring(data, pos)
        datestr, pos = _read_bstring(data, pos)
        race, pos = _read_bstring(data, pos)
        (w, h) = (0, 0)
        shot = None
        # sex u16 + exp floats + filetime, then shot dims + pixels.
        # Layout per pixel is [B, 0xFF, R, G] (byte 1 filler, verified:
        # luma/chroma decodes come out neon, this one gives a sane photo
        # with blue sky). Converted to RGB888 on read.
        pos += 2 + 4 + 4 + 8
        (w, h) = struct.unpack_from("<II", data, pos)
        pos += 8
        if 0 < w <= 1024 and 0 < h <= 1024 and pos + w * h * 4 <= len(data):
            raw = data[pos:pos + w * h * 4]
            rgb = bytearray(w * h * 3)
            for i in range(w * h):
                rgb[i * 3] = raw[i * 4 + 2]
                rgb[i * 3 + 1] = raw[i * 4 + 3]
                rgb[i * 3 + 2] = raw[i * 4]
            shot = (w, h, bytes(rgb))
        day = time = None
        m = re.match(r"(\d{3})\.(\d{2})\.(\d{2})$", datestr)
        if m:
            day, time = int(m.group(1)), f"{m.group(2)}:{m.group(3)}"
        return {"player": player, "level": level, "location": location,
                "day": day, "time": time, "race": race, "shot": shot}
    except (struct.error, ValueError, UnicodeDecodeError, IndexError):
        return None


def ess_thumbnail(shot, maxw=160):
    """PPM bytes for tkinter PhotoImage, subsampled to maxw. None if bad."""
    try:
        w, h, rgb = shot
        if w <= 0 or h <= 0 or len(rgb) < w * h * 3:
            return None
        step = max(1, -(-w // maxw))
        nw, nh = (w + step - 1) // step, (h + step - 1) // step
        out = bytearray()
        for y in range(0, h, step):
            base = y * w * 3
            for x in range(0, w, step):
                o = base + x * 3
                out += rgb[o:o + 3]
        return b"P6\n%d %d\n255\n" % (nw, nh) + bytes(out)
    except (TypeError, ValueError, IndexError):
        return None


def uid_tag(uid):
    """Short display tag: FourCC when printable, hex otherwise."""
    tag = fcc(uid)
    if tag.isprintable():
        return f"{tag} [0x{uid:08x}]"
    return f"[0x{uid:08x}]"


def _text_bytes(dll_path):
    """Executable bytes of a DLL for constant scanning (.text when
    parseable, whole file as fallback)."""
    try:
        import compasse as core
    except ImportError:
        core = None
    try:
        data = Path(dll_path).read_bytes()
    except OSError:
        return None
    if core is None:
        return data
    try:
        sections = core.find_pe_sections(data)
    except Exception:
        return data
    for name, _va, _vsize, rawoff, rawsize in sections:
        if name == ".text":
            return data[rawoff:rawoff + rawsize]
    return data


# Chunk types with documented meanings (SKSE core + PapyrusUtil storage
# vocabulary). Anything else shows raw - never guess.
CHUNK_MEANINGS = {
    "PLGN": "plugin list",
    "REGS": "event registrations",
    "INTV": "ints",
    "FLOV": "floats",
    "STRV": "strings",
    "FORV": "forms",
    "PKGO": "package overrides",
}


def describe_chunks(block):
    """One-line summary of known chunk types, "" when none are known."""
    seen = []
    for c in block["chunks"]:
        tag = fcc(c["type"])
        if tag.isprintable() and tag in CHUNK_MEANINGS \
                and CHUNK_MEANINGS[tag] not in seen:
            seen.append(CHUNK_MEANINGS[tag])
    return ", ".join(seen)


def find_uid_owners(uid, plugins_dir):
    """Installed DLLs whose executable code references the uid constant.

    Plugins register co-save blocks via SetUniqueID(uid), so the uid
    usually appears as an immediate in their .text. A block no installed
    DLL references belongs to a mod that isn't installed: dropping it
    can only help. Candidates, not proof - constants collide, and the
    scan only sees the currently installed set (profiles differ).
    Uid 0 is never scanned (zero bytes match everything).
    """
    if uid == 0:
        return []
    raw = struct.pack("<I", uid)
    owners = []
    try:
        dlls = sorted(Path(plugins_dir).glob("*.dll"))
    except OSError:
        return owners
    for dll in dlls:
        code = _text_bytes(dll)
        if code is not None and raw in code:
            owners.append(dll.name)
    return owners


def find_staging_dir(plugins_dir):
    """Vortex staging dir (all downloaded mods) or None.

    Read from the deployment manifest next to the game Data dir. Staging
    holds mods that are downloaded but not necessarily deployed, so a
    block referenced there belongs to a known-but-disabled mod.
    """
    try:
        data_dir = Path(plugins_dir).parent.parent
        with open(data_dir / "vortex.deployment.json", encoding="utf-8") as f:
            manifest = json.load(f)
    except (OSError, ValueError):
        return None
    staging = manifest.get("stagingPath")
    if staging and Path(staging).exists():
        return Path(staging)
    return None


def locate_uid(uid, plugins_dir, staging_dir=None):
    """Two-tier owner lookup: {"installed": [...], "staged": [...]}.

    installed = referenced by a deployed DLL (mod active). staged =
    referenced only under the staging dir (mod downloaded but not
    deployed). Neither = unknown anywhere, true orphan candidate.
    staging_dir None auto-resolves via the deployment manifest.
    """
    installed = find_uid_owners(uid, plugins_dir) if plugins_dir else []
    staged = []
    if staging_dir is None and plugins_dir:
        staging_dir = find_staging_dir(plugins_dir)
    if staging_dir and uid != 0:
        raw = struct.pack("<I", uid)
        try:
            dlls = sorted(Path(staging_dir).rglob("*.dll"))
        except OSError:
            dlls = []
        for dll in dlls[:400]:
            code = _text_bytes(dll)
            if code is not None and raw in code:
                try:
                    staged.append(str(dll.relative_to(staging_dir)))
                except ValueError:
                    staged.append(dll.name)
                if len(staged) >= 5:
                    break
    return {"installed": installed, "staged": staged}


def drop_plugin(path, uid, backup=True):
    """Remove one plugin block, fixing the header count. Returns
    (removed_bytes, remaining_plugins).

    Refuses uid 0 (SKSE core - this tool removes mod data, not engine
    data) and any file that doesn't parse byte-exact (trailing garbage
    means a layout we don't understand: refuse, don't guess).
    """
    if uid == 0:
        raise ValueError("refusing uid 0 (SKSE core): drop mod data, not engine data")
    path = Path(path)
    header, blocks, trailing = parse_cosave(path)
    if trailing:
        raise ValueError(f"refusing: {trailing} trailing bytes after last block")
    keep = [b for b in blocks if b["uid"] != uid]
    if len(keep) == len(blocks):
        raise ValueError(f"uid {uid_tag(uid)} not present")
    if backup:
        bak = path.parent / (path.name + ".bak")
        if not bak.exists():
            shutil.copy2(path, bak)
    data = path.read_bytes()
    out = bytearray()
    out += struct.pack("<5I", header["signature"], header["format"],
                       header["skseVersion"], header["runtimeVersion"],
                       len(keep))
    for b in keep:
        out += data[b["offset"]:b["offset"] + b["length"]]
    path.write_bytes(bytes(out))
    return sum(b["length"] for b in blocks if b["uid"] == uid), len(keep)


def main():
    parser = argparse.ArgumentParser(
        description="SKSE co-save surgeon - list and drop per-plugin data blocks")
    parser.add_argument("save", help=".skse co-save file")
    parser.add_argument("--drop", default=None,
                        help="plugin uid to drop (FourCC like PLGN, hex, or decimal)")
    parser.add_argument("--plugins-dir", default=None,
                        help="SKSE Plugins folder: list shows which installed "
                             "DLL references each block (orphan candidates)")
    parser.add_argument("--no-backup", action="store_true",
                        help="skip .bak backup before drop")
    args = parser.parse_args()

    save = Path(args.save)
    if not save.exists():
        parser.error(f"save not found: {save}")

    if args.drop is None:
        header, blocks, trailing = parse_cosave(save)
        ver = header["runtimeVersion"]
        print(f"\n{save.name}: fmt={header['format']} "
              f"skse=0x{header['skseVersion']:08x} "
              f"game={ver >> 24}.{(ver >> 16) & 0xFF}.{((ver >> 4) & 0xFFF)} "
              f"({len(blocks)} plugin block(s))")
        for b in blocks:
            total = sum(c["length"] for c in b["chunks"])
            print(f"  0x{b['uid']:08x} {uid_name(b['uid'])}: "
                  f"{len(b['chunks'])} chunk(s), {total} data bytes")
            if args.plugins_dir and b["uid"] != 0:
                loc = locate_uid(b["uid"], args.plugins_dir)
                if loc["installed"]:
                    print(f"    owned by installed: "
                          f"{', '.join(loc['installed'])}")
                elif loc["staged"]:
                    print(f"    known mod, not deployed: "
                          f"{', '.join(loc['staged'][:2])}")
                else:
                    print("    unknown anywhere - true orphan, safe to drop")
        if args.plugins_dir:
            for b in blocks:
                plist = plugin_list_chunk(b, save)
                if plist is not None:
                    break
            else:
                plist = None
            if plist is not None:
                data_dir = Path(args.plugins_dir).parent.parent
                missing = missing_mods(plist, data_dir)
                if missing is None:
                    print("  mod list: unreadable game Data dir")
                elif missing:
                    print(f"  save lists {len(plist)} mods, "
                          f"{len(missing)} missing now: "
                          + ", ".join(missing))
                else:
                    print(f"  save lists {len(plist)} mods, all present")
        if trailing:
            print(f"  WARNING: {trailing} trailing bytes")
        return

    try:
        uid = parse_uid(args.drop)
    except ValueError as exc:
        parser.error(str(exc))
    try:
        removed, left = drop_plugin(save, uid, backup=not args.no_backup)
    except ValueError as exc:
        print(f"FAILED: {exc}")
        sys.exit(1)
    print(f"DROPPED {uid_name(uid)} [0x{uid:08x}]: "
          f"{removed} bytes removed, {left} block(s) left")


if __name__ == "__main__":
    main()
