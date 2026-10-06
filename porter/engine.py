#!/usr/bin/env python3
"""Scan a plugin for hardcoded game addresses and fix matches."""
import hashlib
import json
import struct
import sys
import time
from pathlib import Path

import core
import core.backups
import core.pe
import core.touched

try:
    from core.const import DOS_E_LFANEW, IMAGE_SCN_MEM_EXECUTE
except ImportError:
    DOS_E_LFANEW = 0x3C
    IMAGE_SCN_MEM_EXECUTE = 0x20000000

IMM_MIN = 0x10000
ADD_MNEMS = ("add", "sub")
MEM_MNEMS = ("lea", "mov", "movzx", "movsx")
SHAPE_LEN = 6

def _md():
    if not core.HAS_CAPSTONE:
        return None
    return core.capstone_md()

def sections_chars(data):
    """(name, vaddr, vsize, rawoff, rawsize, chars) or [] when unparseable.

    Layout comes from core.pe; only the characteristics column is read
    here, since core's tuples stop at rawsize.
    """
    try:
        base = core.pe._find_pe_sections(data)
    except Exception:
        return []
    if not base:
        return []
    try:
        e_lfanew = struct.unpack_from("<I", data, DOS_E_LFANEW)[0]
        coff = e_lfanew + 4
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        if magic == 0x20B:
            num_dd = struct.unpack_from("<I", data, opt + 108)[0]
            dd = opt + 112
        elif magic == 0x10B:
            num_dd = struct.unpack_from("<I", data, opt + 92)[0]
            dd = opt + 96
        else:
            return []
        if not 0 < num_dd <= 32:
            num_dd = 16
        sec = dd + num_dd * 8
        out = []
        for i, (name, vaddr, vsize, rawoff, rawsize) in enumerate(base):
            s = sec + i * 40
            chars = struct.unpack_from("<I", data, s + 36)[0]
            out.append((name, vaddr, vsize, rawoff, rawsize, chars))
        return out
    except Exception:
        return []

def image_size(sections):
    end = 0
    for _, vaddr, vsize, _, rawsize, _ in sections:
        end = max(end, vaddr + max(vsize, rawsize))
    return end

def is_packed_exe(data):
    """True if the exe still has its SteamStub wrapper."""
    secs = sections_chars(data)
    if not secs:
        return True
    for name, _, _, _, _, chars in secs:
        if name == ".bind" and chars & IMAGE_SCN_MEM_EXECUTE:
            return True
    md = _md()
    if md is None:
        return False
    assert md is not None
    for name, vaddr, vsize, rawoff, rawsize, chars in secs:
        if name == ".text" and chars & IMAGE_SCN_MEM_EXECUTE:
            window = bytes(data[rawoff:rawoff + 64])
            try:
                insns = list(md.disasm(window, vaddr))
            except Exception:
                return True
            if len(insns) < 3:
                return True
            for ins in insns[:8]:
                if ins.mnemonic in ("in", "out", "hlt", "cli", "sti"):
                    return True
            return False
    return True

def _sweep(md, code, base):
    """Decode byte by byte. Slow fallback for data islands."""
    off, n = 0, len(code)
    while off < n:
        try:
            insns = list(md.disasm(code[off:off + 15], base + off))
        except Exception:
            insns = []
        if insns and insns[0].address == base + off:
            yield insns[0]
            off += insns[0].size or 1
        else:
            off += 1

def _iter_text(data, sections):
    md = _md()
    if md is None:
        return
    plain = [(n, v, vs, o, rs) for n, v, vs, o, rs, _ in sections]
    spans = []
    try:
        funcs = list(core.get_functions_from_pdata(data, plain))
    except Exception:
        funcs = []
    for begin, end in funcs:
        if 0 < end - begin <= 0x10000:
            spans.append((begin, end))
    if spans:
        for begin, end in spans:
            off = core.rva_to_offset(begin, plain)
            if off is None:
                continue
            try:
                for ins in md.disasm(bytes(data[off:off + (end - begin)]),
                                     begin):
                    yield ins
            except Exception:
                continue
        return
    for n, v, vs, o, rs in plain:
        if n != ".text":
            continue
        size = min(vs, rs)
        if o + size > len(data):
            continue
        for ins in _sweep(md, bytes(data[o:o + size]), v):
            yield ins

def _imm_of(ins):
    """(kind, value) for ADD/SUB-imm and non-RIP disp, else None."""
    from core.pe import x86
    for op in ins.operands:
        if op.type == x86.X86_OP_IMM:
            if ins.mnemonic in ADD_MNEMS:
                v = int(op.imm) & 0xFFFFFFFF
                if v >= IMM_MIN:
                    return ("add", v)
        elif op.type == x86.X86_OP_MEM:
            if op.mem.base == x86.X86_REG_RIP:
                continue
            if ins.mnemonic in MEM_MNEMS and op.mem.disp:
                v = int(op.mem.disp) & 0xFFFFFFFF
                if v >= IMM_MIN:
                    return ("mem", v)
    return None

def _looks_thunk(prev_insns, data, sections, site_rva):
    """True if the site is a load-base/add/cache/ret stub."""
    from core.pe import x86
    if prev_insns:
        last = prev_insns[-1]
        if last.address + last.size > site_rva or \
                site_rva - (last.address + last.size) > 32:
            return False
    seen_load = False
    for ins in prev_insns[-4:]:
        if ins.mnemonic != "mov":
            continue
        for op in ins.operands:
            if op.type == x86.X86_OP_MEM and \
                    op.mem.base == x86.X86_REG_RIP:
                seen_load = True
    if not seen_load:
        return False
    off = core.rva_to_offset(site_rva, sections)
    if off is None:
        return False
    md = _md()
    if md is None:
        return False
    try:
        fwd = list(md.disasm(bytes(data[off:off + 24]), site_rva))[:4]
    except Exception:
        return False
    for ins in fwd[1:]:
        if ins.mnemonic == "ret":
            return True
        if ins.mnemonic != "mov":
            continue
        for op in ins.operands:
            if op.type == x86.X86_OP_MEM and \
                    op.mem.base == x86.X86_REG_RIP:
                return True
    return False

def scan_dll(dll_data):
    """Find hardcoded addresses. Returns (rows, note)."""
    if not core.HAS_CAPSTONE:
        return [], "capstone missing - install capstone to scan"
    sections = core.find_pe_sections(dll_data)
    if not sections:
        return [], "not a readable PE file"
    size = image_size([(n, v, vs, o, rs, 0) for n, v, vs, o, rs in sections])
    by_value = {}
    prev = []
    for ins in _iter_text(dll_data, [(n, v, vs, o, rs, 0)
                                     for n, v, vs, o, rs in sections]):
        hit = _imm_of(ins)
        if hit is None:
            prev.append(ins)
            continue
        _, value = hit
        if value < size:
            prev.append(ins)
            continue
        off = core.rva_to_offset(ins.address, sections)
        if off is None:
            prev.append(ins)
            continue
        thunk = _looks_thunk(list(prev),
                             dll_data,
                             [(n, v, vs, o, rs) for n, v, vs, o, rs
                              in sections],
                             ins.address)
        by_value.setdefault(value, []).append(
            {"rva": ins.address, "off": off, "mnemonic": ins.mnemonic,
             "thunk": thunk})
        prev.append(ins)
    rows = []
    for value in sorted(by_value):
        sites = by_value[value]
        thunk = any(s.pop("thunk") for s in sites)
        rows.append({"value": value, "kind": "thunk" if thunk else "inline",
                     "sites": sites, "proposal": None, "basis": "none",
                     "confidence": "unsure"})
    return rows, ""

def _rev_map(id_offsets):
    rev = {}
    for i, off in id_offsets.items():
        if off:
            rev.setdefault(off, []).append(i)
    return rev

def apply_library(rows, old_lib, new_lib):
    """Fill proposals where old value is a known old offset of a live ID."""
    if not old_lib or not new_lib:
        return 0
    rev = _rev_map(old_lib)
    n = 0
    for row in rows:
        if row["proposal"] is not None:
            continue
        ids = rev.get(row["value"])
        if not ids:
            continue
        for i in ids:
            if i in new_lib:
                row["proposal"] = new_lib[i]
                row["basis"] = "library"
                row["confidence"] = "exact"
                n += 1
                break
    return n

def profile_dir():
    """Bundled profiles dir: frozen app resources or repo sources."""
    frozen = getattr(sys, "_MEIPASS", None)
    if frozen:
        return Path(frozen) / "porter" / "profiles"
    return Path(__file__).parent / "profiles"

def apply_profiles(rows, dll_data, profile_dir):
    """Hash-pinned exact profiles. Returns matched row count."""
    digest = hashlib.sha256(bytes(dll_data)).hexdigest()
    matched = 0
    try:
        files = sorted(Path(profile_dir).glob("*.json"))
    except OSError:
        return 0
    for path in files:
        try:
            prof = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if prof.get("sha256") != digest:
            continue
        want = {}
        for pair in prof.get("pairs", []):
            try:
                want[int(pair["old"], 16)] = int(pair["new"], 16)
            except (KeyError, ValueError, TypeError):
                continue
        for row in rows:
            if row["proposal"] is None and row["value"] in want:
                row["proposal"] = want[row["value"]]
                row["basis"] = "exact-profile"
                row["confidence"] = "exact"
                matched += 1
    return matched

def filter_plausible(rows, old_data, old_sections):
    """Keep rows that land on code in the old exe."""
    kept, dropped = [], 0
    for row in rows:
        if row["proposal"] is not None:
            kept.append(row)
            continue
        try:
            ok = looks_like_boundary(old_data, old_sections, row["value"])
        except Exception:
            ok = False
        if ok:
            kept.append(row)
        else:
            dropped += 1
    return kept, dropped

def _op_shape(op):
    from core.pe import x86
    if op.type == x86.X86_OP_REG:
        return "r"
    if op.type == x86.X86_OP_IMM:
        return "i"
    if op.type == x86.X86_OP_MEM:
        if op.mem.base == x86.X86_REG_RIP:
            return "mrip"
        return "m"
    return "o"

def _shape_of(insns):
    return tuple((i.mnemonic, tuple(_op_shape(o) for o in i.operands))
                 for i in insns)

def _shape_at(data, sections, rva, length=SHAPE_LEN):
    off = core.rva_to_offset(rva, sections)
    if off is None:
        return None
    md = _md()
    if md is None:
        return None
    try:
        insns = list(md.disasm(bytes(data[off:off + 96]), rva))[:length]
    except Exception:
        return None
    if not insns or insns[0].address != rva:
        return None
    return _shape_of(insns)

def looks_like_boundary(data, sections, rva):
    """True if any decode lands an instruction on rva."""
    md = _md()
    if md is None:
        return False
    for back in range(1, 25):
        off = core.rva_to_offset(rva - back, sections)
        if off is None:
            continue
        try:
            for ins in md.disasm(bytes(data[off:off + back + 8]), rva - back):
                if ins.address == rva:
                    return True
        except Exception:
            continue
    return False

FINGERPRINT_VERSION = 2
SWEEP_DEFAULT_TIMEOUT = 600

def _insn_sig(ins):
    from core.pe import x86
    ops = []
    for op in ins.operands:
        t = op.type
        if t == x86.X86_OP_REG:
            ops.append("r")
        elif t == x86.X86_OP_IMM:
            ops.append("i")
        elif t == x86.X86_OP_MEM:
            ops.append("R" if op.mem.base == x86.X86_REG_RIP else "m")
        else:
            ops.append("o")
    return (sys.intern(ins.mnemonic), tuple(ops))

def _sweep_spans(new_data, new_sections):
    spans = []
    try:
        funcs = list(core.get_functions_from_pdata(new_data, new_sections))
    except Exception:
        funcs = []
    if funcs:
        for begin, end in funcs:
            if 0 < end - begin <= 0x10000:
                spans.append((begin, end))
    else:
        for n, v, vs, o, rs in new_sections:
            if n == ".text":
                spans.append((v, v + min(vs, rs)))
    return spans

def _sweep_matches(wanted, new_data, new_sections, on_step=None,
                   deadline=None):
    """Find new RVAs with the same shape. Returns (hits, complete)."""
    first = {}
    for old_v, shape in wanted.items():
        first.setdefault(shape[0], []).append((old_v, shape))
    hits = {v: [] for v in wanted}
    md = _md()
    if md is None:
        return hits, False
    spans = _sweep_spans(new_data, new_sections)
    total = max(1, len(spans))
    for idx, (begin, end) in enumerate(spans):
        if deadline is not None and time.monotonic() > deadline:
            return hits, False
        off = core.rva_to_offset(begin, new_sections)
        if off is None:
            continue
        try:
            insns = list(md.disasm(bytes(new_data[off:off + (end - begin)]),
                                   begin))
        except Exception:
            continue
        if len(insns) < SHAPE_LEN:
            continue
        sigs = [_insn_sig(i) for i in insns]
        addrs = [i.address for i in insns]
        for k in range(len(sigs) - SHAPE_LEN + 1):
            cands = first.get(sigs[k])
            if not cands:
                continue
            key = tuple(sigs[k:k + SHAPE_LEN])
            for old_v, shape in cands:
                if key == shape:
                    hits[old_v].append(addrs[k])
        if on_step is not None and (idx & 63) == 0:
            try:
                on_step((idx + 1) / total)
            except Exception:
                pass
    if on_step is not None:
        try:
            on_step(1.0)
        except Exception:
            pass
    return hits, True

def _cache_file(exe_hash, dll_hash):
    import tempfile as _tf
    try:
        d = Path(_tf.gettempdir()) / "opencode" / "porter_cache"
        d.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    return d / ("%s_%s.json" % (exe_hash[:16], dll_hash[:16]))

def apply_fingerprints(rows, old_data, old_sections, new_data, new_sections,
                       dll_hash=None, on_step=None, timeout_s=None,
                       use_cache=True):
    """Apply matches with one shape hit. Returns (matched, complete)."""
    if timeout_s is None:
        timeout_s = SWEEP_DEFAULT_TIMEOUT
    todo = [r for r in rows if r["proposal"] is None]
    if not todo:
        return 0, True
    wanted = {}
    for r in todo:
        try:
            shape = _shape_at(old_data, old_sections, r["value"])
        except Exception:
            shape = None
        if shape is not None:
            wanted[r["value"]] = shape
    if not wanted:
        return 0, True
    if use_cache and dll_hash:
        try:
            exe_hash = hashlib.sha256(bytes(new_data)).hexdigest()
        except Exception:
            exe_hash = ""
        if exe_hash:
            path = _cache_file(exe_hash, dll_hash)
            if path is not None and path.is_file():
                try:
                    saved = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    saved = None
                if saved and saved.get("v") == FINGERPRINT_VERSION and \
                        saved.get("exe") == exe_hash and \
                        saved.get("dll") == dll_hash:
                    res = saved.get("res", {})
                    n = 0
                    for r in todo:
                        ent = res.get(hex(r["value"]))
                        if not ent:
                            continue
                        if ent.get("hits", 0) == 1 and ent.get("new"):
                            r["proposal"] = ent["new"]
                            r["basis"] = "fingerprint"
                            r["confidence"] = "exact"
                            n += 1
                        elif "hits" in ent:
                            r["review_hits"] = ent["hits"]
                    try:
                        if on_step is not None:
                            on_step(1.0)
                    except Exception:
                        pass
                    return n, True
    deadline = None
    if timeout_s and timeout_s > 0:
        deadline = time.monotonic() + timeout_s
    hits, complete = _sweep_matches(wanted, new_data, new_sections,
                                    on_step=on_step, deadline=deadline)
    if not complete:
        return 0, False
    n = 0
    res = {}
    for r in todo:
        hs = hits.get(r["value"], [])
        res[hex(r["value"])] = {"new": None, "hits": len(hs)}
        if len(hs) != 1:
            r["review_hits"] = len(hs)
            continue
        new_rva = hs[0]
        if not looks_like_boundary(new_data, new_sections, new_rva):
            r["review_hits"] = 1
            continue
        if _shape_at(new_data, new_sections, new_rva) != \
                wanted[r["value"]]:
            continue
        r["proposal"] = new_rva
        r["basis"] = "fingerprint"
        r["confidence"] = "exact"
        res[hex(r["value"])] = {"new": new_rva, "hits": 1}
        n += 1
    if use_cache and dll_hash:
        try:
            exe_hash = hashlib.sha256(bytes(new_data)).hexdigest()
        except Exception:
            exe_hash = ""
        if exe_hash:
            path = _cache_file(exe_hash, dll_hash)
            if path is not None:
                try:
                    path.write_text(json.dumps(
                        {"v": FINGERPRINT_VERSION, "exe": exe_hash,
                         "dll": dll_hash, "res": res}), encoding="utf-8")
                except OSError:
                    pass
    return n, complete

RACEMENU_FIXTURE = {
    "sha256": "5225e4e3b185e6fc57c8d31b0cedbe5a030a951d9a744d33071b64c45a38c208",
    "pairs": {0xD38B66: 0xEFD5B6, 0x3BCD59: 0x3C3E19, 0x3BCB08: 0x3C3BC8,
              0x3BCB31: 0x3C3BF1, 0x3BCB17: 0x3C3BD7},
    "offsets": {0xD38B66: [0x8F6E6], 0x3BCD59: [0x8F720],
                0x3BCB08: [0x8F30C], 0x3BCB31: [0x8F313],
                0x3BCB17: [0x8F42D, 0x8F441, 0x8F459]},
}

def selftest():
    """In-memory checks, no game files. Returns (passed, failed, lines)."""
    passed, failed, lines = [], [], []

    def check(name, cond, extra=""):
        (passed if cond else failed).append(name)
        lines.append(("ok   " if cond else "FAIL ") + name +
                     (" [" + extra + "]" if extra and not cond else ""))

    fx = RACEMENU_FIXTURE
    check("fixture-hash-len", len(fx["sha256"]) == 64)
    check("fixture-five-pairs", len(fx["pairs"]) == 5)
    check("fixture-seven-offsets",
          sum(len(v) for v in fx["offsets"].values()) == 7)
    check("fixture-keys-agree", set(fx["pairs"]) == set(fx["offsets"]))

    prof_dir = Path(__file__).resolve().parent / "profiles"
    found = False
    try:
        for path in prof_dir.glob("*.json"):
            try:
                prof = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if prof.get("sha256") == fx["sha256"]:
                got = {}
                for pair in prof.get("pairs", []):
                    try:
                        got[int(pair["old"], 16)] = int(pair["new"], 16)
                    except (KeyError, ValueError, TypeError):
                        continue
                if got == fx["pairs"]:
                    found = True
    except OSError:
        pass
    check("fixture-profile-shipped", found)

    if not core.HAS_CAPSTONE:
        check("capstone-present", False, "capstone missing")
        return passed, failed, lines
    check("capstone-present", True)

    packed = bytearray(0x400)
    struct.pack_into("<I", packed, DOS_E_LFANEW, 0x80)
    packed += bytearray(0x200)
    packed[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", packed, 0x80 + 4 + 2, 1)
    struct.pack_into("<H", packed, 0x80 + 24, 0x20B)
    struct.pack_into("<I", packed, 0x80 + 24 + 108, 16)
    s = 0x80 + 24 + 112 + 16 * 8
    packed[s:s + 8] = b".bind\x00\x00\x00"
    struct.pack_into("<I", packed, s + 8, 0x1000)
    struct.pack_into("<I", packed, s + 12, 0x1000)
    struct.pack_into("<I", packed, s + 16, 0x200)
    struct.pack_into("<I", packed, s + 20, 0x400)
    struct.pack_into("<I", packed, s + 36, 0x60000020)
    check("packed-refused", is_packed_exe(bytes(packed)) is True)

    dll = _synth_plugin()
    rows, note = scan_dll(dll)
    check("synth-one-row", len(rows) == 1, "%d rows %s" % (len(rows), note))
    if rows:
        check("synth-value", rows[0]["value"] == 0xD38B66,
              hex(rows[0]["value"]))
        check("synth-kind", rows[0]["kind"] == "thunk", rows[0]["kind"])
        check("synth-sites", len(rows[0]["sites"]) == 1)
    return passed, failed, lines

def _synth_plugin():
    """Minimal plugin carrying one thunk: base + 0xD38B66, cached, ret."""
    e_lfanew = 0x80
    data = bytearray(0x400)
    struct.pack_into("<I", data, DOS_E_LFANEW, e_lfanew)
    data += bytearray(0x200)
    data[e_lfanew:e_lfanew + 4] = b"PE\x00\x00"
    coff = e_lfanew + 4
    struct.pack_into("<H", data, coff + 2, 1)
    opt = coff + 20
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<I", data, opt + 108, 16)
    sec = opt + 112 + 16 * 8
    end = 0x400 + 0x200
    if len(data) < end:
        data += bytearray(end - len(data))
    data[sec:sec + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", data, sec + 8, 0x200)
    struct.pack_into("<I", data, sec + 12, 0x1000)
    struct.pack_into("<I", data, sec + 16, 0x200)
    struct.pack_into("<I", data, sec + 20, 0x400)
    code = (b"\x48\x8b\x05\x00\x10\x00\x00"
            b"\x48\x81\xc2\x66\x8b\xd3\x00"
            b"\x48\x89\x05\x00\x10\x00\x00"
            b"\xc3")
    data[0x400:0x400 + len(code)] = code
    return bytes(data)

def hits_text(row):
    """Review-row evidence in words, without scary raw counts."""
    n = row.get("review_hits", 0)
    if n > 50:
        return "pattern too common to match safely"
    if n > 1:
        return "%d lookalikes" % n
    if n == 1:
        return "1 lookalike"
    return "no candidate found"

def plain_report(name, rows, note="", skipped=0):
    """Plain-words verdict plus row lines for print()."""
    matched = sum(1 for r in rows if r["proposal"] is not None)
    open_rows = len(rows) - matched
    if note:
        head = note
    elif not rows:
        head = "%s: no hardcoded game addresses found." % name
    elif open_rows == 0:
        head = ("%s: %d hardcoded address(es), all matched to the new "
                "game version." % (name, len(rows)))
    else:
        head = ("%s: %d hardcoded address(es), %d matched, %d need a "
                "human look." % (name, len(rows), matched, open_rows))
    if skipped:
        head += (" %d more value(s) are not code in the old game - "
                 "skipped as constants." % skipped)
    lines = [head]
    for r in rows:
        sites = len(r["sites"])
        if r["proposal"] is not None:
            lines.append("  matched (%s, %s): %d place(s) -> new game "
                         "address (%s)" % (r["kind"], r["basis"], sites,
                                           r["confidence"]))
        else:
            lines.append("  needs review (%s): %d place(s), no safe match "
                         "found" % (r["kind"], sites))
    return lines

def _locate_row_value(data, site_off, site_rva, old_value):
    """Find the value bytes inside the instruction at site_off."""
    if isinstance(site_off, bool) or not isinstance(site_off, int):
        return None, "site offset is not an integer"
    if site_off < 0 or site_off >= len(data):
        return None, "site offset out of range"
    size = None
    if core.HAS_CAPSTONE:
        md = core.capstone_md()
        if md is not None:
            if isinstance(site_rva, int) and not isinstance(site_rva, bool):
                base = site_rva
            else:
                base = site_off
            try:
                insns = list(md.disasm(bytes(data[site_off:site_off + 15]),
                                       base))
            except Exception:
                insns = []
            if insns and insns[0].address == base:
                ins = insns[0]
                try:
                    size = int(ins.size) or None
                except (TypeError, ValueError):
                    size = None
                enc = getattr(ins, "encoding", None)
                if enc is not None:
                    for attr_o, attr_s in (("imm_offset", "imm_size"),
                                           ("disp_offset", "disp_size")):
                        try:
                            width = int(getattr(enc, attr_s, 0) or 0)
                            rel = int(getattr(enc, attr_o, 0) or 0)
                        except (TypeError, ValueError):
                            continue
                        if width <= 0 or width > 8:
                            continue
                        file_off = site_off + rel
                        if file_off < 0 or file_off + width > len(data):
                            continue
                        cur = int.from_bytes(bytes(data[file_off:file_off +
                                                         width]), "little")
                        if cur == old_value & (256 ** width - 1):
                            return (file_off, width), ""
    window = bytes(data[site_off:min(site_off + (size or 15), len(data))])
    try:
        needle = struct.pack("<I", old_value & 0xFFFFFFFF)
    except struct.error:
        return None, "old value is not a 32-bit address"
    first = window.find(needle)
    if first < 0:
        return None, "old value bytes not found at site"
    if window.find(needle, first + 1) >= 0:
        return None, "old value bytes ambiguous at site"
    return (site_off + first, 4), ""

def apply_row_proposal(dll_path, row):
    """Write the row proposal to each site. Backs up first."""
    def _refuse(why):
        return {"ok": False, "patched_sites": 0, "backup_path": None,
                "error": why}

    if not isinstance(row, dict):
        return _refuse("refused: row is not a scan row")
    proposal = row.get("proposal")
    sites = row.get("sites")
    if proposal is None:
        return _refuse("refused: row has no proposal (needs-human-look)")
    if not sites:
        return _refuse("refused: row has no sites")
    if isinstance(proposal, bool) or not isinstance(proposal, int):
        return _refuse("refused: proposal is not an address integer")
    old = row.get("value")
    if isinstance(old, bool) or not isinstance(old, int):
        return _refuse("refused: row value is not an address integer")
    old_u32 = old & 0xFFFFFFFF
    try:
        raw = bytes(Path(dll_path).read_bytes())
    except Exception as exc:
        return _refuse("unreadable file: %s" % exc)
    locs = []
    for i, site in enumerate(sites):
        if not isinstance(site, dict):
            return _refuse("unresolvable site #%d: not a site record" % i)
        found, why = _locate_row_value(raw, site.get("off"),
                                       site.get("rva"), old_u32)
        if found is None:
            return _refuse("unresolvable site #%d: %s" % (i, why))
        file_off, width = found
        if proposal < 0 or proposal >= 256 ** width:
            return _refuse("proposal 0x%X does not fit in %d byte(s)" %
                           (proposal, width))
        locs.append((file_off, width))
    data = bytearray(raw)
    for file_off, width in locs:
        data[file_off:file_off + width] = proposal.to_bytes(width,
                                                            "little")
    try:
        core.backups.backup_bytes(dll_path, bytes(data))
    except Exception as exc:
        return _refuse("write failed: %s" % exc)
    try:
        bak = core.backups.backup_path(dll_path)
        bak_str = str(bak) if bak is not None else None
    except Exception:
        bak_str = None
    try:
        check = bytes(Path(dll_path).read_bytes())
    except Exception as exc:
        return {"ok": False, "patched_sites": 0, "backup_path": bak_str,
                "error": "verify re-read failed: %s" % exc}
    for file_off, width in locs:
        if file_off + width > len(check) or \
                int.from_bytes(check[file_off:file_off + width],
                               "little") != proposal:
            return {"ok": False, "patched_sites": 0,
                    "backup_path": bak_str,
                    "error": "verify failed at file offset 0x%X" % file_off}
    try:
        core.touched.add_touched(Path(dll_path).parent, dll_path)
    except Exception:
        pass
    return {"ok": True, "patched_sites": len(sites),
            "backup_path": bak_str, "error": ""}
