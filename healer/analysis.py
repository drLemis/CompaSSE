#!/usr/bin/env python3
"""Find stale hook offsets and fix them."""

import struct
import shutil
from pathlib import Path

import core as _core
import therapist as _ther

def load_code(dll_path):
    with open(dll_path, "rb") as f:
        data = f.read()
    sections = _core.find_pe_sections(data)
    for name, va, vsize, raw, rawsize in sections:
        if name == ".text":
            off = raw
            sz = min(rawsize, len(data) - off)
            return data, sections, data[off:off + sz]
    return data, sections, b""

# ---------------------------------------------------------------------------
# Pattern scan offset detection
# ---------------------------------------------------------------------------
def find_mov_ebx_imm32(code):
    """Find MOV EBX, imm32 instructions. Returns [(code_offset, value), ...]"""
    results = []
    for i in range(len(code) - 4):
        if code[i] == 0xBB:
            val = struct.unpack_from("<I", code, i + 1)[0]
            if 0x100 < val < 0x100000:
                results.append((i, val))
    return results

def find_id_refs_nearby(code, center, radius=128):
    """Find REL::ID references (48 C7 45 XX imm32) near a code offset.
    Returns [(code_offset, id_val), ...]"""
    results = []
    start = max(0, center - radius)
    end = min(len(code), center + radius)
    for i in range(start, end - 6):
        if code[i:i + 3] == b"\x48\xC7\x45":
            # mov [rbp+disp8], imm32. Any disp8 is sane (|off| <= 128);
            # locals typically live at NEGATIVE disp (e.g. [rbp-8] = 0xF8),
            # so the displacement value must not be range-filtered.
            id_val = struct.unpack_from("<I", code, i + 4)[0]
            if 1000 < id_val < 100000:
                results.append((i, id_val))
        elif code[i:i + 3] == b"\x48\xC7\x85":
            id_val = struct.unpack_from("<I", code, i + 7)[0]
            if 1000 < id_val < 100000:
                results.append((i, id_val))
    return results

def find_call_mov_rip_rax(exe_data, func_off, func_size=0x20000):
    """Find CALL rel32 + MOV [RIP+disp32], RAX patterns in game binary.
    Returns [(offset_from_func, call_target), ...]"""
    results = []
    end = min(func_off + func_size, len(exe_data))
    i = func_off
    while i < end - 12:
        if exe_data[i] == 0xE8:
            rel32 = struct.unpack_from("<i", exe_data, i + 1)[0]
            call_target = i + 5 + rel32
            if exe_data[i + 5] == 0x48 and exe_data[i + 6] == 0x89 and exe_data[i + 7] == 0x05:
                disp32 = struct.unpack_from("<i", exe_data, i + 8)[0]
                rip = i + 12
                dest = rip + disp32
                if 0 <= dest < len(exe_data):
                    results.append((i - func_off, call_target))
            i += 5
        else:
            i += 1
    return results

# ---------------------------------------------------------------------------
# Address library resolution
# ---------------------------------------------------------------------------
def load_current_lib(plugins_dir, game_version=None, extra_dirs=None):
    """Load the versionlib matching the current game version.

    game_version: (major, minor, build) tuple from the game exe, or None.
    A wrong-version lib maps IDs to wrong func RVAs, poisoning every finding,
    so prefer the filename-version match and only fall back to first found.
    """
    dirs = [plugins_dir] + list(extra_dirs or [])
    found = []
    if game_version:
        match = _core.find_versionlib_in_dirs(dirs, game_version)
        if match is not None:
            with open(match, "rb") as f:
                data = f.read()
            if len(data) >= 4 and struct.unpack_from("<I", data, 0)[0] == 5:
                lib = _core.parse_format5(data)
                if lib:
                    return lib
    for p in _core.collect_lib_bins(dirs):
        if not p.name.startswith("versionlib-"):
            continue
        with open(p, "rb") as f:
            data = f.read()
        if len(data) >= 4 and struct.unpack_from("<I", data, 0)[0] == 5:
            lib = _core.parse_format5(data)
            if lib:
                ver = _core.extract_version_from_filename(p.name)
                if game_version and ver == tuple(game_version[:3]):
                    return lib
                found.append(lib)
    return found[0] if found else None

def _exe_version_tuple(exe_path):
    """(major, minor, build) from the exe's VS_FIXEDFILEINFO, or None."""
    packed = _core.runtime_version_from_exe(exe_path)
    return _core.unpack_version(packed) if packed is not None else None

def extract_bytes_at(exe_data, addr, size=16):
    if addr + size > len(exe_data):
        return None
    return bytes(exe_data[addr:addr + size])

def find_byte_sequence(exe_data, seq, start=0, end=None):
    """Find all occurrences of seq in exe_data[start:end]."""
    if end is None:
        end = len(exe_data)
    results = []
    pos = start
    while pos <= end - len(seq):
        pos = exe_data.find(seq, pos, end)
        if pos == -1:
            break
        results.append(pos)
        pos += 1
    return results

def resolve_ambiguous_hook(id_val, scan_offset, candidates, pattern_blob,
                           exe_data, exe_sections, current_lib,
                           old_exe_data, old_secs, old_lib):
    """Callee-identity verdict for one ambiguous hook: winning offset or None.

    Pure; no I/O, no patching. candidates may be plain offsets or
    (offset, target) tuples. Needs the old lib; without it there is
    nothing to anchor the callee to.
    """
    if not candidates or old_lib is None or old_exe_data is None:
        return None
    offs = [c[0] if isinstance(c, tuple) else c for c in candidates]
    if isinstance(pattern_blob, dict):
        pat = dict(pattern_blob)
    else:
        pat = {i: b for i, b in enumerate(bytes(pattern_blob or b""))}
    hook = {"rel_id": id_val, "offset": scan_offset, "pattern": pat}
    status, payload = _ther.disambiguate_hook_by_callee(
        hook, exe_data, exe_sections, current_lib,
        old_exe_data, old_secs, old_lib, offs)
    return payload if status == "resolved" else None

# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------
def analyze_pattern_drift(dll_path, exe_path, plugins_dir, old_exe_path=None,
                   extra_dirs=None):
    """Analyze a plugin DLL for stale pattern scan offsets.
    If old_exe_path is provided, uses it to extract patterns from the old binary."""
    dll_data, dll_sections, code = load_code(dll_path)
    exe_data, exe_sections = _core.load_exe_sections(exe_path)
    current_lib = load_current_lib(plugins_dir, _exe_version_tuple(exe_path),
                                   extra_dirs=extra_dirs)

    old_exe_data = None
    old_exe_sections = None
    old_lib = None
    try:
        has_old = bool(old_exe_path) and Path(old_exe_path).is_file()
    except (OSError, TypeError):
        has_old = False
    if has_old:
        try:
            old_exe_data, old_exe_sections = _core.load_exe_sections(old_exe_path)
        except Exception:
            old_exe_data, old_exe_sections = None, None
        try:
            old_ver = _exe_version_tuple(old_exe_path)
            dirs = [plugins_dir] + list(extra_dirs or [])
            match = _core.find_versionlib_in_dirs(dirs, old_ver) if old_ver else None
            if match is not None:
                old_lib = _core.parse_library_any(str(match))
        except Exception:
            old_lib = None

    findings = []
    seen_offsets = set()
    mov_ebx_list = find_mov_ebx_imm32(code)

    for code_off, scan_offset in mov_ebx_list:
        id_refs = find_id_refs_nearby(code, code_off)
        for _ref_off, id_val in id_refs:
            if current_lib and id_val in current_lib:
                func_rva = current_lib[id_val]
                func_off = _core.rva_to_offset(func_rva, exe_sections)
                if func_off is None:
                    continue
                test_addr = func_off + scan_offset
                pattern = extract_bytes_at(exe_data, test_addr, 16)
                if pattern is None:
                    continue

                # Deduplicate per code site: the same numeric offset at two
                # different sites (or IDs) are two independent hooks.
                key = (code_off, id_val, scan_offset)
                if key in seen_offsets:
                    continue
                seen_offsets.add(key)

                if pattern[0] == 0xE8:
                    matches = find_byte_sequence(exe_data, pattern)
                    if not matches:
                        continue
                    actual_addrs = [m for m in matches if abs(m - test_addr) > 16]
                    if not actual_addrs:
                        continue
                    if len(actual_addrs) == 1:
                        new_offset = actual_addrs[0] - func_off
                        if 0 < new_offset < 0x20000:
                            findings.append({
                                "dll_path": dll_path,
                                "code_offset": code_off,
                                "id_val": id_val,
                                "func_rva": func_rva,
                                "old_offset": scan_offset,
                                "new_offset": new_offset,
                                "pattern": pattern,
                                "expected_addr": test_addr,
                                "actual_addr": actual_addrs[0],
                                "auto_fixable": True,
                            })
                    else:
                        # Ambiguous: N sites share the pattern. One manual
                        # finding with candidates - never N auto-fixable ones
                        # (healing would apply them in turn, last wins blind).
                        cands = sorted({m - func_off for m in actual_addrs
                                        if 0 < m - func_off < 0x20000})
                        if cands:
                            winner = resolve_ambiguous_hook(
                                id_val, scan_offset, cands, pattern,
                                exe_data, exe_sections, current_lib,
                                old_exe_data, old_exe_sections, old_lib)
                            if winner is not None:
                                findings.append({
                                    "dll_path": dll_path,
                                    "code_offset": code_off,
                                    "id_val": id_val,
                                    "func_rva": func_rva,
                                    "old_offset": scan_offset,
                                    "new_offset": winner,
                                    "pattern": pattern,
                                    "expected_addr": test_addr,
                                    "actual_addr": func_off + winner,
                                    "auto_fixable": True,
                                })
                                continue
                            closest = min(cands, key=lambda c: abs(c - scan_offset))
                            findings.append({
                                "dll_path": dll_path,
                                "code_offset": code_off,
                                "id_val": id_val,
                                "func_rva": func_rva,
                                "old_offset": scan_offset,
                                "new_offset": None,
                                "pattern": pattern,
                                "expected_addr": test_addr,
                                "actual_addr": None,
                                "candidates": [(c, None) for c in cands],
                                "closest_candidate": closest,
                                "auto_fixable": False,
                            })
                else:
                    if old_exe_data and old_exe_sections:
                        old_func_off = _core.rva_to_offset(func_rva, old_exe_sections)
                        if old_func_off is not None:
                            old_pattern = extract_bytes_at(old_exe_data, old_func_off + scan_offset, 16)
                            if old_pattern and old_pattern != pattern:
                                matches = find_byte_sequence(exe_data, old_pattern)
                                if matches:
                                    actual_addrs = [m for m in matches if abs(m - test_addr) > 16]
                                    uniq = [(m - func_off) for m in actual_addrs
                                            if 0 < m - func_off < 0x20000]
                                    if len(uniq) == 1:
                                        findings.append({
                                            "dll_path": dll_path,
                                            "code_offset": code_off,
                                            "id_val": id_val,
                                            "func_rva": func_rva,
                                            "old_offset": scan_offset,
                                            "new_offset": uniq[0],
                                            "pattern": old_pattern,
                                            "expected_addr": test_addr,
                                            "actual_addr": actual_addrs[0],
                                            "auto_fixable": True,
                                        })
                                    elif uniq:
                                        cands = sorted(set(uniq))
                                        winner = resolve_ambiguous_hook(
                                            id_val, scan_offset, cands, old_pattern,
                                            exe_data, exe_sections, current_lib,
                                            old_exe_data, old_exe_sections, old_lib)
                                        if winner is not None:
                                            findings.append({
                                                "dll_path": dll_path,
                                                "code_offset": code_off,
                                                "id_val": id_val,
                                                "func_rva": func_rva,
                                                "old_offset": scan_offset,
                                                "new_offset": winner,
                                                "pattern": old_pattern,
                                                "expected_addr": test_addr,
                                                "actual_addr": func_off + winner,
                                                "auto_fixable": True,
                                            })
                                            continue
                                        closest = min(cands, key=lambda c: abs(c - scan_offset))
                                        findings.append({
                                            "dll_path": dll_path,
                                            "code_offset": code_off,
                                            "id_val": id_val,
                                            "func_rva": func_rva,
                                            "old_offset": scan_offset,
                                            "new_offset": None,
                                            "pattern": old_pattern,
                                            "expected_addr": test_addr,
                                            "actual_addr": None,
                                            "candidates": [(c, None) for c in cands],
                                            "closest_candidate": closest,
                                            "auto_fixable": False,
                                        })
                                else:
                                    findings.append({
                                        "dll_path": dll_path,
                                        "code_offset": code_off,
                                        "id_val": id_val,
                                        "func_rva": func_rva,
                                        "old_offset": scan_offset,
                                        "new_offset": None,
                                        "pattern": old_pattern,
                                        "expected_addr": test_addr,
                                        "actual_addr": None,
                                        "auto_fixable": False,
                                        "reason": "Scan pattern gone from new binary - function rewritten, plugin needs recompilation by author",
                                    })
                    else:
                        call_movs = find_call_mov_rip_rax(exe_data, func_off)
                        if len(call_movs) == 1:
                            pattern_off, call_target = call_movs[0]
                            if pattern_off != scan_offset:
                                new_pattern = extract_bytes_at(exe_data, func_off + pattern_off, 16)
                                if new_pattern and new_pattern[0] == 0xE8:
                                    findings.append({
                                        "dll_path": dll_path,
                                        "code_offset": code_off,
                                        "id_val": id_val,
                                        "func_rva": func_rva,
                                        "old_offset": scan_offset,
                                        "new_offset": pattern_off,
                                        "pattern": new_pattern,
                                        "expected_addr": test_addr,
                                        "actual_addr": func_off + pattern_off,
                                        "auto_fixable": True,
                                    })
                        elif len(call_movs) > 1:
                            closest = min(call_movs, key=lambda x: abs(x[0] - scan_offset))
                            findings.append({
                                "dll_path": dll_path,
                                "code_offset": code_off,
                                "id_val": id_val,
                                "func_rva": func_rva,
                                "old_offset": scan_offset,
                                "new_offset": None,
                                "pattern": pattern,
                                "expected_addr": test_addr,
                                "actual_addr": None,
                                "candidates": call_movs,
                                "closest_candidate": closest[0],
                                "auto_fixable": False,
                            })
    try:
        lea_findings, _, _, _ = find_lea_hooks(
            dll_path, exe_path, plugins_dir, old_exe_path,
            extra_dirs=extra_dirs)
        findings.extend(lea_findings)
    except Exception:
        pass
    return findings, dll_data, dll_sections, code

def find_lea_hooks(dll_path, exe_path, plugins_dir, old_exe_path=None,
                   extra_dirs=None):
    """compasse-core-shaped hooks (REL::ID + lea disp32) as healer findings.

    Same finding dicts as analyze_pattern_drift (plus "kind": "lea" and the raw
    "hook" for patching), so cards, CLI print and heal flows work unchanged.
    Ambiguous hooks resolve through callee identity when old-exe ground
    truth exists; otherwise they stay manual with candidates.
    Returns (findings, dll_data, dll_sections, code).
    """
    dll_data, dll_sections, _code = load_code(dll_path)
    exe_data, exe_sections = _core.load_exe_sections(exe_path)
    current_lib = load_current_lib(plugins_dir, _exe_version_tuple(exe_path),
                                   extra_dirs=extra_dirs)
    old_exe_data = None
    old_secs = None
    old_lib = None
    try:
        has_old = bool(old_exe_path) and Path(old_exe_path).is_file()
    except (OSError, TypeError):
        has_old = False
    if has_old:
        try:
            old_exe_data, old_secs = _core.load_exe_sections(old_exe_path)
        except Exception:
            old_exe_data, old_secs = None, None
        try:
            old_ver = _exe_version_tuple(old_exe_path)
            dirs = [plugins_dir] + list(extra_dirs or [])
            match = _core.find_versionlib_in_dirs(dirs, old_ver) if old_ver else None
            if match is not None:
                old_lib = _core.parse_library_any(str(match))
        except Exception:
            old_lib = None
    text_va = None
    for name, va, _vsize, _raw, _rawsize in dll_sections:
        if name == ".text":
            text_va = va
            break

    def emit(dll_path, code_off, rel_id, base, old_off, new_off, base_foff,
             hook, auto, cands=None, closest=None):
        pat_at = new_off if new_off is not None else old_off
        finding = {
            "dll_path": dll_path,
            "code_offset": code_off,
            "id_val": rel_id,
            "func_rva": base,
            "old_offset": old_off,
            "new_offset": new_off,
            "pattern": extract_bytes_at(exe_data, base_foff + pat_at, 16) or b"",
            "expected_addr": base_foff + old_off,
            "actual_addr": (base_foff + new_off
                            if new_off is not None else None),
            "auto_fixable": auto,
            "kind": "lea",
            "hook": hook,
        }
        if not auto:
            finding["candidates"] = [(c, None) for c in (cands or [])]
            finding["closest_candidate"] = closest
        return finding

    findings = []
    if current_lib is None or text_va is None:
        return findings, dll_data, dll_sections, _code
    for hook in _ther.find_hooks(dll_path):
        rel_id, old_off = hook["rel_id"], hook["offset"]
        if rel_id not in current_lib:
            continue
        base = current_lib[rel_id]
        base_foff = _core.rva_to_offset(base, exe_sections)
        if base_foff is None:
            continue
        if _ther.pattern_matches_at(exe_data, exe_sections, base, old_off,
                                    hook["pattern"]):
            continue
        matches = _ther.find_pattern_offsets(exe_data, exe_sections, base,
                                             hook["pattern"], old_off)
        code_off = hook["va"] - text_va
        if len(matches) == 1:
            findings.append(emit(
                dll_path, code_off, rel_id, base, old_off, matches[0],
                base_foff, hook, True))
        else:
            winner = (resolve_ambiguous_hook(
                rel_id, old_off, matches, hook["pattern"],
                exe_data, exe_sections, current_lib,
                old_exe_data, old_secs, old_lib)
                if (matches and old_exe_data is not None) else None)
            if winner is not None:
                findings.append(emit(
                    dll_path, code_off, rel_id, base, old_off, winner,
                    base_foff, hook, True))
            else:
                cands = sorted(matches)
                findings.append(emit(
                    dll_path, code_off, rel_id, base, old_off, None,
                    base_foff, hook, False, cands,
                    min(cands, key=lambda c: abs(c - old_off)) if cands else None))
    return findings, dll_data, dll_sections, _code

# ---------------------------------------------------------------------------
# Healing
# ---------------------------------------------------------------------------
def heal_plugin(dll_path, finding, backup=True):
    """Patch the plugin DLL with the corrected offset."""
    new_offset = finding["new_offset"]
    if finding.get("kind") == "lea" and "hook" in finding:
        return _ther.patch_hook_offset(dll_path, finding["hook"], new_offset)
    code_off = finding["code_offset"]
    dll_data, dll_sections, _ = load_code(dll_path)
    text_section = None
    for name, va, vsize, raw, rawsize in dll_sections:
        if name == ".text":
            text_section = (va, raw)
            break
    if text_section is None:
        return False
    text_va, text_raw = text_section
    file_off = text_raw + code_off
    if backup:
        bak_path = dll_path.parent / (dll_path.name + ".bak")
        if not bak_path.exists():
            shutil.copy2(dll_path, bak_path)
    data = bytearray(dll_path.read_bytes())
    struct.pack_into("<I", data, file_off + 1, new_offset)  # +1 to skip 0xBB opcode
    dll_path.write_bytes(data)
    return True

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
