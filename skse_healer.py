#!/usr/bin/env python3
"""
SKSE Healer - Detect and fix broken SKSE plugins with stale hardcoded offsets.

Problem class addressed: Pattern scan offset drift.
When the game updates, functions restructure internally. Plugins that hardcode
an offset from a known REL::ID function to scan for byte patterns end up
pointing at the wrong location. This tool finds the pattern at the stale offset,
locates where it actually moved to in the current binary, and patches the offset.

Usage:
    python skse_healer.py <plugin.dll> --game <SkyrimSE.exe> [--plugins-dir <dir>]
    python skse_healer.py <plugin.dll> --game <SkyrimSE.exe> --heal
"""

import struct
import sys
import argparse
import shutil
from pathlib import Path


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
    sec = dd_start + num_dd * 8
    sections = []
    for _ in range(num_sections):
        vsize = struct.unpack_from("<I", data, sec + 8)[0]
        va = struct.unpack_from("<I", data, sec + 12)[0]
        rawsize = struct.unpack_from("<I", data, sec + 16)[0]
        raw = struct.unpack_from("<I", data, sec + 20)[0]
        name = data[sec:sec + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        sections.append((name, va, vsize, raw, rawsize))
        sec += 40
    return sections


def rva_to_offset(rva, sections):
    for _name, va, vsize, raw, rawsize in sections:
        if va <= rva < va + max(vsize, rawsize):
            return rva - va + raw
    return None


def load_code(dll_path):
    with open(dll_path, "rb") as f:
        data = f.read()
    sections = find_pe_sections(data)
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
            stack_off = code[i + 3]
            if stack_off < 0x80:
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
def parse_format5(data):
    """Parse format 5 versionlib (dense u32 array). Returns {id: offset}."""
    if len(data) < 96:
        return None
    if struct.unpack_from("<I", data, 0)[0] != 5:
        return None
    count = struct.unpack_from("<I", data, 92)[0]
    entries = {}
    for i in range(count):
        off = struct.unpack_from("<I", data, 96 + i * 4)[0]
        if off != 0:
            entries[i] = off
    return entries


def load_current_lib(plugins_dir, game_version=None):
    """Load the versionlib matching the current game version."""
    for p in plugins_dir.glob("versionlib-*.bin"):
        with open(p, "rb") as f:
            data = f.read()
        if len(data) >= 4 and struct.unpack_from("<I", data, 0)[0] == 5:
            lib = parse_format5(data)
            if lib:
                return lib
    return None


# ---------------------------------------------------------------------------
# Game binary analysis
# ---------------------------------------------------------------------------
def load_game_sections(exe_path):
    with open(exe_path, "rb") as f:
        exe = f.read()
    sections = find_pe_sections(exe)
    return exe, sections


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


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------
def analyze_plugin(dll_path, exe_path, plugins_dir, old_exe_path=None):
    """Analyze a plugin DLL for stale pattern scan offsets.
    If old_exe_path is provided, uses it to extract patterns from the old binary."""
    dll_data, dll_sections, code = load_code(dll_path)
    exe_data, exe_sections = load_game_sections(exe_path)
    current_lib = load_current_lib(plugins_dir)

    old_exe_data = None
    old_exe_sections = None
    if old_exe_path:
        old_exe_data, old_exe_sections = load_game_sections(old_exe_path)

    findings = []
    seen_offsets = set()
    mov_ebx_list = find_mov_ebx_imm32(code)

    for code_off, scan_offset in mov_ebx_list:
        id_refs = find_id_refs_nearby(code, code_off)
        for _ref_off, id_val in id_refs:
            if current_lib and id_val in current_lib:
                func_rva = current_lib[id_val]
                func_off = rva_to_offset(func_rva, exe_sections)
                if func_off is None:
                    continue
                test_addr = func_off + scan_offset
                pattern = extract_bytes_at(exe_data, test_addr, 16)
                if pattern is None:
                    continue

                # Deduplicate: same offset value already handled
                if scan_offset in seen_offsets:
                    continue
                seen_offsets.add(scan_offset)

                if pattern[0] == 0xE8:
                    matches = find_byte_sequence(exe_data, pattern)
                    if not matches:
                        continue
                    actual_addrs = [m for m in matches if abs(m - test_addr) > 16]
                    if not actual_addrs:
                        continue
                    for actual_addr in actual_addrs:
                        new_offset = actual_addr - func_off
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
                                "actual_addr": actual_addr,
                                "auto_fixable": True,
                            })
                else:
                    if old_exe_data and old_exe_sections:
                        old_func_off = rva_to_offset(func_rva, old_exe_sections)
                        if old_func_off is not None:
                            old_pattern = extract_bytes_at(old_exe_data, old_func_off + scan_offset, 16)
                            if old_pattern and old_pattern != pattern:
                                matches = find_byte_sequence(exe_data, old_pattern)
                                if matches:
                                    actual_addrs = [m for m in matches if abs(m - test_addr) > 16]
                                    for actual_addr in actual_addrs:
                                        new_offset = actual_addr - func_off
                                        if 0 < new_offset < 0x20000:
                                            findings.append({
                                                "dll_path": dll_path,
                                                "code_offset": code_off,
                                                "id_val": id_val,
                                                "func_rva": func_rva,
                                                "old_offset": scan_offset,
                                                "new_offset": new_offset,
                                                "pattern": old_pattern,
                                                "expected_addr": test_addr,
                                                "actual_addr": actual_addr,
                                                "auto_fixable": True,
                                            })
                                else:
                                    # Old pattern doesn't exist in new binary
                                    # Function was rewritten, plugin needs recompilation
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
                        # No old binary provided - use heuristic fallback
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
    return findings, dll_data, dll_sections, code


# ---------------------------------------------------------------------------
# Healing
# ---------------------------------------------------------------------------
def heal_plugin(dll_path, finding, backup=True):
    """Patch the plugin DLL with the corrected offset."""
    new_offset = finding["new_offset"]
    code_off = finding["code_offset"]
    # The MOV EBX, imm32 is at code_off in .text section
    # We need to convert code offset to file offset
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
    # Backup
    if backup:
        bak_path = dll_path.parent / (dll_path.name + ".bak")
        if not bak_path.exists():
            shutil.copy2(dll_path, bak_path)
    # Patch
    data = bytearray(dll_path.read_bytes())
    struct.pack_into("<I", data, file_off + 1, new_offset)  # +1 to skip 0xBB opcode
    dll_path.write_bytes(data)
    return True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="SKSE Healer - detect and fix stale pattern scan offsets in SKSE plugins"
    )
    parser.add_argument("plugin", nargs="?", help="Plugin DLL to analyze")
    parser.add_argument("--game", help="Path to SkyrimSE.exe (current version)")
    parser.add_argument("--old-game", help="Path to old SkyrimSE.exe (version plugin was built against)")
    parser.add_argument("--plugins-dir", help="SKSE Plugins directory")
    parser.add_argument("--heal", action="store_true", help="Patch the plugin")
    parser.add_argument("--no-backup", action="store_true", help="Skip backup before heal")
    args = parser.parse_args()

    if not args.plugin:
        parser.error("plugin DLL path required")

    plugin_path = Path(args.plugin)
    if not plugin_path.exists():
        parser.error(f"Plugin not found: {plugin_path}")

    if args.game:
        game_path = Path(args.game)
    else:
        game_path = plugin_path.parent.parent.parent.parent / "SkyrimSE.exe"
    if not game_path.exists():
        parser.error(f"Game exe not found: {game_path}")

    plugins_dir = Path(args.plugins_dir) if args.plugins_dir else plugin_path.parent
    if not plugins_dir.exists():
        parser.error(f"Plugins dir not found: {plugins_dir}")

    old_game_path = None
    if args.old_game:
        old_game_path = Path(args.old_game)
        if not old_game_path.exists():
            parser.error(f"Old game exe not found: {old_game_path}")

    findings, dll_data, dll_sections, code = analyze_plugin(
        plugin_path, game_path, plugins_dir, old_game_path
    )

    if not findings:
        print(f"No stale offsets detected in {plugin_path.name}")
        return

    print(f"\n{'='*60}")
    print(f"  {plugin_path.name}: {len(findings)} stale offset(s) found")
    print(f"{'='*60}")

    for i, f in enumerate(findings):
        print(f"\n  [{i+1}] REL::ID {f['id_val']} (func RVA 0x{f['func_rva']:X})")
        print(f"      Old offset: 0x{f['old_offset']:X}")
        if f['new_offset'] is not None:
            print(f"      New offset: 0x{f['new_offset']:X}")
        elif 'reason' in f:
            print(f"      Status: {f['reason']}")
        else:
            print(f"      New offset: UNKNOWN (multiple candidates)")
        print(f"      Pattern:    {f['pattern'][:8].hex()}...")
        print(f"      Stale addr: 0x{f['expected_addr']:X}")
        if f['actual_addr'] is not None:
            print(f"      Actual addr: 0x{f['actual_addr']:X}")
        if 'candidates' in f:
            print(f"      Candidates: {len(f['candidates'])} CALL+MOV patterns")
            for coff, _ in f['candidates'][:5]:
                print(f"        0x{coff:X} ({coff:+d} from scan offset)")

    if args.heal:
        for f in findings:
            if f['new_offset'] is None:
                print(f"\n  SKIPPED: {plugin_path.name} - needs manual fix")
                continue
            ok = heal_plugin(plugin_path, f, backup=not args.no_backup)
            if ok:
                print(f"\n  PATCHED: {plugin_path.name} "
                      f"0x{f['old_offset']:X} -> 0x{f['new_offset']:X}")
            else:
                print(f"\n  FAILED to patch {plugin_path.name}")
    else:
        print(f"\n  Run with --heal to apply fixes")


if __name__ == "__main__":
    main()
