"""Hook/pattern/xref scanning for fixing."""
import struct
from pathlib import Path
from core.backups import backup_bytes
from core.pe import HAS_CAPSTONE, capstone_md, find_export_rva, find_pe_sections, get_functions_from_pdata, iat_range, rva_to_offset, x86
from core.touched import add_touched

PATTERN_SCAN_RANGE = 0x1000  # scan offsets 0..0x1000 for the pattern

def find_hooks(dll_path):
    """Find REL::ID hooks. Returns a list of hook dicts."""
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

    md = capstone_md()
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

def find_pattern_offsets(exe, sections, base_offset, pattern, old_offset, window=0x400):
    """List offsets near old_offset where the pattern matches."""
    matches = []
    lo = max(0, old_offset - window)
    hi = old_offset + window
    for off in range(lo, hi + 1):
        rva = base_offset + off
        foff = rva_to_offset(rva, sections)
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
    """True if the pattern matches at base_offset + offset."""
    foff = rva_to_offset(base_offset + offset, sections)
    if foff is None:
        return False
    for i, expected in sorted(pattern.items()):
        if foff + i >= len(exe) or exe[foff + i] != expected:
            return False
    return True

def disambiguate_hook_by_callee(hook, exe, exe_sections, addresslib,
                                old_exe, old_secs, old_lib, candidates=None):
    """Resolve an ambiguous hook by callee address. Never guesses."""
    rel_id = hook["rel_id"]
    old_off = hook["offset"]
    pattern = hook["pattern"]
    base_new = addresslib.get(rel_id)
    if base_new is None:
        return ("still-ambiguous", None)
    if pattern.get(0) != 0xE8:
        return ("still-ambiguous", None)  # not a call hook; method N/A
    if candidates is None:
        candidates = find_pattern_offsets(exe, exe_sections, base_new, pattern, old_off)
    if len(candidates) == 1:
        return ("resolved", candidates[0])
    if not candidates:
        return ("unfixable", None)

    def rva2off(exe_data, secs, rva):
        for name, vaddr, vsize, rawoff, rawsize in secs:
            if vaddr <= rva < vaddr + max(vsize, rawsize):
                off = rawoff + (rva - vaddr)
                return off if off + 5 <= len(exe_data) else None
        return None

    base_old = old_lib.get(rel_id)
    if base_old is None:
        return ("still-ambiguous", None)  # no old anchor
    old_site = base_old + old_off
    old_foff = rva2off(old_exe, old_secs, old_site)
    if old_foff is None or old_exe[old_foff] != 0xE8:
        return ("still-ambiguous", None)  # old site unreadable/not a call
    old_target = old_site + 5 + struct.unpack_from("<i", old_exe, old_foff + 1)[0]
    rev_ids = [i for i, o in old_lib.items() if o == old_target]
    if not rev_ids:
        return ("still-ambiguous", None)  # callee has no ID anchor
    expected = {addresslib[i] for i in rev_ids if i in addresslib}
    if not expected:
        return ("unfixable", rev_ids)  # callee gone upstream
    winners = []
    for c in candidates:
        site = base_new + c
        foff = rva2off(exe, exe_sections, site)
        if foff is None:
            continue
        target = site + 5 + struct.unpack_from("<i", exe, foff + 1)[0]
        if target in expected:
            winners.append(c)
    if len(winners) == 1:
        return ("resolved", winners[0])
    if not winners:
        return ("unfixable", rev_ids)
    return ("still-ambiguous", None)

# ---------------------------------------------------------------------------
# Offset patch
# ---------------------------------------------------------------------------
def patch_hook_offset(dll_path, hook, new_offset):
    """Write the new lea displacement. Returns True if patched."""
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
    try:
        add_touched(Path(dll_path).parent, dll_path)
    except Exception:
        pass
    return True

# ---------------------------------------------------------------------------
# High-level operations
# ---------------------------------------------------------------------------
def collect_xref_ids(dll_path):
    """IDs in RIP-read data slots. None when unavailable."""
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
    by_name = {n: (v, o, s) for n, v, _, o, s in sections}
    if ".text" not in by_name:
        return None

    md = capstone_md()
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

    vals = set()
    iat = iat_range(data)
    for sname in (".data", ".rdata"):
        if sname not in by_name:
            continue
        vaddr, rawoff, rawsize = by_name[sname]
        for k in range(0, rawsize - 8):
            rva = vaddr + k
            if rva not in rip_targets:
                continue
            if iat is not None and iat[0] <= rva < iat[1]:
                continue
            for width, fmt in ((8, "<Q"), (4, "<I")):
                if k + width > rawsize:
                    continue
                vals.add(struct.unpack_from(fmt, data, rawoff + k)[0])
    return vals

def count_xref_ids(dll_path, id_set):
    """Count data slots that hold known IDs and code reads."""
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

    md = capstone_md()
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
    iat = iat_range(data)
    for sname in (".data", ".rdata"):
        if sname not in by_name:
            continue
        vaddr, rawoff, rawsize = by_name[sname]
        for k in range(0, rawsize - 8):
            rva = vaddr + k
            if rva not in rip_targets:
                continue
            if iat is not None and iat[0] <= rva < iat[1]:
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
    """List version checks in the plugin. None when unavailable."""
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

    md = capstone_md()
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

    # Version-gate strings in .rdata, keyed by RVA.
    # Skip undecodable bytes and require word boundaries.
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
