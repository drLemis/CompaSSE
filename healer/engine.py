#!/usr/bin/env python3
"""Check one SKSE plugin and report HEALTHY, FIXABLE, RISKY, or BROKEN."""

import json
from pathlib import Path

import core
import therapist
from healer import analysis as healer

RECIPE_FORMAT = 1
RECIPE_KINDS = ("hook", "healer", "flags")

def _exe_tuple(exe_path):
    try:
        packed = core.runtime_version_from_exe(exe_path)
    except Exception:
        return None
    return core.unpack_version(packed) if packed is not None else None

def game_ver_str(exe_path):
    """'1.7.104' style version for recipe matching, or None."""
    try:
        t = _exe_tuple(exe_path)
        if t is None:
            return None
        return f"{t[0]}.{t[1]}.{t[2]}"
    except Exception:
        return None

def _ever_ids(dirs):
    ever = set()
    try:
        bins = core.collect_lib_bins(dirs)
    except Exception:
        return ever
    for b in bins:
        try:
            lib = core.parse_library_any(str(b))
        except Exception:
            continue
        if lib:
            ever.update(lib.keys())
    return ever

def _translated_ids(plugins_dir, run_tup):
    """IDs covered by translation_table.bin for this game version."""
    try:
        data = (Path(plugins_dir) / "CompaSSE"
                / "translation_table.bin").read_bytes()
    except OSError:
        return set()
    try:
        parsed = core.read_translation_table(data)
    except Exception:
        return set()
    if parsed is None:
        return set()
    _, fmt, stamp, versions = parsed
    game_str = None
    if run_tup is not None:
        try:
            game_str = f"{run_tup[0]}.{run_tup[1]}.{run_tup[2]}"
        except Exception:
            game_str = None
    if fmt == 3 and stamp != game_str:
        return set()
    if fmt not in (1, 3):
        return set()
    return {oid for _, ent in versions for oid, _ in ent}

def _grade_uncovered(uncovered, xref_n):
    """Sort missing IDs into stray or gutted."""
    cov = sorted(uncovered)
    if not cov:
        return ("ok", [])
    blocks, start, prev = [], cov[0], cov[0]
    for v in cov[1:]:
        if v - prev > 256:
            blocks.append((start, prev))
            start = v
        prev = v
    blocks.append((start, prev))
    big = max(blocks, key=lambda b: (b[1] - b[0], b[0]))
    big_n = sum(1 for v in cov if big[0] <= v <= big[1])
    pct = len(cov) / xref_n if xref_n else 0
    if len(cov) >= 10 or big_n >= 8 or pct >= 0.10:
        return ("gutted", [big[0], big[1], big_n])
    return ("stray", [])

EXC_NAMES = {"0XC0000005": "access violation",
             "0XC00000FD": "stack overflow",
             "0XC0000094": "division by zero",
             "0XC000001D": "illegal instruction"}

def _last_run_crash(dll_name, plugins_dir):
    """Last starting crash for this DLL. None if none."""
    import re as _re
    try:
        text = (Path(plugins_dir) / "CompaSSE" / "!CompaSSE.log"
                ).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    rec, watching, fault = None, False, None
    for line in text.splitlines():
        mm = _re.search(r"legacy: attempting load of (\S+)", line)
        if mm:
            watching = mm.group(1) == dll_name
            fault = None
            continue
        if watching and fault is None:
            mv = _re.search(r"VEH: code=(0x[0-9A-Fa-f]+) addr=\S+ \((.*?)\)",
                            line)
            if mv:
                fault = (mv.group(1), mv.group(2))
                continue
        mc = _re.search(r"legacy: (\S+) CRASHED in (Query|Load)", line)
        if mc and mc.group(1) == dll_name:
            rec = {"stage": mc.group(2),
                   "code": fault[0] if fault else None,
                   "place": fault[1] if fault else None}
            watching, fault = False, None
    return rec

def _crash_line(rec):
    """One plain line naming the crash kind and fault location."""
    code = (rec.get("code") or "").upper()
    kind = EXC_NAMES.get(code, f"crash {code}" if code else "crash")
    place = rec.get("place") or "unknown location"
    if place == "?":
        place = "unknown location"
    if place.startswith("skse64"):
        where = f"inside SKSE itself ({place})"
    elif ".dll" in place:
        where = f"inside its own code ({place})"
    else:
        where = f"at {place}"
    return (f"Crashed with {kind} {where} while starting "
            f"({rec.get('stage')}).")

def _skse_log_path():
    return Path.home() / "Documents" / "My Games" \
        / "Skyrim Special Edition" / "SKSE" / "skse64.log"

def _skse_disabled(dll_name, log_path=None):
    """SKSE gave up on this DLL at load in a recorded run."""
    import re as _re
    try:
        text = (Path(log_path) if log_path else _skse_log_path()
                ).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    for line in text.splitlines():
        m = _re.search(r"plugin (\S+\.dll).*disabled, fatal", line)
        if m and m.group(1) == dll_name:
            return True
    return False

def _crashlogger_hit(dll_name, crash_dir=None):
    """(kind, ) if the newest crash report names this DLL as faulting.

    Kind is plain words; the raw report keeps the offsets.
    """
    import re as _re
    base = Path(crash_dir) if crash_dir else _skse_log_path().parent
    try:
        logs = sorted(base.glob("crash-*.log"),
                      key=lambda p: p.stat().st_mtime)
    except OSError:
        return None
    if not logs:
        return None
    try:
        text = logs[-1].read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    m = _re.search(r'Unhandled exception "([^"]+)" at 0x[0-9A-Fa-f]+ '
                   r"(\S+\.dll)(?:\+([0-9A-Fa-f]+))?", text)
    if not m or m.group(2) != dll_name:
        return None
    raw = m.group(1)
    kinds = {"EXCEPTION_ACCESS_VIOLATION": "access violation",
             "EXCEPTION_STACK_OVERFLOW": "stack overflow",
             "EXCEPTION_INT_DIVIDE_BY_ZERO": "division by zero",
             "EXCEPTION_ILLEGAL_INSTRUCTION": "illegal instruction"}
    return next((v for k, v in kinds.items() if k in raw), raw)

def _last_run_loaded(dll_name):
    """True if SKSE logged this DLL as loaded in the last recorded run."""
    import re as _re
    try:
        text = (Path.home() / "Documents" / "My Games"
                / "Skyrim Special Edition" / "SKSE" / "skse64.log"
                ).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    for line in text.splitlines():
        mm = _re.search(r"plugin (\S+\.dll).*loaded correctly", line)
        if mm and mm.group(1) == dll_name:
            return True
    return False

def _xref_callers(dll_path):
    """Map each data-slot value to the code spots that read it."""
    if not core.HAS_CAPSTONE:
        return None
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, x86
    except ImportError:
        return None
    try:
        with open(dll_path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    sections = core.find_pe_sections(data)
    if not sections:
        return None
    by_name = {n: (v, o, s) for n, v, _, o, s in sections}
    if ".text" not in by_name:
        return None
    md = core.capstone_md()
    readers = {}
    try:
        for begin, end in core.get_functions_from_pdata(data, sections):
            if end - begin > 0x10000:
                continue
            off = core.rva_to_offset(begin, sections)
            if off is None:
                continue
            for ins in md.disasm(data[off:off + (end - begin)], begin):
                for op in ins.operands:
                    if op.type == x86.X86_OP_MEM \
                            and op.mem.base == x86.X86_REG_RIP:
                        tgt = ins.address + ins.size + op.mem.disp
                        readers.setdefault(tgt, []).append(ins.address)
    except Exception:
        return None
    if not readers:
        return None
    import struct as _st
    out = {}
    iat = core.iat_range(data)
    for sname in (".data", ".rdata"):
        if sname not in by_name:
            continue
        vaddr, rawoff, rawsize = by_name[sname]
        for k in range(0, rawsize - 8):
            rva = vaddr + k
            if rva not in readers:
                continue
            if iat is not None and iat[0] <= rva < iat[1]:
                continue
            for width, fmt in ((8, "<Q"), (4, "<I")):
                if k + width > rawsize:
                    continue
                val = _st.unpack_from(fmt, data, rawoff + k)[0]
                out.setdefault(val, set()).update(readers[rva])
    return {v: sorted(r) for v, r in out.items() if r}

def _checked_use(dll_path, spots):
    """Mark each spot True if the value is tested before use."""
    if not spots:
        return {}
    if not core.HAS_CAPSTONE:
        return None
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, x86
    except ImportError:
        return None
    try:
        with open(dll_path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    secs = core.find_pe_sections(data)
    if not secs:
        return None
    funcs = sorted(b for b, e in
                   core.get_functions_from_pdata(data, secs)
                   if e - b <= 0x10000)
    if not funcs:
        return None

    def func_of(rva):
        lo, hi, ans = 0, len(funcs) - 1, None
        while lo <= hi:
            mid = (lo + hi) // 2
            if funcs[mid] <= rva:
                ans = funcs[mid]
                lo = mid + 1
            else:
                hi = mid - 1
        return ans

    try:
        md = core.capstone_md()
        reg_name = md.reg_name
    except Exception:
        return None

    def family(reg):
        try:
            nm = reg_name(reg)
        except Exception:
            return None
        if not nm:
            return None
        nm = nm.lower()
        base = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9",
                "r10", "r11", "r12", "r13", "r14", "r15")
        subs = (("al", "ah", "ax", "eax"), ("bl", "bh", "bx", "ebx"),
                ("cl", "ch", "cx", "ecx"), ("dl", "dh", "dx", "edx"),
                ("sil", "si", "esi"), ("dil", "di", "edi"),
                ("r8b", "r8w", "r8d"), ("r9b", "r9w", "r9d"),
                ("r10b", "r10w", "r10d"), ("r11b", "r11w", "r11d"),
                ("r12b", "r12w", "r12d"), ("r13b", "r13w", "r13d"),
                ("r14b", "r14w", "r14d"), ("r15b", "r15w", "r15d"))
        for i, b in enumerate(base):
            if nm == b or nm in subs[i]:
                return b
        return None

    jumps = {"jz", "je", "jnz", "jne", "jb", "jnae", "jae", "jnb",
             "jbe", "ja", "jl", "jge", "jle", "jg", "js", "jns", "jp",
             "jnp", "jo", "jno", "jcxz", "jecxz", "jrcxz"}
    out = {}
    try:
        for spot in spots:
            owner = func_of(spot)
            if owner is None:
                continue
            off = core.rva_to_offset(owner, secs)
            if off is None:
                continue
            insns = list(md.disasm(data[off:off + 0x10000], owner))
            insns = [i for i in insns if i.address < owner + 0x10000][:400]
            at = next((k for k, i in enumerate(insns)
                       if i.address == spot), None)
            if at is None or not insns[at].operands:
                continue
            first = insns[at].operands[0]
            if first.type != x86.X86_OP_REG:
                continue
            want = family(first.reg)
            if want is None:
                continue
            seen_test = False
            verdict = None
            for nxt in insns[at + 1:at + 41]:
                ops = nxt.operands
                if nxt.mnemonic in ("test", "cmp", "or"):
                    regs = [o.reg for o in ops
                            if o.type == x86.X86_OP_REG]
                    if any(family(r) == want for r in regs):
                        seen_test = True
                        continue
                if nxt.mnemonic in jumps and seen_test:
                    verdict = True
                    break
                if nxt.mnemonic in ("call", "jmp") and ops \
                        and ops[0].type == x86.X86_OP_REG \
                        and family(ops[0].reg) == want:
                    verdict = False
                    break
                if nxt.mnemonic == "ret":
                    break
            if verdict is not None:
                out[spot] = verdict
    except Exception:
        return None
    return out

def _code_ctx(dll_path):
    """Shared disassembly context, or None. One capstone pass per file."""
    if not core.HAS_CAPSTONE:
        return None
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, x86
    except ImportError:
        return None
    try:
        with open(dll_path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    secs = core.find_pe_sections(data)
    if not secs:
        return None
    funcs = sorted(b for b, e in
                   core.get_functions_from_pdata(data, secs)
                   if e - b <= 0x10000)
    if not funcs:
        return None
    try:
        md = core.capstone_md()
    except Exception:
        return None
    base = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9",
            "r10", "r11", "r12", "r13", "r14", "r15")
    subs = (("al", "ah", "ax", "eax"), ("bl", "bh", "bx", "ebx"),
            ("cl", "ch", "cx", "ecx"), ("dl", "dh", "dx", "edx"),
            ("sil", "si", "esi"), ("dil", "di", "edi"),
            ("r8b", "r8w", "r8d"), ("r9b", "r9w", "r9d"),
            ("r10b", "r10w", "r10d"), ("r11b", "r11w", "r11d"),
            ("r12b", "r12w", "r12d"), ("r13b", "r13w", "r13d"),
            ("r14b", "r14w", "r14d"), ("r15b", "r15w", "r15d"))

    def family(reg):
        try:
            nm = md.reg_name(reg)
        except Exception:
            return None
        if not nm:
            return None
        nm = nm.lower()
        for i, b in enumerate(base):
            if nm == b or nm in subs[i]:
                return b
        return None

    def func_of(rva):
        lo, hi, ans = 0, len(funcs) - 1, None
        while lo <= hi:
            mid = (lo + hi) // 2
            if funcs[mid] <= rva:
                ans = funcs[mid]
                lo = mid + 1
            else:
                hi = mid - 1
        return ans

    def insns_of(owner):
        off = core.rva_to_offset(owner, secs)
        if off is None:
            return []
        try:
            block = list(md.disasm(data[off:off + 0x10000], owner))
        except Exception:
            return []
        return [i for i in block if i.address < owner + 0x10000][:400]

    return {"data": data, "secs": secs, "md": md, "x86": x86,
            "family": family, "func_of": func_of, "insns_of": insns_of}

def _null_sink(dll_path, spots):
    """Unchecked call sites with a verified null path after the call.

    For a read spot whose value reaches an indirect call untested,
    checks whether rax is tested plus branched right after that call
    (directly, or via one mov copy). Returns {spot: call_rva} for
    patchable sites only, {} when none, None on failure.
    """
    if not spots:
        return {}
    ctx = _code_ctx(dll_path)
    if ctx is None:
        return None
    md, x86 = ctx["md"], ctx["x86"]
    family, func_of, insns_of = ctx["family"], ctx["func_of"], \
        ctx["insns_of"]
    jumps = {"jz", "je", "jnz", "jne", "jb", "jnae", "jae", "jnb",
             "jbe", "ja", "jl", "jge", "jle", "jg", "js", "jns", "jp",
             "jnp", "jo", "jno", "jcxz", "jecxz", "jrcxz"}
    out = {}
    try:
        for spot in spots:
            owner = func_of(spot)
            if owner is None:
                continue
            insns = insns_of(owner)
            at = next((k for k, i in enumerate(insns)
                       if i.address == spot), None)
            if at is None or not insns[at].operands:
                continue
            first = insns[at].operands[0]
            if first.type != x86.X86_OP_REG:
                continue
            want = family(first.reg)
            if want is None:
                continue
            call_at = None
            for nxt in insns[at + 1:at + 41]:
                ops = nxt.operands
                if nxt.mnemonic in ("test", "cmp", "or"):
                    regs = [o.reg for o in ops
                            if o.type == x86.X86_OP_REG]
                    if any(family(r) == want for r in regs):
                        break
                if nxt.mnemonic in ("call", "jmp") and ops \
                        and ops[0].type == x86.X86_OP_REG \
                        and family(ops[0].reg) == want:
                    call_at = insns.index(nxt)
                    break
                if nxt.mnemonic == "ret":
                    break
            if call_at is None:
                continue
            aliased = {"rax"}
            verdict = False
            for nxt in insns[call_at + 1:call_at + 26]:
                ops = nxt.operands
                if nxt.mnemonic == "mov" and len(ops) == 2 \
                        and ops[0].type == x86.X86_OP_REG \
                        and ops[1].type == x86.X86_OP_REG:
                    try:
                        if family(ops[1].reg) in aliased:
                            aliased.add(family(ops[0].reg))
                    except Exception:
                        pass
                    continue
                if nxt.mnemonic in ("test", "cmp"):
                    regs = {family(o.reg) for o in ops
                            if o.type == x86.X86_OP_REG}
                    regs.discard(None)
                    if regs & aliased:
                        for look in insns[insns.index(nxt) + 1:
                                          insns.index(nxt) + 7]:
                            if look.mnemonic in jumps:
                                verdict = True
                                break
                            if look.mnemonic in ("call", "ret"):
                                break
                        break
                if nxt.mnemonic in ("call", "jmp", "ret"):
                    break
            if verdict:
                out[spot] = insns[call_at].address
    except Exception:
        return None
    return out

def amputate_call(dll_path, call_rva):
    """Force an indirect call site to return null, same size.

    call reg (2 bytes) becomes xor eax,eax; call [mem] (6 bytes)
    becomes xor eax,eax + nops. Anything else is refused. The
    author's own null path downstream does the rest.
    """
    ctx = _code_ctx(dll_path)
    if ctx is None:
        return False
    data, secs = ctx["data"], ctx["secs"]
    owner = ctx["func_of"](call_rva)
    if owner is None:
        return False
    target = None
    for ins in ctx["insns_of"](owner):
        if ins.address != call_rva:
            continue
        if ins.mnemonic not in ("call", "jmp") or not ins.operands:
            return False
        op = ins.operands[0]
        if op.type != ctx["x86"].X86_OP_REG and not (
                op.type == ctx["x86"].X86_OP_MEM):
            return False
        if ins.size == 2 and op.type == ctx["x86"].X86_OP_REG:
            target = (call_rva, bytes((0x31, 0xC0)))
        elif ins.size == 6 and op.type == ctx["x86"].X86_OP_MEM:
            target = (call_rva, bytes((0x31, 0xC0, 0x90, 0x90,
                                       0x90, 0x90)))
        break
    if target is None:
        return False
    rva, blob = target
    off = core.rva_to_offset(rva, secs)
    if off is None or off + len(blob) > len(data):
        return False
    raw = bytearray(data)
    if bytes(raw[off:off + len(blob)]) not in (
            bytes((0xFF, 0xD0)), bytes((0xFF, 0xD1)),
            bytes((0xFF, 0xD2)), bytes((0xFF, 0xD3)),
            bytes((0xFF, 0xD4)), bytes((0xFF, 0xD5)),
            bytes((0xFF, 0xD6)), bytes((0xFF, 0xD7))):
        if not (len(blob) == 6 and raw[off] == 0xFF
                and (raw[off + 1] & 0x38) == 0x10
                and (raw[off + 1] & 0xC0) != 0xC0):
            return False
    raw[off:off + len(blob)] = blob
    try:
        core.backup_bytes(Path(dll_path), bytes(raw))
    except Exception:
        return False
    try:
        core.add_touched(Path(dll_path).parent, dll_path)
    except Exception:
        pass
    return True

def _game_kind(exe_data, secs, rva):
    """What lives at a game address: function or data.

    pdata-verified only. Function names exist nowhere in shipped
    files (bins are numbers by design), so this never invents one.
    Needs the exe the offset came from; without it, no answer.
    """
    if exe_data is None or secs is None:
        return (None, None)
    for begin, end in core.get_functions_from_pdata(exe_data, secs):
        if begin <= rva < end:
            return ("function", None)
    return ("data", None)

def _startup_reachable(dll_path, spots):
    """True for spots reachable from startup code."""
    if not spots:
        return {}
    if not core.HAS_CAPSTONE:
        return None
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, x86
    except ImportError:
        return None
    import struct as _st
    try:
        with open(dll_path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    secs = core.find_pe_sections(data)
    if not secs:
        return None
    text = None
    for name, vaddr, vsize, rawoff, rawsize in secs:
        if name == ".text":
            text = (vaddr, rawoff, rawsize)
            break
    if text is None:
        return None
    tvaddr, trawoff, trawsize = text
    funcs = sorted(b for b, e in
                   core.get_functions_from_pdata(data, secs)
                   if e - b <= 0x10000)
    if not funcs:
        return None

    def func_of(rva):
        lo, hi, ans = 0, len(funcs) - 1, None
        while lo <= hi:
            mid = (lo + hi) // 2
            if funcs[mid] <= rva:
                ans = funcs[mid]
                lo = mid + 1
            else:
                hi = mid - 1
        return ans

    md = core.capstone_md()
    calls = {}
    try:
        for idx, begin in enumerate(funcs):
            off = core.rva_to_offset(begin, secs)
            if off is None:
                continue
            nxt = funcs[idx + 1] \
                if idx + 1 < len(funcs) else tvaddr + trawsize
            size = min(nxt - begin, trawsize - (off - trawoff))
            if size <= 0:
                continue
            for ins in md.disasm(data[off:off + size], begin):
                if ins.mnemonic == "call" and ins.operands \
                        and ins.operands[0].type == x86.X86_OP_IMM:
                    tgt = ins.operands[0].imm
                    if tvaddr <= tgt < tvaddr + trawsize:
                        calls.setdefault(begin, set()).add(tgt)
    except Exception:
        return None

    entries = set()
    try:
        e_lfanew = _st.unpack_from("<I", data, 0x3C)[0]
        ep = _st.unpack_from("<I", data,
                             e_lfanew + 4 + 20 + 16)[0]
        if ep:
            entries.add(func_of(ep) or ep)
    except Exception:
        pass
    for exp in (b"SKSEPlugin_Query", b"SKSEPlugin_Load",
                b"SKSEPlugin_PreLoad"):
        try:
            rva = core.find_export_rva(data, secs, exp)
        except Exception:
            rva = None
        if rva is not None:
            entries.add(func_of(rva) or rva)

    seen, stack = set(), [e for e in entries if e is not None]
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        owner = func_of(cur)
        for dst in calls.get(owner if owner else cur, ()):
            if dst not in seen:
                stack.append(dst)

    return {s: (func_of(s) in seen) for s in spots}

def _shown_ids(uncovered, cap=8):
    """First cap IDs shown. Rest counted."""
    shown = list(uncovered[:cap])
    return shown, max(0, len(uncovered) - len(shown))

def _reach_tail(reach, spots):
    """Short reachability note for one address."""
    if not spots or not reach:
        return ""
    if any(reach.get(s, False) for s in spots):
        return " Reachable from load."
    return " Only runs when in use."

STOP_TOKENS = frozenset(
    "repos src include external build release microsoft windows skse "
    "commonlibsse commonlib dll exe http https www com github trunk "
    "trampoline logger interfaces impl std string vector interfaces "
    "address library plug plugin load query version info name "
    "error failed null true false void bool int char const static "
    "the and for with from that this".split())

def _words(text):
    import re as _re
    return {w for w in _re.findall(r"[A-Za-z]{4,}", text.lower())
            if w not in STOP_TOKENS}

def _mod_tokens(dll_path):
    """Distinctive words from the mod data."""
    try:
        with open(dll_path, "rb") as f:
            data = f.read()
    except OSError:
        return set()
    secs = core.find_pe_sections(data)
    if not secs:
        return set()
    import re as _re
    out = set()
    for name, _, _, rawoff, rawsize in secs:
        if name not in (".rdata", ".data"):
            continue
        blob = data[rawoff:rawoff + rawsize]
        for m in _re.finditer(rb"[ -~]{4,80}", blob):
            try:
                out |= _words(m.group(0).decode("ascii"))
            except UnicodeDecodeError:
                pass
    return out

def _func_strings(exe_data, secs, begin, end, cap=8):
    """ASCII strings referenced from one game function (sampled)."""
    import re as _re
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    off = core.rva_to_offset(begin, secs)
    if off is None:
        return []
    out = []
    try:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = False
        for ins in md.disasm(exe_data[off:off + (end - begin)], begin):
            m = _re.search(r"rip \+ 0x([0-9A-Fa-f]+)", ins.op_str)
            if not m:
                continue
            tgt = ins.address + ins.size + int(m.group(1), 16)
            toff = core.rva_to_offset(tgt, secs)
            if toff is None:
                continue
            m2 = _re.match(rb"[ -~]{4,60}\x00",
                           exe_data[toff:toff + 62])
            if m2:
                try:
                    out.append(m2.group(0)[:-1].decode("ascii"))
                except UnicodeDecodeError:
                    pass
                if len(out) >= cap:
                    break
    except Exception:
        pass
    return out

def _caller_counts(exe_data, secs):
    """{game rva: direct-call count} over .text. Slow: cache per run."""
    import struct as _st
    text = None
    for name, vaddr, _, rawoff, rawsize in secs:
        if name == ".text":
            text = (vaddr, rawoff, rawsize)
            break
    if text is None:
        return {}
    tvaddr, trawoff, trawsize = text
    out = {}
    try:
        i, end = trawoff, trawoff + trawsize - 5
        while i < end:
            if exe_data[i] == 0xE8:
                tgt = (i - trawoff + tvaddr) + 5 + _st.unpack_from(
                    "<i", exe_data, i + 1)[0]
                out[tgt] = out.get(tgt, 0) + 1
                i += 5
            else:
                i += 1
    except Exception:
        pass
    return out

def _rank_candidates(hook, candidates, base, exe_data, secs, mod_tokens,
                     caller_counts=None):
    """Rank hook sites by fit. Best first."""
    import struct as _st
    import bisect
    try:
        funcs = sorted(
            (b, e) for b, e in core.get_functions_from_pdata(
                exe_data, secs))
        starts = [b for b, _ in funcs]
    except Exception:
        return []
    def stem_hit(a, b, n=6):
        k = 0
        for x, y in zip(a, b):
            if x != y:
                break
            k += 1
        return k >= n

    ranked = []
    for cand in candidates:
        site = base + cand
        fo = core.rva_to_offset(site, secs)
        if fo is None or fo + 5 > len(exe_data):
            continue
        if exe_data[fo] != 0xE8:
            continue
        tgt = site + 5 + _st.unpack_from("<i", exe_data, fo + 1)[0]
        fi = bisect.bisect_right(starts, tgt) - 1
        if fi < 0:
            continue
        fb, fe = funcs[fi]
        if not fb <= tgt < fe:
            continue
        strs = _func_strings(exe_data, secs, fb, fe)
        ctoks = set()
        for s in strs:
            ctoks |= _words(s)
        shared = sorted(
            c for c in ctoks
            if any(stem_hit(c, m) for m in mod_tokens))
        if not shared:
            continue
        score, reasons = 2 * len(shared), []
        reasons.append(f"shares {', '.join(shared[:3])} with the mod")
        if 1 <= len(strs) <= 5:
            score += 1
            reasons.append("focused loader")
        if caller_counts is not None:
            n = caller_counts.get(tgt, 0)
            reasons.append(f"{n} caller(s) game-wide")
            if n <= 2:
                score += 1
        ranked.append((cand, score, reasons))
    ranked.sort(key=lambda r: (-r[1], r[0]))
    return ranked

def _hook_health(hooks, exe_data, exe_secs, current_lib, old_ctx=None):
    ok, stale, ambiguous, gone, missing = [], [], [], [], []
    cands = {}
    fixed = {}
    for h in hooks or []:
        rid = h.get("rel_id")
        off = h.get("offset")
        pat = h.get("pattern")
        if rid not in (current_lib or {}):
            missing.append(rid)
            continue
        base = current_lib[rid]
        try:
            if therapist.pattern_matches_at(exe_data, exe_secs, base, off, pat):
                ok.append(rid)
                continue
            matches = therapist.find_pattern_offsets(
                exe_data, exe_secs, base, pat, off)
        except Exception:
            gone.append(rid)
            continue
        if len(matches) == 1:
            stale.append(rid)
            fixed[rid] = (h, matches[0])
        elif len(matches) > 1:
            winner = None
            if old_ctx is not None:
                try:
                    status, payload = therapist.disambiguate_hook_by_callee(
                        h, exe_data, exe_secs, current_lib, *old_ctx,
                        candidates=matches)
                    if status == "resolved":
                        winner = payload
                except Exception:
                    winner = None
            if winner is not None:
                stale.append(rid)
                fixed[rid] = (h, winner)
            else:
                ambiguous.append(rid)
                cands[rid] = (h, base, matches)
        else:
            gone.append(rid)
    return {"ok": ok, "stale": stale, "ambiguous": ambiguous,
            "gone": gone, "missing": missing, "candidates": cands,
            "fixed": fixed}

def checkup_plugin(dll_path, exe_path, plugins_dir, old_exe_path=None,
                   extra_dirs=None, on_step=None, healer_scan=True):
    def step(text, frac):
        if on_step is not None:
            on_step(text, frac)

    dll_path = Path(dll_path)
    exe_path = Path(exe_path) if exe_path else None
    plugins_dir = Path(plugins_dir) if plugins_dir else dll_path.parent
    dirs = [plugins_dir] + list(extra_dirs or [])

    run_tup = _exe_tuple(exe_path) if exe_path else None
    packed = None
    if exe_path:
        try:
            packed = core.runtime_version_from_exe(exe_path)
        except Exception:
            packed = None
    step("Reading the mod...", 0.05)
    info = therapist.analyze_plugin(dll_path, packed)
    flag = info.get("flag")
    vi = info.get("version_indep")
    hooks = info.get("hooks", [])
    try:
        dt = core.pe_build_dt(dll_path)
        year = dt.year if dt else None
    except Exception:
        year = None

    legacy = False
    if flag is None and vi is None:
        try:
            with open(dll_path, "rb") as f:
                raw = f.read()
            secs = core.find_pe_sections(raw)
            legacy = secs and (
                core.find_export_rva(raw, secs, b"SKSEPlugin_Query")
                is not None
                or core.find_export_rva(raw, secs, b"SKSEPlugin_Load")
                is not None)
        except OSError:
            legacy = False
        if not legacy:
            return {"name": dll_path.name, "verdict": "UNKNOWN",
                    "title": "Not a Skyrim plugin",
                    "lines": ["No SKSE marker found. This file is probably "
                              "not a Skyrim mod, so there is nothing to fix."],
                    "action": "none",
                    "details": {"hooks": 0, "build_year": year}}

    step("Loading game data...", 0.15)
    exe_data = exe_secs = None
    if exe_path and Path(exe_path).is_file():
        try:
            exe_data, exe_secs = core.load_exe_sections(exe_path)
        except Exception:
            exe_data = None
    step("Loading address list...", 0.30)
    current_lib = None
    try:
        current_lib = healer.load_current_lib(
            plugins_dir, run_tup, extra_dirs=extra_dirs)
    except Exception:
        current_lib = None

    step("Checking old game file...", 0.40)
    old_ctx = None
    if old_exe_path and Path(old_exe_path).is_file():
        try:
            old_data, old_secs = core.load_exe_sections(old_exe_path)
            old_ver = _exe_tuple(old_exe_path)
            match = core.find_versionlib_in_dirs(dirs, old_ver) \
                if old_ver else None
            old_lib = core.parse_library_any(str(match)) \
                if match is not None else None
            if old_lib is not None:
                old_ctx = (old_data, old_secs, old_lib)
        except Exception:
            old_ctx = None

    step("Mapping addresses...", 0.55)
    callers = None
    try:
        callers = _xref_callers(dll_path)
    except Exception:
        callers = None
    if callers is None:
        try:
            xref = therapist.collect_xref_ids(dll_path)
        except Exception:
            xref = None
        callers = {}
    else:
        xref = set(callers)
    ever = _ever_ids(dirs)
    cur_ids = set(current_lib or {})
    removed = sorted(v for v in (xref or set())
                     if v != 0 and v not in cur_ids and v in ever)
    covered = _translated_ids(plugins_dir, run_tup)
    uncovered = sorted(v for v in removed
                       if v >= 1000 and v not in covered)

    step("Checking hooks...", 0.75)
    health = {"ok": [], "stale": [], "ambiguous": [],
              "gone": [], "missing": [], "candidates": {}, "fixed": {}}
    if exe_data and current_lib:
        health = _hook_health(hooks, exe_data, exe_secs,
                              current_lib, old_ctx)

    step("Checking stale offsets...", 0.80)
    healer_fixes = []
    if exe_path is not None and healer_scan:
        try:
            findings, _, _, _ = healer.analyze_pattern_drift(
                dll_path, exe_path, plugins_dir, old_exe_path,
                extra_dirs=extra_dirs)
            healer_fixes = [f for f in findings if f.get("auto_fixable")]
        except Exception:
            healer_fixes = []

    step("Checking version gates...", 0.85)
    gates = None
    try:
        gates = therapist.find_version_gates(dll_path)
    except Exception:
        gates = None

    declared = core.unpack_version(vi.get("runtime_ver")) \
        if vi and vi.get("runtime_ver") else None
    crossed = core.crossed_cutoffs(declared, run_tup) \
        if (declared and run_tup) else []
    has_addr = bool(vi and vi.get("has_addr", False))
    has_sigs = bool(vi and vi.get("has_sigs", False))
    needs_patch = bool(
        (flag is not None and flag.get("needs_patch", False))
        or (vi is not None and vi.get("needs_indep", False)))

    step("Writing the verdict...", 0.95)
    lines = []
    if legacy:
        lines.append("Old-style mod with no version marker.")
    if year:
        lines.append(f"Built around {year}.")
    if current_lib is None:
        lines.append("No address list found for your game, "
                     "so lookups could not be verified.")
    if xref is not None:
        lines.append(f"Uses {len(xref)} game address(es).")
    if covered and any(v in covered for v in removed):
        n = sum(1 for v in removed if v in covered)
        lines.append(f"{n} outdated address(es) are covered by the "
                     "CompaSSE translation data.")
    grade, block = _grade_uncovered(uncovered, len(xref or ()))
    id_lines = []
    if grade == "stray":
        shown = ", ".join(str(v) for v in uncovered[:3])
        id_lines.append(f"{len(uncovered)} address(es) are gone "
                        f"({shown}) - risky, but might be harmless "
                        "if the mod never calls them.")
    elif grade == "gutted":
        n, m = len(uncovered), len(xref or ())
        id_lines.append(f"{n} of its {m} game addresses are gone, "
                        f" most in one removed block "
                        f"({block[0]}-{block[1]}). That part of the game "
                        "no longer exists - its features will crash.")
    hook_ids = {h.get("rel_id") for h in hooks or []}
    old_lib = old_ctx[2] if old_ctx else None
    shown_ids, hidden_n = _shown_ids(uncovered)
    shown = [d for d in shown_ids if callers.get(d)]
    try:
        reach = _startup_reachable(
            dll_path, [s for d in shown for s in callers[d]])
    except Exception:
        reach = None
    if reach is None:
        reach = {}
    try:
        checked = _checked_use(
            dll_path, [s for d in shown for s in callers[d]])
    except Exception:
        checked = None
    if checked is None:
        checked = {}
    for dead in shown_ids:
        spots = callers.get(dead, [])
        if dead in hook_ids:
            role = "calls into"
        elif spots:
            role = "reads"
        else:
            role = "may use"
        what = "game code"
        if old_lib is not None and dead in old_lib and old_ctx:
            kind, _ = _game_kind(old_ctx[0], old_ctx[1], old_lib[dead])
            if kind == "function":
                what = "game function"
            elif kind == "data":
                what = "game data"
        tail = _reach_tail(reach, spots)
        votes = [checked[s] for s in spots if s in checked]
        if votes and all(votes):
            tail += " It checks what it gets back."
        elif votes and not any(votes):
            tail += " It uses it without checking first."
        if spots:
            id_lines.append(f"Address {dead} is {what} the mod {role} "
                            f"in {len(spots)} spot(s), first at "
                            f"+0x{spots[0]:X}." + tail)
        else:
            id_lines.append(f"Address {dead} is {what} the mod {role}.")
    if uncovered and old_ctx is None:
        id_lines.append("Point at the old game file for what-kind details "
                        "(function or data) on these.")
    if hidden_n:
        id_lines.append(f"...and {hidden_n} more.")
    amputate = []
    unchecked = [s for d in shown_ids for s in callers.get(d, [])
                 if checked.get(s) is False]
    if unchecked:
        try:
            sinks = _null_sink(dll_path, unchecked) or {}
        except Exception:
            sinks = {}
        seen_ids = set()
        for dead in shown_ids:
            for s in callers.get(dead, []):
                if s in sinks and dead not in seen_ids:
                    seen_ids.add(dead)
                    amputate.append({"id": dead, "spot": s,
                                     "call": sinks[s]})
                    id_lines.append(
                        f"Address {dead} can be forced to its null "
                        f"path (call at +0x{sinks[s]:X}).")
                    break
    n_ok = len(health["ok"])
    n_stale = len(health["stale"])
    if hooks:
        lines.append(f"Checked {len(hooks)} game hook(s): {n_ok} fine, "
                     f"{n_stale} moved, {len(health['ambiguous'])} unclear, "
                     f"{len(health['gone'] + health['missing'])} gone.")
    ranked = {}
    cands = health.get("candidates") or {}
    if isinstance(cands, dict) and cands and exe_data and current_lib:
        try:
            toks = _mod_tokens(dll_path)
            callers = _caller_counts(exe_data, exe_secs)
        except Exception:
            toks, callers = set(), {}
        for rid, (h, base, matches) in cands.items():
            try:
                ranked[rid] = _rank_candidates(
                    h, matches, base, exe_data, exe_secs, toks, callers)
            except Exception:
                ranked[rid] = []
    for rid, order in ranked.items():
        if not order:
            continue
        top, score, reasons = order[0]
        lines.append(f"Hook {rid} leans to +0x{top:X} "
                     f"({'; '.join(reasons)}).")
    if gates:
        lines.append("Has its own game-version check, so it may refuse "
                     "to start on your game.")
    if crossed:
        names = ", ".join(f"{a}.{b}.{c}" for a, b, c in crossed)
        lines.append(f"Built before game change(s) {names}: saved data "
                     "shapes may differ even if it loads.")
    if _skse_disabled(dll_path.name):
        lines.append("SKSE gave up on it while loading in a past run.")
    past_crash = _crashlogger_hit(dll_path.name)
    if past_crash:
        lines.append(f"Named as the crashing mod in a game crash report "
                     f"({past_crash}).")

    crash = _last_run_crash(dll_path.name, plugins_dir)
    if crash:
        return {"name": dll_path.name, "verdict": "BROKEN",
                "title": "Crashed while starting",
                "lines": [_crash_line(crash) + " The loader contained "
                          "it, so your game is safe - but this mod "
                          "cannot run on your setup. Turn it off to "
                          "play, then ask the author for an update."],
                "action": "turn_off",
                "details": {"hooks": len(hooks), "build_year": year,
                            "crash_stage": crash.get("stage"),
                            "needs_patch": needs_patch}}
    loaded_ok = bool(_last_run_loaded(dll_path.name))
    has_alarms = grade != "ok" or uncovered or health["gone"] \
        or health["missing"] or health["ambiguous"] or health["stale"] \
        or gates or crossed or needs_patch or current_lib is None
    if loaded_ok and has_alarms:
        lines = ["SKSE loaded it in your last game run, so it starts. "
                 "What follows may still be wrong."] + lines
    elif loaded_ok:
        lines = ["SKSE loaded it fine in your last game run."] + lines
    lines.extend(id_lines)
    if grade == "gutted" or health["gone"] or health["missing"]:
        verdict, title, action = ("BROKEN", "Needs the mod author",
                                  "turn_off")
    elif not legacy and not has_addr and not has_sigs \
            and (year or 0) < 2025:
        verdict, title, action = ("BROKEN", "Needs the mod author",
                                  "turn_off")
    elif health["stale"]:
        verdict, title, action = ("FIXABLE", "Fixable: outdated addresses",
                                  "fix")
    elif needs_patch and (healer_fixes or health.get("fixed")
                          or amputate
                          or (old_ctx is not None and uncovered)):
        verdict, title, action = ("FIXABLE", "Fixable: outdated addresses",
                                  "fix")
    elif needs_patch:
        lines.append("Version flags are outdated - press Fix in the "
                     "Therapist tab. This tab cannot patch flags.")
        verdict, title, action = ("RISKY", "Fix the flags in Therapist",
                                  "to_therapist")
    elif health["ambiguous"] or gates or crossed or uncovered:
        verdict, title, action = ("RISKY", "Might work, test in game",
                                  "try_first")
    elif current_lib is None:
        verdict, title, action = ("RISKY", "Might work, test in game",
                                  "try_first")
    else:
        verdict, title, action = ("HEALTHY", "Looks healthy", "none")

    verdict, title, action = _cap_loaded(verdict, title, action,
                                         loaded_ok)

    details = {"hooks": len(hooks), "hooks_ok": n_ok,
               "hooks_stale": n_stale,
               "hooks_ambiguous": len(health["ambiguous"]),
               "hooks_gone": len(health["gone"] + health["missing"]),
                "xref": len(xref) if xref is not None else None,
                "removed": removed[:10], "uncovered": uncovered[:10],
               "uncovered_all": uncovered,
                "gates": len(gates or []),
               "crossed": crossed, "build_year": year,
               "needs_patch": needs_patch,
               "ranked": {r: [(o, s) for o, s, _ in v]
                          for r, v in ranked.items()},
               "rank_hooks": {r: health["candidates"][r][0]
                              for r in ranked
                              if r in (health.get("candidates")
                                       or {})},
               "hook_fixes": {r: {"hook": h, "new": n}
                              for r, (h, n) in
                              health.get("fixed", {}).items()},
               "hook_options": {r: {"hook": h, "matches": m}
                                for r, (h, _, m) in
                                health.get("candidates", {}).items()},
               "healer_fixes": healer_fixes,
               "amputate": amputate}
    return {"name": dll_path.name, "verdict": verdict, "title": title,
            "lines": lines, "action": action, "details": details}

def _cap_loaded(verdict, title, action, loaded_ok):
    """A loaded mod is never BROKEN. Cap at RISKY."""
    if loaded_ok and verdict == "BROKEN":
        return ("RISKY", "Loads, but shaky", "try_first")
    return verdict, title, action

def mint_touched(dll_path, plugins_dir, old_exe_path, game_exe,
                 extra_dirs=None, only_ids=None):
    """Mint translation rows for dead addresses."""
    from pathlib import Path as _P
    dll_path, plugins_dir = _P(dll_path), _P(plugins_dir)
    try:
        old_data, old_secs = core.load_exe_sections(old_exe_path)
        new_data, new_secs = core.load_exe_sections(game_exe)
    except Exception as exc:
        return {"minted": [], "gone": 0, "ambiguous": [],
                "error": f"cannot read exe: {exc}"}
    try:
        old_ver = _exe_tuple(old_exe_path)
        new_ver = _exe_tuple(game_exe)
        dirs = [plugins_dir] + list(extra_dirs or [])
        old_match = core.find_versionlib_in_dirs(dirs, old_ver) \
            if old_ver else None
        new_match = core.find_versionlib_in_dirs(dirs, new_ver) \
            if new_ver else None
        old_lib = core.parse_library_any(str(old_match)) \
            if old_match is not None else None
        new_lib = core.parse_library_any(str(new_match)) \
            if new_match is not None else None
    except Exception as exc:
        return {"minted": [], "gone": 0, "ambiguous": [],
                "error": f"cannot read libs: {exc}"}
    if not old_lib or not new_lib:
        return {"minted": [], "gone": 0, "ambiguous": [],
                "error": "need an old and a current address list"}
    if only_ids is not None:
        keep = set(only_ids)
        old_lib = {i: o for i, o in old_lib.items() if i in keep}
    gone, ambiguous, entries = 0, [], []
    try:
        entries, gone, ambiguous = core.mint_missing_translations(
            old_data, old_secs, old_lib, new_data, new_secs, new_lib)
    except Exception as exc:
        return {"minted": [], "gone": gone, "ambiguous": ambiguous,
                "error": f"mint failed: {exc}"}
    if not entries:
        return {"minted": [], "gone": gone, "ambiguous": ambiguous,
                "error": None}
    ver = f"{old_ver[0]}.{old_ver[1]}.{old_ver[2]}" if old_ver else "old"
    try:
        dropped, _ = core.merge_translation_block(
            plugins_dir, ver, entries)
    except Exception as exc:
        return {"minted": [], "gone": gone, "ambiguous": ambiguous,
                "error": f"merge failed: {exc}"}
    return {"minted": entries, "gone": gone, "ambiguous": ambiguous,
            "dropped": dropped, "error": None}

def _decisive_rank(order):
    """Top-ranked offset when the gap is decisive, else None.

    order: [(off, score, reasons)] best-first. Single scored entries
    need real evidence behind them; a crowd needs a clear winner.
    """
    if not order:
        return None
    top, score, _ = order[0]
    if score < 4:
        return None
    if len(order) == 1:
        return top
    if score - order[1][1] >= 3:
        return top
    return None

def plan_fixes(rep, has_old_exe=False, skip_ids=()):
    """Fix items for a check-up report. Pure.

    Each item: {id, kind, label, ...}. Kinds: hook-unique (one clear
    target), hook-ranked (ranked top with a decisive lead), hook-pick
    (choose one), healer (stale offset), mint (needs the old game),
    flags (Therapist's job, info only).
    """
    det = (rep or {}).get("details", {})
    items = []
    for rid, f in (det.get("hook_fixes") or {}).items():
        items.append({"id": f"hook-{rid}", "kind": "hook-unique",
                      "label": f"Hook {rid}: offset "
                               f"{hex(f['hook']['offset'])} -> "
                               f"{hex(f['new'])}",
                      "hook": f["hook"], "new": f["new"]})
    ranked = det.get("ranked", {})
    for rid, order in ranked.items():
        if rid in (det.get("hook_fixes") or {}):
            continue
        picked = _decisive_rank(
            [(o, s, []) for o, s in order]) if order else None
        if picked is None:
            continue
        hooks = det.get("rank_hooks", {})
        if rid not in hooks:
            continue
        items.append({"id": f"rank-{rid}", "kind": "hook-ranked",
                      "label": f"Hook {rid}: likely "
                               f"{hex(hooks[rid]['offset'])} -> "
                               f"{hex(picked)}",
                      "hook": hooks[rid], "new": picked})
    for rid, o in (det.get("hook_options") or {}).items():
        if rid in (det.get("hook_fixes") or {}):
            continue
        if any(i["id"] == f"rank-{rid}" for i in items):
            continue
        sug = None
        for off, _ in (det.get("ranked", {}).get(rid, []))[:1]:
            sug = off
        items.append({"id": f"pick-{rid}", "kind": "hook-pick",
                      "label": f"Hook {rid}: pick the moved offset",
                      "hook": o["hook"], "matches": o["matches"],
                      "selected": sug})
    for f in det.get("healer_fixes", []):
        items.append({"id": f"heal-{f.get('code_offset', id(f))}",
                      "kind": "healer",
                      "label": f"Stale offset "
                               f"{hex(f.get('old_offset', 0))} -> "
                               f"{hex(f.get('new_offset', 0))} "
                               f"(ID {f.get('id_val', '?')})",
                      "finding": f})
    for a in det.get("amputate", []):
        items.append({"id": f"amp-{a['id']}-{a['call']:X}",
                      "kind": "amputate",
                      "label": f"Force null path for address {a['id']} "
                               f"(call at +0x{a['call']:X})",
                      "call": a["call"]})
    if det.get("needs_patch"):
        items.append({"id": "flags", "kind": "flags",
                      "label": "Version flags need the Therapist tab"})
    skipped = set(skip_ids or ())
    all_dead = [v for v in
                (det.get("uncovered_all") or det.get("uncovered") or [])
                if v not in skipped]
    if has_old_exe and all_dead:
        items.append({"id": "mint", "kind": "mint",
                      "label": f"Mint translations for {len(all_dead)} "
                               "dead address(es)",
                      "ids": list(all_dead)})
    return items

def apply_plan(dll_path, plugins_dir, game_exe, extra_dirs, old_exe_path,
               items):
    """Apply chosen fix items. Returns (messages, info).

    info["mint_empty"]: ids a mint run could not mint - offering them
    again is a loop, so callers remember them.
    """
    msgs = []
    info = {"mint_empty": []}

    def _touch(ok):
        if ok:
            try:
                core.add_touched(plugins_dir, dll_path)
            except Exception:
                try:
                    core.add_touched(Path(dll_path).parent, dll_path)
                except Exception:
                    pass
        return ok

    for it in items:
        kind = it.get("kind")
        try:
            if kind in ("hook-unique", "hook-ranked"):
                ok = _touch(therapist.patch_hook_offset(
                    dll_path, it["hook"], it["new"]))
                msgs.append(f"{it['label']}: "
                            f"{'fixed' if ok else 'failed'}")
            elif kind == "hook-pick":
                sel = it.get("selected")
                if sel is None:
                    msgs.append(f"{it['label']}: skipped (no pick)")
                elif _touch(therapist.patch_hook_offset(
                        dll_path, it["hook"], sel)):
                    msgs.append(f"Hook fixed at {hex(sel)}.")
                else:
                    msgs.append("Hook fix failed.")
            elif kind == "healer":
                ok = _touch(healer.heal_plugin(Path(dll_path), it["finding"]))
                msgs.append(f"{it['label']}: "
                            f"{'fixed' if ok else 'failed'}")
            elif kind == "bytes":
                b = it.get("bytes", {})
                ok = _touch(therapist.patch_bytes_guarded(
                    dll_path, b.get("loc_kind"), b.get("loc", -1),
                    b.get("width"), b.get("old", -1), b.get("new", -1),
                    bool(b.get("insn_check"))))
                msgs.append(f"{it['label']}: "
                            f"{'fixed' if ok else 'failed'}")
            elif kind == "amputate":
                ok = _touch(amputate_call(dll_path, it["call"]))
                msgs.append(f"{it['label']}: "
                            f"{'fixed' if ok else 'failed'}")
            elif kind == "mint":
                res = mint_touched(dll_path, plugins_dir, old_exe_path,
                                   game_exe, extra_dirs=extra_dirs,
                                   only_ids=it.get("ids"))
                if res.get("error"):
                    msgs.append(f"Mint failed: {res['error']}")
                elif res["minted"]:
                    msgs.append(f"Minted {len(res['minted'])} "
                                "translation(s). Relaunch to apply.")
                else:
                    msgs.append("Nothing mintable - those functions "
                                "are gone, not moved.")
                    info["mint_empty"].extend(it.get("ids") or [])
        except Exception as exc:
            msgs.append(f"{it.get('label', '?')}: error {exc}")
    return msgs, info

# ---------------------------------------------------------------------------
# Recipes: precomputed, shareable fixes for known mods
#
# One file per mod: {"format": 1, "name": ..., "variants": {clean_sha:
# {game, sha256_patched, label, items}}}. Lookup is hash-first: the
# file's bytes pick the variant, no filename/size/clock matching.
# ---------------------------------------------------------------------------
def _rec_variant(rec):
    v = (rec or {}).get("_variant")
    return v if isinstance(v, dict) else None

def _rec_items(rec):
    v = _rec_variant(rec)
    if v is not None:
        items = v.get("items")
        return items if isinstance(items, list) else []
    return []

def recipe_label(rec):
    v = _rec_variant(rec)
    if v is not None and v.get("label"):
        return v["label"]
    return "Known fix"

def recipes_dirs(plugins_dir=None):
    """User-editable recipe folders: game dir first, repo copy for dev."""
    dirs = []
    if plugins_dir:
        try:
            dirs.append(Path(plugins_dir) / "CompaSSE" / "recipes")
        except Exception:
            pass
    try:
        repo = Path(__file__).resolve().parent.parent / "recipes"
        if repo not in dirs:
            dirs.append(repo)
    except Exception:
        pass
    return dirs

def load_recipes(dirs=None):
    """All valid recipe files found. Bad files are skipped, never fatal."""
    out = []
    for d in dirs or []:
        try:
            files = sorted(Path(d).glob("*.json"))
        except OSError:
            continue
        for f in files:
            try:
                rec = json.loads(f.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(rec, dict):
                continue
            if rec.get("format") != RECIPE_FORMAT:
                continue
            variants = rec.get("variants")
            if not isinstance(variants, dict):
                continue
            good = False
            for v in variants.values():
                if isinstance(v, dict) and v.get("game") \
                        and isinstance(v.get("items"), list):
                    good = True
                    break
            if not good:
                continue
            rec["_path"] = str(f)
            out.append(rec)
    return out

def _sha256_file(path):
    try:
        import hashlib as _hl
        h = _hl.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def recipe_hash_state(dll_path, recipe):
    """clean, modified, or unknown for one file vs a recipe.

    Clean means these exact bytes. Anything else with a stashed
    variant falls back to per-item reads; without one it is unknown.
    """
    v = _rec_variant(recipe)
    if v is None:
        return "unknown"
    try:
        got = _sha256_file(dll_path)
    except Exception:
        got = None
    if got is None:
        return "unknown"
    if got == (recipe or {}).get("_variant_hash"):
        return "clean"
    if isinstance(v, dict) and v.get("sha256_patched") \
            and got == v["sha256_patched"]:
        return "patched"
    return "modified"

def match_recipe(dll_path, game_ver, recipes):
    """First recipe with a variant for these bytes + game, else None.

    Stashes the winning variant on the recipe for status/apply.
    """
    try:
        got = _sha256_file(dll_path)
    except Exception:
        got = None
    if got is None:
        return None
    for rec in recipes or []:
        if not isinstance(rec, dict):
            continue
        variants = rec.get("variants") or {}
        if not isinstance(variants, dict):
            continue
        v = variants.get(got)
        if isinstance(v, dict) and v.get("game") == game_ver:
            rec["_variant"] = v
            rec["_variant_hash"] = got
            return rec
        for clean, v in variants.items():
            if not isinstance(v, dict):
                continue
            if v.get("game") != game_ver:
                continue
            if v.get("sha256_patched") and got == v["sha256_patched"]:
                rec["_variant"] = v
                rec["_variant_hash"] = clean
                return rec
    return None

def plan_item_to_recipe_item(it, picked=False):
    """Plan item -> recipe item, or None when not recordable.

    hook-pick records only an explicitly picked candidate: a suggested
    default is a guess, never a verified fix. amputate/mint are live or
    machine-local actions, not shareable bytes. flags always records.
    """
    kind = (it or {}).get("kind")
    if kind in ("hook-unique", "hook-ranked"):
        hook = dict(it["hook"])
        hook["pattern"] = {str(k): v
                           for k, v in (hook.get("pattern") or {}).items()}
        return ({"kind": "hook", "hook": hook,
                 "new": it["new"], "rel_id": hook.get("rel_id")})
    if kind == "hook-pick":
        if it.get("selected") is None or not picked:
            return None
        hook = dict(it["hook"])
        hook["pattern"] = {str(k): v
                           for k, v in (hook.get("pattern") or {}).items()}
        return ({"kind": "hook", "hook": hook,
                 "new": it["selected"], "rel_id": hook.get("rel_id")})
    if kind == "healer":
        f = it["finding"]
        if f.get("kind") == "lea" or "hook" in f:
            return None
        return ({"kind": "healer",
                 "finding": {"kind": f.get("kind"),
                             "code_offset": f.get("code_offset"),
                             "old_offset": f.get("old_offset"),
                             "new_offset": f.get("new_offset"),
                             "id_val": f.get("id_val")}})
    if kind == "bytes":
        b = it.get("bytes", {}) if isinstance(it.get("bytes"), dict) \
            else it.get("finding", {})
        fields = _bytes_item_fields({"loc_kind": b.get("loc_kind"),
                                     "loc": b.get("loc"),
                                     "width": b.get("width"),
                                     "old": b.get("old"),
                                     "new": b.get("new"),
                                     "insn_check": b.get("insn_check")})
        if fields is None:
            return None
        loc_kind, loc, width, old, new, check = fields
        return ({"kind": "bytes", "loc_kind": loc_kind, "loc": loc,
                 "width": width, "old": old, "new": new,
                 "insn_check": check,
                 "label": str(it.get("label", "byte patch"))[:160]})
    if kind == "flags":
        return {"kind": "flags"}
    return None

def _store_variant(out_dir, dll_stem, clean_hash, variant):
    """Merge one variant into the mod's recipe file. Returns the path."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    dest = out / f"{dll_stem}.json"
    rec = None
    if dest.is_file():
        try:
            rec = json.loads(dest.read_text(encoding="utf-8"))
        except Exception:
            rec = None
        if not isinstance(rec, dict) \
                or rec.get("format") != RECIPE_FORMAT \
                or not isinstance(rec.get("variants"), dict):
            raise ValueError(f"refusing to overwrite foreign file: {dest}")
    if rec is None:
        rec = {"format": RECIPE_FORMAT, "variants": {}}
    rec["variants"][clean_hash] = variant
    dest.write_text(json.dumps(rec, indent=2), encoding="utf-8")
    return dest

def record_recipe(dll_path, exe_path, plugins_dir, old_exe_path,
                  game_ver, out_dir, kinds=("hook-unique", "hook-ranked",
                                            "healer", "flags")):
    """Freeze today's plan into a shareable recipe file (slow path).

    Re-scans the mod; prefer record_applied after a tested fix.
    Plan-time hook picks are never recorded (unverified guesses).
    """
    rep = checkup_plugin(dll_path, exe_path, plugins_dir, old_exe_path)
    det = rep.get("details", {})
    items = []
    for it in plan_fixes(rep, has_old_exe=bool(old_exe_path)):
        if it.get("kind") not in kinds:
            continue
        conv = plan_item_to_recipe_item(it, picked=False)
        if conv is not None:
            items.append(conv)
    if "flags" in kinds and det.get("needs_patch") and \
            not any(i.get("kind") == "flags" for i in items):
        items.append({"kind": "flags"})
    if not items:
        raise ValueError("nothing recordable for this mod")
    clean = _sha256_file(dll_path)
    if not clean:
        raise ValueError("cannot read mod bytes")
    variant = {"game": game_ver,
               "label": rep.get("title", "Known fix"), "items": items}
    return _store_variant(out_dir, Path(dll_path).stem, clean, variant)

def record_applied(dll_stem, clean_hash, recipe_items, game_ver, out_dir,
                   label="Known fix", patched_hash=None):
    """Freeze already-applied fixes into a recipe file. No rescan.

    clean_hash identifies the unmodified mod, recipe_items are
    plan_item_to_recipe_item output, patched_hash (when the result was
    verified byte-identical) unlocks already-fixed matching later.
    Returns the written path.
    """
    items = [it for it in (recipe_items or []) if isinstance(it, dict)]
    if not items:
        raise ValueError("nothing recordable for this mod")
    variant = {"game": game_ver, "label": label, "items": items}
    if patched_hash:
        variant["sha256_patched"] = patched_hash
    return _store_variant(out_dir, dll_stem, clean_hash, variant)

def verify_recipe_variant(clean_bytes, fixed_bytes, variant):
    """True when applying the variant to clean bytes yields fixed bytes.

    Runs entirely on temp copies; game files are never touched. Returns
    (ok, detail) where detail names the first mismatch or counts steps.
    """
    import shutil as _sh
    import tempfile as _tf
    import hashlib as _hl
    items = (variant or {}).get("items") or []
    if not items or not clean_bytes or not fixed_bytes:
        return (False, "nothing to verify")
    clean_hash = _hl.sha256(bytes(clean_bytes)).hexdigest()
    tmpdir = Path(_tf.mkdtemp(prefix="recipe_verify_"))
    try:
        probe = tmpdir / "probe.dll"
        probe.write_bytes(bytes(clean_bytes))
        rec = {"format": RECIPE_FORMAT,
               "variants": {clean_hash: dict(variant or {})},
               "_variant": dict(variant or {}),
               "_variant_hash": clean_hash}
        msgs, _info = apply_recipe(probe, rec, plugins_dir=tmpdir)
        got = probe.read_bytes()
    except Exception as exc:
        return (False, f"verify failed: {exc}")
    finally:
        _sh.rmtree(tmpdir, ignore_errors=True)
    if got == bytes(fixed_bytes):
        return (True, f"{len(items)} step(s) reproduce the fix")
    return (False, "recipe output differs from the fixed mod")

def apply_recipe(dll_path, recipe, plugins_dir=None, game_exe=None,
                 extra_dirs=None, old_exe_path=None):
    """Apply a recipe with per-item verification. Returns (msgs, info).

    Hook items reuse the patch primitive's own guards (instruction
    bytes + current value). Healer items pre-check the recorded old
    value first. Anything mismatched is skipped, never forced.
    """
    dll_path = Path(dll_path)
    msgs, info = [], {"mint_empty": []}
    plan_items = []
    for it, state in recipe_status(dll_path, recipe):
        kind = it.get("kind")
        if state == "done":
            msgs.append(f"{_recipe_step_label(it)}: already applied")
            continue
        if state == "skipped":
            msgs.append(f"{_recipe_step_label(it)}: mod changed, "
                        "skipped")
            continue
        if kind == "flags":
            try:
                did = False
                if therapist.patch_flag(dll_path):
                    did = True
                if therapist.patch_version_independence(dll_path):
                    did = True
                msgs.append("Startup flags: "
                            f"{'fixed' if did else 'already fine'}")
            except Exception as exc:
                msgs.append(f"Startup flags: error {exc}")
        elif kind == "hook":
            hook = dict(it.get("hook", {}))
            try:
                hook["pattern"] = {int(k): v
                                   for k, v in hook.get("pattern", {}).items()}
            except Exception:
                msgs.append(f"Hook {it.get('rel_id')}: bad recipe data, "
                            "skipped")
                continue
            plan_items.append({"id": f"hook-{it.get('rel_id')}",
                               "kind": "hook-unique",
                               "label": f"Hook {it.get('rel_id')}: offset "
                                        f"{hex(hook.get('offset', 0))} -> "
                                        f"{hex(it.get('new', 0))}",
                               "hook": hook, "new": it.get("new")})
        elif kind == "healer":
            f = dict(it.get("finding", {}))
            plan_items.append({"id": f"heal-{f.get('code_offset')}",
                               "kind": "healer",
                               "label": f"Stale offset "
                                        f"{hex(f.get('old_offset', 0))} -> "
                                        f"{hex(f.get('new_offset', 0))}",
                               "finding": f})
        elif kind == "bytes":
            fields = _bytes_item_fields(it)
            if fields is None:
                msgs.append("Byte patch: bad recipe data, skipped")
                continue
            loc_kind, loc, width, old, new, check = fields
            plan_items.append({"id": f"bytes-{loc_kind}-{loc}",
                               "kind": "bytes",
                               "label": f"Byte patch at {hex(loc)}: "
                                        f"{hex(old)} -> {hex(new)}",
                               "bytes": {"loc_kind": loc_kind, "loc": loc,
                                         "width": width, "old": old,
                                         "new": new, "insn_check": check}})
        else:
            msgs.append(f"Unknown recipe step "
                        f"'{kind}', skipped")
    if plan_items:
        m2, i2 = apply_plan(dll_path, plugins_dir, game_exe, extra_dirs,
                            old_exe_path, plan_items)
        msgs.extend(m2)
        info["mint_empty"].extend(i2.get("mint_empty", []))
    return msgs, info

def _recipe_step_label(it):
    kind = (it or {}).get("kind")
    if kind == "flags":
        return "Startup flags"
    if kind == "hook":
        return f"Hook {it.get('rel_id')}"
    if kind == "healer":
        return (f"Stale offset "
                f"{hex((it.get('finding') or {}).get('old_offset', 0))}")
    if kind == "bytes":
        return f"Byte patch at {hex(it.get('loc', 0))}"
    return f"Step '{kind}'"

def _hook_cur(dll_path, hook):
    """Current displacement at a hook site, or None when unreadable."""
    try:
        data = Path(dll_path).read_bytes()
        secs = core.find_pe_sections(data)
        text = None
        for name, va, vsz, raw, rsz in secs:
            if name == ".text":
                text = (va, raw)
                break
        if text is None:
            return None
        off = text[1] + (hook["va"] - text[0])
        if off + 7 > len(data):
            return None
        if bytes(data[off:off + 3]) != b"\x48\x8D\x98":
            return None
        import struct as _st
        return _st.unpack_from("<I", data, off + 3)[0]
    except Exception:
        return None

def recipe_status(dll_path, recipe):
    """Per-item state without writing: pending, done, or skipped.

    Pending means the recorded old value is still in place. Done
    means the new value is already there. Anything else is a changed
    binary the recipe no longer fits.
    """
    dll_path = Path(dll_path)
    items = _rec_items(recipe)
    try:
        hashed = recipe_hash_state(dll_path, recipe)
    except Exception:
        hashed = "unknown"
    if hashed == "clean":
        return [(it, "pending") for it in items]
    if hashed == "patched":
        return [(it, "done") for it in items]
    states = []
    for it in items:
        kind = it.get("kind")
        if kind == "flags":
            try:
                vi = therapist.check_version_independence(dll_path, None)
            except Exception:
                vi = None
            if vi is None:
                states.append((it, "skipped"))
            elif vi.get("needs_indep") or not vi.get("has_ex_v5"):
                states.append((it, "pending"))
            else:
                states.append((it, "done"))
        elif kind == "hook":
            hook = it.get("hook", {})
            cur = _hook_cur(dll_path, hook)
            if cur is None:
                states.append((it, "skipped"))
            elif cur == hook.get("offset"):
                states.append((it, "pending"))
            elif cur == it.get("new"):
                states.append((it, "done"))
            else:
                states.append((it, "skipped"))
        elif kind == "healer":
            f = it.get("finding", {})
            if f.get("kind") == "lea" or "hook" in f:
                states.append((it, "skipped"))
            elif _recipe_healer_precheck(dll_path, f):
                states.append((it, "pending"))
            else:
                states.append((it, "done" if _recipe_healer_is_new(
                    dll_path, f) else "skipped"))
        elif kind == "bytes":
            states.append((it, _bytes_state(dll_path, it)))
        else:
            states.append((it, "skipped"))
    return states

def _bytes_item_fields(it):
    """(loc_kind, loc, width, old, new, insn_check) or None when malformed."""
    try:
        loc_kind = it.get("loc_kind")
        loc = int(it.get("loc", -1))
        width = it.get("width")
        width = None if width is None else int(width)
        old = int(it.get("old", -1))
        new = int(it.get("new", -1))
    except (TypeError, ValueError):
        return None
    if loc_kind not in ("file", "rva") or loc < 0 or old < 0 or new < 0:
        return None
    if width is not None and width not in (1, 4):
        return None
    return (loc_kind, loc, width, old, new, bool(it.get("insn_check")))

def _bytes_state(dll_path, it):
    """pending/done/skipped for one exact-binary byte replacement."""
    fields = _bytes_item_fields(it)
    if fields is None:
        return "skipped"
    loc_kind, loc, width, old, new, check = fields
    try:
        _off, _w, cur = therapist.resolve_bytes_site(
            dll_path, loc_kind, loc, width, check)
    except Exception:
        return "skipped"
    if cur is None:
        return "skipped"
    if cur == old:
        return "pending"
    if cur == new:
        return "done"
    return "skipped"

def _recipe_healer_is_new(dll_path, finding):
    try:
        import struct as _st
        data = Path(dll_path).read_bytes()
        secs = core.find_pe_sections(data)
        text = None
        for name, va, vsz, raw, rsz in secs:
            if name == ".text":
                text = (va, raw)
                break
        if text is None:
            return False
        off = text[1] + finding["code_offset"] + 1
        return _st.unpack_from("<I", data, off)[0] == finding["new_offset"]
    except Exception:
        return False

def _recipe_healer_precheck(dll_path, finding):
    """True when the recorded old value is still in place."""
    try:
        import struct as _st
        data = Path(dll_path).read_bytes()
        secs = core.find_pe_sections(data)
        text = None
        for name, va, vsz, raw, rsz in secs:
            if name == ".text":
                text = (va, raw)
                break
        if text is None:
            return False
        off = text[1] + finding["code_offset"] + 1
        cur = _st.unpack_from("<I", data, off)[0]
        return cur == finding["old_offset"]
    except Exception:
        return False

def _bundled_jig():
    """jig_host.exe shipped inside the frozen app, or None."""
    try:
        import sys as _sys
        base = getattr(_sys, "_MEIPASS", None)
        if not base:
            return None
        cand = Path(base) / "jig_host.exe"
        return cand if cand.is_file() else None
    except OSError:
        return None

def _find_jig(game_exe=None, jig_exe=None):
    """Locate jig_host.exe: bundled, explicit path, sources, game, PATH."""
    bund = _bundled_jig()
    if bund is not None:
        return bund
    if jig_exe:
        cand = Path(jig_exe)
        try:
            if cand.is_file():
                return cand
        except OSError:
            pass
    try:
        src = Path(__file__).resolve().parent.parent / "DLL" / "build" \
            / "jig_host.exe"
        if src.is_file():
            return src
    except OSError:
        pass
    if game_exe:
        try:
            cand = Path(game_exe).parent / "jig_host.exe"
            if cand.is_file():
                return cand
        except OSError:
            pass
    try:
        import shutil as _sh
        found = _sh.which("jig_host.exe")
        if found:
            return Path(found)
    except Exception:
        pass
    return None

def _prepare_altlib(dll_path, plugins_dir, game_exe, tmpdir):
    """Transcoded address lists for mods that cannot parse format 5.

    Returns the altlib dir, or None when the mod reads the current
    format natively or no exact-version source exists. Never invents
    data: without the matching versionlib the check runs unserved.
    """
    try:
        raw = Path(dll_path).read_bytes()
    except OSError:
        return None
    try:
        if core.module_supports_fmt5_bytes(raw):
            return None
    except Exception:
        pass
    try:
        run_tup = _exe_tuple(game_exe) if game_exe else None
    except Exception:
        run_tup = None
    if plugins_dir is None:
        return None
    cands = []
    try:
        for b in sorted(Path(plugins_dir).glob("versionlib-*.bin")):
            if core.extract_version_from_filename(b.name) == \
                    (tuple(run_tup[:3]) if run_tup else None):
                cands.append(b)
    except OSError:
        return None
    if not cands or run_tup is None:
        return None
    src = cands[0]
    outdir = Path(tmpdir) / "altlib"
    try:
        outdir.mkdir(parents=True, exist_ok=True)
        core.convert_format5_to_format2(str(src), str(outdir / src.name))
        for b in sorted(Path(plugins_dir).glob("version-*.bin")):
            if b.name.startswith("versionlib-"):
                continue
            if core.extract_version_from_filename(b.name) == \
                    tuple(run_tup[:3]):
                core.convert_format5_to_format2(
                    str(src), str(outdir / b.name), fmt=1)
                break
    except Exception:
        return None
    return outdir

def run_load_test(dll_path, game_exe=None, plugins_dir=None, jig_exe=None,
                  timeout=20):
    """Start one DLL copy in the isolated jig host.

    Copies the mod to a temp dir (the original is never touched) and
    runs jig_host.exe with a fake SKSE interface under a timeout.
    Returns {"ran": True, "outcome": ...} or {"ran": False, "reason"}.
    """
    import shutil as _sh
    import subprocess as _sp
    import tempfile as _tf
    dll_path = Path(dll_path)
    def _drop(path):
        import time as _t
        for _ in range(10):
            try:
                path.unlink(missing_ok=True)
                return
            except OSError:
                pass
            try:
                _t.sleep(0.1)
            except Exception:
                return

    def _sweep(folder):
        try:
            for stale in list(Path(folder).glob("~heal_*")) + list(Path(folder).glob("~xray_*")):
                _drop(stale)
        except OSError:
            pass

    try:
        if plugins_dir and Path(plugins_dir).is_dir():
            _sweep(plugins_dir)
    except OSError:
        pass
    jig = _find_jig(game_exe, jig_exe)
    if jig is None:
        return {"ran": False, "dll": dll_path.name,
                "reason": "live check tool not found next to the game"}
    stage = Path(plugins_dir) if plugins_dir else None
    try:
        can_stage = stage is not None and stage.is_dir()
    except OSError:
        can_stage = False
    work = stage if can_stage and stage is not None \
        else Path(_tf.mkdtemp(prefix="heal_jig_"))
    copy = work / f"~heal_{dll_path.stem}.tmp"
    try:
        _sh.copy2(dll_path, copy)
    except OSError as exc:
        return {"ran": False, "dll": dll_path.name,
                "reason": f"could not copy the mod: {exc}"}
    res = work / f"~heal_{dll_path.stem}.txt"
    runtime = "0"
    if game_exe:
        try:
            packed = core.runtime_version_from_exe(game_exe)
            if packed is not None:
                runtime = format(packed, "08X")
        except Exception:
            pass
    try:
        game_root = Path(game_exe).parent \
            if game_exe and Path(game_exe).is_file() else None
    except OSError:
        game_root = None
    alt_base = Path(_tf.mkdtemp(prefix="heal_alt_"))
    try:
        altlib = _prepare_altlib(dll_path, plugins_dir, game_exe,
                                 alt_base)
    except Exception:
        altlib = None
    cmd = [str(jig), str(copy), "--out", str(res),
           "--runtime", runtime,
           "--workdir", str(game_root or work)]
    if altlib is not None:
        cmd += ["--altlib", str(altlib)]
    cmd += ["--watchdog", str(max(1000, int(timeout * 1000) - 5000))]
    if game_exe:
        try:
            if Path(game_exe).is_file():
                cmd += ["--game", str(game_exe)]
        except OSError:
            pass
    rc = 0
    try:
        proc = _sp.Popen(cmd, stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
    except OSError as exc:
        _drop(copy)
        return {"ran": False, "dll": dll_path.name,
                "reason": f"could not start the check: {exc}"}
    try:
        proc.wait(timeout=timeout)
        rc = proc.returncode
    except _sp.TimeoutExpired:
        rc = -1
    finally:
        if proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=10)
            except Exception:
                pass
        _drop(copy)
    if rc == -1:
        _drop(res)
        return {"ran": True, "dll": dll_path.name, "outcome": "timeout",
                "seconds": timeout}
    vals = {}
    multi = {}
    try:
        for line in res.read_text(encoding="utf-8",
                                  errors="replace").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                vals[k] = v
                if k in ("open", "exec", "dialog"):
                    multi.setdefault(k, []).append(v)
    except OSError:
        pass
    finally:
        _drop(res)
    vals["opens"] = multi.get("open", [])
    vals["execs"] = multi.get("exec", [])
    vals["dialogs"] = multi.get("dialog", [])
    try:
        import shutil as _sh2
        _sh2.rmtree(alt_base, ignore_errors=True)
    except Exception:
        pass
    if not vals.get("outcome"):
        if rc != 0:
            vals["outcome"] = "crashed"
            vals.setdefault("stage", "starting")
            code = rc & 0xFFFFFFFF
            vals.setdefault("code", f"0x{code:08X}")
        else:
            vals["outcome"] = "no_result"
    vals["ran"] = True
    vals["dll"] = dll_path.name
    _attach_touched(vals, dll_path, game_exe, plugins_dir)
    return vals

def _old_rev_bins(plugins_dir, current_lib):
    """{offset: id} maps from bins older than the current library."""
    out = []
    try:
        bins = core.collect_lib_bins([plugins_dir])
    except Exception:
        return out
    cur = set((current_lib or {}).values())
    for b in bins:
        try:
            lib = core.parse_library_any(str(b))
        except Exception:
            continue
        if not lib:
            continue
        if cur and set(lib.values()) == cur:
            continue
        rev = {}
        for i, o in lib.items():
            rev.setdefault(o, i)
        out.append(rev)
    return out

def _attach_touched(live, dll_path, game_exe, plugins_dir):
    """Map observed addresses back to address-library IDs, in place.

    live["touched"]: current IDs the mod armed (hook targets hit at
    startup). live["touched_gone"]: removed IDs it reached for.
    live["heal"]: hook fixes for touched-but-stale sites, each
    {rel_id, old, new, hook} ready for patch_hook_offset.
    """
    live["touched"] = []
    live["touched_gone"] = []
    live["heal"] = []
    try:
        base = int(live.get("game_base", ""), 16)
    except (ValueError, TypeError):
        return
    try:
        run_tup = _exe_tuple(game_exe) if game_exe else None
        current_lib = healer.load_current_lib(
            plugins_dir, run_tup) if plugins_dir else None
    except Exception:
        current_lib = None
    if not current_lib:
        return
    rev = {}
    for i, o in current_lib.items():
        rev.setdefault(o, i)
    seen = set()
    for raw in live.get("execs", []):
        try:
            addr = int(raw, 16)
        except (ValueError, TypeError):
            continue
        off = addr - base
        if off < 0 or off > 0x4000000:
            continue
        if off in rev and rev[off] not in seen:
            seen.add(rev[off])
            live["touched"].append(rev[off])
    if live.get("outcome") == "crashed":
        try:
            faddr = int((live.get("fault") or "").split("+")[-1], 16)
        except (ValueError, TypeError, IndexError):
            return
        foff = faddr - base
        if 0 <= foff <= 0x4000000:
            if foff in rev:
                live["fault_id"] = rev[foff]
            else:
                for b in _old_rev_bins(plugins_dir, current_lib):
                    if foff in b:
                        live["fault_id"] = b[foff]
                        live["touched_gone"].append(b[foff])
                        break
        return
    try:
        hooks = therapist.find_hooks(dll_path)
    except Exception:
        return
    exe_data, exe_secs = None, None
    try:
        if game_exe:
            exe_data, exe_secs = core.load_exe_sections(game_exe)
    except Exception:
        exe_data = None
    if not exe_data:
        return
    for h in hooks:
        rid = h.get("rel_id")
        if rid not in seen or rid not in current_lib:
            continue
        base_off = current_lib[rid]
        if therapist.pattern_matches_at(exe_data, exe_secs, base_off,
                                   h["offset"], h["pattern"]):
            continue
        try:
            matches = therapist.find_pattern_offsets(
                exe_data, exe_secs, base_off, h["pattern"], h["offset"])
        except Exception:
            continue
        if len(matches) == 1:
            live["heal"].append({"rel_id": rid, "old": h["offset"],
                                 "new": matches[0], "hook": h})

def apply_live(rep, live):
    """Merge an isolated-check result into a check-up report. Pure.

    A live crash only convicts when the static verdict is not already
    HEALTHY. On HEALTHY the card stays untouched (the game outranks
    the stand-in); the forensics move to details for the author.
    """
    if not live or not live.get("ran"):
        return rep
    out = dict(rep)
    out["lines"] = list(rep.get("lines", []))
    out["details"] = dict(rep.get("details", {}))
    out["details"]["heal"] = [dict(c) for c in live.get("heal", [])]
    outcome = live.get("outcome", "")
    if outcome == "crashed":
        stage = live.get("stage") or "starting"
        code = (live.get("code") or "").upper()
        kind = EXC_NAMES.get(code, "crash" if not code else f"crash {code}")
        fault = (live.get("fault") or "").replace("~heal_", "").replace("~xray_", "")
        where = f", {fault}" if fault else ""
        line = (f"Crashed with {kind} while starting ({stage}{where}) "
                f"in the isolated check.")

        def _own_fault():
            if not fault or "+" not in fault:
                return True
            mod = fault.split("+", 1)[0].lower()
            for suf in (".tmp", ".dll"):
                if mod.endswith(suf):
                    mod = mod[:-len(suf)]
            own = Path(rep.get("name", "")).stem.lower()
            return mod == own

        if not _own_fault():
            out["lines"].append(
                line + " It died outside its own code, so the "
                "stand-in may be at fault, not the mod.")
            out["details"]["live_crash"] = {
                "stage": stage, "code": code, "fault": fault,
                "stack": live.get("stack", "")}
            return out
        if rep.get("verdict") == "HEALTHY":
            out["details"]["live_crash"] = {
                "stage": stage, "code": code, "fault": fault,
                "stack": live.get("stack", ""),
                "qi_ids": live.get("qi_ids", "")}
            return out
        out["lines"] = [line + " Turn it off to play, then ask the "
                        "author for an update."]
        out["verdict"] = "BROKEN"
        out["title"] = "Crashed in the isolated check"
        out["action"] = "turn_off"
        return out
    for name in sorted({o for o in live.get("opens", [])
                         if "version" in o.lower()})[:3]:
        out["lines"].append(f"At startup it asked for the address list "
                            f"({name}).")
    if live.get("serve"):
        out["lines"].append("It got a compatible address list in the "
                            "isolated check.")
    for dlg in live.get("dialogs", [])[:2]:
        out["lines"].append(f"It showed an error: {dlg[:120]}.")
    touched = live.get("touched", [])
    if touched:
        shown = ", ".join(str(v) for v in touched[:5])
        out["lines"].append(f"It armed hooks for {len(touched)} game "
                            f"address(es) at startup ({shown}).")
    for dead in live.get("touched_gone", [])[:3]:
        out["lines"].append(f"It reached for removed address {dead} "
                            f"at startup.")
    heal = live.get("heal", [])
    if heal:
        out["lines"].append(f"{len(heal)} armed hook(s) point at the "
                            f"wrong place - healing them may fix it.")
    if outcome in ("loaded", "query_ok"):
        out["lines"].append("It also started in the isolated check.")
    elif outcome in ("load_false", "query_declined"):
        out["lines"].append("It refused to start in the isolated check "
                            "(it said no itself).")
    elif outcome == "no_entry":
        out["lines"].append("It has no SKSE startup to run in isolation.")
    elif outcome == "timeout":
        stuck = live.get("stuck", "")
        if stuck:
            out["lines"].append(f"The isolated check hung at {stuck} - "
                                "it waits on something only the game "
                                "provides.")
        else:
            out["lines"].append("The isolated check timed out - it may be "
                                "waiting on something only the game "
                                "provides.")
    elif outcome == "no_result":
        out["lines"].append("The isolated check gave no result.")
    elif outcome == "load_failed":
        err = live.get("error", "")
        if err == "126":
            out["lines"].append("It needs system files that are missing "
                                "here (usually the VC++ libraries).")
        else:
            out["lines"].append("It could not even be opened "
                                f"(system error {err or '?'}).")
    else:
        out["lines"].append(f"Isolated check said: {outcome}.")
    return out
