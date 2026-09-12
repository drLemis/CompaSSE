#!/usr/bin/env python3
"""Synthetic self-check for CompaSSE detection + healing quality.

Builds minimal fake PE64 files in tmp (no game, no mods needed) and asserts:
  T1 healer byte-scanners find planted MOV EBX + REL::ID refs, ignore noise
  T2 healer E8 unique-match  -> exactly 1 auto-fixable finding
  T3 healer E8 multi-match   -> 0 auto findings, 1 manual w/ candidates
  T4 healer dedupe           -> same offset value at 2 sites = 2 findings
  T5 compasse rva_to_offset  -> resolves RVA in section padding (vsize<rawsize)
  T6 compasse pattern scan   -> unique match + ambiguity reported
  T7 compasse hook patch     -> refuses disp8 LEA (would corrupt next insn)
  T8 compasse find_hooks     -> recall planted hook, no false positive on decoy
  T9 healer heal_plugin      -> end-to-end offset rewrite on T2-style finding
Run: python test_detect.py
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import compasse as C
import skse_healer as H

PASS = []
FAIL = []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("ok   " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


def make_pe64(sections, extra_rvas=(), export=None, timestamp=0):
    """Minimal PE64 blob. sections: [(name, vaddr, vsize, rawoff, rawsize)].
    export: (rva, size) for the export DataDirectory, or None."""
    e_lfanew = 0x80
    data = bytearray(0x400)
    struct.pack_into("<I", data, 0x3C, e_lfanew)
    data += bytearray(0x200)
    data[e_lfanew:e_lfanew + 4] = b"PE\x00\x00"  # e_lfanew points AT sig
    coff = e_lfanew + 4
    struct.pack_into("<I", data, e_lfanew + 8, timestamp)  # COFF TimeDateStamp
    struct.pack_into("<H", data, coff + 2, len(sections))
    opt = coff + 20
    struct.pack_into("<H", data, opt, 0x20B)
    # healer locates sections via num_dd; compasse assumes 16 dirs. Set 16
    # so both parsers land on the same table.
    struct.pack_into("<I", data, opt + 108, 16)
    if export is not None:
        struct.pack_into("<II", data, opt + 112, export[0], export[1])
    sec_start = opt + 112 + 16 * 8
    end = max(r[3] + r[4] for r in sections) if sections else sec_start
    if len(data) < end:
        data += bytearray(end - len(data))
    for i, (name, va, vsz, raw, rsz) in enumerate(sections):
        s = sec_start + i * 40
        data[s:s + 8] = name.encode("ascii")[:8].ljust(8, b"\x00")
        struct.pack_into("<I", data, s + 8, vsz)
        struct.pack_into("<I", data, s + 12, va)
        struct.pack_into("<I", data, s + 16, rsz)
        struct.pack_into("<I", data, s + 20, raw)
    for rva, blob in extra_rvas:
        pass
    return bytes(data)


def put(data, off, blob):
    data = bytearray(data)
    data[off:off + len(blob)] = blob
    return bytes(data)


def fmt5_lib(path, entries, count=8192):
    buf = bytearray(96 + count * 4)
    struct.pack_into("<I", buf, 0, 5)
    struct.pack_into("<I", buf, 92, count)
    for i, off in entries.items():
        struct.pack_into("<I", buf, 96 + i * 4, off)
    path.write_bytes(buf)


def write_exe(path, stale_off, copies, func_rva=0x1100):
    blob = make_pe64([(".text", 0x1000, 0x3000, 0x400, 0x3000)])
    blob = bytearray(blob)
    pat = b"\xE8" + bytes(range(1, 16))
    for c in copies:
        blob[0x400 + (func_rva - 0x1000) + c:0x400 + (func_rva - 0x1000) + c + 16] = pat
    path.write_bytes(blob)
    return pat


def write_plugin(path, mov_offsets, id_val=5000):
    blob = bytearray(make_pe64([(".text", 0x1000, 0x1000, 0x400, 0x1000)]))
    code = bytearray(b"\x90" * 0x400)
    for mo in mov_offsets:
        struct.pack_into("<I", code, mo + 1, 0x200)
        code[mo] = 0xBB
        code[mo + 40:mo + 48] = b"\x48\xC7\x45\xF8" + struct.pack("<I", id_val)
    blob[0x400:0x800] = code
    path.write_bytes(blob)


def main():
    # ---------------------------------------------------------------- T1
    code = b"\x90" + b"\xBB\x34\x12\x00\x00" + b"\x90" * 10 + b"\x48\xC7\x45\xF8\x39\x30\x00\x00" + b"\x90"
    movs = H.find_mov_ebx_imm32(code)
    refs = H.find_id_refs_nearby(code, 1)
    check("T1.mov", movs == [(1, 0x1234)], repr(movs))
    check("T1.idref", any(v == 12345 for _, v in refs), repr(refs))
    check("T1.noise", H.find_mov_ebx_imm32(b"\xBB\x05\x00\x00\x00\xBB\xFF\xFF\xFF\xFF") == [], "range filter")

    # ---------------------------------------------------------------- T2/T3/T4
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="compasse_q_"))
    plugdir = tmp / "plugins"
    plugdir.mkdir()

    # T2: stale@0x200, copies at stale + new site -> unique redirect
    fmt5_lib(plugdir / "versionlib-9-9-9-0.bin", {5000: 0x1100})
    exe2 = tmp / "game2.exe"
    write_exe(exe2, 0x200, [0x200, 0x400])
    dll2 = tmp / "m2.dll"
    write_plugin(dll2, [0x50])
    f2, _, _, _ = H.analyze_plugin(dll2, exe2, plugdir)
    auto2 = [f for f in f2 if f.get("auto_fixable")]
    check("T2.unique_auto", len(f2) == 1 and len(auto2) == 1 and auto2[0]["new_offset"] == 0x400,
          repr([(f.get("new_offset"), f.get("auto_fixable")) for f in f2]))

    # T3: copies at stale + 2 new sites -> ambiguous, must NOT auto-fix
    exe3 = tmp / "game3.exe"
    write_exe(exe3, 0x200, [0x200, 0x400, 0x600])
    dll3 = tmp / "m3.dll"
    write_plugin(dll3, [0x50])
    f3, _, _, _ = H.analyze_plugin(dll3, exe3, plugdir)
    auto3 = [f for f in f3 if f.get("auto_fixable")]
    check("T3.multi_noauto", len(auto3) == 0, f"{len(auto3)} auto")
    check("T3.multi_manual", len(f3) == 1 and "candidates" in f3[0], repr(f3))

    # T4: same offset value, two code sites -> two findings
    exe4 = tmp / "game4.exe"
    write_exe(exe4, 0x200, [0x200, 0x400])
    dll4 = tmp / "m4.dll"
    write_plugin(dll4, [0x50, 0x150])
    f4, _, _, _ = H.analyze_plugin(dll4, exe4, plugdir)
    check("T4.dedupe", len(f4) == 2, f"{len(f4)} findings")

    # T9: end-to-end heal on T2 finding (fresh dll copy)
    dll9 = tmp / "m9.dll"
    write_plugin(dll9, [0x50])
    f9, _, _, _ = H.analyze_plugin(dll9, exe2, plugdir)
    ok9 = H.heal_plugin(dll9, f9[0], backup=False)
    patched = struct.unpack_from("<I", dll9.read_bytes(), 0x400 + 0x50 + 1)[0]
    check("T9.heal", ok9 and patched == 0x400, hex(patched))

    # ---------------------------------------------------------------- T5
    secs = [(".text", 0x1000, 0x200, 0x400, 0x400)]
    check("T5.padding", C.rva_to_offset(0x1250, secs) == 0x650, repr(C.rva_to_offset(0x1250, secs)))

    # ---------------------------------------------------------------- T6
    esecs = [(".text", 0x1000, 0x1000, 0x400, 0x1000)]
    exe6 = bytearray(0x1400)
    exe6[0x400 + 0x100:0x400 + 0x102] = b"\xAA\xBB"
    exe6[0x400 + 0x220:0x400 + 0x222] = b"\xAA\xBB"
    m6 = C.find_pattern_offsets(bytes(exe6), esecs, 0x1000, {0: 0xAA, 1: 0xBB}, 0x100)
    check("T6.ambiguous", sorted(m6) == [0x100, 0x220], repr(m6))
    exe6b = bytearray(0x1400)
    exe6b[0x400 + 0x220:0x400 + 0x222] = b"\xAA\xBB"
    m6b = C.find_pattern_offsets(bytes(exe6b), esecs, 0x1000, {0: 0xAA, 1: 0xBB}, 0x100)
    check("T6.unique", m6b == [0x220], repr(m6b))

    # ---------------------------------------------------------------- T7
    t7 = bytearray(make_pe64([(".text", 0x1000, 0x200, 0x400, 0x400)]))
    t7[0x400:0x405] = b"\x48\x8D\x58\x20\x90"  # lea rax,[rax+0x20] disp8 + nop
    dll7 = tmp / "m7.dll"
    dll7.write_bytes(t7)
    before = dll7.read_bytes()[0x404]
    ok7 = C.patch_hook_offset(dll7, {"va": 0x1000, "offset": 0x20}, 0x60)
    after = dll7.read_bytes()[0x404]
    check("T7.disp8_guard", ok7 is False and before == after == 0x90, f"ok={ok7} byte={after:#x}")

    # ---------------------------------------------------------------- T8 (needs capstone)
    hook_fn = (b"\x48\xC7\x44\x24\x08\x34\x12\x00\x00"   # mov [rsp+8], 0x1234
               b"\xFF\xD0"                               # call rax
               b"\x48\x8D\x80\x40\x00\x00\x00"           # lea rax, [rax+0x40]
               b"\x80\x38\xAA\x80\x78\x01\xBB\x80\x78\x02\xCC\x80\x78\x03\xDD"
               b"\xC3")                                  # 4x cmp + ret
    decoy_fn = (b"\x48\x8D\x80\x10\x00\x00\x00"           # lea alone: no mov/call/cmps
                b"\x90\x90\xC3")
    t8 = bytearray(make_pe64([(".text", 0x1000, 0x400, 0x400, 0x400),
                              (".pdata", 0x2000, 0x18, 0x800, 0x18)]))
    t8[0x400:0x400 + len(hook_fn)] = hook_fn
    t8[0x400 + 0x100:0x400 + 0x100 + len(decoy_fn)] = decoy_fn
    struct.pack_into("<III", t8, 0x800, 0x1000, 0x1000 + len(hook_fn), 0)
    struct.pack_into("<III", t8, 0x80C, 0x1100, 0x1100 + len(decoy_fn), 0)
    dll8 = tmp / "m8.dll"
    dll8.write_bytes(t8)
    h8 = C.find_hooks(dll8)
    good = [h for h in h8 if h["rel_id"] == 0x1234]
    check("T8.recall", len(good) == 1 and good[0]["offset"] == 0x40
          and sorted(good[0]["pattern"].keys()) == [0, 1, 2, 3], repr(h8))
    check("T8.precision", len(h8) == 1, f"{len(h8)} hooks")

    # ---------------------------------------------------------------- T10: mint-missing
    # old lib: id 11 (kept, shifted), 12 (dropped, body survives), 13 (dropped, gone)
    sigA = bytes(range(64))
    sigB = bytes([(i * 7) & 0xFF for i in range(64)])
    sigC = bytes([(i * 13 + 5) & 0xFF for i in range(64)])
    o10 = bytearray(make_pe64([(".text", 0x1000, 0x1000, 0x400, 0x1000)]))
    o10[0x400 + 0x100:0x400 + 0x164] = sigA   # id 11 @0x1100
    o10[0x400 + 0x200:0x400 + 0x264] = sigB   # id 12 @0x1200
    o10[0x400 + 0x300:0x400 + 0x364] = sigC   # id 13 @0x1300 (gone in new)
    n10 = bytearray(make_pe64([(".text", 0x1000, 0x1000, 0x400, 0x1000)]))
    n10[0x400 + 0x300:0x400 + 0x364] = sigA   # id 11 @0x1300 (shifted, kept)
    n10[0x400 + 0x500:0x400 + 0x564] = sigB   # id 12 body @0x1500 (dropped id)
    old_lib10 = {11: 0x1100, 12: 0x1200, 13: 0x1300}
    new_lib10 = {11: 0x1300}
    ent10, rem10, amb10 = C.mint_missing_translations(
        bytes(o10), C.find_pe_sections(bytes(o10)), old_lib10,
        bytes(n10), C.find_pe_sections(bytes(n10)), new_lib10)
    check("T10.mint", ent10 == [(12, 0x1500)], repr(ent10))
    check("T10.removed", rem10 == 1, repr(rem10))  # id 13: old off empty, new lacks
    check("T10.noambig", amb10 == [], repr(amb10))

    # ---------------------------------------------------------------- T11: merge block
    plug11 = tmp / "plug11"
    (plug11 / "CompaSSE").mkdir(parents=True)
    t11 = bytearray(b"TRTL" + struct.pack("<I", 1) + struct.pack("<I", 1))
    vb = b"9.9.9"
    t11 += struct.pack("<I", len(vb)) + vb + b"\x00" * (((len(vb) + 3) & ~3) - len(vb))
    t11 += struct.pack("<I", 2) + struct.pack("<QI", 12, 0xDEAD) + struct.pack("<QI", 77, 0xBEEF)
    (plug11 / "CompaSSE" / "translation_table.bin").write_bytes(t11)
    dropped11, total11 = C.merge_translation_block(plug11, "9.9.10", [(12, 0x1500), (13, 0x1600)])
    raw11 = (plug11 / "CompaSSE" / "translation_table.bin").read_bytes()
    check("T11.merge", dropped11 == 1 and total11 == 3, f"dropped={dropped11} total={total11}")
    check("T11.backup", (plug11 / "CompaSSE" / "translation_table.bin.bak").exists(), "no bak")
    check("T11.roundtrip", len(raw11) > 16 and raw11[:4] == b"TRTL", repr(raw11[:8]))

    # ---------------------------------------------------------------- T12: xref gate
    # fn: mov rax,[rip+disp] -> .data slot; slot holds ID or junk
    t12 = bytearray(make_pe64([(".text", 0x1000, 0x200, 0x400, 0x400),
                               (".data", 0x2000, 0x100, 0x800, 0x100),
                               (".pdata", 0x3000, 0xC, 0x900, 0xC)]))
    # mov rax, [rip+?] @0x1000 -> target 0x2000: disp = 0x2000-(0x1000+7)
    t12[0x400:0x407] = b"\x48\x8B\x05\xF9\x0F\x00\x00" + b"\xC3"
    struct.pack_into("<III", t12, 0x900, 0x1000, 0x1008, 0)
    idset12 = {777777}
    struct.pack_into("<Q", t12, 0x800, 777777)
    dll12 = tmp / "m12.dll"
    dll12.write_bytes(t12)
    check("T12.hit", C.count_xref_ids(dll12, idset12) == 1,
          repr(C.count_xref_ids(dll12, idset12)))
    struct.pack_into("<Q", t12, 0x800, 123)  # junk, not an ID
    dll12.write_bytes(t12)
    check("T12.miss", C.count_xref_ids(dll12, idset12) == 0,
          repr(C.count_xref_ids(dll12, idset12)))
    check("T12.nolib", C.count_xref_ids(dll12, None) is None, "needs set")

    # ---------------------------------------------------------------- T13: gates
    t13 = bytearray(make_pe64([(".text", 0x1000, 0x400, 0x400, 0x400),
                               (".edata", 0x4000, 0x100, 0xA00, 0x100),
                               (".rdata", 0x5000, 0x100, 0xB00, 0x100),
                               (".pdata", 0x3000, 0x30, 0x900, 0x30)],
                              export=(0x4000, 0x100)))
    t13[0x400:0x404] = b"\x8B\x41\x04\xC3"              # mov eax,[rcx+4]; ret
    t13[0x500:0x507] = b"\x81\xF9\x00\x6A\x06\x01\xC3"  # cmp ecx,0x1066A00; ret
    t13[0x510:0x515] = b"\x83\xF8\x05\xC3\x90"          # cmp eax,5 (noise)
    # lea rcx,[rip+disp] -> "version mismatch" @0x5000; disp = 0x5000-(0x1120+7)
    t13[0x520:0x527] = b"\x48\x8D\x0D\xD9\x3E\x00\x00" + b"\xC3"
    t13[0xB00:0xB11] = b"version mismatch\x00"
    struct.pack_into("<III", t13, 0x900, 0x1000, 0x1004, 0)
    struct.pack_into("<III", t13, 0x90C, 0x1100, 0x1107, 0)
    struct.pack_into("<III", t13, 0x918, 0x1110, 0x1115, 0)
    struct.pack_into("<III", t13, 0x924, 0x1120, 0x1128, 0)
    # export dir: 1 name -> SKSEPlugin_Load @0x1000
    struct.pack_into("<I", t13, 0xA00 + 24, 1)
    struct.pack_into("<I", t13, 0xA00 + 28, 0x4040)
    struct.pack_into("<I", t13, 0xA00 + 32, 0x4050)
    struct.pack_into("<I", t13, 0xA00 + 36, 0x4060)
    struct.pack_into("<I", t13, 0xA40, 0x1000)
    struct.pack_into("<I", t13, 0xA50, 0x4070)
    struct.pack_into("<H", t13, 0xA60, 0)
    t13[0xA70:0xA70 + 16] = b"SKSEPlugin_Load\x00"
    dll13 = tmp / "m13.dll"
    dll13.write_bytes(t13)
    g13 = C.find_version_gates(dll13)
    check("T13.avail", g13 is not None, "capstone missing?")
    g13 = g13 or []
    kinds = {(g["kind"], g["rva"]) for g in g13}
    check("T13.iface", ("iface_version_read", 0x1000) in kinds, repr(g13))
    check("T13.packed", ("packed_compare", 0x1100) in kinds, repr(g13))
    check("T13.noise", all(g["rva"] != 0x1110 for g in g13), repr(g13))
    check("T13.stringref", any(g["kind"] == "version_string_ref" and g["rva"] == 0x1120
                               for g in g13), repr(g13))

    # ---------------------------------------------------------------- T14: build timestamp
    t14 = tmp / "m14.dll"
    t14.write_bytes(make_pe64([(".text", 0x1000, 0x100, 0x400, 0x100)],
                              timestamp=1672531200))
    dt14 = C.pe_build_dt(t14)
    check("T14.dt", dt14 is not None and (dt14.year, dt14.month, dt14.day) == (2023, 1, 1),
          repr(dt14))
    t14b = tmp / "m14b.dll"
    t14b.write_bytes(make_pe64([(".text", 0x1000, 0x100, 0x400, 0x100)]))
    check("T14.zero", C.pe_build_dt(t14b) is None, "zero ts")

    # ---------------------------------------------------------------- T17: co-save surgeon
    import skse_surgeon as S

    def make_cosave(uids):
        out = bytearray(struct.pack("<5I", 0x45534B53, 1, 0x02030010,
                                    0x01070680, len(uids)))
        for uid, chunks in uids:
            body = bytearray()
            for t, v, payload in chunks:
                body += struct.pack("<III", t, v, len(payload)) + payload
            out += struct.pack("<III", uid, len(chunks), len(body)) + body
        return bytes(out)

    t17 = tmp / "t17.skse"
    t17.write_bytes(make_cosave([
        (0x00000000, [(0x504C474E, 0, b"AB")]),
        (0x12345678, [(0x52454753, 1, b"CDEF"), (0x52454753, 1, b"")]),
    ]))
    h17, b17, trail17 = S.parse_cosave(t17)
    check("T17.parse", h17["numPlugins"] == 2 and len(b17) == 2
          and trail17 == 0, repr((h17, len(b17), trail17)))
    check("T17.fcc", S.fcc(0x504C474E) == "PLGN", S.fcc(0x504C474E))
    check("T17.uid", S.parse_uid("PLGN") == 0x504C474E, "PLGN")
    check("T17.uidhex", S.parse_uid("0x12345678") == 0x12345678, "hex")
    removed17, left17 = S.drop_plugin(t17, 0x12345678)
    h17b, b17b, trail17b = S.parse_cosave(t17)
    check("T17.drop", left17 == 1 and len(b17b) == 1
          and b17b[0]["uid"] == 0 and trail17b == 0
          and h17b["numPlugins"] == 1, repr((removed17, left17)))
    try:
        S.drop_plugin(t17, 0)
        check("T17.core-refuse", False, "uid 0 dropped!")
    except ValueError:
        check("T17.core-refuse", True, "")
    try:
        S.drop_plugin(t17, 0xDEADBEEF)
        check("T17.missing", False, "dropped absent uid!")
    except ValueError:
        check("T17.missing", True, "")
    (tmp / "t17b.skse").write_bytes(b"junk")
    try:
        S.parse_cosave(tmp / "t17b.skse")
        check("T17.junk", False, "parsed junk!")
    except ValueError:
        check("T17.junk", True, "")

    # ---------------------------------------------------------------- T17b: uid owners
    plugdir = tmp / "plugdir"
    plugdir.mkdir()
    secs17 = [(".text", 0x1000, 0x100, 0x400, 0x100),
              (".rdata", 0x2000, 0x100, 0x800, 0x100)]
    (plugdir / "a.dll").write_bytes(
        put(make_pe64(secs17), 0x400 + 0x20, struct.pack("<I", 0xA1B2C3D4)))
    (plugdir / "b.dll").write_bytes(
        put(make_pe64(secs17), 0x800 + 0x10, struct.pack("<I", 0xA1B2C3D4)))
    check("T17.owner-text",
          S.find_uid_owners(0xA1B2C3D4, str(plugdir)) == ["a.dll"],
          "text only, not rdata")
    check("T17.owner-zero", S.find_uid_owners(0, str(plugdir)) == [],
          "uid 0 never scanned")
    check("T17.owner-missing",
          S.find_uid_owners(0xDEADBEEF, str(plugdir)) == [], "absent uid")
    check("T17.owner-nodir",
          S.find_uid_owners(0xA1B2C3D4, str(tmp / "nodir")) == [], "no dir")
    stage17 = tmp / "stage17"
    (stage17 / "Some Mod").mkdir(parents=True)
    (stage17 / "Some Mod" / "s.dll").write_bytes(
        put(make_pe64(secs17), 0x400 + 0x08, struct.pack("<I", 0xA1B2C3D4)))
    loc17 = S.locate_uid(0xA1B2C3D4, str(plugdir), str(stage17))
    check("T17.locate",
          loc17["installed"] == ["a.dll"]
          and len(loc17["staged"]) == 1
          and loc17["staged"][0].endswith("s.dll"), repr(loc17))
    loc17b = S.locate_uid(0xDEADBEEF, str(plugdir), str(stage17))
    check("T17.locate-empty", loc17b == {"installed": [], "staged": []},
          repr(loc17b))
    check("T17.describe",
          S.describe_chunks({"chunks": [{"type": 0x504C474E}, {"type": 0x52454753},
                                         {"type": 0x504C474E}, {"type": 0xDEADBEEF}]})
          == "plugin list, event registrations", "known vocab")
    check("T17.describe-empty",
          S.describe_chunks({"chunks": [{"type": 0xDEADBEEF}]}) == "", "unknown only")

    # ---------------------------------------------------------------- T17b: PLGN list
    plgn = struct.pack("<H", 3)
    plgn += b"\x00" + struct.pack("<H", 10) + b"Skyrim.esm"
    plgn += b"\x01" + struct.pack("<H", 10) + b"Update.esm"
    plgn += b"\xFE" + struct.pack("<H", 1) + struct.pack("<H", 9) + b"Light.esl"
    t17c = tmp / "t17c.skse"
    t17c.write_bytes(make_cosave([
        (0x00000000, [(0x504C474E, 0, plgn)]),
        (0x12345678, [(0x52454753, 1, b"X")]),
    ]))
    h17c, b17c, _ = S.parse_cosave(t17c)
    pl17 = S.plugin_list_chunk(b17c[0], t17c)
    check("T17.plgn", pl17 == [(0, "Skyrim.esm"), (1, "Update.esm"),
                               (0xFE001, "Light.esl")], repr(pl17))
    check("T17.fmtidx", S.fmt_index(1) == "01" and S.fmt_index(0xFE001) == "FE001",
          "idx fmt")
    mods17 = tmp / "mods17"
    (mods17 / "Data").mkdir(parents=True)
    (mods17 / "Data" / "Skyrim.esm").write_bytes(b"")
    (mods17 / "Data" / "update.ESM").write_bytes(b"")
    miss17 = S.missing_mods(pl17, mods17 / "Data")
    check("T17.missing-mods", miss17 == ["Light.esl"], repr(miss17))
    check("T17.no-plgn", S.plugin_list_chunk(b17c[1], t17c) is None,
          "block without PLGN")

    # ---------------------------------------------------------------- T18: save names + ess
    n18 = S.parse_save_filename(
        "Quicksave0_E6FDD12E_0_426C6F77732D5468652D486F726E73_"
        "WhiterunWorld_002311_20260823010902_9_1.skse")
    check("T18.name", n18 is not None and n18["character"] == "Blows-The-Horns"
          and n18["location"] == "WhiterunWorld" and n18["level"] == 9
          and n18["date"] == "2026-08-23 01:09"
          and n18["label"] == "Quicksave0", repr(n18))
    check("T18.name-underscored",
          (S.parse_save_filename("My_cool_save_0_00_4142_Loc_000000_20260101000000_3_7")
           or {}).get("label") == "My_cool_save", "underscores")
    check("T18.name-bad", S.parse_save_filename("weirdname.ess") is None
          and S.parse_save_filename("A_B_C") is None, "rejects junk")

    def wstr(s):
        b = s.encode("ascii")
        return struct.pack("<H", len(b)) + b

    rgb18 = bytes(range(32))
    blob18 = bytearray(b"TESV_SAVEGAME" + struct.pack("<III", 92, 12, 9))
    blob18 += wstr("Hero") + struct.pack("<I", 5) + wstr("Town")
    blob18 += wstr("023.11.11") + wstr("NordRace")
    blob18 += struct.pack("<HffQII", 1, 1.5, 2.5, 0, 4, 2) + rgb18
    tmp.joinpath("t18.ess").write_bytes(bytes(blob18))
    e18 = S.read_ess_info(tmp / "t18.ess")
    conv18 = b"".join(bytes([rgb18[i * 4 + 2], rgb18[i * 4 + 3], rgb18[i * 4]])
                      for i in range(8))
    check("T18.ess", e18 is not None and e18["player"] == "Hero"
          and e18["level"] == 5 and e18["location"] == "Town"
          and e18["day"] == 23 and e18["time"] == "11:11"
          and e18["shot"] == (4, 2, conv18), repr(e18))
    ppm18 = S.ess_thumbnail((4, 2, conv18), maxw=2)
    check("T18.ppm", ppm18 is not None and ppm18.startswith(b"P6\n2 1\n255\n")
          and ppm18[11:] == bytes([2, 3, 0, 10, 11, 8]), repr(ppm18[:14]))
    (tmp / "t18b.ess").write_bytes(b"junk")
    check("T18.ess-junk", S.read_ess_info(tmp / "t18b.ess") is None, "junk")
    check("T18.thumb-bad", S.ess_thumbnail(None) is None
          and S.ess_thumbnail((0, 0, b"")) is None, "bad shots")


    # ---------------------------------------------------------------- T19: cutoffs
    x19 = C.crossed_cutoffs
    check("T19.all", x19((1, 6, 640), (1, 7, 104))
          == [(1, 6, 653), (1, 6, 1130), (1, 7, 99)], "640->104")
    check("T19.one", x19((1, 6, 1170), (1, 7, 104)) == [(1, 7, 99)],
          "1170->104")
    check("T19.none", x19((1, 7, 104), (1, 7, 104)) == []
          and x19((1, 7, 99), (1, 7, 104)) == [], "same/adjacent")
    check("T19.guards", x19(None, (1, 7, 104)) == []
          and x19((1, 7, 104), None) == []
          and x19((1, 0, 0), (1, 7, 104)) == [], "none/placeholder")

    import compasse_gui as G
    r19 = 0x01070680  # 1.7.104.0, SKSE-true packing
    old19 = 0x01062800  # 1.6.640.0
    base_vi = {"indep_val": 0x1, "indep_ex_val": 0, "has_addr": True,
               "has_sigs": False, "has_unknown": False, "needs_indep": True,
               "runtime_ver": old19, "compat": [old19]}

    def_info = {"flag": {"flag_off": 0, "flag_val": 0, "needs_patch": True},
                "version_indep": dict(base_vi), "hooks": []}
    v19 = G.classify(def_info, 2023, r19)
    check("T19.gui-needsfix", v19["cat"] == "NEEDS_FIX"
          and "1.6.653" in v19["why"] and "1.7.99" in v19["why"], v19["cat"])

    try_info = {"flag": {"flag_off": 0, "flag_val": 0, "needs_patch": True},
                "version_indep": dict(base_vi, compat=[r19]), "hooks": []}
    v19b = G.classify(try_info, 2023, r19)
    check("T19.gui-tryfirst", v19b["cat"] == "MANUAL"
          and "1.7.99" in v19b["why"], v19b["cat"])

    ok_info = {"flag": {"flag_off": 0, "flag_val": 2, "needs_patch": False},
               "version_indep": {"indep_val": 0x5, "indep_ex_val": 0x2,
                                 "has_addr": True, "has_sigs": False,
                                 "has_unknown": False, "needs_indep": False,
                                 "runtime_ver": r19, "compat": [r19]},
               "hooks": []}
    v19c = G.classify(ok_info, 2024, r19)
    check("T19.gui-builtforyou", v19c["cat"] == "OK"
          and "leave it alone" in v19c["why"], v19c["cat"])

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    sys.exit(1 if FAIL else 0)

if __name__ == "__main__":
    main()
