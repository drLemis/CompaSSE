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

    # ---------------------------------------------------------------- T20: fmt5 markers
    # Shim parity: kFmt5Markers == compasse.FMT5_MARKERS.
    import re as _re
    dec_cpp = (HERE / "DLL" / "decoder_detect.cpp").read_text(encoding="utf-8")
    cpp_markers = set(_re.findall(r'"((?:AddressLibraryV5|Address Library V5|'
                                  r'not an Address Library V5 file|AddressLibV2)[^"]*)"',
                                  dec_cpp))
    check("T20.parity",
          {m.decode() for m in C.FMT5_MARKERS} <= cpp_markers,
          repr(cpp_markers))
    neg = bytearray(make_pe64([(".text", 0x1000, 0x100, 0x400, 0x100),
                               (".rdata", 0x2000, 0x100, 0x800, 0x100)]))
    neg[0x800:0x800 + 24] = b"Unsupported address library"
    neg[0x820:0x820 + 12] = b"versionlib-"
    check("T20.old-neg", C.module_supports_fmt5_bytes(bytes(neg)) is False,
          "old strings must not match")
    for i, marker in enumerate(C.FMT5_MARKERS):
        pos = bytearray(bytes(neg))
        pos[0x840 + i * 64:0x840 + i * 64 + len(marker)] = marker
        check(f"T20.pos-{i}", C.module_supports_fmt5_bytes(bytes(pos)) is True,
              repr(marker))
    check("T20.case", C.module_supports_fmt5_bytes(b"addresslibraryv5") is False,
          "markers are case-sensitive")
    check("T20.empty", C.module_supports_fmt5_bytes(b"") is False, "empty")

    # ---------------------------------------------------------------- T23: table stamp
    check("T23.enc-v3",
          C._encode_table_header(3, "1.7.104") == b"TRTL" + struct.pack("<I", 3)
          + struct.pack("<I", 7) + b"1.7.104" + b"\x00",
          "v3 header bytes")
    check("T23.enc-v1",
          C._encode_table_header(1) == b"TRTL" + struct.pack("<I", 1),
          "v1 header bytes")
    v3blob = (C._encode_table_header(3, "1.7.104") + struct.pack("<I", 1)
              + struct.pack("<I", 5) + b"1.6.0" + b"\x00\x00\x00"
              + struct.pack("<I", 1) + struct.pack("<QI", 12, 0x1500))
    check("T23.dec-v3", C._table_header(v3blob) == (3, "1.7.104", 20),
          repr(C._table_header(v3blob)))
    v1blob = b"TRTL" + struct.pack("<I", 1) + struct.pack("<I", 0)
    check("T23.dec-v1", C._table_header(v1blob) == (1, None, 8),
          repr(C._table_header(v1blob)))
    check("T23.dec-bad", C._table_header(b"junk") is None
          and C._table_header(b"TRTL" + struct.pack("<I", 9)) is None
          and C._table_header(b"TRTL" + struct.pack("<I", 3)) is None,
          "rejects junk")
    # merge preserves the v3 stamp and refuses sig-cached v2 rows
    plug23 = tmp / "plug23"
    (plug23 / "CompaSSE").mkdir(parents=True)
    t23 = bytearray(v3blob)
    (plug23 / "CompaSSE" / "translation_table.bin").write_bytes(bytes(t23))
    dropped23, total23 = C.merge_translation_block(plug23, "9.9.10", [(13, 0x1600)])
    raw23 = (plug23 / "CompaSSE" / "translation_table.bin").read_bytes()
    check("T23.merge-stamp", C._table_header(raw23)[:2] == (3, "1.7.104")
          and total23 == 2, f"total={total23}")
    (plug23 / "CompaSSE" / "translation_table.bin").write_bytes(
        b"TRTL" + struct.pack("<I", 2) + struct.pack("<I", 0))
    try:
        C.merge_translation_block(plug23, "9.9.10", [(13, 0x1600)])
        check("T23.merge-v2-refuse", False, "merged sig rows!")
    except RuntimeError:
        check("T23.merge-v2-refuse", True, "")

    # ---------------------------------------------------------------- T24: table stamp
    plug24 = tmp / "plug24"
    (plug24 / "CompaSSE").mkdir(parents=True)
    t24 = plug24 / "CompaSSE" / "translation_table.bin"
    t24.write_bytes(C._encode_table_header(3, "1.6.1170")
                    + struct.pack("<I", 0))
    check("T24.stamp", C.table_build_stamp(plug24) == "1.6.1170",
          repr(C.table_build_stamp(plug24)))
    t24.write_bytes(b"TRTL" + struct.pack("<I", 1)
                    + struct.pack("<I", 0))
    check("T24.legacy", C.table_build_stamp(plug24) is None, "legacy: no warn")
    t24.write_bytes(b"junk")
    check("T24.junk", C.table_build_stamp(plug24) is None, "junk: no warn")
    (plug24 / "CompaSSE" / "translation_table.bin").unlink()
    check("T24.missing", C.table_build_stamp(plug24) is None, "missing: no warn")
    (plug24 / "CompaSSE" / "translation_table.bin").write_bytes(
        C._encode_table_header(3, "1.6.1170") + struct.pack("<I", 0))
    check("T24.state-ok", C.table_state(plug24, "1.6.1170") == ("ok", "1.6.1170"),
          repr(C.table_state(plug24, "1.6.1170")))
    (plug24 / "CompaSSE" / "translation_table.bin").write_bytes(
        C._encode_table_header(3, "1.7.104") + struct.pack("<I", 0))
    check("T24.state-stale", C.table_state(plug24, "1.6.1170") == ("stale", "1.7.104"),
          repr(C.table_state(plug24, "1.6.1170")))
    (plug24 / "CompaSSE" / "translation_table.bin").write_bytes(
        b"TRTL" + struct.pack("<I", 1) + struct.pack("<I", 0))
    check("T24.state-legacy", C.table_state(plug24, "1.6.1170") == ("legacy", None),
          repr(C.table_state(plug24, "1.6.1170")))
    (plug24 / "CompaSSE" / "translation_table.bin").unlink()
    check("T24.state-absent", C.table_state(plug24, "1.6.1170") == ("absent", None),
          repr(C.table_state(plug24, "1.6.1170")))

    # ---------------------------------------------------------------- T21: V5 enforcement gate
    check("T21.new-enforces", C._v5_enforced((1, 7, 104)) is True, "1.7.104")
    check("T21.new99", C._v5_enforced((1, 7, 99)) is True, "1.7.99")
    check("T21.old-skip", C._v5_enforced((1, 6, 1170)) is False, "1.6.1170")
    check("T21.veryold", C._v5_enforced((1, 5, 97)) is False, "1.5.97")
    check("T21.unknown", C._v5_enforced(None) is True, "None=enforce")

    # ---------------------------------------------------------------- T22: old-runtime verdicts
    # Synthetic SKSE plugins: version struct hosted in .rdata.
    from datetime import datetime, timezone as _tz

    def make_plugin(path, indep, ex, compat, year):
        e_lfanew = 0x80
        spec = [(".text", 0x1000, 0x200, 0x400, 0x200),
                (".rdata", 0x2000, 0x600, 0x600, 0x600),
                (".edata", 0x3000, 0x200, 0xC00, 0x200)]
        ts = int(datetime(year, 6, 1, tzinfo=_tz.utc).timestamp())
        blob = bytearray(make_pe64(spec, export=(0x3000, 0x200), timestamp=ts))
        struct.pack_into("<I", blob, 0x600 + 0x304, ex)
        struct.pack_into("<I", blob, 0x600 + 0x308, indep)
        for i, v in enumerate(compat[:16]):
            struct.pack_into("<I", blob, 0x600 + 0x30C + i * 4, v)
        eo = 0xC00
        struct.pack_into("<I", blob, eo + 24, 1)
        struct.pack_into("<I", blob, eo + 28, 0x3040)
        struct.pack_into("<I", blob, eo + 32, 0x3050)
        struct.pack_into("<I", blob, eo + 36, 0x3060)
        struct.pack_into("<I", blob, eo + 0x40, 0x2000)
        struct.pack_into("<I", blob, eo + 0x50, 0x3070)
        struct.pack_into("<H", blob, eo + 0x60, 0)
        blob[eo + 0x70:eo + 0x70 + 18] = b"SKSEPlugin_Version\x00"
        path.write_bytes(bytes(blob))

    r1170 = (1 << 24) | (6 << 16) | (1170 << 4)
    # A: pre-2025 AddressLibrary, Ex=0, built for 1.6.640, on 1.6.1170.
    pa = tmp / "t22a.dll"
    make_plugin(pa, 0x1, 0x0, [old19], 2023)
    via = C.check_version_independence(pa, r1170)
    va = G.classify(C.analyze_plugin(pa, r1170, include_hooks=False), 2023, r1170)
    aa = C._audit_plugin(pa, r1170)
    check("T22a.gate", via["needs_indep"] is False, repr(via["needs_indep"]))
    check("T22a.gui", va["cat"] == "OK", va["cat"])
    check("T22a.audit", aa["verdict"] == "SAFE", aa["verdict"])
    # ...but the same DLL on 1.7.104 IS enforced.
    via19 = C.check_version_independence(pa, r19)
    check("T22a.enforced-new", via19["needs_indep"] is True, "1.7.104 flags it")
    # B: signature scanner, no compat. Never DANGEROUS/BROKEN.
    pb = tmp / "t22b.dll"
    make_plugin(pb, 0x2, 0x0, [], 2023)
    vb = G.classify(C.analyze_plugin(pb, r1170, include_hooks=False), 2023, r1170)
    ab = C._audit_plugin(pb, r1170)
    check("T22b.gui", vb["cat"] == "OK", vb["cat"])
    check("T22b.audit", ab["verdict"] == "SAFE", ab["verdict"])
    # C: version-locked, built for and declaring 1.6.1170. Leave alone.
    pc = tmp / "t22c.dll"
    make_plugin(pc, 0x0, 0x0, [r1170], 2024)
    vc = G.classify(C.analyze_plugin(pc, r1170, include_hooks=False), 2024, r1170)
    ac = C._audit_plugin(pc, r1170)
    check("T22c.gui", vc["cat"] == "OK" and "leave it alone" in vc["why"], vc["cat"])
    check("T22c.audit", ac["verdict"] == "SAFE", ac["verdict"])
    # D: declares 1.7.104 across structural breaks -> MANUAL.
    pd = tmp / "t22d.dll"
    make_plugin(pd, 0x0, 0x0, [old19, r19], 2023)
    ad = C._audit_plugin(pd, r19)
    check("T22d.audit-manual", ad["verdict"] == "MANUAL", ad["verdict"])
    vd = G.classify(C.analyze_plugin(pd, r19, include_hooks=False), 2023, r19)
    check("T22d.gui-manual", vd["cat"] == "MANUAL", vd["cat"])
    # F: correct flags, declares 1.7.104, built for 1.6.640 -> MANUAL.
    pf = tmp / "t22f.dll"
    make_plugin(pf, 0x5, 0x2, [old19, r19], 2023)
    vf = G.classify(C.analyze_plugin(pf, r19, include_hooks=False), 2023, r19)
    check("T22f.gui-manual", vf["cat"] == "MANUAL" and "test in-game" in vf["why"],
          vf["cat"])
    # E: --fix must not touch working old-runtime Ex bytes.
    pe = tmp / "t22e.dll"
    make_plugin(pe, 0x1, 0x0, [old19], 2023)
    before = pe.read_bytes()
    acts = C.fix_plugin(pe, None, None, None, runtime_version=r1170, dry_run=False)
    check("T22e.no-rewrite", pe.read_bytes() == before, repr(acts))
    check("T22e.skip-note", any("pre-V5 runtime" in a for a in acts), repr(acts))

    # ---------------------------------------------------------------- T29: downgrade (mod newer than game)
    pn = tmp / "t29n.dll"
    make_plugin(pn, 0x5, 0x2, [r19], 2025)
    an = C._audit_plugin(pn, old19)
    check("T29.audit", an["verdict"] == "MANUAL" and "newer" in an["reason"],
          an["verdict"] + " | " + an["reason"])
    vn = G.classify(C.analyze_plugin(pn, old19, include_hooks=False), 2025, old19)
    check("T29.gui", vn["cat"] == "MANUAL" and "newer" in vn["why"]
          and not vn["needs_fix"], vn["cat"])
    before29 = pn.read_bytes()
    acts29 = C.fix_plugin(pn, None, None, None, runtime_version=old19, dry_run=False)
    check("T29.noop", pn.read_bytes() == before29 and not acts29, repr(acts29))

    # ---------------------------------------------------------------- T26: one operation at a time
    seq26 = []
    w26 = G.BusyState()
    w26.listen(lambda working, desc: seq26.append((working, desc)))
    check("T26.acquire", w26.acquire() is True and seq26 == [(True, "Working...")],
          repr(seq26))
    check("T26.refuse", w26.acquire() is False and seq26 == [(True, "Working...")],
          repr(seq26))
    check("T26.busy", w26.busy is True, "")
    w26.release()
    check("T26.release", seq26 == [(True, "Working..."), (False, "")]
          and w26.busy is False, repr(seq26))
    check("T26.desc", w26.acquire("Checking x...") is True
          and seq26[-1] == (True, "Checking x..."), repr(seq26[-1]))
    w26.set_desc("Checking y...")
    check("T26.set-desc", seq26[-1] == (True, "Checking y..."), repr(seq26[-1]))
    w26.set_desc("idle-note")
    w26.release()
    check("T26.reacquire", w26.busy is False, "stuck locked")
    try:
        import tkinter as tk
        _r26 = tk.Tk()
        _r26.withdraw()
    except Exception as _e:
        check("T26.gui-skip", True, f"no display ({_e})")
    else:
        _app26 = G.AutoPorterGUI(_r26)
        check("T26.free", _app26.work.busy is False, "")
        check("T26.lock", _app26.work.acquire() is True
              and str(_app26.scan_btn.cget("state")) == "disabled",
              "scan clickable mid-work")
        check("T26.title-busy",
              _r26.title() == f"CompaSSE v{G.core.VERSION} - Working...",
              _r26.title())
        _app26.work.release()
        check("T26.unlock", str(_app26.scan_btn.cget("state")) == "normal",
              "scan stuck disabled")
        check("T26.title-idle", _r26.title() == f"CompaSSE v{G.core.VERSION}",
              _r26.title())
        import tkinter.font as _tkfont
        _f26 = _tkfont.Font(family="TkDefaultFont", size=11, weight="bold")
        _t26, _cut26 = G._ellipsize(_f26, "short.dll")
        check("T26.short", _t26 == "short.dll" and _cut26 is False, repr(_t26))
        _long26 = "x" * 200 + ".dll"
        _t26b, _cut26b = G._ellipsize(_f26, _long26)
        check("T26.long", _cut26b is True and _t26b.endswith("...")
              and _f26.measure(_t26b) <= G.NAME_PX, repr(_t26b[-12:]))
        _lp = Path("verylong_" + "n" * 150 + ".dll")
        _lpc = G.PendingCard(_r26, _lp, on_scan=lambda *a: None)
        check("T26.tip-cut", _lpc.name_lbl.cget("text").endswith("...")
              and bool(_lpc.name_lbl.bind("<Enter>")),
              _lpc.name_lbl.cget("text")[-12:])
        from types import SimpleNamespace as _NS
        _lpc._on_name_resize(_NS(width=120))
        _t26c = _lpc.name_lbl.cget("text")
        check("T26.refit-cut", _t26c.endswith("...")
              and _lpc._font.measure(_t26c) <= 120, repr(_t26c[-12:]))
        _lpc._on_name_resize(_NS(width=10000))
        check("T26.refit-full", _lpc.name_lbl.cget("text") == _lp.name,
              _lpc.name_lbl.cget("text")[-12:])
        _spc = G.PendingCard(_r26, Path("short.dll"), on_scan=lambda *a: None)
        check("T26.tip-full", _spc.name_lbl.cget("text") == "short.dll"
              and not _spc.name_lbl.bind("<Enter>"),
              _spc.name_lbl.cget("text"))
        _f26 = {"dll_path": Path("x.dll"), "id_val": 1, "func_rva": 0x1000,
                "old_offset": 0x10, "new_offset": 0x20, "auto_fixable": True}
        _hc = G.HealerCard(_r26, _f26, None, [], on_heal=lambda *a: None)
        _hc.set_working(True)
        check("T26.heal-lock", str(_hc.heal_btn.cget("state")) == "disabled", "")
        _hc.set_working(False)
        check("T26.heal-back", str(_hc.heal_btn.cget("state")) == "normal", "")
        _hc.mark_fixed(True, "")
        _hc.set_working(True)
        _hc.set_working(False)
        check("T26.fixed-stays", str(_hc.heal_btn.cget("state")) == "disabled",
              "fixed button re-enabled")
        _b26 = {"uid": 0x12345678,
                "chunks": [{"type": 0x504C474E, "version": 0,
                            "length": 0, "offset": 0}]}
        _sc = G.SurgeonCard(_r26, Path("s.skse"), _b26, None, 100,
                            on_drop=lambda *a: None)
        _sc.set_working(True)
        check("T26.drop-lock", str(_sc.drop_btn.cget("state")) == "disabled", "")
        _sc.set_working(False)
        check("T26.drop-back", str(_sc.drop_btn.cget("state")) == "normal", "")
        _r26.destroy()

    # ---------------------------------------------------------------- T27: list + per-card scan
    try:
        import tkinter as tk
        _r27 = tk.Tk()
        _r27.withdraw()
    except Exception as _e:
        check("T27.gui-skip", True, f"no display ({_e})")
    else:
        import time as _time
        _fake = tmp / "fakegame"
        _plug27 = _fake / "Data" / "SKSE" / "Plugins"
        _plug27.mkdir(parents=True)
        (_fake / "SkyrimSE.exe").write_bytes(b"")
        for _n in ("a.dll", "b.dll", "c.dll"):
            (_plug27 / _n).write_bytes(make_pe64(
                [(".text", 0x1000, 0x100, 0x400, 0x100)]))
        _app27 = G.AutoPorterGUI(_r27)
        _app27.game_exe = _fake / "SkyrimSE.exe"

        check("T27.list", _app27.list_dlls() is True
              and sum(isinstance(c, G.PendingCard) for c in _app27.cards) == 3,
              f"{len(_app27.cards)} cards")
        check("T27.pending-text", "3 not checked yet" in _app27.c_other.cget("text"),
              _app27.c_other.cget("text"))
        check("T27.scan-all-label", _app27.scan_btn.cget("text") == "Scan all",
              _app27.scan_btn.cget("text"))

        _errs27 = []
        _orig27 = G.messagebox.showerror
        G.messagebox.showerror = lambda *a, **k: _errs27.append(a)
        _res27 = {"done": False}
        try:
            _first = _app27.cards[0]
            _app27._scan_single(_first)
            _deadline27 = _time.time() + 20.0

            def _tick27():
                if _res27["done"]:
                    return
                replaced = not any(
                    isinstance(c, G.PendingCard)
                    and c.dll_path == _first.dll_path
                    for c in _app27.cards)
                settled = replaced and not _app27.work.busy
                if not settled and _time.time() < _deadline27:
                    _r27.after(50, _tick27)
                    return
                _res27["single"] = replaced and not _app27.work.busy
                _second = next((c for c in _app27.cards
                                if isinstance(c, G.PendingCard)), None)
                if _second is not None and _app27.work.acquire():
                    _app27._scan_single(_second)
                    _res27["refuse"] = (
                        _second in _app27.cards
                        and isinstance(_second, G.PendingCard)
                        and _app27.work.busy)
                    _app27.work.release()
                else:
                    _res27["refuse"] = None
                _res27["done"] = True
                _r27.quit()

            _r27.after(50, _tick27)
            _r27.after(25000, _r27.quit)
            _r27.mainloop()
            check("T27.single", _res27.get("single") and not _errs27,
                  f"errs={_errs27} res={_res27}")
            check("T27.single-count",
                  "2 not checked yet" in _app27.c_other.cget("text"),
                  _app27.c_other.cget("text"))
            check("T27.scan-data",
                  any(d == _first.dll_path for d, _, _ in _app27._scan_data),
                  "missing entry")
            check("T27.refuse", _res27.get("refuse") is True,
                  f"res={_res27}")
        finally:
            G.messagebox.showerror = _orig27
        _r27.destroy()

    # ---------------------------------------------------------------- T25: notice vs old game
    # Withdrawn root + real 1.6.1170 exe + legacy table: the yellow
    # notice must appear (this stayed silent before the legacy fix).
    try:
        import tkinter as tk
        _root = tk.Tk()
        _root.withdraw()
    except Exception as _e:
        check("T25.gui-skip", True, f"no display ({_e})")
    else:
        import compasse_gui as _G
        from pathlib import Path as _P
        _old = _P(r"C:\Users\Lemis\AppData\Local\Temp\opencode\oldexe\SkyrimSE-1.6.1170.exe.unpacked.exe")
        _packed = C.runtime_version_from_exe(_old) if _old.exists() else None
        _game = C.unpack_version(_packed) if _packed else None
        if _game is None:
            check("T25.gui-skip", True, "old exe unreadable")
        else:
            _gs = f"{_game[0]}.{_game[1]}.{_game[2]}"
            _plug = tmp / "plug25"
            (_plug / "CompaSSE").mkdir(parents=True)
            (_plug / "CompaSSE" / "translation_table.bin").write_bytes(
                b"TRTL" + struct.pack("<I", 1) + struct.pack("<I", 0))
            _app = _G.AutoPorterGUI(_root)
            _app.game_exe = _old
            _app._check_table_stamp(_plug)
            _root.update_idletasks()
            check("T25.legacy-shows",
                  _app.notice_frame.winfo_manager() == "pack"
                  and _gs in _app.notice_lbl.cget("text"),
                  _app.notice_lbl.cget("text"))
            (_plug / "CompaSSE" / "translation_table.bin").write_bytes(
                C._encode_table_header(3, _gs) + struct.pack("<I", 0))
            _app._check_table_stamp(_plug)
            _root.update_idletasks()
            check("T25.match-hides",
                  _app.notice_frame.winfo_manager() == "", "still packed")
            (_plug / "CompaSSE" / "translation_table.bin").write_bytes(
                C._encode_table_header(3, "9.9.9") + struct.pack("<I", 0))
            _app._check_table_stamp(_plug)
            _root.update_idletasks()
            check("T25.stale-shows",
                  _app.notice_frame.winfo_manager() == "pack"
                  and "9.9.9" in _app.notice_lbl.cget("text"),
                  _app.notice_lbl.cget("text"))
        _root.destroy()

    # ---------------------------------------------------------------- T28: game version line
    _old28 = Path(r"C:\Users\Lemis\AppData\Local\Temp\opencode\oldexe\SkyrimSE-1.6.1170.exe.unpacked.exe")
    if _old28.exists():
        check("T28.version", G.game_version_line(_old28) ==
              f"Game: {_old28.name} (1.6.1170)", G.game_version_line(_old28))
    else:
        check("T28.version-skip", True, "no old exe around")
    check("T28.none", G.game_version_line(None) == "Game: SkyrimSE.exe",
          G.game_version_line(None))
    _empty28 = tmp / "empty28.exe"
    _empty28.write_bytes(b"")
    check("T28.unreadable", G.game_version_line(_empty28) == "Game: empty28.exe",
          G.game_version_line(_empty28))

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    sys.exit(1 if FAIL else 0)

if __name__ == "__main__":
    main()
