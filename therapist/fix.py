"""Version flags and guarded byte patches."""
import struct
from pathlib import Path
from core.backups import backup_bytes
from core.pe import HAS_CAPSTONE, capstone_md, find_export_rva, find_pe_sections, rva_to_offset, x86
from core.touched import add_touched
from core.versions import FLAG_STRUCT_OFFSET, KVIEX_ADDR_LIB_V5, KVI_ADDR_LIB_POST_AE, KVI_STRUCTS_POST629, KVI_TARGET, VERSION_INDEP_OFFSET

def _record_touch(dll_path):
    """Record one fixed DLL."""
    try:
        add_touched(Path(dll_path).parent, dll_path)
    except Exception:
        pass

def patch_flag(dll_path):
    """Set versionIndependenceEx 0->2. Returns True if patched."""
    data = bytearray(open(dll_path, "rb").read())
    sections = find_pe_sections(data)
    rva = find_export_rva(data, sections, b"SKSEPlugin_Version")
    struct_off = rva_to_offset(rva, sections)
    flag_off = struct_off + FLAG_STRUCT_OFFSET
    if struct.unpack_from("<I", data, flag_off)[0] != 0:
        return False
    struct.pack_into("<I", data, flag_off, 2)
    backup_bytes(dll_path, bytes(data))
    _record_touch(dll_path)
    return True

def patch_version_independence(dll_path):
    """Set version flags so SKSE accepts the plugin. Returns True if patched."""
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
    _record_touch(dll_path)
    return True

def patch_flag_force(dll_path):
    """Set versionIndependenceEx to 2 even if set. Returns True if changed."""
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
    _record_touch(dll_path)
    return old != 2

def patch_version_independence_force(dll_path):
    """Set version flags even if set. Returns True if changed."""
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
    _record_touch(dll_path)
    return (old_indep != new_indep) or (old_flag != new_flag)

def _find_imm_at(data, off):
    """Find the immediate covering off. Returns (off, size, value) or None."""
    if not HAS_CAPSTONE:
        return None
    md = capstone_md()
    starts = [off] + list(range(max(0, off - 15), off))
    for start in starts:
        try:
            insns = list(md.disasm(bytes(data[start:start + 15]), start))
        except Exception:
            continue
        if not insns or insns[0].address != start:
            continue
        ins = insns[0]
        enc = getattr(ins, "encoding", None)
        if enc is None or getattr(enc, "imm_size", 0) <= 0:
            continue
        for op in ins.operands:
            if op.type != x86.X86_OP_IMM:
                continue
            io = start + enc.imm_offset
            isz = enc.imm_size
            if io < 0 or io + isz > len(data):
                continue
            if start == off or (io <= off < io + isz):
                val = int.from_bytes(bytes(data[io:io + isz]), "little")
                return (io, isz, val)
    return None

def resolve_bytes_site(dll_path, loc_kind, loc, width, insn_check=False):
    """Resolve a byte site to (file_off, width, value)."""
    try:
        with open(dll_path, "rb") as f:
            data = bytes(f.read())
    except OSError:
        return (None, None, None)
    sections = find_pe_sections(data)
    if loc_kind == "rva":
        off = rva_to_offset(loc, sections)
    elif loc_kind == "file":
        off = loc
    else:
        return (None, None, None)
    if off is None or off < 0 or off >= len(data):
        return (None, None, None)
    if insn_check:
        found = _find_imm_at(data, off)
        if found is None:
            return (None, None, None)
        off, isz, cur = found
        if width is not None and isz != width:
            return (None, None, None)
        return (off, isz, cur)
    if width not in (1, 4):
        return (None, None, None)
    if off + width > len(data):
        return (None, None, None)
    cur = int.from_bytes(data[off:off + width], "little")
    return (off, width, cur)

def patch_bytes_guarded(dll_path, loc_kind, loc, width, old, new,
                        insn_check=False):
    """Write new bytes only if current bytes match old. Returns True if patched."""
    try:
        off, eff_width, cur = resolve_bytes_site(
            dll_path, loc_kind, loc, width, insn_check)
    except Exception:
        return False
    if off is None or cur != old:
        return False
    width = eff_width
    try:
        with open(dll_path, "rb") as f:
            data = bytearray(f.read())
    except OSError:
        return False
    if new < 0 or new >= 256 ** width:
        return False
    data[off:off + width] = new.to_bytes(width, "little")
    if int.from_bytes(bytes(data[off:off + width]), "little") != new:
        return False
    backup_bytes(dll_path, bytes(data))
    _record_touch(dll_path)
    return True
