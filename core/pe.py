"""PE sections, exports, and disassembly."""
import struct

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, x86
    HAS_CAPSTONE = True
except ImportError:
    Cs = CS_ARCH_X86 = CS_MODE_64 = x86 = None
    HAS_CAPSTONE = False

def capstone_md(detail=True):
    """Return an x64 disassembler. None without capstone."""
    if not HAS_CAPSTONE:
        return None
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = detail
    return md

def pe_build_dt(dll_path):
    """Build timestamp as UTC datetime. None if missing."""
    try:
        from datetime import datetime, timezone
        with open(dll_path, "rb") as f:
            hdr = f.read(0x400)
        pe_off = struct.unpack_from("<I", hdr, 0x3C)[0]
        if pe_off + 8 > len(hdr) or hdr[pe_off:pe_off + 4] != b"PE\x00\x00":
            return None
        ts = struct.unpack_from("<I", hdr, pe_off + 8)[0]
        if not ts:
            return None
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except Exception:
        return None

# ---------------------------------------------------------------------------
# PE helpers
# ---------------------------------------------------------------------------
def find_pe_sections(data):
    """Section table. [] if the bytes are not a PE."""
    try:
        return _find_pe_sections(data)
    except Exception:
        return []

def _find_pe_sections(data):
    if len(data) < 0x40:
        return []
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew < 0 or e_lfanew + 6 > len(data):
        return []
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
    # Clamp bad headers to 16 dirs.
    if not 0 < num_dd <= 32:
        num_dd = 16
    sec_start = dd_start + num_dd * 8
    sections = []
    for i in range(num_sections):
        s = sec_start + i * 40
        name = data[s:s + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize = struct.unpack_from("<I", data, s + 8)[0]
        vaddr = struct.unpack_from("<I", data, s + 12)[0]
        rawoff = struct.unpack_from("<I", data, s + 20)[0]
        rawsize = struct.unpack_from("<I", data, s + 16)[0]
        sections.append((name, vaddr, vsize, rawoff, rawsize))
    return sections

def rva_to_offset(rva, sections):
    for name, vaddr, vsize, rawoff, rawsize in sections:
        # Include disk padding. vsize alone misses tail RVAs.
        if vaddr <= rva < vaddr + max(vsize, rawsize):
            return rawoff + (rva - vaddr)
    return None

def iat_range(data):
    """Import address table range. None if missing."""
    try:
        if len(data) < 0x40:
            return None
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        opt = e_lfanew + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        if magic == 0x20B:
            dd = opt + 112
        elif magic == 0x10B:
            dd = opt + 96
        else:
            return None
        rva, size = struct.unpack_from("<II", data, dd + 12 * 8)
        if not rva or not size:
            return None
        return (rva, rva + size)
    except Exception:
        return None

def find_export_rva(data, sections, export_name_bytes):
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:
        dd_start = opt + 112
    elif magic == 0x10B:
        dd_start = opt + 96
    else:
        return None
    export_rva = struct.unpack_from("<I", data, dd_start)[0]
    if export_rva == 0:
        return None
    export_off = rva_to_offset(export_rva, sections)
    if export_off is None:
        return None
    num_names = struct.unpack_from("<I", data, export_off + 24)[0]
    addr_names = struct.unpack_from("<I", data, export_off + 32)[0]
    addr_ords = struct.unpack_from("<I", data, export_off + 36)[0]
    addr_funcs = struct.unpack_from("<I", data, export_off + 28)[0]
    names_off = rva_to_offset(addr_names, sections)
    ords_off = rva_to_offset(addr_ords, sections)
    funcs_off = rva_to_offset(addr_funcs, sections)
    if not all([names_off, ords_off, funcs_off]):
        return None
    for i in range(num_names):
        name_rva = struct.unpack_from("<I", data, names_off + i * 4)[0]
        name_off = rva_to_offset(name_rva, sections)
        if name_off is None:
            continue
        if data[name_off:name_off + len(export_name_bytes)] == export_name_bytes:
            ord_idx = struct.unpack_from("<H", data, ords_off + i * 2)[0]
            return struct.unpack_from("<I", data, funcs_off + ord_idx * 4)[0]
    return None

# ---------------------------------------------------------------------------
# Hook detection (REL::ID + offset + pattern)
# ---------------------------------------------------------------------------
def get_functions_from_pdata(data, sections):
    pdata = None
    for name, vaddr, vsize, rawoff, rawsize in sections:
        if name == ".pdata":
            pdata = (vaddr, rawoff, rawsize)
            break
    if not pdata:
        return []
    pvaddr, prawoff, prawsize = pdata
    funcs = []
    for i in range(0, prawsize, 12):
        begin = struct.unpack_from("<I", data, prawoff + i)[0]
        end = struct.unpack_from("<I", data, prawoff + i + 4)[0]
        if begin and end and end > begin:
            funcs.append((begin, end))
    return funcs

# ---------------------------------------------------------------------------
# Pattern scan in game exe
# ---------------------------------------------------------------------------
def load_exe_sections(exe_path):
    with open(exe_path, "rb") as f:
        exe = f.read()
    sections = find_pe_sections(exe)
    return exe, sections
