"""Flag and version checks."""
import struct
from core.pe import find_export_rva, find_pe_sections, rva_to_offset
from core.versions import FLAG_STRUCT_OFFSET, KVIEX_ADDR_LIB_V5, KVI_ADDR_LIB_POST_AE, KVI_KNOWN, KVI_SIGNATURES, KVI_STRUCTS_POST629, VERSION_INDEP_OFFSET, _BUILD_TIME_CUTOFF, _BUILD_TIME_SENTINEL, _v5_enforced, unpack_version
from therapist.scan import find_hooks

try:
    from core.const import COMPAT_LIST_OFFSET as _OFF_FLAG
except ImportError:  # core.const not yet merged; struct layout fallback
    _OFF_FLAG = 0x30C

# ---------------------------------------------------------------------------
# Layer 1: flag patch
# ---------------------------------------------------------------------------
def check_flag(dll_path):
    """Flag status. None if not an SKSE plugin."""
    with open(dll_path, "rb") as f:
        data = bytearray(f.read())
    sections = find_pe_sections(data)
    if not sections:
        return None
    rva = find_export_rva(data, sections, b"SKSEPlugin_Version")
    if rva is None:
        return None
    struct_off = rva_to_offset(rva, sections)
    if struct_off is None:
        return None
    flag_off = struct_off + FLAG_STRUCT_OFFSET
    if flag_off + 4 > len(data):
        return None
    flag_val = struct.unpack_from("<I", data, flag_off)[0]
    return {
        "name": dll_path.name,
        "flag_off": flag_off,
        "flag_val": flag_val,
        "needs_patch": flag_val == 0,
    }

# ---------------------------------------------------------------------------
# Layer 1b: versionIndependence patch
# ---------------------------------------------------------------------------
def check_version_independence(dll_path, runtime_version=None):
    """Flag values and patch need. None if not an SKSE plugin."""
    with open(dll_path, "rb") as f:
        data = f.read()
    sections = find_pe_sections(data)
    if not sections:
        return None
    rva = find_export_rva(data, sections, b"SKSEPlugin_Version")
    if rva is None:
        return None
    struct_off = rva_to_offset(rva, sections)
    if struct_off is None:
        return None

    indep_off = struct_off + VERSION_INDEP_OFFSET
    flag_off = struct_off + FLAG_STRUCT_OFFSET
    compat_off = struct_off + _OFF_FLAG
    if indep_off + 4 > len(data) or flag_off + 4 > len(data):
        return None

    indep_val = struct.unpack_from("<I", data, indep_off)[0]
    indep_ex_val = struct.unpack_from("<I", data, flag_off)[0]

    runtime_ver = None
    if compat_off + 4 <= len(data):
        first_compat = struct.unpack_from("<I", data, compat_off)[0]
        if first_compat != 0:
            runtime_ver = first_compat

    compat_list = []
    for ci in range(16):
        co = compat_off + ci * 4
        if co + 4 > len(data):
            break
        v = struct.unpack_from("<I", data, co)[0]
        if v == 0:
            break
        compat_list.append(v)

    has_addr = bool(indep_val & KVI_ADDR_LIB_POST_AE)
    has_sigs = bool(indep_val & KVI_SIGNATURES)
    has_structs = bool(indep_val & KVI_STRUCTS_POST629)
    has_ex_v5 = bool(indep_ex_val & KVIEX_ADDR_LIB_V5)
    has_unknown = bool(indep_val & ~KVI_KNOWN)

    build_time = 0
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 8 < len(data):
        build_time = struct.unpack_from("<I", data, pe_off + 8)[0]

    # SKSE rejects when PostAE is set without V5, or when the runtime
    # is missing from compatibleVersions.
    run_tup = unpack_version(runtime_version) if runtime_version else None
    pre_cutoff = _BUILD_TIME_SENTINEL <= build_time < _BUILD_TIME_CUTOFF
    if has_addr:
        needs_indep = pre_cutoff and not has_ex_v5 \
            and _v5_enforced(run_tup)
    elif has_sigs and not has_unknown:
        needs_indep = False
    else:
        needs_indep = bool(compat_list) and runtime_version is not None \
            and runtime_version not in compat_list

    return {
        "indep_val": indep_val,
        "indep_ex_val": indep_ex_val,
        "has_addr": has_addr,
        "has_sigs": has_sigs,
        "has_unknown": has_unknown,
        "needs_indep": needs_indep,
        "pre_cutoff": pre_cutoff,
        "has_ex_v5": has_ex_v5,
        "runtime_ver": runtime_ver,
        "compat": compat_list,
    }

def analyze_plugin(dll_path, runtime_version=None, include_hooks=True):
    """Analyze a single plugin. Returns dict with flag + versionIndependence + hooks info.

    include_hooks=False skips the capstone disassembly pass (seconds per
    DLL) for fast scans; callers run find_hooks on demand at fix time.
    """
    info = {"name": dll_path.name, "flag": None, "version_indep": None, "hooks": [],
            "hooks_scanned": include_hooks}
    flag = check_flag(dll_path)
    if flag is not None:
        info["flag"] = flag
    vi = check_version_independence(dll_path, runtime_version)
    if vi is not None:
        info["version_indep"] = vi
    if include_hooks:
        info["hooks"] = find_hooks(dll_path)
    return info
