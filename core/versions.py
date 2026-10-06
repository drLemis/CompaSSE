"""Game versions and SKSE flag values."""
from core.const import FLAG_STRUCT_OFFSET, VERSION_INDEP_OFFSET
from core.pe import pe_build_dt

__all__ = [
    "VERSION",
    "KVI_ADDR_LIB_POST_AE",
    "KVI_SIGNATURES",
    "KVI_STRUCTS_POST629",
    "KVI_KNOWN",
    "KVI_TARGET",
    "KVIEX_ADDR_LIB_V5",
    "STRUCTURAL_CUTOFFS",
    "FLAG_STRUCT_OFFSET",
    "VERSION_INDEP_OFFSET",
    "crossed_cutoffs",
    "_built_before_1_7_99",
    "built_before_1_7_99",
    "_v5_enforced",
    "v5_enforced",
    "runtime_version_from_exe",
    "unpack_version",
    "_packed_to_ver",
    "packed_to_ver",
    "compat_match",
]

VERSION = "2.0.0"

# versionIndependence flags (from SKSE64 PluginManager.cpp)
KVI_ADDR_LIB_POST_AE = 1 << 0

KVI_SIGNATURES = 1 << 1

KVI_STRUCTS_POST629 = 1 << 2

KVI_KNOWN = KVI_ADDR_LIB_POST_AE | KVI_SIGNATURES | KVI_STRUCTS_POST629

KVI_TARGET = KVI_ADDR_LIB_POST_AE | KVI_STRUCTS_POST629  # 0x5

# versionIndependenceEx flags
KVIEX_ADDR_LIB_V5 = 1 << 1  # 0x2

# Breaks no flag patch can fix.
STRUCTURAL_CUTOFFS = ((1, 6, 653), (1, 6, 1130), (1, 7, 99))

def crossed_cutoffs(declared, running):
    """Cutoffs between declared and running. [] if unknown."""
    if not declared or not running:
        return []
    if declared < (1, 5, 0) or running < (1, 5, 0):
        return []
    return [c for c in STRUCTURAL_CUTOFFS if declared < c <= running]

# SKSE rejects these builds without V5 when PostAE is set.
_BUILD_TIME_SENTINEL = 520128000      # 1986-06-19 (sentinel "no timestamp")

_BUILD_TIME_CUTOFF = 1748217600       # 2025-05-26

# 1.7.99 layout change. Old builds may crash on 1.7.99+.
_CUTOFF_1_7_99_TS = 1786579200        # 2026-08-20 00:00 UTC

def _built_before_1_7_99(dll_path):
    try:
        import datetime
        dt = pe_build_dt(dll_path)
        if dt is None:
            return False
        return dt.timestamp() < _CUTOFF_1_7_99_TS
    except Exception:
        return False

def built_before_1_7_99(dll_path):
    """True if the DLL build predates 1.7.99."""
    return _built_before_1_7_99(dll_path)

# Old SKSE never checks Ex: only 1.7+ enforces the V5 scheme.
_V5_ENFORCED_FROM = (1, 7, 0)

def _v5_enforced(running):
    """True if this game version requires V5 flags."""
    if running is None:
        return True
    return tuple(running[:3]) >= _V5_ENFORCED_FROM

def v5_enforced(running):
    """True if this game version requires V5 flags."""
    return _v5_enforced(running)

# Offsets live in core.const; re-exported here for backwards compatibility.

def runtime_version_from_exe(exe_path):
    """Packed game version from the exe. None if unreadable."""
    try:
        import ctypes
        from ctypes import wintypes
        ver = ctypes.windll.version
        size = ver.GetFileVersionInfoSizeW(str(exe_path), None)
        if not size:
            return None
        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(str(exe_path), 0, size, buf):
            return None
        vsffi = wintypes.DWORD()
        vslen = wintypes.UINT()
        ptr = ctypes.c_void_p()
        if not ver.VerQueryValueW(buf, "\\", ctypes.byref(ptr), ctypes.byref(vslen)):
            return None
        ffi = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_uint32 * 13)).contents
        # VS_FIXEDFILEINFO: [2]=ffileversionMS (major, minor), [3]=LS (build, rev)
        major = ffi[2] >> 16
        minor = ffi[2] & 0xFFFF
        build = ffi[3] >> 16
        rev = ffi[3] & 0xFFFF
        return (major << 24) | (minor << 16) | (build << 4) | rev
    except Exception:
        return None

def unpack_version(packed):
    """Packed int to (major, minor, build)."""
    if packed is None: return None
    return (packed >> 24, (packed >> 16) & 0xFF, (packed >> 4) & 0xFFF)

def compat_match(compat, runtime_version):
    """Match level of runtime in compat list. None if no match."""
    if runtime_version is None or not compat:
        return None
    if runtime_version in compat:
        return "exact"
    masked = runtime_version & ~0xF
    if any((v & ~0xF) == masked for v in compat):
        return "rev"
    return None

def _packed_to_ver(packed):
    """Packed int to M.m.b.r string."""
    return f"{packed >> 24}.{((packed >> 16) & 0xFF)}.{((packed >> 4) & 0xFFF)}.{packed & 0xF}"

def packed_to_ver(packed):
    """Packed int to M.m.b.r string."""
    return _packed_to_ver(packed)
