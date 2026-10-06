"""Offsets and limits shared by core and tools."""
# SKSEPlugin_Version struct field offsets (bytes from struct base).
FLAG_STRUCT_OFFSET = 0x304  # versionIndependenceEx field
VERSION_INDEP_OFFSET = 0x308  # versionIndependence field
COMPAT_VERSIONS_OFFSET = 0x30C  # compatibleVersions[0] field

# Healer pattern-scan heuristics (see healer/analysis.py).
MOV_IMM32_MIN = 0x100  # MOV EBX, imm32 values below this are noise
MOV_IMM32_MAX = 0x100000  # values above this are addresses, not IDs
FUNC_SCAN_SIZE = 0x20000  # default window for CALL/MOV pattern search

# Therapist hook-scan limits (see therapist/scan.py).
PATTERN_SCAN_RANGE = 0x1000  # scan offsets 0..0x1000 for the pattern
MAX_FUNC_SIZE = 0x10000  # functions larger than this are skipped

# PE section characteristics flag (IMAGE_SCN_MEM_EXECUTE).
PE_EXECUTE_FLAG = 0x20000000
IMAGE_SCN_MEM_EXECUTE = PE_EXECUTE_FLAG  # alias for porter/engine.py

# DOS header offset to PE signature.
DOS_E_LFANEW = 0x3C
COMPAT_LIST_OFFSET = COMPAT_VERSIONS_OFFSET  # alias for therapist/audit.py
