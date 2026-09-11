# AddressLibrary Shim DLL - Technical Documentation

A runtime shim that intercepts Skyrim SE address library reads and patches
plugin version flags at load time, so plugins compiled for older game
versions work on the current runtime. No disk patching of individual mods
needed - everything happens in memory when SKSE loads each plugin.

## Table of Contents

1. [Overview](#overview)
2. [How SKSE Loads Plugins](#how-skse-loads-plugins)
3. [The Address Library Problem](#the-address-library-problem)
4. [Architecture](#architecture)
5. [Hook Chain (13 hooks)](#hook-chain-13-hooks)
6. [Address Library Formats](#address-library-formats)
7. [Format Detection (Decoder)](#format-detection-decoder)
8. [Serve Logic](#serve-logic)
9. [Translation](#translation)
10. [GetProcAddress + LoadLibrary Hooks](#getprocaddress--loadlibrary-hooks)
11. [MessageBox Interception](#messagebox-interception)
12. [Crash VEH](#crash-veh)
13. [Deployment](#deployment)
14. [Log File Reference](#log-file-reference)
15. [Known Limitations](#known-limitations)

---

## Overview

When Skyrim SE updates, its address library changes. Plugins compiled for
older runtimes either get rejected by SKSE (version check fails) or read the
wrong offsets (address library mismatch). CompaSSE solves both problems:

1. **CompaSSE.exe** patches the version flags on disk so SKSE accepts the
   plugin (fixes "must be recompiled" errors)
2. **This shim DLL** hooks file APIs at runtime to serve compatible address
   library data so the plugin gets the right function offsets

Both are needed: the patcher fixes what SKSE checks, the shim fixes what
the mods read.

## How SKSE Loads Plugins

SKSE's plugin loader works in two passes:

### Pass 1: Version check (via GetProcAddress)
For each `.dll` in `Data/SKSE/Plugins/`, SKSE calls:
```c
GetProcAddress(hModule, "SKSEPlugin_Version");
```
This returns a pointer to a `SKSEPluginVersionData` struct exported by the
plugin. SKSE checks two fields:
- `versionIndependenceEx` (offset `+0x304`): must have bit `0x2` set
  (`AddressLibraryV5`) for modern runtimes
- `versionIndependence` (offset `+0x308`): must have bits `0x1 | 0x4` set
  (`AddressLibrary | Structs`)

If these flags are missing, SKSE shows "must be recompiled" and rejects the
plugin.

**Some plugins bypass GetProcAddress** - SKSE reads the version struct
directly from the PE export table (e.g. dosemetha.dll). The shim's
LoadLibrary hooks catch these by patching flags at module-load time.

### Pass 2: Plugin initialization
If the version check passes, SKSE calls the plugin's `SKSEPlugin_Load`
export. The plugin initializes and typically opens the address library file
(`versionlib-X-Y-Z-W.bin` or `version-X-Y-Z-W.bin`) to look up function
offsets for the current runtime.

### Where it breaks
Old plugins may have:
1. Missing version flags -> SKSE rejects them (our GetProcAddress + LoadLibrary
   hooks fix this)
2. Correct flags but wrong format reader -> they open the library file but
   can't parse the format (our serve logic fixes this)
3. Correct flags, correct format, but stale offsets -> they read the library
   but get wrong addresses (our translation table fixes this)

## The Address Library Problem

Skyrim SE's Address Library has evolved through multiple binary formats:

| Format | Name             | Structure                              | Used by                              |
|--------|------------------|----------------------------------------|--------------------------------------|
|   0    | Fixed entries    | 16-byte records (8-bit head + offset)  | Very old mods                        |
|   1    | Delta-compressed | Header + compressed entries            | CommonLibSSE 1.5.x (SE mode)         |
|   2    | Sorted pairs     | Header + sorted {id, offset} pairs     | CommonLibSSE 1.6.x / commonlibsse-ng |
|   5    | Dense array      | 96-byte header + u32[offset_table[id]] | CommonLibSSE-ng (AE mode), IAL       |

Each AddressLibrary version ships a `versionlib-X-Y-Z-W.bin` file
(format 5, ~565K entries) and optionally a `version-X-Y-Z-W.bin` file
(format 1, ~395K entries). The format 5 file is denser and faster to
parse, but older plugins only understand format 1 or 2.

## Architecture

```
+------------------------------------------------------------+
|                    Skyrim SE Process                       |
|                                                            |
|  +----------+   +----------+   +----------+   +--------+   |
|  | Plugin A |   | Plugin B |   | Plugin C |   |  SKSE  |   |
|  | (V2 fmt) |   | (V1 fmt) |   | (V5 fmt) |   |        |   |
|  +----+-----+   +----+-----+   +----+-----+   +---+----+   |
|       |              |              |             |        |
| ------+--------------+--------------+-------------+--------|
|       |              |              |             |        |
|  +----v--------------v--------------v-------------v-----+  |
|  |           !CompaSSE.dll (13 hooks)                   |  |
|  |                                                      |  |
|  |  GetProcAddress hook                                 |  |
|  |    Patches SKSEPlugin_Version flags so SKSE          |  |
|  |    accepts old plugins                               |  |
|  |                                                      |  |
|  |  LoadLibraryW/A/ExW + LdrLoadDll hooks               |  |
|  |    Catch plugins SKSE inspects directly from         |  |
|  |    the export table (bypassing GetProcAddress)       |  |
|  |                                                      |  |
|  |  CreateFileW / CreateFileA / CreateFile2             |  |
|  |  CreateFileMappingW / NtCreateFile / NtOpenFile      |  |
|  |    Intercept address library file opens              |  |
|  |    Determine caller's format capability              |  |
|  |    Serve compatible temp file                        |  |
|  |                                                      |  |
|  |  MessageBoxW/A hooks                                 |  |
|  |    Log all error dialogs for diagnosis               |  |
|  |    Pass through unchanged (no suppression)           |  |
|  |                                                      |  |
|  |  Crash VEH                                           |  |
|  |    Log access violations with module info +          |  |
|  |    register dump                                     |  |
|  +------------------------------------------------------+  |
|                         |                                  |
|  -----------------------+----------------------------------|
|                         |                                  |
|  +----------------------v-------------------------------+  |
|  |              Temp files in %TEMP%                    |  |
|  |  !CompaSSE_{pid}_fmt0.bin                            |  |
|  |  !CompaSSE_{pid}_fmt1.bin                            |  |
|  |  !CompaSSE_{pid}_fmt2.bin                            |  |
|  |  !CompaSSE_{pid}_fmt5.bin                            |  |
|  +------------------------------------------------------+  |
+------------------------------------------------------------+
```

### File structure

| File                 | Purpose                                                                             |
|----------------------|-------------------------------------------------------------------------------------|
| `main.cpp`           | DLL entry point, `SKSEPlugin_Version` export, `SKSEPlugin_Load`, crash VEH          |
| `hooks.cpp`          | All 13 API hooks, serve logic, format selection, translation                      |
| `hooks.h`            | Public interface: `install_hooks`, `uninstall_hooks`, `set_self`, `shim_log`        |
| `decoder_detect.cpp` | PE import analysis to detect what address library format a plugin can parse         |
| `decoder_detect.h`   | `DecoderType` enum, `detect_decoder`, `resolve_caller_module`, `decoder_for_module` |
| `transcode.cpp`      | Format transcoding: parse/encode format 0, 1, 2, 5                                  |
| `transcode.h`        | Transcoder API                                                                      |
| `build_shim.bat`     | MSVC build script                                                                   |
| `deploy.ps1`         | Build + deploy automation                                                           |

## Hook Chain (13 hooks)

The shim installs 13 hooks via [MinHook](https://github.com/TsudaKageyu/minhook):

### File API hooks (6)

| Hook                 | Target       | Purpose                                          |
|----------------------|--------------|--------------------------------------------------|
| `CreateFileW`        | kernel32.dll | Primary interception point for Win32 callers     |
| `CreateFileA`        | kernel32.dll | ANSI fallback (rarely used by plugins)           |
| `CreateFile2`        | kernel32.dll | WinRT/UWP path (defensive)                       |
| `CreateFileMappingW` | kernel32.dll | Catches callers that map the real file handle    |
| `NtCreateFile`       | ntdll.dll    | NT-level interception for mods that bypass Win32 |
| `NtOpenFile`         | ntdll.dll    | NT-level interception (same as NtCreateFile)     |

### Module-load hooks (4)

| Hook             | Target       | Purpose                                              |
|------------------|--------------|------------------------------------------------------|
| `GetProcAddress` | kernel32.dll | Patches `SKSEPlugin_Version` flags at runtime        |
| `LoadLibraryW`   | kernel32.dll | Patches flags on load (catches export-table readers) |
| `LoadLibraryA`   | kernel32.dll | ANSI variant                                         |
| `LoadLibraryExW` | kernel32.dll | Extended variant                                     |
| `LdrLoadDll`     | ntdll.dll    | Catches ntdll-level loads (bypasses kernel32)        |

### Diagnostic hooks (2)

| Hook             | Target       | Purpose                                       |
|------------------|--------------|-----------------------------------------------|
| `MessageBoxW`    | user32.dll   | Logs all error dialogs for diagnosis          |
| `MessageBoxA`    | user32.dll   | Logs all error dialogs (ANSI)                 |

### Hook installation order

All hooks are created during `DllMain(DLL_PROCESS_ATTACH)`, then enabled
atomically via `MH_EnableHook(MH_ALL_HOOKS)`. The `SKSEPlugin_Load` export
also calls `install_hooks` as a safety net (with a guard against double-init).

### Reentrancy guards

Three boolean guards prevent infinite recursion:
- **`g_loading`**: Set while `ensure_buffers()` reads the real bin file.
  Prevents `CreateFileW -> NtCreateFile -> CreateFileW` loops.
- **`g_serving_alt`**: Set while `serve_versionlib` opens the alt path
  (versionlib-*.bin when caller requested version-*.bin). Same purpose.
- **`g_ntRedirecting`** (thread-local): Set during `NtCreateFile ->
  CreateFileW` redirect. The NT call internally calls Win32, which would
  re-enter our hook.

## Address Library Formats

### Format 0 - Fixed entries
```
Header: magic(4) + version(16) + name(N) + ptr_size(4)
Entries: { id(8 bytes), offset(8 bytes) } repeated
```
Simple but large. Used by very old plugins before CommonLibSSE.

### Format 1 - Delta-compressed
```
Header: magic(4) + version(16) + name(N) + ptr_size(4)
Entries: type_byte + compressed delta-encoded {id, offset} pairs
```
The "legacy SE" format. Files named `version-X-Y-Z-W.bin`.
Used by CommonLibSSE compiled without AE support.

### Format 2 - Sorted pairs
```
Header: magic(4) + version(16) + name(N) + ptr_size(4)
Entries: type_byte + compressed delta-encoded {id, offset} pairs
```
The "universal" format. Works with most CommonLibSSE versions.
Intermediate format for transcoding - everything can read it.

### Format 5 - Dense array
```
Header: 96 bytes (magic + version + name + ptr_size + count)
Data: u32 offset_table[count]  (index = ID, value = offset)
```
The "modern" format. Files named `versionlib-X-Y-Z-W.bin`.
Smallest file size (~2.2MB for 565K entries vs ~14MB for format 1/2).
Only CommonLibSSE-ng with AE support can read this.

### Format sizes for Skyrim SE 1.7.104

| Format | File                     | Size             | Entry count |
|--------|--------------------------|------------------|-------------|
|   1    | version-1-7-104-0.bin    | 3,570,871 bytes  | 395,946     |
|   2    | (transcoded from fmt5)   | ~9,200,000 bytes | ~435,000+   |
|   5    | versionlib-1-7-104-0.bin | 2,263,132 bytes  | 565,759     |

The format 1 file has fewer entries because it only includes IDs that have
non-zero offsets in the current runtime. Format 5 includes ALL IDs (zeros
for unmapped ones). Format 2 is transcoded from the non-zero fmt5 entries
(~435K on 1.7.104) with translation-table remaps applied on top.

## Format Detection (Decoder)

The shim determines what format each plugin can parse by analyzing its PE
import table. This happens in `decoder_detect.cpp`.

### Import-based heuristic

| Imports                                  | Detected as  | Format served  |
|------------------------------------------|--------------|----------------|
| `CreateFileMapping*` + `istream` symbols | `DECODER_V5` | Format 5       |
| `CreateFileMapping*` only (no istream)   | `DECODER_V2` | Format 2       |
| `istream` symbols only (no mmap)         | `DECODER_V1` | Format 2       |
| Neither                                  | `DECODER_V2` | Format 2 (def) |

**Why this works:** CommonLibSSE's address library reader evolved alongside
its I/O strategy:
- Old CommonLibSSE (1.5.x): reads the bin via `std::ifstream` -> format 1
- Mid CommonLibSSE (1.6.x): reads via `std::ifstream` -> format 2
- New commonlibsse-ng: memory-maps the file -> format 5
- po3_PapyrusExtender: memory-maps without istream -> format 2

The import table captures this evolution because the I/O method is baked in
at compile time. Note: even DECODER_V1 callers get served format 2 because
format 2 is a superset that all CommonLibSSE versions can parse.

### Caller resolution

`resolve_caller_module()` uses `RtlCaptureStackBackTrace` to walk the call
stack from inside the hook, skipping the shim's own frames and system DLLs
(ntdll, kernel32, msvcrt, etc.), to find the plugin module that triggered
the hook.

When the stack walk fails (returns null), the shim defaults to format 2 -
the most broadly compatible format.

### Caching

Decoder detection results are cached per-module in a static hash map with a
critical section. The PE import analysis runs only once per plugin.

## Serve Logic

When a plugin opens an address library file, the serve chain works as follows:

### 1. Path matching

`is_versionlib_path()` checks if the filename matches:
- `versionlib-X-Y-Z-W.bin` (any caller)
- `version-X-Y-Z-W.bin` (any caller)

Both patterns are intercepted.

### 2. SKSE pass-through

If the caller is identified as `skse64*.dll`, the real file is served
unmodified. SKSE itself needs the actual address library.

### 3. Format prefix routing

**`versionlib-` prefix (most plugins):**
- `DECODER_V5` -> pass-through (real fmt5 file)
- `DECODER_V2` -> format 2 (transcoded temp file)
- `DECODER_V1` or `DECODER_NONE` -> format 2 (default, most compatible)

**`version-` prefix (old SE plugins):**
- If the path matches the **current runtime** version (e.g. contains
  "1-7-104"): serve transcoded format 1 from the temp file
- If it's an **old version**: pass through directly (real file is already
  format 1)

The current runtime is detected by extracting the version string from the
bin filename and storing it in `g_currentVersion`.

### 4. Buffer building

`ensure_buffers()` lazily reads the real bin file and builds in-memory
buffers for all four formats:

```
Real .bin (fmt5) ---+--- g_fmt5 (raw copy)
                    +--- g_fmt5_patched (translated offsets)
                    +--- g_fmt2 (transcoded, translations applied)
                    +--- g_fmt1 (transcoded from fmt2)
                    +--- g_fmt0 (transcoded from fmt2)
```

When the source is format 1/2, the process is similar but starts from fmt2
and transcodes up to fmt5.

### 5. Temp file materialization

`ensure_temp_file(format)` writes the in-memory buffer to a temp file:
```
%TEMP%\!CompaSSE_{pid}_fmt{0,1,2,5}.bin
```

Temp files are created once per process and reused for all callers that
need the same format.

### 6. Handle redirect

The hook returns a handle to the temp file instead of the real file. The
caller reads the temp file as if it were the real address library.

### Format selection summary

```
Caller requests versionlib-*.bin
+- Caller is SKSE -> pass-through (real file)
+- Caller is V5 (mmap + istream) -> pass-through (real fmt5 file)
+- Caller is V2 (default for null caller) -> fmt2 temp file
+- Caller is V1 (istream only) -> fmt2 temp file
+- Unknown -> fmt2 temp file

Caller requests version-*.bin
+- Current runtime version -> transcoded fmt1 temp file
+- Old version -> pass-through (real file is already fmt1)
```

## Translation

No old-bin merging happens at serve time: legacy readers get the current
runtime's data, transcoded, with translation-table remaps applied. Old
game versions feed the system one step earlier - `CompaSSE.exe
--build-translations` mints the remap rows from old bins plus old-exe
ground truth (see the main README).

### Translation table

`CompaSSE\translation_table.bin` is a binary file containing cross-version ID
remappings. Located in `Data/SKSE/Plugins/CompaSSE/` subfolder.

Format:
```
"TRTL" magic
u32 format_version (1)
u32 version_count
For each version:
  u32 version_string_len
  char version_string[len] (padded to 4-byte alignment)
  u32 entry_count
  For each entry:
    u64 old_id
    u32 new_offset
```

Generated by `compasse.exe --build-translations`. Each entry maps an old
version's ID to the correct offset in the current game binary.

### Format 5 patching

For format 5 callers, the shim creates `g_fmt5_patched` - a copy of the
raw format 5 file with translated offsets patched in-place.
This is a surgical modification: only the u32 values at positions
`96 + id * 4` are changed. The file structure, header, and entry count
remain identical, so format 5 readers parse it without noticing the
modification.

## GetProcAddress + LoadLibrary Hooks

### GetProcAddress hook

The `Hook_GetProcAddress` function intercepts all `GetProcAddress` calls in
the process. When it detects a lookup for `"SKSEPlugin_Version"`, it
patches the returned struct's version flags:

```cpp
// versionIndependenceEx at +0x304: set AddressLibraryV5 (0x2)
*(uint32_t*)(raw + 0x304) |= 0x2;
// versionIndependence at +0x308: set AddressLibrary | Structs (0x5)
*(uint32_t*)(raw + 0x308) |= 0x5;
```

This makes SKSE accept plugins that were compiled without the modern
version flags, without modifying the DLL files on disk.

### LoadLibrary + LdrLoadDll hooks

Some plugins bypass GetProcAddress - SKSE reads the version struct directly
from the PE export table (e.g. dosemetha.dll). The LoadLibrary hooks catch
these by calling `patch_skse_version_flags()` on every newly loaded module.

The four hooks cover all DLL load paths:
- `LoadLibraryW` / `LoadLibraryA` / `LoadLibraryExW` (kernel32.dll)
- `LdrLoadDll` (ntdll.dll) - catches loads that bypass kernel32 entirely

**Performance:** All version-check hooks are lightweight - they only activate
for `SKSEPlugin_Version` lookups (GetProcAddress) or once per module load
(LoadLibrary/LdrLoadDll).

## MessageBox Interception

Both `MessageBoxW` and `MessageBoxA` are hooked to log all error dialogs.
Every MessageBox call is written to the log with caption and first 200 chars
of text, for post-mortem diagnosis.

MessageBox calls are **not suppressed** - they pass through and display
normally. The hook only adds logging.

## Crash VEH

A Vectored Exception Handler is installed during `SKSEPlugin_Load` to log
access violations with diagnostic information:

- Faulting module name and offset (resolved via `GetModuleHandleExW`)
- Full register dump (RAX through R15)
- Debug events (0x4001xxxx) are suppressed - the game raises these during
  normal init and passing them through kills the process silently

The VEH does **not** suppress real exceptions - it logs and re-throws via
`EXCEPTION_CONTINUE_SEARCH`.

## Deployment

### Manual build
```cmd
cd DLL
cmd /c build_shim.bat
```
Output: `DLL\build\!CompaSSE.dll`

### Automated deploy
```powershell
.\DLL\deploy.ps1                     # build + deploy
.\DLL\deploy.ps1 -Kill -Launch       # kill + build + deploy + launch
.\DLL\deploy.ps1 -NoBuild -Kill      # skip build, deploy last
.\DLL\deploy.ps1 -DryRun             # preview only
```

### DLL naming

The shim must be deployed under the name `!CompaSSE.dll`

ASCII sort: `'!'` (0x21) < `'A'` (0x41), so `!CompaSSE.dll`
is loaded before any other properly named DLL.

## Log File Reference

The shim writes a log file at:
```
Data/SKSE/Plugins/!CompaSSE.log
```

### Log entry format
```
[YYYY-MM-DD HH:MM:SS.mmm] pid=PROCESS_ID message
```

### Key log messages

| Message | Meaning |
|---------|---------|
| `install_hooks: CreateFileW ok` | Hook installed successfully |
| `install_hooks: enable ok` | All hooks enabled |
| `GetProcAddress: patched SKSEPlugin_Version flags for module at ADDR` | Version flags patched |
| `loadtime LoadLibraryW: patched SKSEPlugin_Version mod=...` | Flags patched at load time |
| `serve VERSIONLIB -> format N (transcoded) for MODULE` | Temp file served |
| `serve PATH -> pass-through for SKSE (MODULE)` | SKSE gets the real file |
| `load_translations: loaded N remapped IDs from N version tables` | Translation table loaded |
| `MessageBoxW intercepted! caption=X text=Y` | Error dialog logged |

## Known Limitations

### Caller identification
Some mods call address library APIs through syscall stubs or deeply inlined
code, causing `resolve_caller_module()` to return null. In these cases the
shim defaults to format 2. If a mod needs a different format and can't be
identified, it will fail.

### Translation table coverage
The translation table covers known ID remappings between major game versions.
IDs not in the table may have stale offsets after a game update.

### Thread safety
The serve logic uses an SRW lock (`g_lock`) to protect buffer building and
temp file materialization. Format selection and handle creation happen
outside the lock. This is safe for the single-threaded plugin loading
phase but could race if plugins spawn threads that open the address library
concurrently.

### Temp files
Temp files persist until process exit (cleaned up in `uninstall_hooks`).
If the game crashes, orphaned temp files remain in `%TEMP%`. They are
small (~2-14MB) and harmless.
