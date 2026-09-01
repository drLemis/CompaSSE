# CompaSSE
**Reanimate old SKSE plugins for current Skyrim Special Edition. Or at least try to.**

This is a simple tool that occasionally fixes outdated Skyrim Script Extender (SKSE) plugins, allowing them to run on modern game runtimes without waiting for mod authors to recompile them.

## The Problem
Skyrim updates break plugins. When a new game version releases, plugins built for the old runtime are automatically rejected by SKSE and fail to load. This happens for three main reasons:
1.  **Missing version independence flag**: CommonLibNG plugins often lack the `versionIndependenceEx` flag, causing SKSE to reject them, because there is no way to tell if they will even work on the new version.
2.  **Incompatible version declaration**: Plugins declare a specific game version they support. When the game updates, this declaration no longer matches, and SKSE refuses to load them.
3.  **Stale offsets**: Some plugins use `REL::ID(n) + hardcoded offset` for pattern checks. After a game update, these offsets become stale, breaking the plugin's internal logic. The AddressLibrary.dll been out for years, but before that - it was wild out there. And here we are now.

## The Solution
CompaSSE applies three fix layers to "broken" SKSE plugins:
1.  **Flag Patch**: Corrects the `versionIndependenceEx` flag to `AddressLibraryV5` (0x2), which is required for modern SKSE. This will allow SKSE to at least load it properly.
2.  **Version Independence Patch**: Overrides the plugin's version declaration, marking it as compatible with all post-AE (1.6.629+) runtimes and skipping build-time compatibility checks.
3.  **Offset/Pattern Fix**: Automatically resolves stale offsets via Address Library, scans the game executable for the correct pattern, and patches the plugin to use the updated displacement.
Additionally, it can convert format 5 Address Library bins to format 2, allowing older plugins to parse them, but if you're that deep - there is something so wrong at this point that you should never trust some random too from The Internetz to do that.

## Prerequisites
*   Python 3.6+
*   A lotta free time and an itch for old mods on your modern Skyrim release.
### Optional prerequisites
*   `capstone` library for hook detection (install via `pip install capstone`). The flag and version independence patches work without it.

## Commands
```bash
# Scan plugins to see what needs fixing (dry run)
python compasse.py --scan <plugins_dir>

# Fix all plugins in a directory (requires game exe and Address Library)
python compasse.py --fix <plugins_dir> --game <SkyrimSE.exe> --addresslib <versionlib.bin>

# Analyze a single DLL
python compasse.py --dll <plugin.dll> --scan
python compasse.py --dll <plugin.dll> --fix --game <exe> --addresslib <bin>
```
Or just run the CompaSSE.exe like everyone does.

## Building from source
The release is a single self-contained EXE built with [PyInstaller](https://pyinstaller.org/) and the shim DLL.

Prerequisites: Python 3.x, `pip install pyinstaller`.

```powershell
.\build_release.ps1
```

Output lands in `release\`:

```
release/
├─ CompaSSE-<version>.zip          <- same content, distribution convenience
├─ CompaSSE.exe                    <- user-usable main tool
└─ Data/SKSE/Plugins/
   └─ _AddressLibraryShim.dll      <- unmodified, shipped as-is
```

The shim DLL is intentionally **not** embedded - it ships unchanged beside the
EXE and is consumed by SKSE at game runtime, never extracted or modified by
the tool. Later its source code will be published, as I'll be satisfied by it.

### Reproducible builds
`build_release.ps1` pins the build timestamp (`SOURCE_DATE_EPOCH`) and Python
hash seed (`PYTHONHASHSEED`), so two builds from the same source tree produce
**byte-identical** EXEs. Verify with:

```powershell
(Get-FileHash release/CompaSSE.exe -Algorithm SHA256).Hash
```

This keeps AV engine reputation stable across builds: one clean scan of a
released hash stays clean for that hash instead of resetting on every rebuild.

### Why signed EXEs matter (AV / VirusTotal)
The tool's job is patching game/DLL binaries, which reads as suspicious to AV
heuristics by nature. The release deliberately avoids the classic malware
signatures: no obfuscation, no UPX, no runtime modification of shipped files,
and backups go to a dedicated subfolder rather than next to the originals.
An unsigned EXE will still occasionally trip reputation-based engines
if a release scans flagged, submit it as a false positive to the vendor
(Microsoft, Bitdefender) with the source link.

## Secret sauce
This is bundled with custom-made DLL for rerouting different versions of AddressLibrary calls from a pool of DLLs to proper instructions, so the outdated library presenting itself as modern can actually get proper addresses instead of the modern ones. Don't ask how it works. It is awful under the hood. I will throw it into garbage one day, but it is yet to come.
