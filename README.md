# CompaSSE

## TL;DR

Skyrim SE keeps getting updates. Every update breaks old SKSE mods because
the addresses where game functions live change. Mod authors have to recompile
their mods for each update, and most don't.

CompaSSE fixes this. It has two parts that work together:

1. **CompaSSE.exe** patches mods on disk so SKSE accepts them (fixes the
   "must be recompiled" error)
2. **!CompaSSE.dll** intercepts address library reads at runtime
   so mods get the right function offsets for the current game version

Run the patcher once, drop the shim in, and old mods work again.

**If a mod was built with CommonLibSSE and uses Address Library (most modern
mods), CompaSSE makes it work. If a mod has hardcoded offsets or uses the
old SKSE library, nothing can help - it needs a rewrite by the author.**

---

## What it does

CompaSSE fixes outdated Skyrim Script Extender (SKSE) plugins so they load
on modern game runtimes without waiting for mod author recompiles. It has
two components that solve different parts of the problem:

### 1. CompaSSE.exe - patches mods on disk

A Python CLI/GUI that fixes the version flags SKSE checks during load:

- **Audit** - checks each plugin against compatibility rules and gives a
  verdict: SAFE / NEEDS FIX / BROKEN / UNKNOWN
- **Fix** - patches `versionIndependenceEx` and `versionIndependence` flags
  so SKSE accepts the plugin (fixes "must be recompiled" errors)
- **Scan** - shows current flag status without changes

```bash
# Audit all plugins - shows which are safe, which need fixes, which are dead
python compasse.py --audit --plugins-dir <dir>

# Scan and show flag status
python compasse.py --scan --plugins-dir <dir>

# Apply fixes (requires game exe + address library)
python compasse.py --fix --plugins-dir <dir> --game SkyrimSE.exe --addresslib versionlib.bin

# Build translation table (auto-detects paths from game exe location)
python compasse.py --build-translations --game SkyrimSE.exe --plugins-dir <dir>
```

### 2. !CompaSSE.dll - serves correct offsets at runtime

A C++ DLL placed in `Data/SKSE/Plugins/` that hooks Windows APIs. Even
after flag patching, old mods still read the wrong offsets from the address
library because the format or version changed. The shim intercepts these
reads and serves compatible data.

Both components are needed: the patcher fixes what SKSE checks, the shim
fixes what the mods read.

See [DLL/README.md](DLL/README.md) for the full technical breakdown.

## Compatibility rules

A mod is safe if and only if:
1. It was built with **CommonLibSSE** (not the old `skse_github/common` lib)
2. It uses **Address Library** for function lookups (`REL::ID`)
3. The game functions it calls **still exist** in the current version

**Red flags**: hardcoded offsets, old `skse_github/common` library, no
`SKSEPlugin_Version` export. These mods are usually dead without a rewrite.

## Quick deploy

```powershell
# 1. Patch mods on disk (fixes "must be recompiled" errors)
python compasse.py --fix --plugins-dir "D:\...\Data\SKSE\Plugins" `
    --game "D:\...\SkyrimSE.exe" `
    --addresslib "D:\...\Data\SKSE\Plugins\versionlib-1-7-104-0.bin"

# 2. Deploy the shim DLL (serves correct offsets at runtime)
.\DLL\deploy.ps1

# Or do both at once:
.\DLL\deploy.ps1 -Kill -Launch
```

## How it works (TL;DR)

### Step 1: Flag patching (CompaSSE.exe)

SKSE checks each plugin's `SKSEPlugin_Version` export for two flags:
- `versionIndependenceEx` at offset +0x304 must have bit 0x2
- `versionIndependence` at offset +0x308 must have bits 0x1 | 0x4

Old mods don't have these flags set. CompaSSE.exe patches them on disk so
SKSE accepts the plugin during its two-pass load.

### Step 2: Address library serving (shim DLL)

After SKSE loads a patched mod, the mod opens the address library bin to
look up function offsets. The shim intercepts this read and serves a
compatible version based on what the mod can parse:
- Format 5 callers (commonlibsse-ng) get the real file
- Format 2 callers (most mods) get a transcoded temp file
- Format 1 callers (old CommonLibSSE) get a transcoded temp file

The shim also applies cross-version translation tables so mods get the
offsets they expect for the current game version.

## Building from source

Prerequisites: Visual Studio Build Tools (MSVC), Python 3.x

```powershell
# Build the shim DLL (from the DLL folder: the script uses relative paths)
cd DLL
cmd /c build_shim.bat
cd ..

# Build the release bundle (PyInstaller + shim DLL)
.\build_release.ps1
```

## Project structure
```
CompaSSE/
+- compasse.py              # CLI tool (audit/scan/fix)
+- compasse_gui.py          # GUI tool (per-mod cards)
+- skse_healer.py           # Stale-offset detector/healer (also a GUI tab)
+- test_detect.py           # Synthetic self-check: python test_detect.py
+- CompaSSE.spec            # PyInstaller spec for GUI exe
+- build_release.ps1        # Release bundle builder
+- DLL/
|  +- deploy.ps1            # Build + deploy automation
|  +- build_shim.bat        # MSVC build script
|  +- main.cpp              # DLL entry, SKSE exports, crash VEH
|  +- hooks.cpp             # All 13 API hooks, serve logic, translation
|  +- hooks.h               # Hook interface
|  +- decoder_detect.cpp    # Import-based format detection
|  +- transcode.cpp         # Format transcoding (0/1/2/5)
|  +- minhook/              # MinHook library (hooking framework)
|  +- README.md             # Full technical documentation
+- README.md                # This file
```
