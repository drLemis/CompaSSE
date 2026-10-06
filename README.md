# CompaSSE

Every Skyrim SE update moves engine functions around or removes them. CompaSSE keeps outdated mods alive.

It has two parts:
- `CompaSSE.exe` patches old plugins on disk so SKSE loads them.
- `!CompaSSE.dll` sits in `Data/SKSE/Plugins/` and hands each mod the offsets it expects.

This only helps mods built with CommonLibSSE that read through Address Library.
It will not fix mods built with the old SKSE headers. Those need new code from the author. Hardcoded addresses only get fixed when Porter finds a single safe match.

## How to use it
Open the Therapist tab in `CompaSSE.exe`:

1. Press Scan all, read the verdict on each card.
2. Press Fix on the ones marked fixable.
3. Press Undo if a mod behaves worse after the fix.

If a hook matches in several places, CompaSSE checks the called function before it picks one. It leaves the rest for you to review though. You can learn more in [DLL/README.md](DLL/README.md).

## How it works

SKSE reads the `SKSEPlugin_Version` struct in each plugin. It wants bit 0x2 set at offset +0x304, and bits 0x1 and 0x4 set at offset +0x308. A lot of old plugins lack them, so we patch it in files.

After that the mod opens its address library bin. Old readers cannot parse the new bins format, so the shim watches the "open file" call. It automatically hands modern format 5 readers the real file, and hands format 1 and 2 readers a temp file in the format they parse. It also swaps in translated offsets for the current game version if any known.

## Build it

You need Visual Studio Build Tools and Python 3.

```powershell
# Build the shim first. Run this from the DLL folder.
cd DLL
cmd /c build_shim.bat
cd ..

# Then build the app bundle
.\build_release.ps1
```

## Files

- `compasse_gui.py` holds the main window
- `core/` holds PE, version, and library code
- `therapist/` holds scan and fix code for the Therapist tab
- `healer/` checks one mod for stale hook offsets
- `surgeon/` trims plugin blocks from `.skse` saves
- `porter/` lists hardcoded addresses and patches matched rows
- `DLL/` holds the shim source. Start with `DLL/README.md`
