# !CompaSSE.dll

If you updated Skyrim and half your load order died with `must be recompiled`, this is the part that brings it back.

The DLL loads first because of the `!` in its name. It watches SKSE load your mods. When a mod asks for version info - it patches the answer in memory. When a mod opens the address library it hands over a copy that mod can actually read. Your mod files stay untouched. You will still find temp bins and a log where the shim works, but nothing in `Data` gets rewritten by this DLL.

## How a mod loads, and where it dies

SKSE walks `Data/SKSE/Plugins/` and does two passes per DLL.

First it asks for `SKSEPlugin_Version` with `GetProcAddress`. It wants bit 0x2 at +0x304 and bits 0x1 and 0x4 at +0x308. No flags means rejection on the spot because DLL is not an SKSE-compatible mod. Some mods never go through `GetProcAddress` at all though - SKSE is able to read their export table direct. Such mods can be identified and worked with via `LoadLibrary` hook.

Then SKSE calls `SKSEPlugin_Load` on each mod. The mod opens `versionlib-X-Y-Z-W.bin` or `version-X-Y-Z-W.bin` and starts resolving IDs - that is the point of second and third failure. An old reader chokes on a new bin format, or it parses fine and still gets wrong addresses because the game engine chunks moved.

## Formats

| Format | Who reads it | File looks like |
|---|---|---|
| 0 | Ancient stuff | Fixed 16-byte records |
| 1 | CommonLibSSE 1.5.x | `version-*.bin` |
| 2 | CommonLibSSE 1.6.x | Sorted pairs |
| 5 | commonlibsse-ng | `versionlib-*.bin`, dense array |

## The hooks

MinHook does the work. Everything gets created in `DllMain`, `SKSEPlugin_Load` runs the install again in case something loaded early, with a guard so it never inits twice.

| Hook | Where | Why it exists |
|---|---|---|
| `CreateFileW` | kernel32 | Most mods open the bin here |
| `CreateFileA` | kernel32 | ANSI stragglers |
| `CreateFile2` | kernel32 | WinRT path |
| `CreateFileMappingW` / `A` | kernel32 | Mods that map instead of reading |
| `OpenFileMappingW` / `A` | kernel32 | Mostly logging, tells you who mapped what |
| `MapViewOfFile` | kernel32 | Catches the view itself |
| `NtCreateFile` / `NtOpenFile` | ntdll | For mods that skip Win32 entirely |

Module loads, 5 total. `GetProcAddress` patches flags on lookup. `LoadLibraryW`, `LoadLibraryA`, `LoadLibraryExW`, and `LdrLoadDll` patch flags when a module appears, whichever road it took in.

Dialogs, 2 total. `MessageBoxW` and `MessageBoxA` just log. They never block the popup, so leave your hopes there. You will see caption plus 200 chars in the log and that is it.

Reentry is the annoying part. Three guards handle it:
* `g_loading` is set while we read the real bin ourselves;
* `g_serving_alt` covers the case where we open the other prefix on your behalf;
* `g_ntRedirecting` is thread-local for the Nt call that reenters Win32 underneath.

## Figuring out what a mod can read

Mapped file plus `istream` smells like V5. Mapped file alone smells like V2. Plain `istream` smells like V1. No info means we play safe with fmt2 and hope for the best.

Imports lie on commonlibsse-ng 3.7 and older, cache code pulls in mapping calls it never uses for bins. So we also grep `.rdata` and `.data` for literal strings. V5 strings mean a dual reader that usually handles both, and it keeps the real file with `dualV5=1` in the log. No CommonLib strings at all means some custom minimal loader, (hello Display Tweaks and friends), and that keeps the real file too. Only a proven legacy reader gets the temp, CommonLib strings present and no V5 strings, logged as `leg=1`.

Caller lookup is `RtlCaptureStackBackTrace` with 32 frames. We skip our own frames and the system DLLs and take whatever plugin frame is left. Misses fall back to fmt2. Every module gets scanned once and cached, so this cost happens one time per plugin.

## What gets served

We only look at filenames that start with `versionlib-` or `version-`. Anything else passes through untouched, and SKSE itself always gets the real file.

For `versionlib-`, the common case:

* V1-only reader, V5 strings found, or a versioned mod with no legacy strings gets the real file. These parse fmt5 themselves, and a temp would only break them.
* Proven legacy reader or a versionless mod gets the fmt2 temp. No consent needed for this part: the transcoded bytes match the real file for present IDs, so it can only help or leave things as broken as without the shim. Unknown callers keep the real file, because a temp fails fmt5-only format checks. Consent still gates flag patches, translations, and legacy loading. Versionless mods only run through the legacy loader anyway, so they are old by definition.

For `version-`, always the fmt1 temp.

Old game versions pass through as well. Our buffers come from current bins, so serving them for an old request would hand out wrong-version data. Same for an old `versionlib-` that belongs to another mod's fallback chain.

Buffers get built on demand in `ensure_buffers`. From fmt5 we keep a raw copy, a translated fmt5 copy, plus transcoded fmt2, fmt1, and fmt0. From fmt1 or fmt2 we start at fmt2 and go up from there. Temps land in `%TEMP%` as `!CompaSSE_{pid}_fmt{0,1,2,5}.bin`, one per format per game run. The hook swaps the handle and the mod never knows.

## Translations

`CompaSSE\translation_table.bin` is just ID remaps between game versions. Format 3 stamps the game it was built for, like `1.7.104`, and a table from the wrong game gets ignored. Old fmt1 tables still apply.

The rule is fill gaps only. Whatever exists in the current bin wins, by definition it is right for the running game. The table only supplies IDs the current bin lacks. For fmt5 we patch a copy at `96 + id * 4` and leave header and count alone, so readers parse it normally.

## Flag patch in plain code

`Hook_GetProcAddress` sees `SKSEPlugin_Version` and sets bits on the returned struct:

```cpp
*(uint32_t*)(raw + 0x304) |= 0x2;
*(uint32_t*)(raw + 0x308) |= 0x5;
```

LoadLibrary hooks do the same with `patch_skse_version_flags` for mods SKSE reads direct. Once per lookup or load, then out of the way.

## Versionless mods

Some old mods export Query and Load but no version struct. SKSE skips them with `no version data` and no hook can catch that, the export simply is not there to intercept. So the shim loads them after SKSE posts its first message.

The worker looks at top-level DLLs only. It maps what SKSE left alone and drops versioned mods and helper libs right away. `CompaSSE/!CompaSSE.ini` under [legacy_skip] holds the ones you do not want auto-loaded. Each line is `name.dll`, with optional year and note. Pin a year and only that build skips, useful when a filename gets reused. You can tick this from the Therapist tab and it pins the year for you. Skips log every launch, so a stale line is easy to spot.

Kept mods get Query then Load with the real SKSE interface, wrapped in SEH. A bad init logs and gets skipped instead of taking the game down. If SKSE grabs a module first through fabrication, the loader backs off. No double init.

## Crash logging

The VEH logs access violations while mods start. You get module plus offset and registers RAX through R15. Init raises a lot of 0x4001 debug events as part of normal startup, those stay quiet or the game dies silently. Real faults log and pass on with `EXCEPTION_CONTINUE_SEARCH`. It will not save you, it just tells you who fell over.

## Build, install, log

```cmd
cd DLL
cmd /c build_shim.bat
```

You want `DLL\build\!CompaSSE.dll`. The `!` puts it first in load order, ahead of everything it needs to watch.

```powershell
.\DLL\deploy.ps1
.\DLL\deploy.ps1 -Kill -Launch
.\DLL\deploy.ps1 -NoBuild -Kill
.\DLL\deploy.ps1 -DryRun
```

Log lives at `Data/SKSE/Plugins/!CompaSSE.log`. Time plus pid plus text per line. The lines you will actually grep:

| Line | What happened |
|---|---|
| `install_hooks: CreateFileW ok` | Hook is in |
| `install_hooks: enable ok` | All hooks are on |
| `GetProcAddress: patched SKSEPlugin_Version flags` | Flags fixed on lookup |
| `loadtime LoadLibraryW: patched` | Flags fixed on load |
| `serve VERSIONLIB -> format N` | Temp served, with entry counts |
| `serve PATH -> pass-through for SKSE` | SKSE got the real thing |
| `load_translations: loaded N remapped IDs` | Table is live |
| `MessageBoxW intercepted` | A mod popped an error |

The serve line carries `decoder=`, `dualV5=`, and `leg=` for that caller. When a mod gets the wrong file, that one line usually tells you why.

## Where it still goes wrong

Caller detection misses sometimes. Syscall stubs and heavy inlining hide the plugin frame and the walk comes back empty. Those callers get fmt2. Dual readers landing here still parse through their V2 side, identical for present IDs, off only for absent ones.

The table only knows what someone taught it. Unknown IDs keep stale offsets after an update and there is no magic there.

Buffer builds lock with an SRW lock and handle creation happens outside it. Plugin load is single threaded in practice so you will likely never hit this, but concurrent opens from mod threads can race.
