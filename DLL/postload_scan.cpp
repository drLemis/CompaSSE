#include "postload_scan.h"
#include "hooks.h"
#include "decoder_detect.h"
#include "transcode.h"

#include <Psapi.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <algorithm>

#pragma comment(lib, "Psapi.lib")

// ---- PE helpers ----

struct SectionInfo {
    const char* name;
    uint8_t* base;
    DWORD virtualSize;
    DWORD rawSize;
    DWORD characteristics;
};

static bool get_code_sections(HMODULE mod, std::vector<SectionInfo>& sections) {
    sections.clear();
    const auto* dos = (const IMAGE_DOS_HEADER*)mod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto* nt = (const IMAGE_NT_HEADERS64*)((const uint8_t*)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;

    const auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            sections.push_back({
                (const char*)sec[i].Name,
                (uint8_t*)mod + sec[i].VirtualAddress,
                sec[i].Misc.VirtualSize,
                sec[i].SizeOfRawData,
                sec[i].Characteristics
            });
        }
    }
    return !sections.empty();
}

// Check if a module has a specific named export
static bool has_export(HMODULE mod, const char* name) {
    const auto* dos = (const IMAGE_DOS_HEADER*)mod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto* nt = (const IMAGE_NT_HEADERS64*)((const uint8_t*)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0) return false;

    const auto* expDir = (const IMAGE_EXPORT_DIRECTORY*)((const uint8_t*)mod + dir.VirtualAddress);
    const DWORD* names = (const DWORD*)((const uint8_t*)mod + expDir->AddressOfNames);
    for (DWORD i = 0; i < expDir->NumberOfNames; ++i) {
        const char* n = (const char*)((const uint8_t*)mod + names[i]);
        if (_stricmp(n, name) == 0) return true;
    }
    return false;
}

// Count imports from a specific DLL
static int count_imports_from(HMODULE mod, const char* targetDll) {
    const auto* dos = (const IMAGE_DOS_HEADER*)mod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    const auto* nt = (const IMAGE_NT_HEADERS64*)((const uint8_t*)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0) return 0;

    const auto* imp = (const IMAGE_IMPORT_DESCRIPTOR*)((const uint8_t*)mod + dir.VirtualAddress);
    int count = 0;
    for (; imp->Name != 0; ++imp) {
        const char* dllName = (const char*)((const uint8_t*)mod + imp->Name);
        if (_stricmp(dllName, targetDll) == 0) {
            // Count functions imported from this DLL
            const uintptr_t* thunk = imp->OriginalFirstThunk
                ? (const uintptr_t*)((const uint8_t*)mod + imp->OriginalFirstThunk)
                : (const uintptr_t*)((const uint8_t*)mod + imp->FirstThunk);
            for (; *thunk != 0; ++thunk)
                count++;
        }
    }
    return count;
}

// Check if module imports CreateFileMapping (sign of mmap usage)
static bool imports_mmap(HMODULE mod) {
    const auto* dos = (const IMAGE_DOS_HEADER*)mod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto* nt = (const IMAGE_NT_HEADERS64*)((const uint8_t*)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0) return false;

    const auto* imp = (const IMAGE_IMPORT_DESCRIPTOR*)((const uint8_t*)mod + dir.VirtualAddress);
    for (; imp->Name != 0; ++imp) {
        const char* dllName = (const char*)((const uint8_t*)mod + imp->Name);
        if (_stricmp(dllName, "kernel32.dll") != 0 && _stricmp(dllName, "KernelBase.dll") != 0)
            continue;

        const uintptr_t* thunk = imp->OriginalFirstThunk
            ? (const uintptr_t*)((const uint8_t*)mod + imp->OriginalFirstThunk)
            : (const uintptr_t*)((const uint8_t*)mod + imp->FirstThunk);
        for (; *thunk != 0; ++thunk) {
            if (*thunk & 0x8000000000000000ULL) continue;
            const auto* byName = (const IMAGE_IMPORT_BY_NAME*)((const uint8_t*)mod + (*thunk & 0x7FFFFFFFFFFFFFFFULL));
            if (strstr((const char*)byName->Name, "CreateFileMapping") ||
                strstr((const char*)byName->Name, "MapViewOfFile") ||
                strstr((const char*)byName->Name, "OpenFileMapping"))
                return true;
        }
    }
    return false;
}

// Check if module imports any istream-related symbols (from msvcp*.dll)
static bool imports_istream(HMODULE mod) {
    const auto* dos = (const IMAGE_DOS_HEADER*)mod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto* nt = (const IMAGE_NT_HEADERS64*)((const uint8_t*)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0) return false;

    const auto* imp = (const IMAGE_IMPORT_DESCRIPTOR*)((const uint8_t*)mod + dir.VirtualAddress);
    for (; imp->Name != 0; ++imp) {
        const char* dllName = (const char*)((const uint8_t*)mod + imp->Name);
        // msvcp*.dll or similar C++ runtime DLLs
        if (_strnicmp(dllName, "msvcp", 5) != 0) continue;

        const uintptr_t* thunk = imp->OriginalFirstThunk
            ? (const uintptr_t*)((const uint8_t*)mod + imp->OriginalFirstThunk)
            : (const uintptr_t*)((const uint8_t*)mod + imp->FirstThunk);
        for (; *thunk != 0; ++thunk) {
            if (*thunk & 0x8000000000000000ULL) continue;
            const auto* byName = (const IMAGE_IMPORT_BY_NAME*)((const uint8_t*)mod + (*thunk & 0x7FFFFFFFFFFFFFFFULL));
            const char* fname = (const char*)byName->Name;
            if (strstr(fname, "?0?$basic_ifstream") || strstr(fname, "basic_filebuf"))
                return true;
        }
    }
    return false;
}

// ---- Scanning for hardcoded game offsets ----
// CommonLibSSE uses `REL::ID(nnnnn).address()` which compiles to:
//   call IDDatabase::get()
//   ... binary search ...
//   add rax, [module_base]
// Old plugins (without Address Library) may use hardcoded addresses:
//   mov rax, 0x14XXXXXX    ; absolute 1.5.97 address
//   lea rcx, [rip+0xYYYYYY] ; offset to game function
// We scan for `lea` instructions with RIP-relative displacements that might
// point into known game address ranges.

struct HardcodedRef {
    uint8_t* address;   // address in plugin code
    int64_t displacement; // RIP-relative displacement
    const char* section;
};

// Scan code sections for RIP-relative addressing that might reference game addresses.
// Game addresses are typically 0x140000000 + RVA (for the main EXE).
// In plugin code, RIP-relative displacements encode the offset from the instruction end.
static void scan_for_hardcoded_refs(HMODULE mod, const wchar_t* modName,
                                     std::vector<HardcodedRef>& refs) {
    std::vector<SectionInfo> sections;
    if (!get_code_sections(mod, sections)) return;

    for (auto& sec : sections) {
        uint8_t* end = sec.base + min(sec.virtualSize, sec.rawSize);
        for (uint8_t* p = sec.base; p + 7 < end; ++p) {
            // Pattern: 48 8D xx yy yy yy yy  (lea reg, [rip+disp32])
            // where the displacement might reference a game function
            if (p[0] == 0x48 && p[1] == 0x8D) {
                uint8_t modrm = p[2];
                uint8_t reg = (modrm >> 3) & 7;
                uint8_t rm = modrm & 7;
                // RIP-relative has mod=00, rm=101
                if ((modrm & 0xC7) == 0x05) {
                    int32_t disp = (int32_t)(p[3] | (p[4] << 8) | (p[5] << 16) | (p[6] << 24));
                    uint8_t* instrEnd = p + 7;
                    uint8_t* target = instrEnd + disp;

                    // Check if displacement looks like it could point to game code
                    // Game EXE base is typically 0x140000000, plugin base varies
                    // A large positive displacement (>10MB) might indicate a game address
                    if (disp > 0x100000 || disp < -0x100000) {
                        refs.push_back({p, disp, sec.name});
                    }
                }
            }
        }
    }
}

// ---- Module analysis ----

struct ModuleAnalysis {
    wchar_t path[MAX_PATH];
    wchar_t name[MAX_PATH];
    HMODULE base;
    DWORD size;
    bool hasSkseVersion;        // exports SKSEPlugin_Version
    bool usesAddressLibrary;    // has versionlib in its imports or loads the bin
    bool hasMmap;               // imports CreateFileMapping/MapViewOfFile
    bool hasIstream;            // imports C++ ifstream
    DecoderType decoderType;    // from import detection
    int hardcodedRefCount;      // number of suspicious RIP-relative refs
    bool hasRelocReloc;         // contains "REL::" or "IDDatabase" strings
};

static void analyze_module(HMODULE mod, ModuleAnalysis& out) {
    memset(&out, 0, sizeof(out));
    out.base = mod;
    out.decoderType = DECODER_NONE;

    GetModuleFileNameW(mod, out.path, MAX_PATH);
    const wchar_t* bs = wcsrchr(out.path, L'\\');
    bs = bs ? bs + 1 : out.path;
    wcscpy_s(out.name, bs);

    MODULEINFO mi;
    if (GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi)))
        out.size = mi.SizeOfImage;

    // Check for SKSE exports
    out.hasSkseVersion = has_export(mod, "SKSEPlugin_Version") || has_export(mod, "SKSEPlugin_Query");

    // Decode import patterns
    out.hasMmap = imports_mmap(mod);
    out.hasIstream = imports_istream(mod);
    out.usesAddressLibrary = out.hasMmap || out.hasIstream;
    out.decoderType = decoder_for_module(mod, nullptr);

    // Scan for hardcoded refs
    std::vector<HardcodedRef> refs;
    scan_for_hardcoded_refs(mod, out.name, refs);
    out.hardcodedRefCount = (int)refs.size();

    // Quick string scan for CommonLibSSE markers in data sections
    // Look for "REL::" or "IDDatabase" in the module's readable memory
    out.hasRelocReloc = false;
    MODULEINFO mi2;
    if (GetModuleInformation(GetCurrentProcess(), mod, &mi2, sizeof(mi2))) {
        const uint8_t* base = (const uint8_t*)mi2.lpBaseOfDll;
        // Search first 4KB of data for markers (quick heuristic)
        size_t searchLen = min((DWORD)4096, mi2.SizeOfImage);
        for (size_t i = 0; i + 10 < searchLen; ++i) {
            if (memcmp(base + i, "REL::ID", 7) == 0 ||
                memcmp(base + i, "IDDatabase", 10) == 0 ||
                memcmp(base + i, "addresslib", 10) == 0) {
                out.hasRelocReloc = true;
                break;
            }
        }
    }
}

// ---- Main scan function ----

// Global: track which plugins we've already scanned (avoid double-scan)
static bool g_scanned = false;

void postload_scan_all(HMODULE self_module) {
    if (g_scanned) return;
    g_scanned = true;

    shim_log("=== POST-LOAD PLUGIN SCAN ===");

    // Wrap entire scan in SEH - we're analyzing untrusted plugin code, protect against crashes
    __try {

    HMODULE hMods[512];
    DWORD cbNeeded = 0;
    if (!EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
        shim_log("scan: EnumProcessModules FAILED (err=%lu)", GetLastError());
        return;
    }

    int totalModules = cbNeeded / sizeof(HMODULE);
    int pluginCount = 0;
    int sksePluginCount = 0;
    int addressLibUsers = 0;
    int nonAddressLibUsers = 0;

    // Classify system DLLs to skip
    auto is_system = [](const wchar_t* name) -> bool {
        if (_wcsnicmp(name, L"api-ms-", 7) == 0) return true;
        if (_wcsnicmp(name, L"ext-ms-", 7) == 0) return true;
        const wchar_t* sysDlls[] = {
            L"ntdll.dll", L"kernel32.dll", L"kernelbase.dll", L"user32.dll",
            L"advapi32.dll", L"sechost.dll", L"msvcrt.dll", L"ucrtbase.dll",
            L"vcruntime140.dll", L"vcruntime140_1.dll", L"msvcp140.dll",
            L"combase.dll", L"ole32.dll", L"oleaut32.dll", L"shell32.dll",
            L"shlwapi.dll", L"version.dll", L"winmm.dll", L"d3d11.dll",
            L"d3dcompiler_47.dll", L"dxgi.dll", L"d3dx11_43.dll",
            L"inputhost.dll", L"CoreUIComponents.dll", L"CoreMessaging.dll",
            L"windows.storage.dll", L"bcp47mrm.dll", L"apphelp.dll",
            L"profapi.dll", L"icu.dll", L"cfgmgr32.dll", L"devobj.dll",
            L"crypt32.dll", L"bcrypt.dll", L"bcryptprimitives.dll",
            L"ws2_32.dll", L"nsi.dll", L"wldp.dll", L"secur32.dll",
            L"sspicli.dll", L"msasn1.dll", L"cryptsp.dll", L"rsaenh.dll",
            L"cryptdll.dll", L"imagehlp.dll", L"clbcatq.dll",
            L"propsys.dll", L"wevtapi.dll", L"folderisprovider.dll",
            L"netutils.dll", L"samlib.dll", L"samcli.dll",
            L"amsi.dll", L"mpo.dll", L"rmclient.dll", L"twinapi.dll",
            L"twinapi.appcore.dll", L"twinui.dll", L"twinui.appcore.dll",
            L"dwmapi.dll", L"uxtheme.dll", L"fontsub.dll",
            L"imm32.dll", L"msctf.dll", L"textinputframework.dll",
            L"ntmarta.dll", L"wintypes.dll", L"Windows.Codecs.dll",
            L"msi.dll", L"sxs.dll", L"comsvcs.dll", L"comctl32.dll",
            L"riched20.dll", L"usp10.dll", L"msimg32.dll",
            L"dwmcore.dll", L"d2d1.dll", L"dwrite.dll", L"wtsapi32.dll",
            L"setupapi.dll", L"rpcrt4.dll", L"linkinfo.dll",
            L"acppage.dll", L"dui70.dll", L"duser.dll",
            L"shdocvw.dll", L"api-ms-win-core-*.dll",
            nullptr
        };
        for (int i = 0; sysDlls[i]; ++i)
            if (_wcsicmp(name, sysDlls[i]) == 0) return true;
        return false;
    };

    for (int i = 0; i < totalModules; ++i) {
        wchar_t modPath[MAX_PATH];
        if (GetModuleFileNameW(hMods[i], modPath, MAX_PATH) == 0) continue;

        const wchar_t* base = wcsrchr(modPath, L'\\');
        base = base ? base + 1 : modPath;

        // Skip system DLLs
        if (is_system(base)) continue;

        ModuleAnalysis ma;
        analyze_module(hMods[i], ma);

        // Only log non-trivial modules (our shim, SKSE plugins, Skyrim-related)
        bool isSelf = (hMods[i] == self_module);
        bool isSkse = (_wcsnicmp(base, L"skse64", 6) == 0);
        bool isGame = (_wcsnicmp(base, L"skyrim", 6) == 0);
        bool isPlugin = (_wcsnicmp(base + 1, L".dll", 4) == 0); // *.dll in plugins folder

        // Log ALL DLLs from the Plugins folder or that are SKSE-related
        wchar_t pluginsDir[MAX_PATH];
        if (self_module) {
            GetModuleFileNameW(self_module, pluginsDir, MAX_PATH);
            wchar_t* slash = wcsrchr(pluginsDir, L'\\');
            if (slash) *(slash + 1) = 0;
        }

        bool inPluginsFolder = false;
        if (self_module) {
            wchar_t selfDir[MAX_PATH];
            GetModuleFileNameW(self_module, selfDir, MAX_PATH);
            wchar_t* slash = wcsrchr(selfDir, L'\\');
            if (slash) {
                *slash = 0;
                inPluginsFolder = (_wcsnicmp(modPath, selfDir, wcslen(selfDir)) == 0);
            }
        }

        if (isSelf || isSkse || inPluginsFolder) {
            pluginCount++;

            const wchar_t* decoderStr = L"NONE";
            switch (ma.decoderType) {
                case DECODER_V1: decoderStr = L"V1"; break;
                case DECODER_V2: decoderStr = L"V2"; break;
                case DECODER_V5: decoderStr = L"V5"; break;
                default: break;
            }

            if (ma.hasSkseVersion) sksePluginCount++;
            if (ma.usesAddressLibrary) addressLibUsers++;
            else nonAddressLibUsers++;

            const wchar_t* verdict = L"OK";
            if (!ma.usesAddressLibrary && ma.hardcodedRefCount > 0)
                verdict = L"HARDCODED";
            else if (!ma.hasSkseVersion)
                verdict = L"NOT_SKSE";

            shim_log("  [%d] %ls - %ls (decoder=%ls adlib=%d)",
                     pluginCount, ma.name, verdict, decoderStr,
                     ma.usesAddressLibrary);

            if (isSelf) shim_log("    *** THIS IS THE SHIM ***");
        }
    }

    shim_log("=== SCAN SUMMARY ===");
    shim_log("  total_modules=%d  plugins=%d  skse_exports=%d", totalModules, pluginCount, sksePluginCount);
    shim_log("  address_lib_users=%d  non_address_lib=%d", addressLibUsers, nonAddressLibUsers);
    shim_log("=== END SCAN ===");

    } __except(EXCEPTION_EXECUTE_HANDLER) {
        shim_log("=== SCAN CRASHED: exception 0x%08X ===", GetExceptionCode());
    }
}
