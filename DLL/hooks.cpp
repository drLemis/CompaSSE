#include "hooks.h"

#include "decoder_detect.h"
#include "transcode.h"

#include <MinHook.h>

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <intrin.h>
#include <map>
#include <string>
#include <utility>
#include <vector>

#define COMPASSE_SHIM_VERSION "2.0.2"

// ---- GetProcAddress interception (SKSE version bypass) ----
typedef FARPROC (WINAPI* pfnGetProcAddress)(HMODULE, LPCSTR);
static pfnGetProcAddress fpGetProcAddress = nullptr;

// Touched gate (defined below, next to the other ini loaders): only
// consented plugins receive shim services. Hook install is never gated.
static bool is_touched_module(HMODULE mod);
static bool is_touched_name(const wchar_t* base);
static bool touched_gate(HMODULE mod, const char* what);
static void touched_skip_log_once(const wchar_t* base, const char* what);
static void touched_set_allowed_for_caller(HMODULE caller);

// Minted below (needs the exe-version helpers); see fabricate_version_struct.
static FARPROC WINAPI fabricate_version_struct(HMODULE mod);

static FARPROC WINAPI Hook_GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    FARPROC result = fpGetProcAddress(hModule, lpProcName);
    if (!lpProcName) return result;

    // Only intercept data export "SKSEPlugin_Version" (18 chars)
    // Skip ordinal lookups (high bit set) and short/long names
    if (((uintptr_t)lpProcName & ~0xFFFF) == 0) return result;
    if (lpProcName[0] != 'S' || lpProcName[18] != '\0') return result;
    if (memcmp(lpProcName, "SKSEPlugin_Version", 18) != 0) return result;

    // Touched gate: only consented plugins get flag patches or a fake
    // struct. Unconsented modules keep the real (possibly null) result.
    if (!touched_gate(hModule, "GetProcAddress")) return result;

    if (!result) {
        // Legacy plugin: no version export, SKSE would skip it outright.
        // Hand it a fabricated compatible struct so it gets attempted.
        FARPROC fake = fabricate_version_struct(hModule);
        if (fake) return fake;
        return result;
    }

    // Patch versionIndependence flags so SKSE accepts the plugin.
    // versionIndependenceEx at +0x304: set AddressLibraryV5 (0x2)
    // versionIndependence   at +0x308: set AddressLibrary|Structs (0x5)
    shim_log("GPA hook: MATCH SKSEPlugin_Version module=%p result=%p", (void*)hModule, (void*)result);
    uint8_t* raw = (uint8_t*)result;
    {
        DWORD oldProt = 0;
        BOOL ok1 = VirtualProtect(raw + 0x304, 8, PAGE_READWRITE, &oldProt);
        if (!ok1) {
            shim_log("GPA hook: VirtualProtect FAILED to make RW (err=%lu, addr=%p)", GetLastError(), (void*)(raw + 0x304));
        }
        *(uint32_t*)(raw + 0x304) |= 0x2;
        *(uint32_t*)(raw + 0x308) |= 0x5;
        BOOL ok2 = VirtualProtect(raw + 0x304, 8, oldProt, &oldProt);
        if (!ok2) {
            shim_log("GPA hook: VirtualProtect FAILED to restore (err=%lu)", GetLastError());
        }
    }

    shim_log("GetProcAddress: patched SKSEPlugin_Version flags for module at %p", (void*)hModule);
    return result;
}

// ---- Load-time patch: SKSE reads some plugins' version flags directly from
// the PE export table, bypassing GetProcAddress (e.g. dosemetha.dll). Patch
// them in memory right after the module loads, before SKSE inspects. ----

// Patch versionIndependenceEx (+0x304 |= 0x2) and versionIndependence
// (+0x308 |= 0x5) on the SKSEPlugin_Version data export of `mod`, if present.
static void patch_skse_version_flags(HMODULE mod, const char* via) {
    const auto* dos = (const IMAGE_DOS_HEADER*)mod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    const auto* nt = (const IMAGE_NT_HEADERS64*)((const uint8_t*)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return;

    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0) return;

    const auto* expDir = (const IMAGE_EXPORT_DIRECTORY*)((const uint8_t*)mod + dir.VirtualAddress);
    const DWORD* names = (const DWORD*)((const uint8_t*)mod + expDir->AddressOfNames);
    const WORD*  ords  = (const WORD*)((const uint8_t*)mod + expDir->AddressOfNameOrdinals);
    const DWORD* funcs = (const DWORD*)((const uint8_t*)mod + expDir->AddressOfFunctions);

    uint8_t* ver = nullptr;
    for (DWORD i = 0; i < expDir->NumberOfNames; ++i) {
        const char* n = (const char*)((const uint8_t*)mod + names[i]);
        if (strcmp(n, "SKSEPlugin_Version") != 0) continue;
        WORD ord = ords[i];
        ver = (uint8_t*)mod + funcs[ord];   // data export: RVA of the struct
        break;
    }
    if (!ver) return;

    // Touched gate (before any write): unconsented plugins keep real bytes.
    if (!touched_gate(mod, via)) return;

    {
        DWORD oldProt = 0;
        if (!VirtualProtect(ver + 0x304, 8, PAGE_READWRITE, &oldProt)) {
            shim_log("loadtime %s: VirtualProtect FAILED (err=%lu, ver=%p)", via, GetLastError(), (void*)ver);
            return;
        }
        uint32_t ex = *(uint32_t*)(ver + 0x304);
        uint32_t vi = *(uint32_t*)(ver + 0x308);
        *(uint32_t*)(ver + 0x304) |= 0x2;
        *(uint32_t*)(ver + 0x308) |= 0x5;
        VirtualProtect(ver + 0x304, 8, oldProt, &oldProt);
        shim_log("loadtime %s: patched SKSEPlugin_Version mod=%p ver=%p (ex=0x%X->0x%X, vi=0x%X->0x%X)",
                 via, (void*)mod, (void*)ver, ex, ex | 0x2, vi, vi | 0x5);
    }
}

typedef HMODULE (WINAPI* pfnLoadLibraryW)(LPCWSTR);
typedef HMODULE (WINAPI* pfnLoadLibraryA)(LPCSTR);
typedef HMODULE (WINAPI* pfnLoadLibraryExW)(LPCWSTR, HANDLE, DWORD);
static pfnLoadLibraryW fpLoadLibraryW = nullptr;
static pfnLoadLibraryA fpLoadLibraryA = nullptr;
static pfnLoadLibraryExW fpLoadLibraryExW = nullptr;

static HMODULE WINAPI Hook_LoadLibraryW(LPCWSTR name) {
    HMODULE h = fpLoadLibraryW(name);
    if (h) patch_skse_version_flags(h, "LoadLibraryW");
    return h;
}
static HMODULE WINAPI Hook_LoadLibraryA(LPCSTR name) {
    HMODULE h = fpLoadLibraryA(name);
    if (h) patch_skse_version_flags(h, "LoadLibraryA");
    return h;
}
static HMODULE WINAPI Hook_LoadLibraryExW(LPCWSTR name, HANDLE file, DWORD flags) {
    HMODULE h = fpLoadLibraryExW(name, file, flags);
    if (h) patch_skse_version_flags(h, "LoadLibraryExW");
    return h;
}

// ---- MessageBox interception ----
typedef int (WINAPI* pfnMessageBoxW)(HWND, LPCWSTR, LPCWSTR, UINT);
static pfnMessageBoxW fpMessageBoxW = nullptr;

static int WINAPI Hook_MessageBoxW(HWND hWnd, LPCWSTR text, LPCWSTR caption, UINT type) {
    shim_log("MessageBoxW intercepted! caption=%ls text=%.200ls", caption ? caption : L"(null)", text ? text : L"(null)");
    // Don't suppress - let it show as usual
    return fpMessageBoxW(hWnd, text, caption, type);
}

typedef int (WINAPI* pfnMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
static pfnMessageBoxA fpMessageBoxA = nullptr;

static int WINAPI Hook_MessageBoxA(HWND hWnd, LPCSTR text, LPCSTR caption, UINT type) {
    shim_log("MessageBoxA intercepted! caption=%s text=%.200s", caption ? caption : "(null)", text ? text : "(null)");
    return fpMessageBoxA(hWnd, text, caption, type);
}
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef LONG NTSTATUS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

#define OBJ_CASE_INSENSITIVE 0x00000040
#define FILE_OPEN 0x00000001
#define FILE_DIRECTORY_FILE 0x00000001

typedef NTSTATUS(NTAPI* pfnNtCreateFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength);

typedef NTSTATUS(NTAPI* pfnNtOpenFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions);

// ---- trampolines (filled by MH_CreateHook) ----
static decltype(&CreateFileW) fpCreateFileW = nullptr;
static decltype(&CreateFileA) fpCreateFileA = nullptr;
static decltype(&CreateFile2) fpCreateFile2 = nullptr;
static decltype(&CreateFileMappingW) fpCreateFileMappingW = nullptr;
static decltype(&OpenFileMappingW) fpOpenFileMappingW = nullptr;
static decltype(&CreateFileMappingA) fpCreateFileMappingA = nullptr;
static decltype(&OpenFileMappingA) fpOpenFileMappingA = nullptr;
static decltype(&MapViewOfFile) fpMapViewOfFile = nullptr;
static pfnNtCreateFile fpNtCreateFile = nullptr;
static pfnNtOpenFile fpNtOpenFile = nullptr;

// ---- LdrLoadDll: single choke point that catches ALL DLL loads, including
// plugins SKSE loads directly via ntdll (bypassing kernel32 LoadLibrary). ----
typedef NTSTATUS(NTAPI* pfnLdrLoadDll)(PWSTR, PULONG, PUNICODE_STRING, PHANDLE);
static pfnLdrLoadDll fpLdrLoadDll = nullptr;

static NTSTATUS NTAPI Hook_LdrLoadDll(PWSTR searchPath, PULONG flags,
                                      PUNICODE_STRING name, PHANDLE baseAddr) {
    NTSTATUS status = fpLdrLoadDll(searchPath, flags, name, baseAddr);
    if (NT_SUCCESS(status) && baseAddr && *baseAddr)
        patch_skse_version_flags((HMODULE)*baseAddr, "LdrLoadDll");
    return status;
}

static HMODULE g_self = nullptr;
static SRWLOCK g_lock = SRWLOCK_INIT; // guards all lazy state below

// One snapshot of what a calling module can parse. Every serve point
// (stream open, both mapping hooks) decides from the same snapshot
// through keep_real_bytes, so the rule lives in exactly one place.
struct CallerCaps {
    DecoderType type = DECODER_NONE;
    bool dualV5 = false;
    bool legacy = false;
    bool hasVer = false;
};

static CallerCaps caller_caps(HMODULE caller) {
    CallerCaps c;
    if (!caller) return c;
    c.type = decoder_for_module(caller, g_self);
    c.dualV5 = module_supports_fmt5(caller);
    c.legacy = module_is_legacy_reader(caller);
    c.hasVer = module_has_version_export(caller);
    return c;
}

// Healthy fmt5-native readers parse the real file; a transcoded temp
// fails their format check. Custom fmt5 readers (own minimal loader,
// no CommonLib strings at all) carry neither marker set, so versioned
// callers without legacy strings keep the real bytes too - unless the
// caller shows neither stream nor mapping imports (V2 default): those
// read the file by hand and predate fmt5, so they take the temp like
// 1.5.x gave them. Only proven legacy readers and versionless
// (legacy-loaded) callers get the temp: both predate fmt5 and cannot
// parse it. Anything else keeps the real bytes: same as no shim,
// never worse.
static bool keep_real_bytes(const CallerCaps& c) {
    if (c.type == DECODER_V1 || c.dualV5) return true;
    if (!c.hasVer || c.legacy) return false;
    return c.type != DECODER_V2;
}

// ---- lazy state (guarded by g_lock) ----
static std::vector<uint8_t> g_fmt2;
static std::vector<uint8_t> g_fmt5;
static std::vector<uint8_t> g_fmt5_patched; // fmt5 copy with translated offsets patched in
static std::vector<uint8_t> g_fmt1;
static std::vector<uint8_t> g_fmt0;
static bool g_loaded = false;
static bool g_loadFailed = false;
static bool g_loading = false; // reentrancy guard for ensure_buffers
static bool g_serving_alt = false; // reentrancy guard for alt-path file open
static thread_local bool g_ntRedirecting = false; // reentrancy guard for NtCreateFile->CreateFileW redirect
static uint32_t g_srcFmt = 0;  // source bin format (1/2/5) once loaded
static wchar_t g_tempPath2[MAX_PATH];
static wchar_t g_tempPath5[MAX_PATH];
static wchar_t g_tempPath1[MAX_PATH];
static wchar_t g_tempPath0[MAX_PATH];
static wchar_t g_currentVersion[32]; // e.g. "1-7-104" extracted from versionlib filename

// Entries in a materialized temp; IDDatabase maps count * 16 bytes.
static uint32_t temp_entry_count(int format) {
    const std::vector<uint8_t>* buf =
        format == 5 ? &g_fmt5_patched : format == 1 ? &g_fmt1 : &g_fmt2;
    if (buf->size() < 28) return 0;
    const uint8_t* d = buf->data();
    uint32_t f = (uint32_t)d[0] | ((uint32_t)d[1] << 8) |
                 ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24);
    if (f == 5) {
        if (buf->size() < 96) return 0;
        return (uint32_t)d[92] | ((uint32_t)d[93] << 8) |
               ((uint32_t)d[94] << 16) | ((uint32_t)d[95] << 24);
    }
    if (f == 1 || f == 2) {
        uint32_t nameLen = (uint32_t)d[20] | ((uint32_t)d[21] << 8) |
                           ((uint32_t)d[22] << 16) | ((uint32_t)d[23] << 24);
        if (nameLen > 256) return 0;
        size_t off = 24 + (size_t)nameLen + 4;
        if (off + 4 > buf->size()) return 0;
        return (uint32_t)d[off] | ((uint32_t)d[off + 1] << 8) |
               ((uint32_t)d[off + 2] << 16) | ((uint32_t)d[off + 3] << 24);
    }
    return 0;
}

#pragma comment(lib, "version.lib")

// Current game version from the host exe, for telling current-version
// requests (transcode + translate) apart from old-version ones (pass
// through untouched). Empty when undeterminable: then all files count
// as current. Lazy (InitOnce): never runs under the loader lock.
static INIT_ONCE g_verOnce = INIT_ONCE_STATIC_INIT;
static wchar_t g_exeVersion[32] = {}; // e.g. L"1-7-104" (major-minor-build)

static BOOL CALLBACK init_exe_version(PINIT_ONCE, PVOID, PVOID*) {
    wchar_t exe[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, exe, MAX_PATH)) return TRUE;
    DWORD ignored = 0;
    DWORD sz = GetFileVersionInfoSizeW(exe, &ignored);
    if (!sz) return TRUE;
    std::vector<uint8_t> buf(sz);
    if (!GetFileVersionInfoW(exe, 0, sz, buf.data())) return TRUE;
    VS_FIXEDFILEINFO* ffi = nullptr;
    UINT len = 0;
    if (!VerQueryValueW(buf.data(), L"\\", (void**)&ffi, &len) || !ffi || len == 0)
        return TRUE;
    swprintf_s(g_exeVersion, L"%u-%u-%u",
               (ffi->dwFileVersionMS >> 16) & 0xFFFF,
               ffi->dwFileVersionMS & 0xFFFF,
               (ffi->dwFileVersionLS >> 16) & 0xFFFF);
    shim_log("exe version: %ls (%ls)", g_exeVersion, exe);
    return TRUE;
}

// True when `path` names a bin for an older game than the running one.
static bool is_old_version_path(const wchar_t* path) {
    InitOnceExecuteOnce(&g_verOnce, init_exe_version, nullptr, nullptr);
    return g_exeVersion[0] && !wcsstr(path, g_exeVersion);
}

// Fabricated version structs for legacy plugins (Query+Load but no
// SKSEPlugin_Version export): SKSE 2.3.1 skips those outright. Layout
// mirrors SKSEPluginVersionData (see main.cpp); SKSE loads plugins
// sequentially, so plain slots are enough.
struct FakeVersionSlot {
    HMODULE mod = nullptr;
    bool consumed = false; // handed out: SKSE owns this module, skip our loader
    uint8_t bytes[0x350] = {};
};
static FakeVersionSlot g_fakeVersions[64];
static LONG g_fakeVersionCount = 0;

static FARPROC WINAPI fabricate_version_struct(HMODULE mod) {
    wchar_t path[MAX_PATH] = {};
    if (!mod || !GetModuleFileNameW(mod, path, MAX_PATH))
        return nullptr;
    // Only actual SKSE plugins, never ourselves or system DLLs.
    size_t len = wcslen(path);
    if (len < 5)
        return nullptr;
    wchar_t low[MAX_PATH] = {};
    for (size_t i = 0; i < len && i < MAX_PATH - 1; ++i)
        low[i] = (wchar_t)towlower(path[i]);
    if (!wcsstr(low, L"skse\\plugins"))
        return nullptr;
    if (!fpGetProcAddress(mod, "SKSEPlugin_Query") ||
        !fpGetProcAddress(mod, "SKSEPlugin_Load"))
        return nullptr;
    // Touched gate: no fake slot for unconsented plugins (the GetProcAddress
    // hook above already logged the skip once).
    if (!is_touched_module(mod)) return nullptr;
    for (LONG i = 0; i < g_fakeVersionCount && i < 64; ++i) {
        if (g_fakeVersions[i].mod == mod) {
            g_fakeVersions[i].consumed = true;
            return (FARPROC)(void*)g_fakeVersions[i].bytes;
        }
    }
    LONG idx = InterlockedIncrement(&g_fakeVersionCount) - 1;
    if (idx < 0 || idx >= 64)
        return nullptr;
    FakeVersionSlot& slot = g_fakeVersions[idx];
    slot.mod = mod;
    uint8_t* b = slot.bytes;
    *(uint32_t*)(b + 0x000) = 1; // dataVersion
    *(uint32_t*)(b + 0x004) = 0x00010000; // pluginVersion 1.0.0.0
    const wchar_t* base = wcsrchr(path, L'\\');
    base = base ? base + 1 : path;
    char name[256] = {};
    for (int i = 0; i < 255 && base[i] && base[i] != L'.'; ++i)
        name[i] = (char)(base[i] < 128 ? base[i] : '?');
    memcpy(b + 0x008, name, sizeof(name)); // pluginName
    memcpy(b + 0x108, "CompaSSE", 9); // author
    *(uint32_t*)(b + 0x304) = 0x2; // versionIndependenceEx: AddressLibraryV5
    *(uint32_t*)(b + 0x308) = 0x5; // versionIndependence: AddressLibrary|Structs
    unsigned a = 0, bb = 0, c = 0; // compatibleVersions[0] = running game
    InitOnceExecuteOnce(&g_verOnce, init_exe_version, nullptr, nullptr);
    if (swscanf_s(g_exeVersion, L"%u-%u-%u", &a, &bb, &c) == 3)
        *(uint32_t*)(b + 0x30C) =
            ((a & 0xFF) << 24) | ((bb & 0xFF) << 16) |
            ((c & 0xFFF) << 4);
    shim_log("GPA hook: fabricated SKSEPlugin_Version for legacy %hs", name);
    slot.consumed = true;
    return (FARPROC)b;
}

// Skip-list for the legacy loader (CompaSSE\!CompaSSE.ini [skip],
// one entry per line: "name.dll [| year=YYYY] [| note]". ';' '#' and other
// are ignored, matching is case-insensitive). A pinned year skips only
// that build (same DLL filename, different mod); without one every build
// matches. Metadata is for people and tooling; only name+year match.
// Versionless plugins SKSE itself refuses sometimes fault on the current
// game (hardcoded pre-fmt5 lookups); listing one restores the no-shim
// state (SKSE skips it, game starts) instead of force-loading it.
// Missing/unparseable file = empty.
struct LegacySkipEntry {
    std::wstring name;
    int year = 0; // 0 = every build
};
static std::vector<LegacySkipEntry> g_legacySkip;
static bool g_legacySkipLoaded = false;

// TimeDateStamp (seconds since 1970-01-01 UTC) -> civil year.
static int stamp_year(uint32_t stamp) {
    int64_t z = (int64_t)(stamp / 86400) + 719468;
    int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    uint64_t doe = (uint64_t)(z - era * 146097);
    uint64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t y = (int64_t)yoe + era * 400;
    uint64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    uint64_t mp = (5 * doy + 2) / 153;
    unsigned m = (unsigned)(mp + (mp < 10 ? 3 : -9));
    return (int)(y + (m <= 2));
}

static int module_build_year(HMODULE mod) {
    const auto* dos = (const IMAGE_DOS_HEADER*)mod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    const auto* nt = (const IMAGE_NT_HEADERS64*)((const uint8_t*)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    uint32_t stamp = nt->FileHeader.TimeDateStamp;
    if (stamp == 0) return 0;
    int y = stamp_year(stamp);
    return (y >= 1990 && y <= 2100) ? y : 0;
}

// Unified shim config path (CompaSSE\!CompaSSE.ini). Old separate
// files still work when it is missing; when it exists it wins.
static bool config_path(wchar_t* out) {
    if (!g_self) return false;
    if (!GetModuleFileNameW(g_self, out, MAX_PATH)) return false;
    wchar_t* bs = wcsrchr(out, L'\\');
    if (!bs) return false;
    *bs = 0;
    wcscat_s(out, MAX_PATH, L"\\CompaSSE\\!CompaSSE.ini");
    return true;
}

// Section header matcher: true with match set when the line opens
// the wanted section (case-insensitive, surrounding spaces allowed).
// Returns true and sets match when the line opens the wanted section.
static bool section_select(const char* line, const char* want, bool& inSection) {
    const char* p = line;
    while (*p == ' ' || *p == '\t') ++p;
    if (*p != '[') return false;
    const char* end = strchr(p, ']');
    if (!end) return false;
    while (end > p + 1 && (*(end - 1) == ' ' || *(end - 1) == '\t')) --end;
    const char* name = p + 1;
    while (*name == ' ' || *name == '\t') ++name;
    size_t wantLen = strlen(want);
    if ((size_t)(end - name) != wantLen) { inSection = false; return true; }
    inSection = (_strnicmp(name, want, wantLen) == 0);
    return true;
}

static void load_legacy_skip() {
    if (g_legacySkipLoaded) return;
    g_legacySkipLoaded = true;
    if (!g_self) return;
    wchar_t path[MAX_PATH];
    if (!config_path(path) ||
        GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) return;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    char buf[32768];
    DWORD rd = 0;
    BOOL ok = ReadFile(h, buf, sizeof(buf) - 1, &rd, nullptr);
    CloseHandle(h);
    if (!ok || rd == 0) return;
    buf[rd] = 0;
    char* text = buf;
    if (rd > 3 && (unsigned char)buf[0] == 0xEF) {
        if ((unsigned char)buf[1] != 0xBB || (unsigned char)buf[2] != 0xBF) return;
        text += 3;
    }
    bool inSection = false;
    char* ctx = nullptr;
    for (char* line = strtok_s(text, "\r\n", &ctx); line;
         line = strtok_s(nullptr, "\r\n", &ctx)) {
        // Only [skip] is read; old section names are ignored.
        const char* p = line;
        while (*p == ' ' || *p == '\t') ++p;
        if (*p == '[') {
            bool tmp = false;
            inSection = section_select(line, "skip", tmp) && tmp;
            continue;
        }
        if (!inSection) continue;
        while (*line == ' ' || *line == '\t') ++line;
        if (!*line || *line == ';' || *line == '#' || *line == '[' ||
            *line == '\'' || *line == '"')
            continue;
        // Only the filename matches; "name.dll | year=2017 | note".
        // Split first, then read the pieces.
        char* bar = strchr(line, '|');
        int year = 0;
        if (bar) {
            *bar = 0;
            for (char* seg = bar + 1; seg && !year; ) {
                while (*seg == ' ' || *seg == '\t') ++seg;
                char* next = strchr(seg, '|');
                if (next) *next++ = 0;
                if (_strnicmp(seg, "year=", 5) == 0) {
                    int y = 0, digits = 0;
                    for (const char* d = seg + 5;
                         *d >= '0' && *d <= '9'; ++d) {
                        y = y * 10 + (*d - '0');
                        if (++digits > 4) break;
                    }
                    if (digits == 4 && y >= 1990 && y <= 2100) year = y;
                }
                seg = next;
            }
        }
        size_t n = strlen(line);
        while (n > 0 && (line[n - 1] == ' ' || line[n - 1] == '\t')) line[--n] = 0;
        if (!*line || n >= MAX_PATH) continue;
        wchar_t w[MAX_PATH] = {};
        for (size_t i = 0; i < n; ++i) w[i] = (wchar_t)(unsigned char)line[i];
        if (g_legacySkip.size() >= 128) break;
        LegacySkipEntry e;
        e.name = w;
        e.year = year;
        g_legacySkip.push_back(e);
    }
    if (!g_legacySkip.empty())
        shim_log("legacy: skip-list has %zu entr%s", g_legacySkip.size(),
                 g_legacySkip.size() == 1 ? "y" : "ies");
}

static bool is_legacy_skipped(const wchar_t* base) {
    if (!base || !base[0]) return false;
    load_legacy_skip();
    for (auto& s : g_legacySkip) {
        if (_wcsicmp(s.name.c_str(), base) != 0) continue;
        if (s.year == 0) return true;
        int built = 0;
        HMODULE mod = GetModuleHandleW(base);
        if (mod) built = module_build_year(mod);
        if (built == 0 || built == s.year) return true;
    }
    return false;
}

static std::vector<std::wstring> g_touched;
static std::vector<std::wstring> g_serveRaw;
static std::vector<std::wstring> g_serveFmt1;
static bool g_touchedLoaded = false;
static bool g_touchedMissing = false;
static bool g_legacyWarned = false;
static std::map<HMODULE, bool> g_touchedCache; // guarded by g_lock
static std::map<std::wstring, bool> g_touchedSkipLogged; // skip line once per basename per boot
static bool g_translationsAllowed = true; // per-serve touched decision; a miss makes apply_translations add 0

static bool in_list_ci(const std::vector<std::wstring>& list, const wchar_t* w) {
    for (auto& e : list) if (_wcsicmp(e.c_str(), w) == 0) return true;
    return false;
}

static void load_touched() {
    // Call with g_lock held exclusively.
    if (g_touchedLoaded) return;
    g_touchedLoaded = true;
    if (!g_self) { g_touchedMissing = true; return; }
    wchar_t path[MAX_PATH];
    if (!config_path(path) ||
        GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
        g_touchedMissing = true;
        shim_log("touched: no config - legacy mode, serving all plugins");
        return;
    }
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        g_touchedMissing = true;
        shim_log("touched: no config - legacy mode, serving all plugins");
        return;
    }
    char buf[32768];
    DWORD rd = 0;
    BOOL ok = ReadFile(h, buf, sizeof(buf) - 1, &rd, nullptr);
    CloseHandle(h);
    if (!ok || rd == 0) {
        g_touchedMissing = true;
        shim_log("touched: config unreadable - legacy mode, serving all plugins");
        return;
    }
    buf[rd] = 0;
    char* text = buf;
    if (rd > 3 && (unsigned char)buf[0] == 0xEF) {
        if ((unsigned char)buf[1] != 0xBB || (unsigned char)buf[2] != 0xBF) {
            g_touchedMissing = true;
            return;
        }
        text += 3;
    }
    bool inFixed = false;
    bool seenSection = false;
    char* ctx = nullptr;
    for (char* line = strtok_s(text, "\r\n", &ctx); line;
         line = strtok_s(nullptr, "\r\n", &ctx)) {
        {
            const char* p = line;
            while (*p == ' ' || *p == '\t') ++p;
            if (*p == '[') {
                seenSection = true;
                bool tmp = false;
                inFixed = section_select(line, "fixed", tmp) && tmp;
                if (!inFixed && !g_legacyWarned) {
                    // Tripwire: dead headers are ignored, loudly, once.
                    // Rewrite the ini via the current CompaSSE.exe.
                    const char* dead[] = { "touched", "serve_raw", "serve_fmt1", "legacy_skip" };
                    for (int i = 0; i < 4; ++i) {
                        bool d = false;
                        if (section_select(line, dead[i], d) && d) {
                            g_legacyWarned = true;
                            shim_log("LEGACY SECTIONS IGNORED - rewrite via current CompaSSE.exe");
                            break;
                        }
                    }
                }
                continue;
            }
            if (!seenSection || !inFixed) continue;
        }
        while (*line == ' ' || *line == '\t') ++line;
        if (!*line || *line == ';' || *line == '#' || *line == '[') continue;
        int serveMode = 0; // 0 auto, 1 raw, 2 fmt1
        char* bar = strchr(line, '|');
        if (bar) {
            *bar = 0;
            for (char* seg = bar + 1; seg; ) {
                char* next = strchr(seg, '|');
                if (next) *next++ = 0;
                while (*seg == ' ' || *seg == '\t') ++seg;
                if (_strnicmp(seg, "serve=", 6) == 0) {
                    const char* v = seg + 6;
                    while (*v == ' ' || *v == '\t') ++v;
                    if (_strnicmp(v, "raw", 3) == 0
                        && (v[3] == 0 || v[3] == ' ' || v[3] == '\t'))
                        serveMode = 1;
                    else if (_strnicmp(v, "fmt1", 4) == 0
                        && (v[4] == 0 || v[4] == ' ' || v[4] == '\t'))
                        serveMode = 2;
                    else if (_strnicmp(v, "auto", 4) == 0
                        && (v[4] == 0 || v[4] == ' ' || v[4] == '\t'))
                        serveMode = 0;
                }
                seg = next;
            }
        }
        size_t n = strlen(line);
        while (n > 0 && (line[n - 1] == ' ' || line[n - 1] == '\t')) line[--n] = 0;
        char* sp = strchr(line, ' ');
        if (sp) *sp = 0;
        char* tab = strchr(line, '\t');
        if (tab) *tab = 0;
        if (!*line || strlen(line) >= MAX_PATH) continue;
        wchar_t w[MAX_PATH] = {};
        for (size_t i = 0; line[i]; ++i) w[i] = (wchar_t)(unsigned char)line[i];
        if (g_touched.size() >= 512) break;
        if (!in_list_ci(g_touched, w)) g_touched.push_back(w);
        if (serveMode == 1) {
            if (!in_list_ci(g_serveRaw, w) && g_serveRaw.size() < 512) g_serveRaw.push_back(w);
        } else if (serveMode == 2) {
            if (!in_list_ci(g_serveFmt1, w) && g_serveFmt1.size() < 512) g_serveFmt1.push_back(w);
        }
    }
    shim_log("touched: %zu consented plugin(s) (+%zu raw, +%zu fmt1) from !CompaSSE.ini",
             g_touched.size(), g_serveRaw.size(), g_serveFmt1.size());
}

static bool is_touched_name(const wchar_t* base) {
    if (!base || !base[0]) return true; // unknown: fail open
    AcquireSRWLockShared(&g_lock);
    if (!g_touchedLoaded) {
        ReleaseSRWLockShared(&g_lock);
        AcquireSRWLockExclusive(&g_lock);
        if (!g_touchedLoaded) load_touched();
        ReleaseSRWLockExclusive(&g_lock);
        AcquireSRWLockShared(&g_lock);
    }
    bool missing = g_touchedMissing;
    bool hit = false;
    if (!missing) {
        for (auto& t : g_touched) {
            if (_wcsicmp(t.c_str(), base) == 0) { hit = true; break; }
        }
    }
    ReleaseSRWLockShared(&g_lock);
    return missing ? true : hit;
}

static const wchar_t* module_basename(const wchar_t* path) {
    const wchar_t* bs = wcsrchr(path, L'\\');
    const wchar_t* fs = wcsrchr(path, L'/');
    if (bs && fs) return bs > fs ? bs + 1 : fs + 1;
    if (bs) return bs + 1;
    if (fs) return fs + 1;
    return path;
}

static bool is_touched_module(HMODULE mod) {
    if (!mod) return true; // unknown caller: fail open
    AcquireSRWLockShared(&g_lock);
    auto it = g_touchedCache.find(mod);
    if (it != g_touchedCache.end()) {
        bool v = it->second;
        ReleaseSRWLockShared(&g_lock);
        return v;
    }
    ReleaseSRWLockShared(&g_lock);
    wchar_t path[MAX_PATH] = {};
    const wchar_t* base = L"";
    if (GetModuleFileNameW(mod, path, MAX_PATH)) base = module_basename(path);
    bool hit = is_touched_name(base);
    AcquireSRWLockExclusive(&g_lock);
    if (g_touchedCache.size() >= 512) g_touchedCache.clear();
    g_touchedCache[mod] = hit;
    ReleaseSRWLockExclusive(&g_lock);
    return hit;
}

static bool is_serve_listed(const wchar_t* base, const std::vector<std::wstring>& list) {
    if (!base || !base[0]) return false;
    AcquireSRWLockShared(&g_lock);
    if (!g_touchedLoaded) {
        ReleaseSRWLockShared(&g_lock);
        AcquireSRWLockExclusive(&g_lock);
        if (!g_touchedLoaded) load_touched();
        ReleaseSRWLockExclusive(&g_lock);
        AcquireSRWLockShared(&g_lock);
    }
    bool missing = g_touchedMissing;
    bool hit = false;
    if (!missing) hit = in_list_ci(list, base);
    ReleaseSRWLockShared(&g_lock);
    return missing ? false : hit;
}

static bool is_serve_raw_name(const wchar_t* base) {
    return is_serve_listed(base, g_serveRaw);
}

static bool is_serve_fmt1_name(const wchar_t* base) {
    return is_serve_listed(base, g_serveFmt1);
}

static void touched_skip_log_once(const wchar_t* base, const char* what) {
    std::wstring key(base ? base : L"?");
    for (auto& c : key) c = (wchar_t)towlower(c);
    AcquireSRWLockExclusive(&g_lock);
    if (g_touchedSkipLogged.find(key) != g_touchedSkipLogged.end()) {
        ReleaseSRWLockExclusive(&g_lock);
        return;
    }
    g_touchedSkipLogged[key] = true;
    ReleaseSRWLockExclusive(&g_lock);
    char nm[MAX_PATH] = {};
    for (size_t i = 0; i < key.size() && i < MAX_PATH - 1; ++i)
        nm[i] = (char)(key[i] < 128 ? key[i] : '?');
    shim_log("touched: %s not consented, skipping %s", nm, what);
}

// True when the module may receive shim services; logs one skip line
// per basename per boot. Hook install itself is never gated.
static bool touched_gate(HMODULE mod, const char* what) {
    if (is_touched_module(mod)) return true;
    wchar_t path[MAX_PATH] = {};
    const wchar_t* base = L"?";
    if (mod && GetModuleFileNameW(mod, path, MAX_PATH))
        base = module_basename(path);
    touched_skip_log_once(base, what);
    return false;
}

// Translations serve the calling plugin's missing IDs; an unconsented
// caller gets none (apply_translations then adds 0). Set on the
// transcoding path before ensure_buffers runs (it builds once).
static void touched_set_allowed_for_caller(HMODULE caller) {
    g_translationsAllowed = is_touched_module(caller);
}

// Legacy loader: plugins with Query+Load but no version struct are
// skipped by SKSE outright (it never maps them - no load event to
// catch), so at activation we scan Data/SKSE/Plugins/*.dll and map
// what SKSE left unowned ourselves, then invoke Query/Load with
// SKSE's own interface. A skip-list (CompaSSE\!CompaSSE.ini [skip])
// excludes known faulters. Best effort: Query may
// decline, Load may fail, init may fault (SEH-isolated per plugin
// below).
// call_query/call_load stay POD-only: __try must not share scope with
// C++ objects (C2712). A faulting legacy init must never take the game.
typedef bool (*LegacyQueryFn)(const void* skse, void* info);
typedef bool (*LegacyLoadFn)(const void* skse);
struct LegacyPluginInfo {
    uint32_t infoVersion = 1;
    const char* name = nullptr;
    uint32_t version = 1;
};

static bool call_legacy_query(LegacyQueryFn fn, const void* skse,
                              LegacyPluginInfo* info, bool& crashed) {
    crashed = false;
    __try {
        return fn(skse, info);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        crashed = true;
        return false;
    }
}

static bool call_legacy_load(LegacyLoadFn fn, const void* skse,
                             bool& crashed) {
    crashed = false;
    __try {
        return fn(skse);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        crashed = true;
        return false;
    }
}

static HMODULE map_legacy_module(const wchar_t* full, bool& crashed) {
    crashed = false;
    __try {
        return LoadLibraryW(full);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        crashed = true;
        return nullptr;
    }
}

void legacy_activate_all(const void* skse) {
    if (!skse) {
        shim_log("legacy: no SKSE interface, skipping activation");
        return;
    }
    if (!g_self)
        return;
    wchar_t plugdir[MAX_PATH];
    if (!GetModuleFileNameW(g_self, plugdir, MAX_PATH))
        return;
    wchar_t* bs = wcsrchr(plugdir, L'\\');
    if (!bs)
        return;
    *bs = 0; // ...\Data\SKSE\Plugins: our DLL lives right in it
    wchar_t selfPath[MAX_PATH] = {};
    GetModuleFileNameW(g_self, selfPath, MAX_PATH);
    const wchar_t* selfBase = wcsrchr(selfPath, L'\\');
    selfBase = selfBase ? selfBase + 1 : selfPath;
    wchar_t pattern[MAX_PATH];
    wcscpy_s(pattern, plugdir);
    wcscat_s(pattern, L"\\*.dll");
    WIN32_FIND_DATAW fd;
    HANDLE fh = FindFirstFileW(pattern, &fd);
    if (fh == INVALID_HANDLE_VALUE) {
        shim_log("legacy: auto-scan found no DLLs (%lu)", GetLastError());
        return;
    }
    int done = 0;
    do {
        if (done >= 64)
            break;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;
        if (_wcsicmp(fd.cFileName, selfBase) == 0)
            continue;
        if (is_legacy_skipped(fd.cFileName)) {
            char snm[MAX_PATH] = {};
            for (int i = 0; i < MAX_PATH - 1 && fd.cFileName[i]; ++i)
                snm[i] = (char)(fd.cFileName[i] < 128 ? fd.cFileName[i] : '?');
            shim_log("legacy: %s on skip-list, not loading "
                     "(edit CompaSSE\\!CompaSSE.ini to retry)", snm);
            continue;
        }
        if (GetModuleHandleW(fd.cFileName))
            continue; // SKSE already owns it
        wchar_t full[MAX_PATH];
        wcscpy_s(full, plugdir);
        wcscat_s(full, L"\\");
        wcscat_s(full, fd.cFileName);
        if (GetModuleHandleW(full))
            continue;
        // Touched gate: only consented plugins are force-loaded here.
        if (!is_touched_name(fd.cFileName)) {
            touched_skip_log_once(fd.cFileName, "legacy loader");
            continue;
        }
        char nm[MAX_PATH] = {};
        for (int i = 0; i < MAX_PATH - 1 && fd.cFileName[i]; ++i)
            nm[i] = (char)(fd.cFileName[i] < 128 ? fd.cFileName[i] : '?');
        HMODULE mod = nullptr;
        bool mapCrashed = false;
        mod = map_legacy_module(full, mapCrashed);
        if (mapCrashed) {
            shim_log("legacy: %s CRASHED while mapping, skipped", nm);
            continue;
        }
        if (!mod) {
            shim_log("legacy: %s map failed (%lu), skipping", nm,
                     GetLastError());
            continue;
        }
        if (fpGetProcAddress(mod, "SKSEPlugin_Version")) {
            FreeLibrary(mod); // modern plugin, SKSE owns it
            continue;
        }
        bool owned = false;
        for (LONG q = 0; q < g_fakeVersionCount && q < 64; ++q) {
            if (g_fakeVersions[q].mod == mod && g_fakeVersions[q].consumed) {
                owned = true;
                break;
            }
        }
        if (owned) {
            FreeLibrary(mod); // already owned by SKSE, drop our reference
            continue;
        }
        auto qfn = (LegacyQueryFn)fpGetProcAddress(mod, "SKSEPlugin_Query");
        auto lfn = (LegacyLoadFn)fpGetProcAddress(mod, "SKSEPlugin_Load");
        if (!qfn || !lfn) {
            FreeLibrary(mod); // support lib, not a plugin
            continue;
        }
        shim_log("legacy: attempting load of %s", nm);
        LegacyPluginInfo info;
        info.name = nm;
        bool crashed = false;
        if (!call_legacy_query(qfn, skse, &info, crashed)) {
            shim_log("legacy: %s %s", nm,
                     crashed ? "CRASHED in Query, skipped"
                             : "declined Query, skipped");
            continue;
        }
        if (!call_legacy_load(lfn, skse, crashed)) {
            shim_log("legacy: %s %s", nm,
                     crashed ? "CRASHED in Load, skipped"
                             : "Load returned false, skipped");
            continue;
        }
        ++done;
        shim_log("legacy: %s loaded ok", nm);
    } while (FindNextFileW(fh, &fd));
    FindClose(fh);
    shim_log("legacy: auto-scan done (%d legacy loaded)", done);
}

// True when a v3 build stamp ("M.m.b") names the running game.
static bool table_stamp_current(const char* stamp) {
    InitOnceExecuteOnce(&g_verOnce, init_exe_version, nullptr, nullptr);
    unsigned a = 0, b = 0, c = 0;
    int n = 0;
    if (sscanf_s(stamp, "%u.%u.%u%n", &a, &b, &c, &n) != 3 || stamp[n] != '\0') {
        shim_log("load_translations: unparseable build stamp, ignoring table");
        return false;
    }
    if (!g_exeVersion[0]) {
        shim_log("load_translations: exe version unknown, applying table");
        return true;
    }
    wchar_t want[32];
    swprintf_s(want, L"%u-%u-%u", a, b, c);
    if (wcscmp(want, g_exeVersion) != 0) {
        shim_log("load_translations: table built for %ls, running %ls - skipping",
                 want, g_exeVersion);
        return false;
    }
    return true;
}

// ---- Translation table (cross-version ID remapping) ----
struct TranslationEntry { uint64_t old_id; uint32_t offset; };
static std::vector<TranslationEntry> g_flatTranslations; // flattened: all versions combined
static bool g_translations_loaded = false;

static void load_translations() {
    if (g_translations_loaded) return;
    g_translations_loaded = true;

    // Find CompaSSE\translation_table.bin next to this DLL
    wchar_t dllPath[MAX_PATH];
    if (!GetModuleFileNameW(g_self, dllPath, MAX_PATH)) return;
    wchar_t* bs = wcsrchr(dllPath, L'\\');
    if (bs) bs[1] = 0; else return;
    wchar_t fullPath[MAX_PATH];
    wcscpy_s(fullPath, dllPath);
    wcscat_s(fullPath, L"CompaSSE\\translation_table.bin");

    HANDLE h = fpCreateFileW(fullPath, GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        shim_log("load_translations: no CompaSSE\\translation_table.bin found");
        return;
    }
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart > (1 << 28)) { CloseHandle(h); return; } // 256MB max
    std::vector<uint8_t> buf((size_t)sz.QuadPart);
    DWORD total = 0;
    while (total < buf.size()) {
        DWORD rd = 0;
        if (!ReadFile(h, buf.data() + total, (DWORD)(buf.size() - total), &rd, nullptr) || rd == 0) break;
        total += rd;
    }
    CloseHandle(h);
    if (total != buf.size()) return;

    size_t o = 0;
    if (total < 8 || memcmp(buf.data(), "TRTL", 4) != 0) return;
    o = 4;
    uint32_t fmtVersion = *(uint32_t*)(buf.data() + o); o += 4;
    if (fmtVersion != 1 && fmtVersion != 3) {
        shim_log("load_translations: unsupported format version %u", fmtVersion);
        return;
    }
    if (fmtVersion == 3) {
        // Stamped with the build game version ("M.m.b"): skip tables from
        // another game, whose minted offsets don't apply here.
        if (o + 4 > total) return;
        uint32_t stampLen = *(uint32_t*)(buf.data() + o); o += 4;
        if (stampLen == 0 || stampLen > 32 || o + stampLen > total) {
            shim_log("load_translations: bad v3 stamp, ignoring table");
            return;
        }
        char stamp[33] = {};
        memcpy(stamp, buf.data() + o, stampLen);
        o += (stampLen + 3) & ~3u;
        if (!table_stamp_current(stamp)) return;
    }
    uint32_t verCount = *(uint32_t*)(buf.data() + o); o += 4;

    for (uint32_t v = 0; v < verCount && o < total; ++v) {
        if (o + 4 > total) break;
        uint32_t verLen = *(uint32_t*)(buf.data() + o); o += 4;
        if (verLen > 32 || o + verLen > total) break;
        o += (verLen + 3) & ~3; // skip version string
        if (o + 4 > total) break;
        uint32_t entryCount = *(uint32_t*)(buf.data() + o); o += 4;
        for (uint32_t e = 0; e < entryCount; ++e) {
            if (o + 12 > total) break;
            TranslationEntry te;
            te.old_id = *(uint64_t*)(buf.data() + o); o += 8;
            te.offset = *(uint32_t*)(buf.data() + o); o += 4;
            g_flatTranslations.push_back(te);
        }
    }
    // Deduplicate, keeping the newest version's entry. File order is oldest
    // to newest (build writes versions ascending, merges append), so the
    // last row per ID wins. (std::sort is not stable, so the old
    // sort+unique kept an arbitrary row - a cross-version lottery.)
    {
        std::map<uint64_t, uint32_t> newest;
        for (auto& te : g_flatTranslations) newest[te.old_id] = te.offset;
        g_flatTranslations.clear();
        g_flatTranslations.reserve(newest.size());
        for (auto& kv : newest)
            g_flatTranslations.push_back(TranslationEntry{kv.first, kv.second});
    }
    shim_log("load_translations: loaded %zu remapped IDs from %zu version tables",
             g_flatTranslations.size(), (size_t)verCount);
}

// Fill IDs the current library lacks. Never overwrites: `have` was just
// read from the current bins, so a recorded offset can only match or
// poison (table built for another game version). Returns added count.
// A miss on the touched gate adds 0: unconsented callers get no remaps.
static int apply_translations(std::map<uint64_t, uint64_t>& have) {
    if (!g_translationsAllowed) return 0;
    if (g_flatTranslations.empty()) return 0;
    int added = 0;
    for (auto& te : g_flatTranslations) {
        if (have.find(te.old_id) == have.end()) {
            have[te.old_id] = te.offset;
            added++;
        }
    }
    return added;
}

// Basename after the last slash or backslash. Five call sites shared
// one inline copy each; now they share this.
static const wchar_t* path_basename(const wchar_t* path) {
    const wchar_t* bs = wcsrchr(path, L'\\');
    const wchar_t* fs = wcsrchr(path, L'/');
    if (bs && fs) return bs > fs ? bs + 1 : fs + 1;
    if (bs) return bs + 1;
    if (fs) return fs + 1;
    return path;
}

// Basename must match either:
//   versionlib-X-Y-Z-W.bin  (AE / V2+ format, used by old CommonLibSSE and commonlibsse-ng AE mode)
//   version-X-Y-Z-W.bin     (legacy SE / V1 format, used by commonlibsse-ng SE mode)
static bool is_versionlib_path(const wchar_t* path) {
    const wchar_t* base = path_basename(path);
    size_t len = wcslen(base);
    if (len < 11 + 4) return false;
    // Must start with "versionlib-" or "version-"
    bool hasVlib = (_wcsnicmp(base, L"versionlib-", 11) == 0);
    bool hasVer  = (!hasVlib && _wcsnicmp(base, L"version-", 8) == 0);
    if (!hasVlib && !hasVer) return false;
    // Must end with ".bin"
    if (_wcsnicmp(base + len - 4, L".bin", 4) != 0) return false;
    return true;
}

static bool is_versionlib_handle(HANDLE h) {
    wchar_t buf[MAX_PATH];
    DWORD n = GetFinalPathNameByHandleW(h, buf, MAX_PATH, 0);
    if (n == 0 || n >= MAX_PATH) return false;
    return is_versionlib_path(buf);
}

// Named shared mappings the CommonLib family creates per game version.
static bool is_iddb_mapname(LPCWSTR name) {
    if (!name || !name[0]) return false;
    return wcsstr(name, L"COMMONLIB") || wcsstr(name, L"CommonLibSSE") ||
           wcsstr(name, L"AddressLib") || wcsstr(name, L"IDDB");
}

// File access matching a mapping protection: a read-only temp handle
// would fail callers mapping with write/execute (Error 5).
static DWORD temp_access_for_protect(DWORD protect) {
    DWORD access = GENERIC_READ;
    if (protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                   PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
        access |= GENERIC_WRITE;
    if (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                   PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
        access |= GENERIC_EXECUTE;
    return access;
}

// Shadow mappings: a section left behind by an older run, a zombie
// process or a no-shim run can be SMALLER than this run needs, and no
// API resizes or deletes someone else's section (oversize views die
// with Error 5). Bypass it with a fresh full-size section instead.
static void iddb_shadow_name(const wchar_t* orig, wchar_t* out) {
    size_t maxOrig = MAX_PATH - 11; // room for L"!CompaSSE" + NUL
    size_t n = wcslen(orig);
    if (n > maxOrig) n = maxOrig;
    wcsncpy_s(out, MAX_PATH, orig, n);
    wcscat_s(out, MAX_PATH, L"!CompaSSE");
}

static bool section_fits(HANDLE h, uint64_t need) {
    if (!need) return true;
    void* v = fpMapViewOfFile(h, FILE_MAP_READ, 0, 0, (SIZE_T)need);
    if (v) { UnmapViewOfFile(v); return true; }
    return false;
}

static uint64_t iddb_need_bytes() {
    AcquireSRWLockShared(&g_lock);
    uint32_t ids = g_loaded ? temp_entry_count(2) : 0;
    ReleaseSRWLockShared(&g_lock);
    return (uint64_t)ids * 16;
}

static HANDLE open_iddb_mapping(DWORD access, BOOL inherit, const wchar_t* name, uint64_t need) {
    HANDLE h = fpOpenFileMappingW(access, inherit, name);
    if (!h || !need || section_fits(h, need)) return h;
    CloseHandle(h);
    wchar_t shadow[MAX_PATH];
    iddb_shadow_name(name, shadow);
    HANDLE hs = fpOpenFileMappingW(access, inherit, shadow);
    if (hs) {
        if (section_fits(hs, need)) {
            shim_log("OpenFileMappingW %ls stale (smaller than %llu) -> shadow %ls", name, need, shadow);
            return hs;
        }
        CloseHandle(hs);
    }
    SetLastError(ERROR_FILE_NOT_FOUND);
    shim_log("OpenFileMappingW %ls stale (smaller than %llu), no shadow", name, need);
    return nullptr;
}

static HANDLE create_iddb_mapping(LPSECURITY_ATTRIBUTES sa, DWORD protect,
                                  DWORD sizeHigh, DWORD sizeLow, const wchar_t* name) {
    uint64_t reqSize = ((uint64_t)sizeHigh << 32) | (uint64_t)sizeLow;
    HANDLE h = fpCreateFileMappingW(INVALID_HANDLE_VALUE, sa, protect, sizeHigh, sizeLow, name);
    DWORD err = GetLastError();
    if (!h || err != ERROR_ALREADY_EXISTS || !reqSize) return h;
    if (section_fits(h, reqSize)) return h;
    CloseHandle(h);
    wchar_t shadow[MAX_PATH];
    iddb_shadow_name(name, shadow);
    HANDLE hs = fpCreateFileMappingW(INVALID_HANDLE_VALUE, sa, protect, sizeHigh, sizeLow, shadow);
    DWORD serr = GetLastError();
    if (!hs) {
        shim_log("CreateFileMappingW %ls stale (smaller than %llu), shadow %ls FAILED (err=%lu)",
                 name, reqSize, shadow, serr);
        SetLastError(serr);
        return nullptr;
    }
    if (serr == ERROR_ALREADY_EXISTS && !section_fits(hs, reqSize)) {
        CloseHandle(hs);
        shim_log("CreateFileMappingW %ls stale, shadow %ls stale too - giving up", name, shadow);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return nullptr;
    }
    SetLastError(ERROR_ALREADY_EXISTS);
    shim_log("CreateFileMappingW %ls stale (smaller than %llu) -> shadow %ls size=%llu",
             name, reqSize, shadow, reqSize);
    return hs;
}

// Same check, but also hands back the file path for version comparison.
static bool versionlib_handle_path(HANDLE h, wchar_t* out) {
    DWORD n = GetFinalPathNameByHandleW(h, out, MAX_PATH, 0);
    if (n == 0 || n >= MAX_PATH) return false;
    return is_versionlib_path(out);
}

// Read the real bin and build all three in-memory buffers (fmt1/fmt2/fmt5),
// regardless of the source format. Caller holds g_lock.
static void ensure_buffers(const wchar_t* binPath) {
    if (g_loaded || g_loadFailed || g_loading) return;
    g_loading = true;

    // Extract version string (e.g. "1-7-104") from path for serve_versionlib
    // to match versionlib-X.bin against version-X.bin for the same runtime.
    if (!g_currentVersion[0]) {
        const wchar_t* dash = wcsstr(binPath, L"-");
        if (dash) {
            const wchar_t* start = dash + 1;
            const wchar_t* end = wcsrchr(start, L'-');
            if (end && end > start) {
                size_t len = end - start;
                if (len < 32) { wcsncpy_s(g_currentVersion, 32, start, len); g_currentVersion[len] = L'\0'; }
            }
        }
    }

    // For transcoding: always prefer versionlib-*.bin (format 5, more entries).
    // If caller requests versionlib-*.bin: use it directly as source.
    // If caller requests version-*.bin: try versionlib-*.bin first, fall back to original.
    wchar_t altPath[MAX_PATH] = {};
    bool tried_alt = false;
    const wchar_t* vlib = wcsstr(binPath, L"versionlib-");
    const wchar_t* vonly = !vlib ? wcsstr(binPath, L"version-") : nullptr;
    if (vonly) {
        // version-*.bin gets versionlib-*.bin as alt (more entries, fmt5 source)
        wcscpy_s(altPath, binPath);
        wchar_t* vp = wcsstr(altPath, L"version-");
        if (vp) wmemmove(vp + 11, vp + 8, wcslen(vp + 8) + 1);
        if (vp) wmemcpy(vp, L"versionlib-", 11);
        tried_alt = true;
    }

    // Open: try alt first, then original
    HANDLE h = INVALID_HANDLE_VALUE;
    if (tried_alt) {
        h = fpCreateFileW(altPath, GENERIC_READ,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    }
    if (h == INVALID_HANDLE_VALUE) {
        h = fpCreateFileW(binPath, GENERIC_READ,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    }
    if (h == INVALID_HANDLE_VALUE) {
        g_loadFailed = true;
        g_loading = false;
        shim_log("ensure_buffers: open %ls failed (%lu)", binPath, GetLastError());
        return;
    }
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (LONGLONG)(1 << 30)) {
        CloseHandle(h);
        g_loadFailed = true;
        g_loading = false;
        shim_log("ensure_buffers: bad file size");
        return;
    }
    std::vector<uint8_t> src((size_t)sz.QuadPart);
    DWORD total = 0;
    while (total < src.size()) {
        DWORD rd = 0;
        if (!ReadFile(h, src.data() + total, (DWORD)(src.size() - total), &rd, nullptr) || rd == 0)
            break;
        total += rd;
    }
    CloseHandle(h);
    if (total != src.size()) {
        g_loadFailed = true;
        g_loading = false;
        shim_log("ensure_buffers: short read");
        return;
    }

    std::vector<std::pair<uint64_t, uint64_t>> entries;
    uint32_t version[4];
    std::string name;
    uint32_t ptr_size = 0;

    uint32_t srcFmt = src.size() >= 4
        ? (uint32_t)src[0] | ((uint32_t)src[1] << 8) | ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24)
        : 0;
    g_srcFmt = srcFmt;

    if (srcFmt == 5) {
        // Source is format 5: keep as fmt5, transcode down to fmt2 and fmt1.
        if (!parse_format5(src.data(), src.size(), entries, version, name, ptr_size)) {
            g_loadFailed = true;
            g_loading = false;
            shim_log("ensure_buffers: format5 parse failed (size=%zu, path=%ls)", src.size(), binPath);
            return;
        }
        g_fmt5 = src;
        std::map<uint64_t, uint64_t> have;
        uint32_t mergedPtr = ptr_size;
        static const uint64_t kKeepIds[] = { 41450 };
        for (auto& e : entries) if (e.second != 0) have[e.first] = e.second;
        for (auto id : kKeepIds) {
            size_t pos = 96 + (size_t)id * 4;
            if (pos + 4 <= src.size())
                have[id] = (uint64_t)src[pos] | ((uint64_t)src[pos + 1] << 8) |
                           ((uint64_t)src[pos + 2] << 16) | ((uint64_t)src[pos + 3] << 24);
        }
        load_translations();
        int added = apply_translations(have);
        if (added > 0)
            shim_log("ensure_buffers: translations added %d missing ID(s)", added);
        // Fold in the sibling version- file (same game version): it can
        // carry IDs this dense file lacks, and version- readers get this
        // merged temp now - so every ID either file has must be in it.
        // Absent slots only, never overwrites; capped to the slot range.
        {
            wchar_t vlib[MAX_PATH];
            wcscpy_s(vlib, binPath);
            if (!wcsstr(vlib, L"versionlib-")) {
                // Caller asked for version- itself; normalize to the
                // versionlib- form first (same running version either way).
                wchar_t* vp0 = wcsstr(vlib, L"version-");
                if (vp0) {
                    wmemmove(vp0 + 11, vp0 + 8, wcslen(vp0 + 8) + 1);
                    wmemcpy(vp0, L"versionlib-", 11);
                }
            }
            wchar_t* vp = wcsstr(vlib, L"versionlib-");
            if (vp) {
                wchar_t sib[MAX_PATH];
                wcscpy_s(sib, vlib);
                wchar_t* sp = wcsstr(sib, L"versionlib-");
                wmemmove(sp + 8, sp + 11, wcslen(sp + 11) + 1);
                wmemcpy(sp, L"version-", 8);
                HANDLE h = fpCreateFileW(sib, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (h != INVALID_HANDLE_VALUE) {
                    LARGE_INTEGER sz;
                    if (GetFileSizeEx(h, &sz) && sz.QuadPart > 0 &&
                        sz.QuadPart <= (LONGLONG)(1 << 28)) {
                        std::vector<uint8_t> sbuf((size_t)sz.QuadPart);
                        DWORD rd = 0, got = 0;
                        while (got < sbuf.size()) {
                            if (!ReadFile(h, sbuf.data() + got,
                                          (DWORD)(sbuf.size() - got), &rd, nullptr) || !rd)
                                break;
                            got += rd;
                        }
                        if (got == sbuf.size()) {
                            std::vector<std::pair<uint64_t, uint64_t>> se;
                            uint32_t sv[4];
                            std::string sn;
                            uint32_t sp = 0;
                            if (parse_format2(sbuf.data(), sbuf.size(), se, sv, sn, sp)) {
                                int filled = 0;
                                for (auto& e : se) {
                                    if (e.first < entries.size() &&
                                        have.find(e.first) == have.end()) {
                                        have[e.first] = e.second;
                                        ++filled;
                                    }
                                }
                                if (filled > 0)
                                    shim_log("ensure_buffers: version- sibling filled %d missing ID(s)", filled);
                            } else {
                                shim_log("ensure_buffers: version- sibling unreadable, skipping");
                            }
                        }
                    }
                    CloseHandle(h);
                }
            }
        }
        std::vector<std::pair<uint64_t, uint64_t>> merged(have.begin(), have.end());
        std::sort(merged.begin(), merged.end());
        size_t srcCount = entries.size();
        size_t dropped = 0;
        if (merged.size() > srcCount) {
            auto it = std::remove_if(merged.begin(), merged.end(),
                [srcCount](const auto& e) { return e.first >= srcCount; });
            dropped = (size_t)(merged.end() - it);
            merged.erase(it, merged.end());
        }
        size_t padded = 0;
        if (merged.size() < srcCount) {
            merged.reserve(srcCount);
            for (uint64_t i = (uint64_t)merged.size(); i < (uint64_t)srcCount; ++i) {
                merged.emplace_back(0xFFFFFFFFFFFFFFFFULL - i, 0);
                ++padded;
            }
        }
        if (dropped || padded)
            shim_log("ensure_buffers: count unified to %zu (dropped %zu, padded %zu)",
                     srcCount, dropped, padded);
        if (!encode_format2(g_fmt2, version, name, mergedPtr, merged)) {
            g_loadFailed = true;
            g_loading = false;
            shim_log("ensure_buffers: encode merged fmt2 failed");
            return;
        }
        if (!encode_format0(g_fmt0, version, name, mergedPtr, merged)) {
            g_loadFailed = true;
            g_loading = false;
            shim_log("ensure_buffers: encode merged fmt0 failed");
            return;
        }
        // fmt1 = fmt2 with format byte 1
        if (!format2_to_format1(g_fmt2.data(), g_fmt2.size(), g_fmt1)) {
            g_loadFailed = true;
            g_loading = false;
            shim_log("ensure_buffers: transcode merged fmt2 -> fmt1 failed");
            return;
        }
        // Fill absent slots only: a present offset is correct for this game.
        g_fmt5_patched = src;
        {
            int patched = 0;
            for (const auto& te : g_flatTranslations) {
                if (te.old_id * 4 + 96 + 4 <= g_fmt5_patched.size()) {
                    size_t pos = 96 + (size_t)te.old_id * 4;
                    uint32_t cur = (uint32_t)g_fmt5_patched[pos]
                        | ((uint32_t)g_fmt5_patched[pos + 1] << 8)
                        | ((uint32_t)g_fmt5_patched[pos + 2] << 16)
                        | ((uint32_t)g_fmt5_patched[pos + 3] << 24);
                    if (cur != 0) continue;
                    uint32_t v = (uint32_t)te.offset;
                    g_fmt5_patched[pos]     = (uint8_t)(v & 0xFF);
                    g_fmt5_patched[pos + 1] = (uint8_t)((v >> 8) & 0xFF);
                    g_fmt5_patched[pos + 2] = (uint8_t)((v >> 16) & 0xFF);
                    g_fmt5_patched[pos + 3] = (uint8_t)((v >> 24) & 0xFF);
                    patched++;
                }
            }
            if (patched > 0)
                shim_log("ensure_buffers: fmt5 filled %d missing ID(s)", patched);
        }
    } else if (srcFmt == 1 || srcFmt == 2) {
        // Source is format 1/2: build canonical fmt2 (never serve a fmt1 blob
        // mislabeled as fmt2 - V2 readers check format==2 strictly), then
        // transcode up to fmt5 and down to fmt1.
        if (!parse_format2(src.data(), src.size(), entries, version, name, ptr_size)) {
            g_loadFailed = true;
            g_loading = false;
            shim_log("ensure_buffers: format2 parse failed (size=%zu, path=%ls)", src.size(), binPath);
            return;
        }
        if (srcFmt == 2) {
            g_fmt2 = src;
        } else {
            // parse_format2 already sorts entries; encode canonical fmt2.
            if (!encode_format2(g_fmt2, version, name, ptr_size, entries)) {
                g_loadFailed = true;
                g_loading = false;
                shim_log("ensure_buffers: encode canonical fmt2 failed");
                return;
            }
        }
        uint32_t count = 0;
        if (!format2_to_format5(src.data(), src.size(), g_fmt5, count)) {
            g_loadFailed = true;
            g_loading = false;
            shim_log("ensure_buffers: transcode to fmt5 failed");
            return;
        }
        g_fmt5_patched = g_fmt5; // no merge for format 1/2 sources
        if (!format2_to_format1(src.data(), src.size(), g_fmt1)) {
            g_loadFailed = true;
            g_loading = false;
            shim_log("ensure_buffers: transcode to fmt1 failed");
            return;
        }
    } else {
        g_loadFailed = true;
        g_loading = false;
        shim_log("ensure_buffers: unsupported source format %u (size=%zu, path=%ls)", srcFmt, src.size(), binPath);
        return;
    }

    g_loaded = true;
    g_loading = false;
    shim_log("ensure_buffers: fmt%u source -> fmt0 %zu bytes, fmt1 %zu bytes, fmt2 %zu bytes, fmt5 %zu bytes (%zu entries)",
             srcFmt, g_fmt0.size(), g_fmt1.size(), g_fmt2.size(), g_fmt5.size(), entries.size());
}

// Materialize the temp file for one format. Caller holds g_lock.
static bool ensure_temp_file(int format) {
    wchar_t* ppath = format == 5 ? g_tempPath5 : format == 1 ? g_tempPath1 : format == 0 ? g_tempPath0 : g_tempPath2;
    if (ppath[0] != 0) return true;  // already materialized

    wchar_t dir[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, dir)) return false;
    wchar_t path[MAX_PATH];
    swprintf_s(path, L"%ls!CompaSSE_%lu_fmt%d.bin", dir, GetCurrentProcessId(), format);

    const std::vector<uint8_t>& buf = format == 5 ? g_fmt5_patched : format == 1 ? g_fmt1 : format == 0 ? g_fmt0 : g_fmt2;

    HANDLE w = fpCreateFileW(path, GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (w == INVALID_HANDLE_VALUE) {
        shim_log("ensure_temp_file: create %ls failed (%lu)", path, GetLastError());
        return false;
    }
    DWORD total = 0;
    while (total < buf.size()) {
        DWORD wr = 0;
        if (!WriteFile(w, buf.data() + total, (DWORD)(buf.size() - total), &wr, nullptr) || wr == 0)
            break;
        total += wr;
    }
    CloseHandle(w);
    if (total != buf.size()) {
        shim_log("ensure_temp_file: short write");
        return false;
    }
    wcscpy_s(ppath, MAX_PATH, path);
    return true;
}

// Serve the versionlib bin to one caller in the format its decoder can parse.
static HANDLE serve_versionlib(const wchar_t* path, DWORD access, DWORD share,
                               LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, HANDLE tmpl) {
    HMODULE caller = resolve_caller_module(g_self);
    wchar_t modName[MAX_PATH] = {};
    if (caller) GetModuleFileNameW(caller, modName, MAX_PATH);

    // Readers come for fmt1 when they open a version- file by name;
    // that expectation is strict, independent of decoder detection
    //.
    const wchar_t* base = path_basename(path);
    bool isVersionFile = (_wcsnicmp(base, L"version-", 8) == 0 &&
                          _wcsnicmp(base, L"versionlib-", 11) != 0);

    // SKSE itself (skse64*.dll) always needs the real file - pass through
    if (caller) {
        const wchar_t* modBase = wcsrchr(modName, L'\\');
        modBase = modBase ? modBase + 1 : modName;
        if (_wcsnicmp(modBase, L"skse64", 6) == 0) {
            shim_log("serve %ls -> pass-through for SKSE (%ls)", path, modName);
            return fpCreateFileW(path, access, share, sa, disp, flags, tmpl);
        }
    }

    if (is_old_version_path(path)) {
        shim_log("serve %ls -> pass-through old-version file for %ls", path,
                 modName[0] ? modName : L"(unknown)");
        return fpCreateFileW(path, access, share, sa, disp, flags, tmpl);
    }

    if (caller && is_touched_module(caller)) {
        const wchar_t* modBase = wcsrchr(modName, L'\\');
        modBase = modBase ? modBase + 1 : modName;
        if (is_serve_raw_name(modBase)) {
            shim_log("serve %ls -> fixed:raw for %ls", path,
                     modName[0] ? modName : L"(unknown)");
            return fpCreateFileW(path, access, share, sa, disp, flags, tmpl);
        }
        if (is_serve_fmt1_name(modBase)) {
            touched_set_allowed_for_caller(caller);
            AcquireSRWLockExclusive(&g_lock);
            ensure_buffers(path);
            if (g_loadFailed) {
                ReleaseSRWLockExclusive(&g_lock);
                shim_log("serve: load failed, serving real file");
                return fpCreateFileW(path, access, share, sa, disp, flags, tmpl);
            }
            if (!ensure_temp_file(1)) {
                ReleaseSRWLockExclusive(&g_lock);
                shim_log("serve: temp file failed, serving real file");
                return fpCreateFileW(path, access, share, sa, disp, flags, tmpl);
            }
            ReleaseSRWLockExclusive(&g_lock);
            shim_log("serve %ls -> fixed:fmt1 for %ls", path,
                     modName[0] ? modName : L"(unknown)");
            return fpCreateFileW(g_tempPath1, access, share, sa, disp, flags, tmpl);
        }
    }

    if (caller && !is_touched_module(caller)) {
        wchar_t callerPath[MAX_PATH] = {};
        const wchar_t* callerBase = L"(unknown)";
        if (GetModuleFileNameW(caller, callerPath, MAX_PATH))
            callerBase = module_basename(callerPath);
        touched_skip_log_once(callerBase, "serve");
        shim_log("serve %ls -> untouched=raw for %ls", path,
                 modName[0] ? modName : L"(unknown)");
        return fpCreateFileW(path, access, share, sa, disp, flags, tmpl);
    }

    CallerCaps caps = caller_caps(caller);
    touched_set_allowed_for_caller(caller);
    int format;
    if (!isVersionFile && !caller) {
        // Unknown caller keeps the real file: a temp fails fmt5-only
        // format checks, while the real file is no-shim behavior.
        shim_log("serve %ls -> pass-through unknown caller for %ls", path,
                 modName[0] ? modName : L"(unknown)");
        return fpCreateFileW(path, access, share, sa, disp, flags, tmpl);
    }
    
    if (!isVersionFile && caller && keep_real_bytes(caps)) {
        shim_log("serve %ls -> pass-through fmt5-native reader (decoder=%d dualV5=%d leg=%d ver=%d) for %ls", path,
                 (int)caps.type, caps.dualV5 ? 1 : 0, caps.legacy ? 1 : 0, caps.hasVer ? 1 : 0,
                 modName[0] ? modName : L"(unknown)");
        return fpCreateFileW(path, access, share, sa, disp, flags, tmpl);
    }
    if (isVersionFile) format = 1;
    else format = 2;
    AcquireSRWLockExclusive(&g_lock);
    ensure_buffers(path);
    if (g_loadFailed) {
        ReleaseSRWLockExclusive(&g_lock);
        shim_log("serve: load failed, serving real file");
        return fpCreateFileW(path, access, share, sa, disp, flags, tmpl);
    }
    int tempFmt = format;
    if (!ensure_temp_file(tempFmt)) {
        ReleaseSRWLockExclusive(&g_lock);
        shim_log("serve: temp file failed, serving real file");
        return fpCreateFileW(path, access, share, sa, disp, flags, tmpl);
    }
    const wchar_t* tempPath = tempFmt == 5 ? g_tempPath5 : tempFmt == 1 ? g_tempPath1 : tempFmt == 0 ? g_tempPath0 : g_tempPath2;
    uint32_t ids = temp_entry_count(tempFmt);
    ReleaseSRWLockExclusive(&g_lock);

    shim_log("serve %ls -> fixed:auto:fmt%d (decoder=%d, dualV5=%d, leg=%d, ver=%d, ids=%u, mapbytes=%llu) for %ls", path, tempFmt,
             (int)caps.type, caps.dualV5 ? 1 : 0, caps.legacy ? 1 : 0, caps.hasVer ? 1 : 0,
             ids, (unsigned long long)ids * 16,
             modName[0] ? modName : L"(unknown)");

    return fpCreateFileW(tempPath, access, share, sa, disp, flags, tmpl);
}

static HANDLE WINAPI Hook_CreateFileW(LPCWSTR name, DWORD access, DWORD share,
                                       LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, HANDLE tmpl) {
    if (name && is_versionlib_path(name)) {
        if (!g_loading && !g_serving_alt)
            return serve_versionlib(name, access, share, sa, disp, flags, tmpl);
    }
    return fpCreateFileW(name, access, share, sa, disp, flags, tmpl);
}

static HANDLE WINAPI Hook_CreateFileA(LPCSTR name, DWORD access, DWORD share,
                                       LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, HANDLE tmpl) {
    if (name) {
        int wlen = MultiByteToWideChar(CP_ACP, 0, name, -1, nullptr, 0);
        if (wlen > 0 && wlen <= MAX_PATH) {
            wchar_t wname[MAX_PATH];
            if (MultiByteToWideChar(CP_ACP, 0, name, -1, wname, wlen) > 0 && is_versionlib_path(wname)) {
                if (!g_loading)
                    return serve_versionlib(wname, access, share, sa, disp, flags, tmpl);
            }
        }
    }
    return fpCreateFileA(name, access, share, sa, disp, flags, tmpl);
}

static HANDLE WINAPI Hook_CreateFile2(LPCWSTR name, DWORD access, DWORD share, DWORD disp,
                                       LPCREATEFILE2_EXTENDED_PARAMETERS params) {
    if (name && is_versionlib_path(name)) {
        if (!g_loading && !g_serving_alt)
            return serve_versionlib(name, access, share, nullptr, disp,
                                    params ? params->dwFileFlags : 0, nullptr);
    }
    return fpCreateFile2(name, access, share, disp, params);
}

// Defensive: catches callers that mapped the REAL bin handle and redirects to temp file.
static HANDLE WINAPI Hook_CreateFileMappingW(HANDLE hFile, LPSECURITY_ATTRIBUTES sa, DWORD protect,
                                             DWORD sizeHigh, DWORD sizeLow, LPCWSTR name) {
    if ((hFile == nullptr || hFile == INVALID_HANDLE_VALUE) && is_iddb_mapname(name)) {
        uint64_t reqSize = ((uint64_t)sizeHigh << 32) | (uint64_t)sizeLow;
        HMODULE caller = resolve_caller_module(g_self);
        wchar_t modName[MAX_PATH] = L"(unknown)";
        if (caller) GetModuleFileNameW(caller, modName, MAX_PATH);
        const wchar_t* base = wcsrchr(modName, L'\\');
        HANDLE h = create_iddb_mapping(sa, protect, sizeHigh, sizeLow, name);
        DWORD err = h ? 0 : GetLastError();
        shim_log("CreateFileMappingW %ls size=%llu -> %s (err=%lu) for %ls", name,
                 reqSize, h ? "ok" : "FAILED", err, base ? base + 1 : modName);
        return h;
    }
    if (hFile != INVALID_HANDLE_VALUE && is_versionlib_handle(hFile)) {
        HMODULE caller = resolve_caller_module(g_self);
        CallerCaps caps = caller_caps(caller);
        touched_set_allowed_for_caller(caller);

    int format;
    wchar_t binPath[MAX_PATH] = {};
    {
        wchar_t fpath[MAX_PATH];
        if (!versionlib_handle_path(hFile, fpath))
            return fpCreateFileMappingW(hFile, sa, protect, sizeHigh, sizeLow, name);
        if (is_old_version_path(fpath))
            return fpCreateFileMappingW(hFile, sa, protect, sizeHigh, sizeLow, name);
        wcscpy_s(binPath, fpath);
        const wchar_t* base = path_basename(fpath);
        bool versionDash = (_wcsnicmp(base, L"version-", 8) == 0 &&
            _wcsnicmp(base, L"versionlib-", 11) != 0);
        wchar_t callerPath[MAX_PATH] = {};
        const wchar_t* callerBase = L"(unknown)";
        if (caller && GetModuleFileNameW(caller, callerPath, MAX_PATH))
            callerBase = path_basename(callerPath);
        bool fixedCaller = caller && is_touched_module(caller);
        bool forceRaw = fixedCaller && is_serve_raw_name(callerBase);
        bool forceFmt1 = !forceRaw && fixedCaller && is_serve_fmt1_name(callerBase);
        if (forceRaw) {
            shim_log("serve mapping -> fixed:raw for %ls", callerBase);
            return fpCreateFileMappingW(hFile, sa, protect, sizeHigh, sizeLow, name);
        }
        if (forceFmt1) {
            shim_log("serve mapping -> fixed:fmt1 for %ls", callerBase);
        } else if (caller && !is_touched_module(caller)) {
            // Untouched keeps the real mapping (no-shim).
            touched_skip_log_once(callerBase, "serve mapping");
            shim_log("serve mapping -> untouched=raw for %ls", callerBase);
            return fpCreateFileMappingW(hFile, sa, protect, sizeHigh, sizeLow, name);
        }
        if (!versionDash && !caller)
            return fpCreateFileMappingW(hFile, sa, protect, sizeHigh, sizeLow, name);
        if (!versionDash && caller && !forceFmt1 && keep_real_bytes(caps))
            return fpCreateFileMappingW(hFile, sa, protect, sizeHigh, sizeLow, name);
        format = (versionDash || forceFmt1) ? 1 : 2;
    }

        wchar_t modName[MAX_PATH] = L"(unknown)";
        if (caller) GetModuleFileNameW(caller, modName, MAX_PATH);

        AcquireSRWLockExclusive(&g_lock);
        if (!g_loaded && !g_loadFailed)
            ensure_buffers(binPath);
        bool ok = g_loaded && ensure_temp_file(format);
        const wchar_t* tempPath = format == 5 ? g_tempPath5 : format == 1 ? g_tempPath1 : g_tempPath2;
        ReleaseSRWLockExclusive(&g_lock);
        if (ok) {
            HANDLE temp = fpCreateFileW(tempPath, temp_access_for_protect(protect),
                                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                        nullptr, OPEN_EXISTING, 0, nullptr);
            if (temp != INVALID_HANDLE_VALUE) {
                HANDLE mapping = fpCreateFileMappingW(temp, sa, protect, sizeHigh, sizeLow, name);
                CloseHandle(temp);
                const wchar_t* base = wcsrchr(modName, L'\\');
                shim_log("CreateFileMappingW: redirecting versionlib handle to temp fixed:auto:fmt%d (dualV5=%d leg=%d ver=%d) for %ls",
                         format, caps.dualV5 ? 1 : 0, caps.legacy ? 1 : 0, caps.hasVer ? 1 : 0,
                         base ? base + 1 : modName);
                return mapping;
            }
        }
    }
    return fpCreateFileMappingW(hFile, sa, protect, sizeHigh, sizeLow, name);
}

// Log-only: who opens the shared IDDB mapping, and whether it exists yet.
static HANDLE WINAPI Hook_OpenFileMappingW(DWORD access, BOOL inherit, LPCWSTR name) {
    HANDLE h;
    bool iddb = is_iddb_mapname(name);
    if (iddb)
        h = open_iddb_mapping(access, inherit, name, iddb_need_bytes());
    else
        h = fpOpenFileMappingW(access, inherit, name);
    if (iddb) {
        HMODULE caller = resolve_caller_module(g_self);
        wchar_t modName[MAX_PATH] = L"(unknown)";
        if (caller) GetModuleFileNameW(caller, modName, MAX_PATH);
        const wchar_t* base = wcsrchr(modName, L'\\');
        shim_log("OpenFileMappingW %ls -> %s for %ls", name,
                 h ? "opened" : "missing", base ? base + 1 : modName);
    }
    return h;
}

// ANSI twins: some libs (commonlib-shared via REX) map through A calls,
// which never reach the W hooks above.
static HANDLE WINAPI Hook_CreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES sa, DWORD protect,
                                             DWORD sizeHigh, DWORD sizeLow, LPCSTR name) {
    wchar_t wname[MAX_PATH] = {};
    if (name) MultiByteToWideChar(CP_ACP, 0, name, -1, wname, MAX_PATH);
    if ((hFile == nullptr || hFile == INVALID_HANDLE_VALUE) && is_iddb_mapname(wname)) {
        uint64_t reqSize = ((uint64_t)sizeHigh << 32) | (uint64_t)sizeLow;
        HMODULE caller = resolve_caller_module(g_self);
        wchar_t modName[MAX_PATH] = L"(unknown)";
        if (caller) GetModuleFileNameW(caller, modName, MAX_PATH);
        const wchar_t* base = wcsrchr(modName, L'\\');
        HANDLE h = create_iddb_mapping(sa, protect, sizeHigh, sizeLow, wname);
        DWORD err = h ? 0 : GetLastError();
        shim_log("CreateFileMappingA %s size=%llu -> %s (err=%lu) for %ls", name ? name : "(null)",
                 reqSize, h ? "ok" : "FAILED", err, base ? base + 1 : modName);
        return h;
    }
    if (hFile != INVALID_HANDLE_VALUE && is_versionlib_handle(hFile)) {
        HMODULE caller = resolve_caller_module(g_self);
        CallerCaps caps = caller_caps(caller);
        touched_set_allowed_for_caller(caller);

    int format;
    wchar_t binPath[MAX_PATH] = {};
    {
        wchar_t fpath[MAX_PATH];
        if (!versionlib_handle_path(hFile, fpath))
            return fpCreateFileMappingA(hFile, sa, protect, sizeHigh, sizeLow, name);
        if (is_old_version_path(fpath))
            return fpCreateFileMappingA(hFile, sa, protect, sizeHigh, sizeLow, name);
        wcscpy_s(binPath, fpath);
        const wchar_t* base = path_basename(fpath);
        bool versionDash = (_wcsnicmp(base, L"version-", 8) == 0 &&
            _wcsnicmp(base, L"versionlib-", 11) != 0);
        wchar_t callerPath[MAX_PATH] = {};
        const wchar_t* callerBase = L"(unknown)";
        if (caller && GetModuleFileNameW(caller, callerPath, MAX_PATH))
            callerBase = path_basename(callerPath);
        bool fixedCaller = caller && is_touched_module(caller);
        bool forceRaw = fixedCaller && is_serve_raw_name(callerBase);
        bool forceFmt1 = !forceRaw && fixedCaller && is_serve_fmt1_name(callerBase);
        if (forceRaw) {
            shim_log("serve mapping -> fixed:raw for %ls", callerBase);
            return fpCreateFileMappingA(hFile, sa, protect, sizeHigh, sizeLow, name);
        }
        if (forceFmt1) {
            shim_log("serve mapping -> fixed:fmt1 for %ls", callerBase);
        } else if (caller && !is_touched_module(caller)) {
            // Untouched keeps the real mapping (no-shim).
            touched_skip_log_once(callerBase, "serve mapping");
            shim_log("serve mapping -> untouched=raw for %ls", callerBase);
            return fpCreateFileMappingA(hFile, sa, protect, sizeHigh, sizeLow, name);
        }
    // Same shape as the W twin (see serve_versionlib for the rule).
    // Unknown callers keep the real file; no consent check: only
    // proven legacy shapes take the temp.
    if (!versionDash && !caller)
        return fpCreateFileMappingA(hFile, sa, protect, sizeHigh, sizeLow, name);
    if (!versionDash && caller && !forceFmt1 && keep_real_bytes(caps))
        return fpCreateFileMappingA(hFile, sa, protect, sizeHigh, sizeLow, name);
    format = (versionDash || forceFmt1) ? 1 : 2;
    }

        wchar_t modName[MAX_PATH] = L"(unknown)";
        if (caller) GetModuleFileNameW(caller, modName, MAX_PATH);

        AcquireSRWLockExclusive(&g_lock);
        if (!g_loaded && !g_loadFailed)
            ensure_buffers(binPath);
        bool ok = g_loaded && ensure_temp_file(format);
        const wchar_t* tempPath = format == 5 ? g_tempPath5 : format == 1 ? g_tempPath1 : g_tempPath2;
        ReleaseSRWLockExclusive(&g_lock);
        if (ok) {
            HANDLE temp = fpCreateFileW(tempPath, temp_access_for_protect(protect),
                                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                        nullptr, OPEN_EXISTING, 0, nullptr);
            if (temp != INVALID_HANDLE_VALUE) {
                HANDLE mapping = fpCreateFileMappingA(temp, sa, protect, sizeHigh, sizeLow, name);
                DWORD err = mapping ? 0 : GetLastError();
                CloseHandle(temp);
                const wchar_t* base = wcsrchr(modName, L'\\');
                shim_log("CreateFileMappingA: redirecting versionlib handle to temp fixed:auto:fmt%d (dualV5=%d leg=%d ver=%d) -> %s (err=%lu) for %ls",
                         format, caps.dualV5 ? 1 : 0, caps.legacy ? 1 : 0, caps.hasVer ? 1 : 0,
                         mapping ? "ok" : "FAILED", err, base ? base + 1 : modName);
                return mapping;
            }
        }
    }
    return fpCreateFileMappingA(hFile, sa, protect, sizeHigh, sizeLow, name);
}

static HANDLE WINAPI Hook_OpenFileMappingA(DWORD access, BOOL inherit, LPCSTR name) {
    wchar_t wname[MAX_PATH] = {};
    if (name) MultiByteToWideChar(CP_ACP, 0, name, -1, wname, MAX_PATH);
    bool iddb = is_iddb_mapname(wname);
    HANDLE h;
    if (iddb)
        h = open_iddb_mapping(access, inherit, wname, iddb_need_bytes());
    else
        h = fpOpenFileMappingA(access, inherit, name);
    if (iddb) {
        HMODULE caller = resolve_caller_module(g_self);
        wchar_t modName[MAX_PATH] = L"(unknown)";
        if (caller) GetModuleFileNameW(caller, modName, MAX_PATH);
        const wchar_t* base = wcsrchr(modName, L'\\');
        shim_log("OpenFileMappingA %s -> %s for %ls", name ? name : "(null)",
                 h ? "opened" : "missing", base ? base + 1 : modName);
    }
    return h;
}

// Failure-only: a failed view is the actual "failed to create mapping"
// moment, whatever the API path. Successes are too frequent to log.
static LPVOID WINAPI Hook_MapViewOfFile(HANDLE hMap, DWORD access, DWORD offHigh,
                                        DWORD offLow, SIZE_T bytes) {
    LPVOID v = fpMapViewOfFile(hMap, access, offHigh, offLow, bytes);
    if (!v) {
        DWORD err = GetLastError();
        HMODULE caller = resolve_caller_module(g_self);
        wchar_t modName[MAX_PATH] = L"(unknown)";
        if (caller) GetModuleFileNameW(caller, modName, MAX_PATH);
        const wchar_t* base = wcsrchr(modName, L'\\');
        shim_log("MapViewOfFile bytes=%llu access=0x%lx -> FAILED (err=%lu) for %ls",
                 (unsigned long long)bytes, access, err, base ? base + 1 : modName);
    }
    return v;
}

// Convert NT path like "\??\C:\path\file.bin" -> "C:\path\file.bin".
static bool nt_path_to_win32(const wchar_t* nt, wchar_t* out, size_t outLen) {
    if (wcslen(nt) > 4 && nt[0] == L'\\' && nt[1] == L'?' && nt[2] == L'?' && nt[3] == L'\\') {
        wcscpy_s(out, outLen, nt + 4);
        return true;
    }
    wcscpy_s(out, outLen, nt);
    return false;
}

static NTSTATUS NTAPI Hook_NtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength) {

    if (!ObjectAttributes || !ObjectAttributes->ObjectName || !ObjectAttributes->ObjectName->Buffer) {
        return fpNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                              AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
                              CreateOptions, EaBuffer, EaLength);
    }

    // Reentrancy: CreateFileW internally calls NtCreateFile. If we redirected to CreateFileW,
    // the internal NtCreateFile would redirect back -> infinite loop. Pass through directly.
    if (g_ntRedirecting)
        return fpNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                              AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
                              CreateOptions, EaBuffer, EaLength);

    PUNICODE_STRING objName = ObjectAttributes->ObjectName;
    USHORT charCount = objName->Length / sizeof(wchar_t);
    if (charCount == 0 || charCount >= MAX_PATH)
        return fpNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                              AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
                              CreateOptions, EaBuffer, EaLength);

    wchar_t win32Path[MAX_PATH];
    wcsncpy_s(win32Path, MAX_PATH, objName->Buffer, charCount);
    win32Path[charCount] = L'\0';

    // Check basename directly for versionlib
    const wchar_t* base = path_basename(win32Path);
    bool isVlib = (wcslen(base) >= 12 &&  // "version-X-Y-Z-W.bin" minimum
                   ((_wcsnicmp(base, L"versionlib-", 11) == 0) ||
                    (_wcsnicmp(base, L"version-", 8) == 0)) &&
                   _wcsnicmp(base + wcslen(base) - 4, L".bin", 4) == 0);
    if (!isVlib)
        return fpNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                              AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
                              CreateOptions, EaBuffer, EaLength);

    // Reentrancy: ensure_buffers opens the real bin via CreateFileW -> NtCreateFile.
    // g_serving_alt: serve_versionlib opens alt path via fpCreateFileW -> NtCreateFile.
    if (g_loading || g_serving_alt)
        return fpNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                              AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
                              CreateOptions, EaBuffer, EaLength);

    // Strip \??\ prefix for Win32 path
    wchar_t cleanPath[MAX_PATH];
    nt_path_to_win32(win32Path, cleanPath, MAX_PATH);

    HMODULE caller = resolve_caller_module(g_self);
    wchar_t modName[MAX_PATH] = {};
    if (caller) GetModuleFileNameW(caller, modName, MAX_PATH);

    // SKSE itself always gets pass-through
    if (caller) {
        const wchar_t* modBase = wcsrchr(modName, L'\\');
        modBase = modBase ? modBase + 1 : modName;
        if (_wcsnicmp(modBase, L"skse64", 6) == 0) {
            return fpNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                                  AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
                                   CreateOptions, EaBuffer, EaLength);
        }
    }

    // Redirect to CreateFileW which has full serve logic.
    g_ntRedirecting = true;
    HANDLE h = CreateFileW(cleanPath, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    g_ntRedirecting = false;
    if (h != INVALID_HANDLE_VALUE) {
        *FileHandle = h;
        IoStatusBlock->Status = 0;  // STATUS_SUCCESS
        IoStatusBlock->Information = 0;
        return 0;
    }

    // Fallback: pass through to real NtCreateFile
    shim_log("NtCreateFile: CreateFileW redirect failed (err=%lu), passing through", GetLastError());
    return fpNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                          AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
                          CreateOptions, EaBuffer, EaLength);
}

// NtOpenFile: used by some CommonLibSSE versions for address library loading
static NTSTATUS NTAPI Hook_NtOpenFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions) {

    if (!ObjectAttributes || !ObjectAttributes->ObjectName || !ObjectAttributes->ObjectName->Buffer) {
        return fpNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                            ShareAccess, OpenOptions);
    }

    // Reentrancy: CreateFileW internally calls NtOpenFile. If we redirected to CreateFileW,
    // the internal NtOpenFile would redirect back -> infinite loop. Pass through directly.
    if (g_ntRedirecting)
        return fpNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                            ShareAccess, OpenOptions);

    PUNICODE_STRING objName = ObjectAttributes->ObjectName;
    USHORT charCount = objName->Length / sizeof(wchar_t);
    if (charCount == 0 || charCount >= MAX_PATH)
        return fpNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                            ShareAccess, OpenOptions);

    wchar_t win32Path[MAX_PATH];
    wcsncpy_s(win32Path, MAX_PATH, objName->Buffer, charCount);
    win32Path[charCount] = L'\0';

    const wchar_t* bs = wcsrchr(win32Path, L'\\');
    const wchar_t* fs = wcsrchr(win32Path, L'/');
    const wchar_t* base = (bs && fs) ? (bs > fs ? bs + 1 : fs + 1)
                        : bs ? bs + 1
                        : fs ? fs + 1
                        : win32Path;
    bool isVlib = (wcslen(base) >= 12 &&
                   ((_wcsnicmp(base, L"versionlib-", 11) == 0) ||
                    (_wcsnicmp(base, L"version-", 8) == 0)) &&
                   _wcsnicmp(base + wcslen(base) - 4, L".bin", 4) == 0);
    if (!isVlib)
        return fpNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                            ShareAccess, OpenOptions);

    if (g_loading || g_serving_alt)
        return fpNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                            ShareAccess, OpenOptions);

    wchar_t cleanPath[MAX_PATH];
    nt_path_to_win32(win32Path, cleanPath, MAX_PATH);

    HMODULE caller = resolve_caller_module(g_self);
    wchar_t modName[MAX_PATH] = {};
    if (caller) GetModuleFileNameW(caller, modName, MAX_PATH);

    g_ntRedirecting = true;
    HANDLE h = CreateFileW(cleanPath, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    g_ntRedirecting = false;
    if (h != INVALID_HANDLE_VALUE) {
        *FileHandle = h;
        IoStatusBlock->Status = 0;
        IoStatusBlock->Information = 0;
        return 0;
    }

    shim_log("NtOpenFile: CreateFileW redirect failed (err=%lu), passing through", GetLastError());
    return fpNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                        ShareAccess, OpenOptions);
}

void set_self(HMODULE module) {
    g_self = module;
}

static bool g_hooksInstalled = false;

bool install_hooks(HMODULE self_module) {
    g_self = self_module;

    if (g_hooksInstalled) {
        shim_log("install_hooks: already installed, skipping");
        return true;
    }

    shim_log("!CompaSSE shim version %s", COMPASSE_SHIM_VERSION);

    MH_STATUS st = MH_Initialize();
    if (st != MH_OK) {
        shim_log("install_hooks: MH_Initialize failed (%d)", (int)st);
        return false;
    }

    bool ok = true;
    st = MH_CreateHook(&CreateFileW, &Hook_CreateFileW, (void**)&fpCreateFileW);
    shim_log("install_hooks: CreateFileW %s", st == MH_OK ? "ok" : "FAILED");
    ok = ok && st == MH_OK;

    st = MH_CreateHook(&CreateFileA, &Hook_CreateFileA, (void**)&fpCreateFileA);
    shim_log("install_hooks: CreateFileA %s", st == MH_OK ? "ok" : "FAILED");
    ok = ok && st == MH_OK;

    st = MH_CreateHook(&CreateFile2, &Hook_CreateFile2, (void**)&fpCreateFile2);
    shim_log("install_hooks: CreateFile2 %s", st == MH_OK ? "ok" : "FAILED");
    ok = ok && st == MH_OK;

    st = MH_CreateHook(&CreateFileMappingW, &Hook_CreateFileMappingW, (void**)&fpCreateFileMappingW);
    shim_log("install_hooks: CreateFileMappingW %s", st == MH_OK ? "ok" : "FAILED");
    ok = ok && st == MH_OK;

    st = MH_CreateHook(&OpenFileMappingW, &Hook_OpenFileMappingW, (void**)&fpOpenFileMappingW);
    shim_log("install_hooks: OpenFileMappingW %s", st == MH_OK ? "ok" : "FAILED");
    ok = ok && st == MH_OK;

    st = MH_CreateHook(&CreateFileMappingA, &Hook_CreateFileMappingA, (void**)&fpCreateFileMappingA);
    shim_log("install_hooks: CreateFileMappingA %s", st == MH_OK ? "ok" : "FAILED");
    ok = ok && st == MH_OK;

    st = MH_CreateHook(&OpenFileMappingA, &Hook_OpenFileMappingA, (void**)&fpOpenFileMappingA);
    shim_log("install_hooks: OpenFileMappingA %s", st == MH_OK ? "ok" : "FAILED");
    ok = ok && st == MH_OK;

    st = MH_CreateHook(&MapViewOfFile, &Hook_MapViewOfFile, (void**)&fpMapViewOfFile);
    shim_log("install_hooks: MapViewOfFile %s", st == MH_OK ? "ok" : "FAILED");
    ok = ok && st == MH_OK;

    // Hook GetProcAddress to patch SKSEPlugin_Version flags at runtime
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (kernel32) {
        auto pGPA = (pfnGetProcAddress)GetProcAddress(kernel32, "GetProcAddress");
        if (pGPA) {
            st = MH_CreateHook(pGPA, &Hook_GetProcAddress, (void**)&fpGetProcAddress);
            shim_log("install_hooks: GetProcAddress %s", st == MH_OK ? "ok" : "FAILED");
            ok = ok && st == MH_OK;
        }
    }

    // Hook LoadLibrary* to patch SKSEPlugin_Version flags at module-load time
    // (catches plugins SKSE inspects directly from the export table, bypassing
    // GetProcAddress - e.g. dosemetha.dll).
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (k32) {
        auto pW = (pfnLoadLibraryW)GetProcAddress(k32, "LoadLibraryW");
        if (pW) {
            st = MH_CreateHook(pW, &Hook_LoadLibraryW, (void**)&fpLoadLibraryW);
            shim_log("install_hooks: LoadLibraryW %s", st == MH_OK ? "ok" : "FAILED");
            ok = ok && st == MH_OK;
        }
        auto pA = (pfnLoadLibraryA)GetProcAddress(k32, "LoadLibraryA");
        if (pA) {
            st = MH_CreateHook(pA, &Hook_LoadLibraryA, (void**)&fpLoadLibraryA);
            shim_log("install_hooks: LoadLibraryA %s", st == MH_OK ? "ok" : "FAILED");
            ok = ok && st == MH_OK;
        }
        auto pEx = (pfnLoadLibraryExW)GetProcAddress(k32, "LoadLibraryExW");
        if (pEx) {
            st = MH_CreateHook(pEx, &Hook_LoadLibraryExW, (void**)&fpLoadLibraryExW);
            shim_log("install_hooks: LoadLibraryExW %s", st == MH_OK ? "ok" : "FAILED");
            ok = ok && st == MH_OK;
        }
    }

    // Hook MessageBoxW to detect error dialogs
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32) {
        auto pMBW = (pfnMessageBoxW)GetProcAddress(user32, "MessageBoxW");
        if (pMBW) {
            st = MH_CreateHook(pMBW, &Hook_MessageBoxW, (void**)&fpMessageBoxW);
            shim_log("install_hooks: MessageBoxW %s", st == MH_OK ? "ok" : "FAILED");
            ok = ok && st == MH_OK;
        }
        auto pMBA = (pfnMessageBoxA)GetProcAddress(user32, "MessageBoxA");
        if (pMBA) {
            st = MH_CreateHook(pMBA, &Hook_MessageBoxA, (void**)&fpMessageBoxA);
            shim_log("install_hooks: MessageBoxA %s", st == MH_OK ? "ok" : "FAILED");
            ok = ok && st == MH_OK;
        }
    }

    // Hook NtCreateFile from ntdll.dll
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        auto pNtCreateFile = (pfnNtCreateFile)GetProcAddress(ntdll, "NtCreateFile");
        if (pNtCreateFile) {
            st = MH_CreateHook(pNtCreateFile, &Hook_NtCreateFile, (void**)&fpNtCreateFile);
            shim_log("install_hooks: NtCreateFile %s", st == MH_OK ? "ok" : "FAILED");
            ok = ok && st == MH_OK;
        } else {
            shim_log("install_hooks: NtCreateFile not found in ntdll");
        }
        auto pNtOpenFile = (pfnNtOpenFile)GetProcAddress(ntdll, "NtOpenFile");
        if (pNtOpenFile) {
            st = MH_CreateHook(pNtOpenFile, &Hook_NtOpenFile, (void**)&fpNtOpenFile);
            shim_log("install_hooks: NtOpenFile %s", st == MH_OK ? "ok" : "FAILED");
            ok = ok && st == MH_OK;
        } else {
            shim_log("install_hooks: NtOpenFile not found in ntdll");
        }
        auto pLdr = (pfnLdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
        if (pLdr) {
            st = MH_CreateHook(pLdr, &Hook_LdrLoadDll, (void**)&fpLdrLoadDll);
            shim_log("install_hooks: LdrLoadDll %s", st == MH_OK ? "ok" : "FAILED");
            ok = ok && st == MH_OK;
        } else {
            shim_log("install_hooks: LdrLoadDll not found in ntdll");
        }
    } else {
        shim_log("install_hooks: ntdll.dll not loaded");
    }

    st = MH_EnableHook(MH_ALL_HOOKS);
    shim_log("install_hooks: enable %s", st == MH_OK ? "ok" : "FAILED");
    g_hooksInstalled = true;

    // Load translation table at startup
    load_translations();

    return ok;
}

void uninstall_hooks() {
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    // Delete temp files (no persistent handles anymore)
    if (g_tempPath2[0]) { DeleteFileW(g_tempPath2); g_tempPath2[0] = 0; }
    if (g_tempPath5[0]) { DeleteFileW(g_tempPath5); g_tempPath5[0] = 0; }
    if (g_tempPath1[0]) { DeleteFileW(g_tempPath1); g_tempPath1[0] = 0; }
    if (g_tempPath0[0]) { DeleteFileW(g_tempPath0); g_tempPath0[0] = 0; }
    shim_log("uninstall_hooks: done");
}

void shim_log(const char* fmt, ...) {
    static CRITICAL_SECTION cs;
    static bool csInit = [] { InitializeCriticalSection(&cs); return true; }();
    (void)csInit;

    EnterCriticalSection(&cs);

    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf_s(msg, _TRUNCATE, fmt, ap);
    va_end(ap);

    SYSTEMTIME st;
    GetLocalTime(&st);
    char line[1400];
    int n = sprintf_s(line, "[%04u-%02u-%02u %02u:%02u:%02u.%03u] pid=%lu %s\r\n",
                      st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                      st.wMilliseconds, GetCurrentProcessId(), msg);
    if (n > 0) {
        char path[MAX_PATH] = {};
        DWORD len = g_self ? GetModuleFileNameA(g_self, path, MAX_PATH) : 0;
        if (len > 0 && len < MAX_PATH && path[0]) {
            // Replace the DLL basename's extension with .log, in CompaSSE subfolder.
            char* slash = strrchr(path, '\\');
            if (slash) {
                // Insert "CompaSSE\" before the filename
                char filename[MAX_PATH];
                strcpy_s(filename, slash + 1);
                char* dot = strrchr(filename, '.');
                if (dot) *dot = 0;
                strcat_s(filename, ".log");
                *(slash + 1) = 0;
                strcat_s(path, "CompaSSE\\");
                strcat_s(path, filename);
            } else {
                path[0] = 0;
            }
        } else {
            len = GetTempPathA(MAX_PATH, path);
            if (len > 0 && len < MAX_PATH)
                strcat_s(path, "!CompaSSE.log");
            else
                path[0] = 0;
        }
        if (path[0]) {
            static bool fresh = true;
            HANDLE h = CreateFileA(path, FILE_APPEND_DATA,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   nullptr, fresh ? CREATE_ALWAYS : OPEN_ALWAYS,
                                   FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h != INVALID_HANDLE_VALUE) {
                fresh = false;
                DWORD written = 0;
                WriteFile(h, line, (DWORD)n, &written, nullptr);
                CloseHandle(h);
            }
        }
    }

    LeaveCriticalSection(&cs);
}
