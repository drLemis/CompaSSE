#include "hooks.h"

#include "decoder_detect.h"
#include "transcode.h"

#include <MinHook.h>

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstdint>
#include <cwchar>
#include <intrin.h>
#include <map>
#include <string>
#include <utility>
#include <vector>

// ---- GetProcAddress interception (SKSE version bypass) ----
typedef FARPROC (WINAPI* pfnGetProcAddress)(HMODULE, LPCSTR);
static pfnGetProcAddress fpGetProcAddress = nullptr;

static FARPROC WINAPI Hook_GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    FARPROC result = fpGetProcAddress(hModule, lpProcName);
    if (!result || !lpProcName) return result;

    // Only intercept data export "SKSEPlugin_Version" (18 chars)
    // Skip ordinal lookups (high bit set) and short/long names
    if (((uintptr_t)lpProcName & ~0xFFFF) == 0) return result;
    if (lpProcName[0] != 'S' || lpProcName[18] != '\0') return result;
    if (memcmp(lpProcName, "SKSEPlugin_Version", 18) != 0) return result;

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

// Quarantine list from CompaSSE\quarantine.ini (one decimal/hex ID per
// line, ';' '#' and [sections] ignored). Missing/unparseable file = empty.
static std::vector<uint64_t> g_quarantine;
static bool g_quarantine_loaded = false;

static void load_quarantine() {
    if (g_quarantine_loaded) return;
    g_quarantine_loaded = true;
    if (!g_self) return;
    wchar_t path[MAX_PATH];
    if (!GetModuleFileNameW(g_self, path, MAX_PATH)) return;
    wchar_t* bs = wcsrchr(path, L'\\');
    if (!bs) return;
    *bs = 0;
    wcscat_s(path, L"\\CompaSSE\\quarantine.ini");
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    char buf[8192];
    DWORD rd = 0;
    BOOL ok = ReadFile(h, buf, sizeof(buf) - 1, &rd, nullptr);
    CloseHandle(h);
    if (!ok || rd == 0) return;
    buf[rd] = 0;
    if (buf[0] == '\0') return;
    // Tolerate a UTF-8 BOM (Notepad-saved files); reject UTF-16 outright.
    char* text = buf;
    if (rd > 3 && (unsigned char)buf[0] == 0xEF) {
        if ((unsigned char)buf[1] != 0xBB || (unsigned char)buf[2] != 0xBF) return;
        text += 3;
    } else if (rd > 2 && (unsigned char)buf[0] == 0xFF) {
        shim_log("load_quarantine: ignoring non-ANSI file (save as ANSI/UTF-8)");
        return;
    }
    int skipped = 0;
    char* ctx = nullptr;
    for (char* line = strtok_s(text, "\r\n", &ctx); line;
         line = strtok_s(nullptr, "\r\n", &ctx)) {
        while (*line == ' ' || *line == '\t') ++line;
        if (!*line || *line == ';' || *line == '#' || *line == '[') continue; // not an entry
        unsigned long long v = 0;
        bool hex = (line[0] == '0' && (line[1] == 'x' || line[1] == 'X'));
        int n = sscanf_s(line, hex ? "%llx" : "%llu", &v);
        if (n != 1 || v == 0 || v >= (1ULL << 40)) { ++skipped; continue; }
        if (g_quarantine.size() >= 8192) break;
        g_quarantine.push_back((uint64_t)v);
    }
    // Only malformed ID lines count as skipped; comments never do.
    shim_log("load_quarantine: %zu ID(s)%s", g_quarantine.size(),
             skipped ? " (some entries skipped)" : "");
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
    if (fmtVersion != 1) {
        shim_log("load_translations: unsupported format version %u", fmtVersion);
        return;
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

// Apply translation table: remap old_id -> offset for the current runtime.
// Caller holds g_lock. Returns number of remapped entries.
static int apply_translations(std::map<uint64_t, uint64_t>& have) {
    if (g_flatTranslations.empty()) return 0;
    int remapped = 0;
    for (auto& te : g_flatTranslations) {
        auto it = have.find(te.old_id);
        if (it != have.end()) {
            if (it->second != te.offset) {
                it->second = te.offset;
                remapped++;
            }
        } else {
            // ID from a version we don't have a bin for - still add it
            have[te.old_id] = te.offset;
            remapped++;
        }
    }
    return remapped;
}

// Basename must match either:
//   versionlib-X-Y-Z-W.bin  (AE / V2+ format, used by old CommonLibSSE and commonlibsse-ng AE mode)
//   version-X-Y-Z-W.bin     (legacy SE / V1 format, used by commonlibsse-ng SE mode)
static bool is_versionlib_path(const wchar_t* path) {
    const wchar_t* bs = wcsrchr(path, L'\\');
    const wchar_t* fs = wcsrchr(path, L'/');
    const wchar_t* base = (bs && fs) ? (bs > fs ? bs + 1 : fs + 1)
                        : bs ? bs + 1
                        : fs ? fs + 1
                        : path;
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
        // version-*.bin → try versionlib-*.bin as alt (has more entries, fmt5 source)
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
        if (!g_quarantine_loaded) load_quarantine();
        int quarantined = 0;
        for (auto id : g_quarantine) quarantined += (int)have.erase(id);
        if (quarantined > 0)
            shim_log("ensure_buffers: quarantined %d ID(s)", quarantined);
        load_translations();
        int remapped = apply_translations(have);
        std::vector<std::pair<uint64_t, uint64_t>> merged(have.begin(), have.end());
        std::sort(merged.begin(), merged.end());
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
        // g_fmt5_patched: copy of raw fmt5 with translated offsets patched in.
        g_fmt5_patched = src;
        {
            int patched = 0;
            for (const auto& te : g_flatTranslations) {
                if (te.old_id * 4 + 96 + 4 <= g_fmt5_patched.size()) {
                    size_t pos = 96 + (size_t)te.old_id * 4;
                    uint32_t v = (uint32_t)te.offset;
                    g_fmt5_patched[pos]     = (uint8_t)(v & 0xFF);
                    g_fmt5_patched[pos + 1] = (uint8_t)((v >> 8) & 0xFF);
                    g_fmt5_patched[pos + 2] = (uint8_t)((v >> 16) & 0xFF);
                    g_fmt5_patched[pos + 3] = (uint8_t)((v >> 24) & 0xFF);
                    patched++;
                }
            }
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

    // Determine prefix: "version-" (old SE) vs "versionlib-" (AE/NG)
    const wchar_t* bs = wcsrchr(path, L'\\');
    const wchar_t* fs = wcsrchr(path, L'/');
    const wchar_t* base = (bs && fs) ? (bs > fs ? bs + 1 : fs + 1)
                        : bs ? bs + 1
                        : fs ? fs + 1
                        : path;
    bool hasVersionPrefix = (_wcsnicmp(base, L"version-", 8) == 0 && _wcsnicmp(base, L"versionlib-", 11) != 0);

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

    // Pass through by default, transcode only on format mismatch
    DecoderType type = caller ? decoder_for_module(caller, g_self) : DECODER_NONE;
    int format;
    if (hasVersionPrefix) {
        shim_log("serve %ls -> pass-through version- file for %ls (decoder=%d)",
                 path, modName[0] ? modName : L"(unknown)", (int)type);
        return fpCreateFileW(path, access, share, sa, disp, flags, tmpl);
    } else if (type == DECODER_V1) format = 1;
    else format = 2;

    // Transcode the requested file itself to the caller's format; only
    // fmt1/fmt2 temps are ever served (nothing routes to fmt5).
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
    ReleaseSRWLockExclusive(&g_lock);

    shim_log("serve %ls -> format %d (transcoded, decoder=%d) for %ls", path, tempFmt,
             (int)type, modName[0] ? modName : L"(unknown)");

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
    if (hFile != INVALID_HANDLE_VALUE && is_versionlib_handle(hFile)) {
        HMODULE caller = resolve_caller_module(g_self);
        DecoderType type = caller ? decoder_for_module(caller, g_self) : DECODER_NONE;

        // Determine prefix (name may be NULL for unnamed mappings)
        bool hasVersionPrefix = false;
        if (name) {
            const wchar_t* bs = wcsrchr(name, L'\\');
            const wchar_t* fs = wcsrchr(name, L'/');
            const wchar_t* base = (bs && fs) ? (bs > fs ? bs + 1 : fs + 1)
                                : bs ? bs + 1
                                : fs ? fs + 1
                                : name;
            hasVersionPrefix = (_wcsnicmp(base, L"version-", 8) == 0 &&
                                _wcsnicmp(base, L"versionlib-", 11) != 0);
        }

    int format;
    if (hasVersionPrefix) {
        return fpCreateFileMappingW(hFile, sa, protect, sizeHigh, sizeLow, name);
    }
    {
        wchar_t fpath[MAX_PATH];
        if (versionlib_handle_path(hFile, fpath) && is_old_version_path(fpath))
            return fpCreateFileMappingW(hFile, sa, protect, sizeHigh, sizeLow, name);
    }
    format = (caller && type == DECODER_V1) ? 1 : 2;

        wchar_t modName[MAX_PATH] = L"(unknown)";
        if (caller) GetModuleFileNameW(caller, modName, MAX_PATH);

        AcquireSRWLockExclusive(&g_lock);
        bool ok = g_loaded && ensure_temp_file(format);
        const wchar_t* tempPath = format == 5 ? g_tempPath5 : format == 1 ? g_tempPath1 : g_tempPath2;
        ReleaseSRWLockExclusive(&g_lock);
        if (ok) {
            HANDLE temp = fpCreateFileW(tempPath, GENERIC_READ,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                        nullptr, OPEN_EXISTING, 0, nullptr);
            if (temp != INVALID_HANDLE_VALUE) {
                shim_log("CreateFileMappingW: redirecting versionlib handle to temp fmt%d", format);
                HANDLE mapping = fpCreateFileMappingW(temp, sa, protect, sizeHigh, sizeLow, name);
                CloseHandle(temp);
                return mapping;
            }
        }
    }
    return fpCreateFileMappingW(hFile, sa, protect, sizeHigh, sizeLow, name);
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
    const wchar_t* bs = wcsrchr(win32Path, L'\\');
    const wchar_t* fs = wcsrchr(win32Path, L'/');
    const wchar_t* base = (bs && fs) ? (bs > fs ? bs + 1 : fs + 1)
                        : bs ? bs + 1
                        : fs ? fs + 1
                        : win32Path;
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
