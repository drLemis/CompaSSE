#include "decoder_detect.h"

#include <cstring>
#include <cwchar>
#include <unordered_map>

bool is_system_module(const wchar_t* path) {
    wchar_t low[MAX_PATH];
    size_t len = wcslen(path);
    if (len >= MAX_PATH) len = MAX_PATH - 1;
    for (size_t i = 0; i < len; ++i) low[i] = (wchar_t)towlower(path[i]);
    low[len] = 0;

    if (wcsstr(low, L"api-ms-win-crt") || wcsstr(low, L"msvcp") ||
        wcsstr(low, L"vcruntime") || wcsstr(low, L"ucrtbase") ||
        wcsstr(low, L"kernel32") || wcsstr(low, L"ntdll"))
        return true;
    if (wcsncmp(low, L"c:\\windows\\system32", 19) == 0) return true;
    return false;
}

DecoderType detect_decoder(HMODULE mod) {
    if (!mod) return DECODER_NONE;

    const auto* dos = (const IMAGE_DOS_HEADER*)mod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return DECODER_NONE;
    const auto* nt = (const IMAGE_NT_HEADERS64*)((const uint8_t*)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return DECODER_NONE;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return DECODER_NONE;

    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0) return DECODER_NONE;

    const auto* imp = (const IMAGE_IMPORT_DESCRIPTOR*)((const uint8_t*)mod + dir.VirtualAddress);
    bool hasIstream = false, hasMmap = false;

    for (; imp->Name != 0; ++imp) {
        const uintptr_t* thunk = imp->OriginalFirstThunk
            ? (const uintptr_t*)((const uint8_t*)mod + imp->OriginalFirstThunk)
            : (const uintptr_t*)((const uint8_t*)mod + imp->FirstThunk);
        for (; *thunk != 0; ++thunk) {
            if (*thunk & 0x8000000000000000ULL) continue; // import by ordinal
            const auto* byName = (const IMAGE_IMPORT_BY_NAME*)((const uint8_t*)mod + (*thunk & 0x7FFFFFFFFFFFFFFFULL));
            const char* fname = (const char*)byName->Name;
            if (strstr(fname, "istream") || strstr(fname, "seekg") || strstr(fname, "tellg"))
                hasIstream = true;
            else if (strstr(fname, "CreateFileMapping") || strstr(fname, "MapViewOfFile") || strstr(fname, "OpenFileMapping"))
                hasMmap = true;
        }
    }

    // Both (CreateFileMapping + istream): fmt5 reader - commonlibsse-ng with mmap caching
    // Mmap-only: fmt2 reader - po3_PapyrusExtender (mmap, no istream)
    // Istream-only: fmt1 reader - old CommonLibSSE (PrismaUI, etc.)
    // Neither: fmt2 reader (default)
    if (hasMmap && hasIstream) return DECODER_V5;
    if (hasIstream && !hasMmap) return DECODER_V1;
    return DECODER_V2;
}

HMODULE resolve_caller_module(HMODULE self_module) {
    void* frames[32] = {};
    USHORT n = RtlCaptureStackBackTrace(1, 32, frames, nullptr);
    for (USHORT i = 0; i < n; ++i) {
        HMODULE mod = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                (LPCWSTR)frames[i], &mod))
            continue;
        if (mod == self_module) continue;
        wchar_t path[MAX_PATH];
        if (GetModuleFileNameW(mod, path, MAX_PATH) == 0) continue;
        if (is_system_module(path)) continue;
        return mod;
    }
    return nullptr;
}

DecoderType decoder_for_module(HMODULE mod, HMODULE self_module) {
    (void)self_module; // kept for API symmetry; not needed for the lookup

    struct Cache {
        std::unordered_map<HMODULE, DecoderType> map;
        CRITICAL_SECTION cs;
        Cache() { InitializeCriticalSection(&cs); }
        ~Cache() { DeleteCriticalSection(&cs); }
    };
    static Cache cache; // static-init struct: CRITICAL_SECTION ready before any hook runs

    EnterCriticalSection(&cache.cs);
    auto it = cache.map.find(mod);
    if (it != cache.map.end()) {
        DecoderType t = it->second;
        LeaveCriticalSection(&cache.cs);
        return t;
    }
    DecoderType t = detect_decoder(mod);
    cache.map[mod] = t;
    LeaveCriticalSection(&cache.cs);
    return t;
}

static const char* const kFmt5Markers[] = {
    "AddressLibraryV5",
    "Address Library V5",
    "not an Address Library V5 file",
    "AddressLibV2",
};

static const char* const kFmt2OnlyMarkers[] = {
    "CommonLibSSEOffsets",
    "Unsupported address library format",
    "within the address library",
    "failed to create shared mapping",
};

static bool scan_markers(const uint8_t* base, size_t size,
                         const char* const* marks, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        const char* m = marks[i];
        size_t len = strlen(m);
        if (len == 0 || len > size)
            continue;
        const uint8_t* p = base;
        const uint8_t* end = base + size - len + 1;
        for (; p < end; ++p) {
            if (p[0] == (uint8_t)m[0] && memcmp(p, m, len) == 0)
                return true;
        }
    }
    return false;
}

static bool scan_module_marks(HMODULE mod, const char* const* marks,
                              size_t count) {
    const auto* dos = (const IMAGE_DOS_HEADER*)mod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    const auto* nt = (const IMAGE_NT_HEADERS64*)((const uint8_t*)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return false;
    const auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        char name[9] = {};
        memcpy(name, sec->Name, 8);
        if (strcmp(name, ".rdata") != 0 && strcmp(name, ".data") != 0)
            continue;
        // A fault here must never take down the game
        __try {
            const uint8_t* base = (const uint8_t*)mod + sec->VirtualAddress;
            if (scan_markers(base, sec->Misc.VirtualSize, marks, count))
                return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    return false;
}

static bool scan_module_fmt5(HMODULE mod) {
    return scan_module_marks(mod, kFmt5Markers,
                             sizeof(kFmt5Markers) / sizeof(kFmt5Markers[0]));
}

static bool scan_module_legacy(HMODULE mod) {
    return scan_module_marks(mod, kFmt2OnlyMarkers,
                             sizeof(kFmt2OnlyMarkers) /
                             sizeof(kFmt2OnlyMarkers[0]));
}

// One cache for every per-module boolean signal
enum ScanKind { SCAN_FMT5, SCAN_LEGACY, SCAN_VERSION };

static bool cached_scan(HMODULE mod, ScanKind kind, bool (*scan)(HMODULE)) {
    struct Cache {
        std::unordered_map<uint64_t, bool> map;
        CRITICAL_SECTION cs;
        Cache() { InitializeCriticalSection(&cs); }
        ~Cache() { DeleteCriticalSection(&cs); }
    };
    static Cache cache; // same static-init pattern as the decoder cache
    uint64_t key = ((uint64_t)mod << 2) | (uint64_t)kind;
    EnterCriticalSection(&cache.cs);
    auto it = cache.map.find(key);
    if (it != cache.map.end()) {
        bool found = it->second;
        LeaveCriticalSection(&cache.cs);
        return found;
    }
    LeaveCriticalSection(&cache.cs);

    bool found = scan(mod);

    EnterCriticalSection(&cache.cs);
    cache.map[key] = found;
    LeaveCriticalSection(&cache.cs);
    return found;
}

bool module_supports_fmt5(HMODULE mod) {
    if (!mod)
        return false;
    return cached_scan(mod, SCAN_FMT5, scan_module_fmt5);
}

bool module_is_legacy_reader(HMODULE mod) {
    if (!mod)
        return false;
    return cached_scan(mod, SCAN_LEGACY, scan_module_legacy);
}

static bool scan_version_export(HMODULE mod) {
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)mod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    const IMAGE_NT_HEADERS64* nt =
        (const IMAGE_NT_HEADERS64*)((const uint8_t*)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return false;
    const IMAGE_DATA_DIRECTORY& dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0)
        return false;
    bool found = false;
    __try {
        const IMAGE_EXPORT_DIRECTORY* exp =
            (const IMAGE_EXPORT_DIRECTORY*)((const uint8_t*)mod +
                                            dir.VirtualAddress);
        const DWORD* names = (const DWORD*)((const uint8_t*)mod +
                                            exp->AddressOfNames);
        for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
            const char* n =
                (const char*)((const uint8_t*)mod + names[i]);
            if (n[0] == 'S' && strcmp(n, "SKSEPlugin_Version") == 0) {
                found = true;
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    return found;
}

bool module_has_version_export(HMODULE mod) {
    if (!mod)
        return false;
    return cached_scan(mod, SCAN_VERSION, scan_version_export);
}