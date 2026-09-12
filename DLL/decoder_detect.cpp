#include "decoder_detect.h"

#include <cstring>
#include <cwchar>
#include <unordered_map>

namespace {

// True if the module path belongs to the OS/CRT and should be skipped when
// resolving the caller of a hooked API.
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

} // namespace

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
    // 32 frames: CRT ifstream opens bury the plugin frame deep behind
    // system DLLs; 8 routinely missed it and misclassified healthy mods.
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