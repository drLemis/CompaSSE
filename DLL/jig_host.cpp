// jig_host: isolated SKSE plugin starter for X-Ray live checks.
//
// Loads ONE copied DLL with a fake SKSE interface, calls its Query/Load
// under SEH, and writes key=value results. Never touches the game or the
// original file; the Python parent enforces the timeout from outside.
// Usage: jig_host.exe <dll> --out <result> --runtime <hex> --workdir <dir>
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct SKSEInterface {
    uint32_t skseVersion;
    uint32_t runtimeVersion;
    uint32_t editorVersion;
    uint32_t isEditor;
    void* (*QueryInterface)(uint32_t id);
    uint32_t (*GetPluginHandle)(void);
    uint32_t (*GetReleaseIndex)(void);
    const void* (*GetPluginInfo)(const char* name);
};

struct SKSEVersionData {
    uint32_t dataVersion;
    uint32_t pluginVersion;
    char name[256];
    char author[256];
    char supportEmail[252];
    uint32_t versionIndependenceEx;
    uint32_t versionIndependence;
    uint32_t compatibleVersions[16];
    uint32_t seVersionRequired;
};

struct SKSEMessaging {
    uint32_t interfaceVersion;
    bool (*RegisterListener)(uint32_t handle, const char* sender,
                             void (*handler)(void*));
    bool (*Dispatch)(uint32_t msgType, void* data, uint32_t dataLen,
                     const char* receiver);
};

static bool MsgRegister(uint32_t, const char*, void (*)(void*)) { return true; }
static bool MsgDispatch(uint32_t, void*, uint32_t, const char*) { return true; }
static SKSEMessaging g_msg = {1, MsgRegister, MsgDispatch};

// Interface 5 is kMessaging in this SKSE generation (mirrors the
// shim's own post-load listener). Everything else is genuinely
// absent, same as a missing optional SKSE plugin.
static char g_qi[256] = {};
static void* NullQI(uint32_t id) {
    char b[16];
    sprintf_s(b, "%u,", id);
    if (strlen(g_qi) + strlen(b) < sizeof(g_qi))
        strcat_s(g_qi, b);
    return id == 5 ? &g_msg : nullptr;
}
static uint32_t OneHandle(void) { return 1; }
static uint32_t ZeroRel(void) { return 0; }
static const void* NullInfo(const char*) { return nullptr; }

static FILE* g_out = nullptr;
static const char* g_stage = "start";
static DWORD g_watchdog_ms = 0;
static HANDLE g_main_thread = nullptr;
static bool g_notaps = false;
static DWORD WINAPI Watchdog(LPVOID);
static DWORD g_code = 0;
static DWORD g_main_tid = 0;
static char g_fault[260] = {};
static char g_stack[1536] = {};

static void fault_name(void* at, char* out, size_t n);
static HMODULE g_mod = nullptr;

// Walk the FAULTING stack, not ours: return addresses above Rsp that
// land inside the tested module name its callers. Best effort; frame
// pointers are optional on x64, so entries are candidates, ordered.
static void fault_stack(CONTEXT* ctx, char* out, size_t n) {
    size_t pos = 0;
    int kept = 0;
    if (!ctx) return;
    for (int i = 0; i < 96 && kept < 8 && pos + 24 < n; i++) {
        uintptr_t cand = 0;
        __try {
            cand = *(volatile uintptr_t*)(ctx->Rsp + (uintptr_t)i * 8);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            break;
        }
        HMODULE owner = nullptr;
        if (!cand) continue;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)cand, &owner);
        if (!owner || owner != g_mod) continue;
        char f[260] = {};
        fault_name((void*)cand, f, sizeof(f));
        int w = _snprintf_s(out + pos, n - pos, _TRUNCATE, "%s%s",
                            pos ? "," : "", f);
        if (w < 0) break;
        pos += (size_t)w;
        kept++;
    }
}

// Filter runs where the address is visible; the handler only reports.
static void fault_name(void* at, char* out, size_t n) {
    HMODULE owner = nullptr;
    if (at && GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                 GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                 (LPCWSTR)at, &owner)) {
        char buf[MAX_PATH] = {};
        GetModuleFileNameA(owner, buf, MAX_PATH);
        const char* slash = strrchr(buf, '\\');
        _snprintf_s(out, n, _TRUNCATE, "%s+0x%llX",
                    slash ? slash + 1 : buf,
                    (unsigned long long)((uintptr_t)at - (uintptr_t)owner));
    } else if (at) {
        _snprintf_s(out, n, _TRUNCATE, "unknown+0x%p", at);
    }
}

// Filter runs where the address is visible; the handler only reports.
static DWORD FaultFilter(EXCEPTION_POINTERS* ex) {
    g_code = ex && ex->ExceptionRecord ? ex->ExceptionRecord->ExceptionCode : 0;
    void* at = ex && ex->ExceptionRecord ? ex->ExceptionRecord->ExceptionAddress : nullptr;
    fault_name(at, g_fault, sizeof(g_fault));
    fault_stack(ex->ContextRecord, g_stack, sizeof(g_stack));
    return EXCEPTION_EXECUTE_HANDLER;
}

// Second net: Vectored handler sees every thread. Main-thread faults
// fall through to the SEH below; any other thread writes the verdict
// and gets out, since nothing there can catch it.
static LONG WINAPI CrashVEH(EXCEPTION_POINTERS* ex) {
    if (!ex || !ex->ExceptionRecord)
        return EXCEPTION_CONTINUE_SEARCH;
    if (GetCurrentThreadId() == g_main_tid)
        return EXCEPTION_CONTINUE_SEARCH;
    if (g_out) {
        char b[32];
        char f[260] = {};
        sprintf_s(b, "0x%08lX", ex->ExceptionRecord->ExceptionCode);
        fault_name(ex->ExceptionRecord->ExceptionAddress, f, sizeof(f));
        fprintf(g_out, "outcome=crashed\nstage=%s/worker\ncode=%s\nfault=%s\n",
                g_stage, b, f);
        if (g_qi[0]) fprintf(g_out, "qi_ids=%s\n", g_qi);
        {
            char s[1536] = {};
            fault_stack(ex->ContextRecord, s, sizeof(s));
            if (s[0]) fprintf(g_out, "stack=%s\n", s);
        }
        fclose(g_out);
        g_out = nullptr;
    }
    _exit(4);
    return EXCEPTION_CONTINUE_SEARCH;
}

// Watchdog: hangs become forensics. After N ms without a verdict,
// suspend the main thread, record where it is stuck, and exit loud.
static DWORD WINAPI Watchdog(LPVOID) {
    if (!g_watchdog_ms) return 0;
    Sleep(g_watchdog_ms);
    if (!g_out) _exit(5);
    if (g_main_thread && SuspendThread(g_main_thread) != (DWORD)-1) {
        CONTEXT ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if (GetThreadContext(g_main_thread, &ctx)) {
            char f[260] = {};
            fault_name((void*)ctx.Rip, f, sizeof(f));
            char s[1536] = {};
            fault_stack(&ctx, s, sizeof(s));
            fprintf(g_out, "outcome=timeout\nstage=%s\nstuck=%s\n",
                    g_stage, f);
            if (s[0]) fprintf(g_out, "stack=%s\n", s);
        }
        ResumeThread(g_main_thread);
    } else if (g_out) {
        fprintf(g_out, "outcome=timeout\nstage=%s\n", g_stage);
    }
    if (g_out) fclose(g_out);
    _exit(5);
    return EXCEPTION_CONTINUE_SEARCH;
}

static void emit(const char* k, const char* v) {
    if (g_out) fprintf(g_out, "%s=%s\n", k, v);
}

static void emit_hex(const char* k, unsigned long long v) {
    if (g_out) fprintf(g_out, "%s=0x%llX\n", k, v);
}

// In-process tap: after mapping the mod, rewrite its own import slots
// for CreateFileW and VirtualProtect so every versionlib open and every
// executable-memory write is logged. Same process, no extra library.
static HANDLE(WINAPI* RealCreateFileW)(LPCWSTR, DWORD, DWORD,
    LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = nullptr;
static BOOL(WINAPI* RealVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD) =
    nullptr;

static wchar_t g_altlib[MAX_PATH] = {};

static HANDLE WINAPI TapCreateFileW(LPCWSTR name, DWORD access, DWORD share,
        LPSECURITY_ATTRIBUTES sec, DWORD disp, DWORD flags, HANDLE tmpl) {
    if (name) {
        char b[MAX_PATH] = {};
        WideCharToMultiByte(CP_UTF8, 0, name, -1, b, sizeof(b), nullptr,
                            nullptr);
        const char* slash = strrchr(b, '\\');
        const char* fwd = strrchr(b, '/');
        if (fwd && (!slash || fwd > slash)) slash = fwd;
        const char* leaf = slash ? slash + 1 : b;
        bool islib = !_strnicmp(leaf, "versionlib-", 11) ||
                     !_strnicmp(leaf, "version-", 8);
        if (g_out) fprintf(g_out, "open=%s\n", leaf);
        if (islib) {
            if (!g_altlib[0]) {
                if (g_out) fprintf(g_out, "noserve=%s\n", leaf);
            } else {
                wchar_t alt[MAX_PATH] = {};
                wcscpy_s(alt, g_altlib);
                wcscat_s(alt, L"\\");
                size_t n = strlen(leaf) + 1;
                for (size_t i = 0; i < n && i + wcslen(alt) < MAX_PATH;
                     i++)
                    alt[wcslen(alt)] = (wchar_t)(unsigned char)leaf[i];
                DWORD attrs = GetFileAttributesW(alt);
                if (attrs != INVALID_FILE_ATTRIBUTES &&
                    !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                    if (g_out) fprintf(g_out, "serve=%s\n", leaf);
                    return RealCreateFileW(alt, access, share, sec, disp,
                                           flags, tmpl);
                }
                if (g_out) fprintf(g_out, "noserve=%s\n", leaf);
            }
        }
    }
    return RealCreateFileW(name, access, share, sec, disp, flags, tmpl);
}

static BOOL WINAPI TapVirtualProtect(LPVOID addr, SIZE_T size, DWORD prot,
        PDWORD old) {
    if (g_out && (prot & 0xF0)) {
        fprintf(g_out, "exec=0x%p\n", addr);
    }
    return RealVirtualProtect(addr, size, prot, old);
}

static void tap_imports(HMODULE mod) {
    BYTE* base = (BYTE*)mod;
    auto dos = (IMAGE_DOS_HEADER*)base;
    auto nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    DWORD rva = nt->OptionalHeader.DataDirectory[1].VirtualAddress;
    if (!rva) return;
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    auto realCFW = (void*)GetProcAddress(k32, "CreateFileW");
    auto realVP = (void*)GetProcAddress(k32, "VirtualProtect");
    for (auto imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + rva); imp->Name;
         imp++) {
        auto thunk = (IMAGE_THUNK_DATA64*)(base + imp->FirstThunk);
        for (; thunk->u1.Function; thunk++) {
            void** slot = (void**)&thunk->u1.Function;
            DWORD old = 0;
            if (*slot == realCFW) {
                VirtualProtect(slot, 8, PAGE_READWRITE, &old);
                *slot = (void*)TapCreateFileW;
                VirtualProtect(slot, 8, old, &old);
            } else if (*slot == realVP) {
                VirtualProtect(slot, 8, PAGE_READWRITE, &old);
                *slot = (void*)TapVirtualProtect;
                VirtualProtect(slot, 8, old, &old);
            }
        }
    }
}

#include "minhook/include/MinHook.h"

// Process-wide hook: catches every caller including CRT ifstream
// internals, which never go through the mod's own import table.
static int(WINAPI* RealMessageBoxW)(HWND, LPCWSTR, LPCWSTR, UINT) =
    nullptr;
static int(WINAPI* RealMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT) = nullptr;

static void log_dialog(const char* cap, const char* text) {
    if (g_out) fprintf(g_out, "dialog=%s: %.120s\n", cap ? cap : "",
                       text ? text : "");
}

static int WINAPI TapMessageBoxW(HWND wnd, LPCWSTR text, LPCWSTR cap,
        UINT type) {
    char b[128] = {}, c[64] = {};
    if (text)
        WideCharToMultiByte(CP_UTF8, 0, text, 120, b, sizeof(b), nullptr,
                            nullptr);
    if (cap)
        WideCharToMultiByte(CP_UTF8, 0, cap, 63, c, sizeof(c), nullptr,
                            nullptr);
    log_dialog(c, b);
    (void)wnd;
    (void)type;
    return IDOK;
}

static int WINAPI TapMessageBoxA(HWND wnd, LPCSTR text, LPCSTR cap,
        UINT type) {
    char b[128] = {}, c[64] = {};
    if (text) strncpy_s(b, text, _TRUNCATE);
    if (cap) strncpy_s(c, cap, _TRUNCATE);
    log_dialog(c, b);
    (void)wnd;
    (void)type;
    return IDOK;
}

static void hook_file_apis(void) {
    LoadLibraryW(L"user32.dll");
    if (MH_Initialize() != MH_OK) return;
    if (MH_CreateHookApi(L"kernel32", "CreateFileW", TapCreateFileW,
                         (void**)&RealCreateFileW) != MH_OK)
        return;
    MH_CreateHookApi(L"kernel32", "VirtualProtect", TapVirtualProtect,
                     (void**)&RealVirtualProtect);
    if (MH_CreateHookApi(L"user32", "MessageBoxW", TapMessageBoxW,
                         (void**)&RealMessageBoxW) == MH_OK &&
        MH_CreateHookApi(L"user32", "MessageBoxA", TapMessageBoxA,
                         (void**)&RealMessageBoxA) == MH_OK &&
        MH_EnableHook(MH_ALL_HOOKS) == MH_OK) {
        if (g_out) fprintf(g_out, "hooks=w,a\n");
    }
}

struct PluginInfo {
    uint32_t infoVersion;
    const char* name;
    uint32_t version;
};

// Real SKSE passes (interface, info); single-arg relics ignore the
// extra register, so always passing both is compatible either way.
typedef bool (__cdecl* QueryFn)(const SKSEInterface*, PluginInfo*);
typedef bool (__cdecl* LoadFn)(const SKSEInterface*);

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) return 2;
    const wchar_t* dll = argv[1];
    const wchar_t* out = nullptr;
    uint32_t runtime = 0;
    const wchar_t* game = nullptr;
    for (int i = 2; i < argc; i++) {
        if (!wcscmp(argv[i], L"--notaps")) {
            g_notaps = true;
            continue;
        }
        if (i + 1 >= argc) break;
        if (!wcscmp(argv[i], L"--out")) out = argv[i + 1];
        else if (!wcscmp(argv[i], L"--runtime")) runtime = wcstoul(argv[i + 1], nullptr, 16);
        else if (!wcscmp(argv[i], L"--workdir")) SetCurrentDirectoryW(argv[i + 1]);
        else if (!wcscmp(argv[i], L"--game")) game = argv[i + 1];
        else if (!wcscmp(argv[i], L"--altlib")) wcscpy_s(g_altlib, argv[i + 1]);
        else if (!wcscmp(argv[i], L"--watchdog")) g_watchdog_ms = wcstoul(argv[i + 1], nullptr, 10);
        else continue;
        i++;
    }
    if (!g_notaps) {
        if (g_watchdog_ms) {
            HANDLE self = nullptr;
            DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                            GetCurrentProcess(), &self, 0, FALSE,
                            DUPLICATE_SAME_ACCESS);
            g_main_thread = self ? self : GetCurrentThread();
            HANDLE wt = CreateThread(nullptr, 0, Watchdog, nullptr, 0,
                                     nullptr);
            if (wt) CloseHandle(wt);
        }
    }
    if (out) _wfopen_s(&g_out, out, L"w");
    if (g_out) setvbuf(g_out, nullptr, _IONBF, 0);
    g_main_tid = GetCurrentThreadId();
    if (!g_notaps) {
        __try {
            hook_file_apis();
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    AddVectoredExceptionHandler(1, CrashVEH);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);

    SKSEInterface skse = {};
    skse.runtimeVersion = runtime;
    skse.QueryInterface = NullQI;
    skse.GetPluginHandle = OneHandle;
    skse.GetReleaseIndex = ZeroRel;
    skse.GetPluginInfo = NullInfo;

    if (game) {
        HMODULE gm = LoadLibraryExW(game, nullptr,
                                    DONT_RESOLVE_DLL_REFERENCES);
        if (gm) {
            char b[32];
            sprintf_s(b, "%p", gm);
            emit("game_base", b);
        } else {
            char b[32];
            sprintf_s(b, "%lu", GetLastError());
            emit("game_map_error", b);
        }
    }

    HMODULE mod = nullptr;
    __try {
        g_stage = "loadlibrary";
        mod = LoadLibraryW(dll);
        if (!mod) {
            char b[32];
            sprintf_s(b, "%lu", GetLastError());
            emit("outcome", "load_failed");
            emit("error", b);
            if (g_out) fclose(g_out);
            return 0;
        }
        emit("outcome", "mapped");
        g_mod = mod;
        __try {
            tap_imports(mod);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }

        auto ver = (SKSEVersionData*)GetProcAddress(mod, "SKSEPlugin_Version");
        if (ver) {
            emit_hex("ex_val", ver->versionIndependenceEx);
            emit_hex("indep_val", ver->versionIndependence);
        } else {
            emit("version", "absent");
        }
        auto q = (QueryFn)GetProcAddress(mod, "SKSEPlugin_Query");
        auto l = (LoadFn)GetProcAddress(mod, "SKSEPlugin_Load");
        g_qi[0] = 0;
        emit("has_query", q ? "1" : "0");
        emit("has_load", l ? "1" : "0");
        if (!q && !l) {
            emit("outcome", "no_entry");
            FreeLibrary(mod);
            if (g_out) fclose(g_out);
            return 0;
        }
        PluginInfo info = {};
        info.infoVersion = 1;
        info.name = "jig";
        info.version = 1;
        if (q) {
            g_stage = "query";
            if (!q(&skse, &info)) {
                emit("outcome", "query_declined");
                FreeLibrary(mod);
                if (g_out) fclose(g_out);
                return 0;
            }
            emit("outcome", "query_ok");
        }
        if (l) {
            g_stage = "load";
            if (!l(&skse)) {
                emit("outcome", "load_false");
            } else {
                emit("outcome", "loaded");
            }
        }
        if (g_qi[0]) emit("qi_ids", g_qi);
        FreeLibrary(mod);
    } __except (FaultFilter(GetExceptionInformation())) {
        char b[32];
        sprintf_s(b, "0x%08lX", g_code);
        emit("outcome", "crashed");
        emit("stage", g_stage);
        emit("code", b);
        if (g_fault[0]) emit("fault", g_fault);
        if (g_stack[0]) emit("stack", g_stack);
        if (g_qi[0]) emit("qi_ids", g_qi);
    }
    if (g_out) fclose(g_out);
    return 0;
}
