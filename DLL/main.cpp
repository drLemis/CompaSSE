#include <windows.h>
#include <Psapi.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include "hooks.h"

#pragma comment(lib, "Psapi.lib")

// ---- SKSE structures (from ianpatt/skse64 PluginAPI.h) ----

struct SKSEPluginVersionData {
    enum { kVersion = 1 };
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

extern "C" __declspec(dllexport) const SKSEPluginVersionData     SKSEPlugin_Version = {
    1, 0x00010000, "!CompaSSE", "CompaSSE", "",
    0x2, 0x5, {0}, 0
};

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

static HMODULE g_selfModule = nullptr;
// Reentrancy: log_ptr may fault on an unmapped-but-canonical pointer.
// A nested fault re-enters this VEH (VEH preempts SEH, so log_ptr's
// __try never sees it) -> infinite recursion. Bail out when nested.
static thread_local bool t_inCrashVeh = false;

// ---- VEH: log real crashes, skip debug events ----
static void log_ptr(const char* name, void* p);  // defined below CrashVEH
static LONG WINAPI CrashVEH(EXCEPTION_POINTERS* ex) {
    if (!ex || !ex->ExceptionRecord)
        return EXCEPTION_CONTINUE_SEARCH;

    DWORD code = ex->ExceptionRecord->ExceptionCode;

    // Suppress debug events (0x4001xxxx) - game raises these during normal init.
    // Passing them through as unhandled kills the process silently.
    if ((code & 0xFFFF0000) == 0x40010000)
        return EXCEPTION_CONTINUE_EXECUTION;

    if (t_inCrashVeh)
        return EXCEPTION_CONTINUE_SEARCH;  // nested fault: do not recurse
    t_inCrashVeh = true;

    void* faultAddr = ex->ExceptionRecord->ExceptionAddress;

    // Resolve which module owns the fault address (crashes below shim = game/core)
    char modName[MAX_PATH] = "?";
    HMODULE owner = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCWSTR)faultAddr, &owner);
    if (owner) {
        char buf[MAX_PATH] = {};
        GetModuleFileNameA(owner, buf, MAX_PATH);
        const char* slash = strrchr(buf, '\\');
        snprintf(modName, sizeof(modName), "%s+0x%llX", slash ? slash + 1 : buf,
                 (unsigned long long)((uintptr_t)faultAddr - (uintptr_t)owner));
    }

    // Only log real crashes (AV, illegal ins, stack overflow, etc.)
    shim_log("VEH: code=0x%08X addr=%p (%s)", code, faultAddr, modName);

    if (ex->ContextRecord) {
        shim_log("  RIP=%p RAX=%p RBX=%p RCX=%p RDX=%p",
                 (void*)ex->ContextRecord->Rip, (void*)ex->ContextRecord->Rax,
                 (void*)ex->ContextRecord->Rbx, (void*)ex->ContextRecord->Rcx,
                 (void*)ex->ContextRecord->Rdx);
        shim_log("  RSI=%p RDI=%p RSP=%p RBP=%p",
                 (void*)ex->ContextRecord->Rsi, (void*)ex->ContextRecord->Rdi,
                 (void*)ex->ContextRecord->Rsp, (void*)ex->ContextRecord->Rbp);
        shim_log("  R8=%p R9=%p R10=%p R11=%p R12=%p R13=%p R14=%p R15=%p",
                 (void*)ex->ContextRecord->R8, (void*)ex->ContextRecord->R9,
                 (void*)ex->ContextRecord->R10, (void*)ex->ContextRecord->R11,
                 (void*)ex->ContextRecord->R12, (void*)ex->ContextRecord->R13,
                 (void*)ex->ContextRecord->R14, (void*)ex->ContextRecord->R15);
        // Pointer peek: identifies game classes via vtable (see offline RTTI walk).
        auto* c = ex->ContextRecord;
        log_ptr("RAX", (void*)c->Rax); log_ptr("RBX", (void*)c->Rbx);
        log_ptr("RCX", (void*)c->Rcx); log_ptr("RDX", (void*)c->Rdx);
        log_ptr("RSI", (void*)c->Rsi); log_ptr("RDI", (void*)c->Rdi);
        log_ptr("R8", (void*)c->R8);   log_ptr("R9", (void*)c->R9);
    }

    t_inCrashVeh = false;
    return EXCEPTION_CONTINUE_SEARCH;
}

// Safe pointer peek for crash forensics: logs what a register points at.
// [reg] often holds a vtable pointer -> offline RTTI walk identifies the
// game class. __try/__except: the pointer may be garbage; never recurse.
static void log_ptr(const char* name, void* p) {
    uintptr_t v = (uintptr_t)p;
    if (v < 0x10000 || v >= 0x0000800000000000ULL)
        return;  // null / kernel / non-canonical: nothing to learn
    // Canonical != mapped. Probe with VirtualQuery (never faults) instead
    // of trusting the address: guard pages and unmapped holes AV on read.
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi)
        || !(mbi.State & MEM_COMMIT)
        || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
        shim_log("  [%s=%p (?)] unreadable", name, p);
        return;
    }
    DWORD prot = mbi.Protect & 0xFF;
    if (prot != PAGE_READONLY && prot != PAGE_READWRITE && prot != PAGE_WRITECOPY
        && prot != PAGE_EXECUTE_READ && prot != PAGE_EXECUTE_READWRITE
        && prot != PAGE_EXECUTE_WRITECOPY) {
        shim_log("  [%s=%p (?)] unreadable", name, p);
        return;
    }
    uint64_t pointee = 0;
    __try {
        pointee = *(volatile uint64_t*)p;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        shim_log("  [%s=%p (?)] unreadable", name, p);
        return;
    }
    // Which module owns the POINTER and the POINTEE (vtable -> game exe
    // or a DLL)? Both narrow the crashed object's class offline.
    char modName[MAX_PATH] = "?";
    HMODULE owner = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCWSTR)p, &owner);
    if (owner) {
        char buf[MAX_PATH] = {};
        GetModuleFileNameA(owner, buf, MAX_PATH);
        const char* slash = strrchr(buf, '\\');
        snprintf(modName, sizeof(modName), "%s+0x%llX", slash ? slash + 1 : buf,
                 (unsigned long long)((uintptr_t)p - (uintptr_t)owner));
    }
    char tgtName[MAX_PATH] = "?";
    HMODULE towner = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCWSTR)(uintptr_t)pointee, &towner);
    if (towner) {
        char buf[MAX_PATH] = {};
        GetModuleFileNameA(towner, buf, MAX_PATH);
        const char* slash = strrchr(buf, '\\');
        snprintf(tgtName, sizeof(tgtName), "%s+0x%llX", slash ? slash + 1 : buf,
                 (unsigned long long)((uintptr_t)pointee - (uintptr_t)towner));
    }
    shim_log("  [%s=%p (%s) -> %p (%s)]", name, p, modName, (void*)pointee, tgtName);
}

// ---- SKSEPlugin_Load ----
extern "C" __declspec(dllexport) bool SKSEPlugin_Load(const SKSEInterface* skse) {
    bool ok = install_hooks(g_selfModule);
    AddVectoredExceptionHandler(1, CrashVEH);
    return true;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_selfModule = hinst;
        set_self(hinst);
        install_hooks(hinst);
    } else if (reason == DLL_PROCESS_DETACH)
        uninstall_hooks();
    return TRUE;
}
