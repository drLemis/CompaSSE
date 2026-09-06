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

// ---- VEH: log real crashes, skip debug events ----
static LONG WINAPI CrashVEH(EXCEPTION_POINTERS* ex) {
    if (!ex || !ex->ExceptionRecord)
        return EXCEPTION_CONTINUE_SEARCH;

    DWORD code = ex->ExceptionRecord->ExceptionCode;

    // Suppress debug events (0x4001xxxx) - game raises these during normal init.
    // Passing them through as unhandled kills the process silently.
    if ((code & 0xFFFF0000) == 0x40010000)
        return EXCEPTION_CONTINUE_EXECUTION;

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
    }

    return EXCEPTION_CONTINUE_SEARCH;
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
