#pragma once
#include <windows.h>

// Install all hooks. Returns true on success.
bool install_hooks(HMODULE self_module);
// Uninstall hooks and release resources (called at PROCESS_DETACH).
void uninstall_hooks();
// Record this module's hinst so shim_log can name the log after the DLL.
void set_self(HMODULE module);
// Append a timestamped line to <dll dir>\<dll name>.log. Never crashes.
void shim_log(const char* fmt, ...);