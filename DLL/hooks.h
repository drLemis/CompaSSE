#pragma once
#include <windows.h>

bool install_hooks(HMODULE self_module);

void uninstall_hooks();

void set_self(HMODULE module);

void shim_log(const char* fmt, ...);

void legacy_activate_all(const void* skse);