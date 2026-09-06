#pragma once
#include <windows.h>

// Called after all SKSE plugins have loaded.
// Analyzes every loaded module for Address Library usage, hardcoded offsets, etc.
void postload_scan_all(HMODULE self_module);
