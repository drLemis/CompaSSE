#pragma once
#include <windows.h>

enum DecoderType { DECODER_NONE = 0, DECODER_V1 = 1, DECODER_V2 = 2, DECODER_V5 = 5 };

// Detect decoder type from a module's import table:
//   mmap + istream -> DECODER_V5 (commonlibsse-ng with mmap caching)
//   mmap only      -> DECODER_V2
//   istream only   -> DECODER_V1 (old CommonLibSSE, needs format-1)
//   neither        -> DECODER_V2 (default)
DecoderType detect_decoder(HMODULE mod);

// Walk the stack (RtlCaptureStackBackTrace, up to 8 frames) and return the
// first module that is not a system/CRT module and not the shim itself.
// Returns nullptr if none found.
HMODULE resolve_caller_module(HMODULE self_module);

// Cached lookup: detect once per module, cache in a map guarded by a critical section.
DecoderType decoder_for_module(HMODULE mod, HMODULE self_module);