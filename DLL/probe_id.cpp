#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <vector>
#include <string>
#include <utility>
#include "transcode.h"

static bool read_file(const char* path, std::vector<uint8_t>& out) {
    FILE* f = nullptr;
    if (fopen_s(&f, path, "rb") != 0 || !f) return false;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return false; }
    out.resize((size_t)sz);
    if (sz > 0 && fread(out.data(), 1, (size_t)sz, f) != (size_t)sz) { fclose(f); return false; }
    fclose(f);
    return true;
}

int main(int argc, char** argv) {
    if (argc != 2) { printf("usage: probe.exe <plugins_dir>\n"); return 2; }
    const uint64_t ID = 0x5CF42;

    const char* files[] = {
        "versionlib-1-6-317-0.bin",
        "versionlib-1-6-318-0.bin",
        "versionlib-1-6-323-0.bin",
        "versionlib-1-6-342-0.bin",
        "versionlib-1-6-353-0.bin",
        "versionlib-1-6-629-0.bin",
        "versionlib-1-6-640-0.bin",
        "versionlib-1-6-659-0.bin",
        "versionlib-1-6-1130-0.bin",
        "versionlib-1-6-1170-0.bin",
        "versionlib-1-6-1179-0.bin",
        "versionlib-1-7-99-0.bin",
        "versionlib-1-7-104-0.bin",
    };

    for (auto fn : files) {
        std::string path = std::string(argv[1]) + "\\" + fn;
        std::vector<uint8_t> d;
        if (!read_file(path.c_str(), d)) { printf("%s: READ FAIL\n", fn); continue; }

        uint32_t fmt = d.size() >= 4 ? (uint32_t)d[0] | ((uint32_t)d[1] << 8) | ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24) : 0;
        if (fmt == 5) {
            uint32_t count = d.size() >= 96 ? (uint32_t)d[92] | ((uint32_t)d[93] << 8) | ((uint32_t)d[94] << 16) | ((uint32_t)d[95] << 24) : 0;
            uint32_t off = (ID < count) ? (uint32_t)d[96 + ID * 4] | ((uint32_t)d[97 + ID * 4] << 8) | ((uint32_t)d[98 + ID * 4] << 16) | ((uint32_t)d[99 + ID * 4] << 24) : 0;
            printf("%s: fmt5 count=%u ID=0x%llX -> 0x%X\n", fn, count, ID, off);
        } else {
            std::vector<std::pair<uint64_t, uint64_t>> old;
            uint32_t v[4]; std::string nm; uint32_t optr = 0;
            if (!parse_format2(d.data(), d.size(), old, v, nm, optr)) {
                printf("%s: fmt%d parse FAILED\n", fn, fmt);
                continue;
            }
            uint64_t val = 0;
            bool found = false;
            for (auto& e : old) { if (e.first == ID) { val = e.second; found = true; break; } }
            printf("%s: fmt%d count=%zu ptr=%u ID=0x%llX -> %s 0x%llX\n", fn, fmt, old.size(), optr, ID, found ? "0x" : "MISSING", val);
        }
    }
    return 0;
}
