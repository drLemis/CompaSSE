// Verify old-ID merge reproduces the working patched bin.
// Usage: test_merge.exe <fmt5.bin> <plugins_dir>
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>
#include <algorithm>

#include "transcode.h"

// Read a whole file into memory.
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
    if (argc != 3) {
        printf("usage: test_merge.exe <fmt5.bin> <plugins_dir>\n");
        return 2;
    }

    std::vector<uint8_t> fmt5;
    if (!read_file(argv[1], fmt5)) { printf("FAIL: read fmt5\n"); return 1; }

    std::vector<std::pair<uint64_t, uint64_t>> entries;
    uint32_t version[4];
    std::string name;
    uint32_t ptr_size = 0;
    if (!parse_format5(fmt5.data(), fmt5.size(), entries, version, name, ptr_size)) {
        printf("FAIL: parse format5\n");
        return 1;
    }
    printf("fmt5: %zu entries, ver=%u.%u.%u.%u\n", entries.size(), version[0], version[1], version[2], version[3]);

    // Simulate merge using old versionlib-*.bin files in plugins_dir.
    std::map<uint64_t, uint64_t> have;
    for (auto& e : entries) if (e.second != 0) have[e.first] = e.second; // drop fmt5 zeros
    printf("  ID 0x5CF42 before merge: offset=0x%X\n", (unsigned)(have.count(0x5CF42) ? have[0x5CF42] : 0));

    // scan plugins dir for version-*.bin only (legacy SE)
    // Fill missing ids only (newest bin first). The user's working artifact
    // (versionlib-1-7-104-0-patched.bin, 824108 entries) = fmt5 nonzero-only
    // base + these bins; versionlib-1-6-* bins add 0 IDs and their gap-fill
    // offsets point at different code in 1.7.104, so they must NOT be merged.
    const char* patterns[] = { "version-*.bin" };
    // collect bins first, sort newest first by minor, then merge
    std::vector<std::pair<unsigned, std::string>> names; // minor, path
    for (unsigned p = 0; p < sizeof(patterns) / sizeof(patterns[0]); ++p) {
        std::string pat = std::string(argv[2]) + "\\" + patterns[p];
        WIN32_FIND_DATAA fd;
        HANDLE hfind = FindFirstFileA(pat.c_str(), &fd);
        if (hfind == INVALID_HANDLE_VALUE) continue;
        do {
            std::string full = std::string(argv[2]) + "\\" + fd.cFileName;
            std::vector<uint8_t> d;
            if (!read_file(full.c_str(), d)) continue;
            uint32_t fmt = d.size() >= 4 ? (uint32_t)d[0] | ((uint32_t)d[1] << 8) | ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24) : 0;
            if (fmt != 1 && fmt != 2) continue;
            std::vector<std::pair<uint64_t, uint64_t>> old;
            uint32_t v[4]; std::string nm; uint32_t optr = 0;
            if (!parse_format2(d.data(), d.size(), old, v, nm, optr)) continue;
            // version-1-5-NN-0.bin -> minor
            unsigned minor = 0;
            char* h = strstr((char*)fd.cFileName, "-1-");
            if (h) { char* h2 = strchr(h + 3, '-'); if (h2) minor = (unsigned)strtoul(h2 + 1, nullptr, 10); }
            if (minor > 0) names.push_back({ minor, full });
        } while (FindNextFileA(hfind, &fd));
        FindClose(hfind);
    }
    std::sort(names.begin(), names.end(),
              [](const std::pair<unsigned, std::string>& a, const std::pair<unsigned, std::string>& b) { return a.first > b.first; });
    int binsScanned = 0;
    for (auto& nb : names) {
        std::vector<uint8_t> d;
        if (!read_file(nb.second.c_str(), d)) continue;
        std::vector<std::pair<uint64_t, uint64_t>> old;
        uint32_t v[4]; std::string nm; uint32_t optr = 0;
        if (!parse_format2(d.data(), d.size(), old, v, nm, optr)) continue;
        ++binsScanned;
        int added = 0;
        for (auto& e : old) {
            if (e.first == 0x5CF42) printf("  %s has 0x5CF42 -> 0x%llX\n", nb.second.c_str(), e.second);
            if (have.find(e.first) == have.end()) { have[e.first] = e.second; added++; }
        }
        if (added) printf("  %s: +%d IDs (total %zu)\n", nb.second.c_str(), added, have.size());
    }
    printf("  ID 0x5CF42 after merge: offset=0x%X\n", (unsigned)(have.count(0x5CF42) ? have[0x5CF42] : 0));
    printf("merged %d old bins -> %zu entries\n", binsScanned, have.size());
    printf("PASS: merge complete\n");
    return 0;
}
