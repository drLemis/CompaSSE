// Standalone transcoder test. Usage: test_transcode.exe <fmt2.bin> <fmt5_reference.bin>
#include <cstdio>
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "transcode.h"

static bool read_file(const char* path, std::vector<uint8_t>& out) {
    FILE* f = nullptr;
    if (fopen_s(&f, path, "rb") != 0 || !f) return false;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) {
        fclose(f);
        return false;
    }
    out.resize((size_t)sz);
    if (sz > 0 && fread(out.data(), 1, (size_t)sz, f) != (size_t)sz) {
        fclose(f);
        return false;
    }
    fclose(f);
    return true;
}

// Minimal format-5 reader: header + dense u32 array -> {id, offset} map.
static bool parse_fmt5(const std::vector<uint8_t>& data, std::map<uint64_t, uint64_t>& out) {
    size_t off = 0;
    auto rd32 = [&](uint32_t& v) -> bool {
        if (off + 4 > data.size()) return false;
        v = (uint32_t)data[off] | ((uint32_t)data[off + 1] << 8) |
            ((uint32_t)data[off + 2] << 16) | ((uint32_t)data[off + 3] << 24);
        off += 4;
        return true;
    };
    uint32_t fmt, ptr, dfmt, count;
    if (!rd32(fmt) || fmt != 5) return false;
    if (off + 16 > data.size()) return false; off += 16; // version
    if (off + 64 > data.size()) return false; off += 64; // name
    if (!rd32(ptr) || !rd32(dfmt) || !rd32(count)) return false;
    if (off + (size_t)count * 4 > data.size()) return false;
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t v = (uint32_t)data[off] | ((uint32_t)data[off + 1] << 8) |
                     ((uint32_t)data[off + 2] << 16) | ((uint32_t)data[off + 3] << 24);
        off += 4;
        if (v != 0) out[i] = v;
    }
    return true;
}

int main(int argc, char** argv) {
    if (argc != 3) {
        printf("usage: test_transcode.exe <fmt2.bin> <fmt5_reference.bin>\n");
        return 2;
    }

    std::vector<uint8_t> fmt2, ref;
    if (!read_file(argv[1], fmt2) || !read_file(argv[2], ref)) {
        printf("FAIL: could not read input files\n");
        return 1;
    }

    std::vector<std::pair<uint64_t, uint64_t>> entries;
    uint32_t version[4];
    std::string name;
    uint32_t ptr_size = 0;
    if (!parse_format2(fmt2.data(), fmt2.size(), entries, version, name, ptr_size)) {
        printf("FAIL: parse_format2 failed\n");
        return 1;
    }
    uint64_t max_id = 0;
    for (const auto& e : entries)
        if (e.first > max_id) max_id = e.first;

    std::vector<uint8_t> out;
    uint32_t out_count = 0;
    if (!format2_to_format5(fmt2.data(), fmt2.size(), out, out_count)) {
        printf("FAIL: format2_to_format5 failed\n");
        return 1;
    }

    printf("entries: %zu, max_id: %llu, count: %u\n", entries.size(),
           (unsigned long long)max_id, out_count);
    if (entries.empty()) {
        printf("FAIL: no entries\n");
        return 1;
    }

    if (out == ref) {
        printf("PASS: byte-identical to reference (%zu bytes)\n", out.size());
        return 0;
    }

    // Not identical: compare the id->offset maps for diagnostics.
    std::map<uint64_t, uint64_t> m2, m5;
    for (const auto& e : entries) m2[e.first] = e.second;
    if (!parse_fmt5(ref, m5)) {
        printf("FAIL: reference is not a parseable format-5 bin\n");
        return 1;
    }
    std::map<uint64_t, uint64_t> all = m2; // union of keys
    for (const auto& kv : m5) all[kv.first] = kv.second;

    size_t mismatches = 0, printed = 0;
    for (const auto& kv : all) {
        auto it2 = m2.find(kv.first);
        auto it5 = m5.find(kv.first);
        uint64_t v2 = it2 != m2.end() ? it2->second : 0;
        uint64_t v5 = it5 != m5.end() ? it5->second : 0;
        if (v2 != v5) {
            ++mismatches;
            if (printed < 5) {
                printf("  mismatch id=%llu: fmt2=%llu fmt5=%llu\n",
                       (unsigned long long)kv.first, (unsigned long long)v2, (unsigned long long)v5);
                ++printed;
            }
        }
    }

    size_t byteDiff = 0;
    size_t common = out.size() < ref.size() ? out.size() : ref.size();
    for (size_t i = 0; i < common; ++i)
        if (out[i] != ref[i]) ++byteDiff;
    byteDiff += out.size() > ref.size() ? out.size() - ref.size() : ref.size() - out.size();

    printf("FAIL: %zu byte differences (%zu map mismatches)\n", byteDiff, mismatches);
    return 1;
}