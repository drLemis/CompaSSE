// test_fmt5.cpp - verify fmt5 -> fmt2 -> parse round-trip against real bin
#include <cstdio>
#include <cstdint>
#include <vector>
#include <string>
#include "transcode.h"

static bool read_file(const char* path, std::vector<uint8_t>& out) {
    FILE* f = fopen(path, "rb");
    if (!f) return false;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    out.resize(sz);
    if (fread(out.data(), 1, sz, f) != (size_t)sz) { fclose(f); return false; }
    fclose(f);
    return true;
}

int main(int argc, char** argv) {
    if (argc < 2) { fprintf(stderr, "usage: test_fmt5 <fmt5.bin>\n"); return 1; }
    std::vector<uint8_t> src;
    if (!read_file(argv[1], src)) { fprintf(stderr, "read fail\n"); return 1; }

    std::vector<std::pair<uint64_t,uint64_t>> e5;
    uint32_t v5[4]; std::string n5; uint32_t p5;
    if (!parse_format5(src.data(), src.size(), e5, v5, n5, p5)) { fprintf(stderr, "parse_format5 FAILED\n"); return 1; }
    printf("fmt5: %zu entries, ptr=%u, name=%s\n", e5.size(), p5, n5.c_str());

    std::vector<uint8_t> fmt2;
    if (!format5_to_format2(src.data(), src.size(), fmt2)) { fprintf(stderr, "format5_to_format2 FAILED\n"); return 1; }
    printf("fmt2: %zu bytes\n", fmt2.size());

    std::vector<std::pair<uint64_t,uint64_t>> e2;
    uint32_t v2[4]; std::string n2; uint32_t p2;
    if (!parse_format2(fmt2.data(), fmt2.size(), e2, v2, n2, p2)) { fprintf(stderr, "parse_format2 FAILED\n"); return 1; }
    printf("fmt2 parsed: %zu entries, ptr=%u, name=%s\n", e2.size(), p2, n2.c_str());

    if (e5.size() != e2.size()) { fprintf(stderr, "ENTRY COUNT MISMATCH: %zu vs %zu\n", e5.size(), e2.size()); return 1; }
    int mism = 0;
    for (size_t i = 0; i < e5.size(); i++) {
        if (e5[i].first != e2[i].first || e5[i].second != e2[i].second) {
            if (mism < 10)
                printf("  MISMATCH[%zu]: want id=%llu off=%llu got id=%llu off=%llu\n",
                       i, (unsigned long long)e5[i].first, (unsigned long long)e5[i].second,
                       (unsigned long long)e2[i].first, (unsigned long long)e2[i].second);
            mism++;
        }
    }
    printf("round-trip: %zu entries, %d mismatches\n", e2.size(), mism);
    return mism ? 1 : 0;
}