#include <cstdio>
#include <cstdlib>
#include <vector>
#include <string>
#include <cstdint>
#include "transcode.h"
static int read_file(const char* p, std::vector<uint8_t>& d) {
    FILE* f = fopen(p, "rb"); if (!f) return 0;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    d.resize((size_t)n); return fread(d.data(), 1, d.size(), f) == d.size();
}
int main(int argc, char** argv) {
    std::vector<uint8_t> d;
    if (argc < 3 || !read_file(argv[1], d)) return 1;
    std::vector<std::pair<uint64_t,uint64_t>> e;
    uint32_t v[4]; std::string nm; uint32_t ptr=0;
    if (!parse_format2(d.data(), d.size(), e, v, nm, ptr)) { printf("parse fail\n"); return 1; }
    printf("fmt%s ver=%u.%u.%u.%u count=%zu\n", "2", v[0],v[1],v[2],v[3], e.size());
    for (int i = 2; i < argc; i++) {
        uint64_t id = strtoull(argv[i], nullptr, 0);
        uint64_t found = 0; int hit = 0;
        for (auto& x : e) if (x.first == id) { found = x.second; hit = 1; break; }
        printf("  ID 0x%llX -> %s 0x%llX\n", (unsigned long long)id, hit ? "RVA" : "NOT FOUND (or 0)", (unsigned long long)found);
    }
    return 0;
}
