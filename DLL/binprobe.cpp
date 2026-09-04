// binprobe.cpp - parse Address Library bin, find entries near target RVAs
// Usage: binprobe <bin> <rva1> <rva2> ...
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <vector>
#include <algorithm>

static bool read_u8(const uint8_t* d, size_t sz, size_t& off, uint8_t& v) {
    if (off + 1 > sz) return false; v = d[off++]; return true;
}
static bool read_u16(const uint8_t* d, size_t sz, size_t& off, uint16_t& v) {
    if (off + 2 > sz) return false; v = (uint16_t)(d[off] | (d[off+1]<<8)); off += 2; return true;
}
static bool read_u32(const uint8_t* d, size_t sz, size_t& off, uint32_t& v) {
    if (off + 4 > sz) return false; v = d[off] | (d[off+1]<<8) | (d[off+2]<<16) | (d[off+3]<<24); off += 4; return true;
}
static bool read_u64(const uint8_t* d, size_t sz, size_t& off, uint64_t& v) {
    if (off + 8 > sz) return false; v = 0; for (int i=0;i<8;i++) v |= (uint64_t)d[off+i] << (8*i); off += 8; return true;
}

int main(int argc, char** argv) {
    if (argc < 3) { fprintf(stderr, "usage: binprobe <bin> <rva>...\n"); return 1; }
    FILE* f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", argv[1]); return 1; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> buf(sz);
    if (fread(buf.data(), 1, sz, f) != (size_t)sz) { fprintf(stderr, "read fail\n"); return 1; }
    fclose(f);

    size_t off = 0;
    uint32_t format; read_u32(buf.data(), sz, off, format);
    off += 16; // version
    uint32_t nameLen; read_u32(buf.data(), sz, off, nameLen);
    off += nameLen;
    uint32_t ptrSize; read_u32(buf.data(), sz, off, ptrSize);
    uint32_t count; read_u32(buf.data(), sz, off, count);

    std::vector<std::pair<uint64_t,uint64_t>> entries;
    entries.reserve(count);
    uint64_t prevId=0, prevOffset=0;
    for (uint32_t i=0;i<count;i++) {
        uint8_t type; if (!read_u8(buf.data(), sz, off, type)) break;
        uint8_t lo = type & 0xF, hi = type >> 4;
        uint64_t id;
        switch (lo) {
            case 0: { uint64_t v; if(!read_u64(buf.data(),sz,off,v)) goto done; id=v; break; }
            case 1: id = prevId+1; break;
            case 2: { uint8_t v; if(!read_u8(buf.data(),sz,off,v)) goto done; id=prevId+v; break; }
            case 3: { uint8_t v; if(!read_u8(buf.data(),sz,off,v)) goto done; id=prevId-v; break; }
            case 4: { uint16_t v; if(!read_u16(buf.data(),sz,off,v)) goto done; id=prevId+v; break; }
            case 5: { uint16_t v; if(!read_u16(buf.data(),sz,off,v)) goto done; id=prevId-v; break; }
            case 6: { uint16_t v; if(!read_u16(buf.data(),sz,off,v)) goto done; id=v; break; }
            case 7: { uint32_t v; if(!read_u32(buf.data(),sz,off,v)) goto done; id=v; break; }
            default: goto done;
        }
        uint64_t tmp = (hi & 8) ? (prevOffset / ptrSize) : prevOffset;
        uint64_t offset;
        switch (hi & 7) {
            case 0: { uint64_t v; if(!read_u64(buf.data(),sz,off,v)) goto done; offset=v; break; }
            case 1: offset = tmp+1; break;
            case 2: { uint8_t v; if(!read_u8(buf.data(),sz,off,v)) goto done; offset=tmp+v; break; }
            case 3: { uint8_t v; if(!read_u8(buf.data(),sz,off,v)) goto done; offset=tmp-v; break; }
            case 4: { uint16_t v; if(!read_u16(buf.data(),sz,off,v)) goto done; offset=tmp+v; break; }
            case 5: { uint16_t v; if(!read_u16(buf.data(),sz,off,v)) goto done; offset=tmp-v; break; }
            case 6: { uint16_t v; if(!read_u16(buf.data(),sz,off,v)) goto done; offset=v; break; }
            case 7: { uint32_t v; if(!read_u32(buf.data(),sz,off,v)) goto done; offset=v; break; }
            default: goto done;
        }
        if (hi & 8) offset *= ptrSize;
        entries.emplace_back(id, offset);
        prevId = id; prevOffset = offset;
    }
done:
    printf("format=%u count=%zu\n", format, entries.size());
    for (int a = 2; a < argc; a++) {
        uint64_t target = strtoull(argv[a], nullptr, 0);
        // find nearest by offset
        std::vector<std::pair<uint64_t,uint64_t>> near;
        for (auto& e : entries) {
            int64_t delta = (int64_t)e.second - (int64_t)target;
            near.push_back({(uint64_t)llabs(delta), e.first});
        }
        std::partial_sort(near.begin(), near.begin()+5, near.end());
        printf("nearest to RVA 0x%llX:\n", (unsigned long long)target);
        for (int i=0;i<5 && i<(int)near.size();i++) {
            // find the actual offset for this id
            for (auto& e : entries) if (e.first == near[i].second) {
                printf("  ID 0x%llX -> RVA 0x%llX (delta %lld)\n",
                    (unsigned long long)e.first, (unsigned long long)e.second, (long long)near[i].first);
                break;
            }
        }
    }
    return 0;
}