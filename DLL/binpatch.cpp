// binpatch.cpp - append missing IDs to an Address Library bin
// Usage: binpatch <bin> <oldbin...> <outbin>
// Reads current bin, appends any (id,offset) from old bins whose id is missing.
// Appended entries use absolute encoding (type 0x00 = u64 id + u64 offset).
// Loader sorts after unpack, so order doesn't matter. Only header count patched.
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <map>
#include <string>
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

// Parse bin into sorted entries. Returns header fields and the byte offset where entries start.
static bool parse_bin(const uint8_t* d, size_t sz,
                      std::vector<std::pair<uint64_t,uint64_t>>& entries,
                      uint32_t version[4], std::string& name, uint32_t& ptr_size,
                      size_t& entriesStart) {
    entries.clear();
    size_t off = 0;
    uint32_t format; if (!read_u32(d, sz, off, format)) return false;
    if (format != 1 && format != 2) return false;
    for (int i=0;i<4;i++) if (!read_u32(d, sz, off, version[i])) return false;
    uint32_t nameLen; if (!read_u32(d, sz, off, nameLen)) return false;
    if (off + nameLen > sz) return false;
    name.assign((const char*)d+off, nameLen);
    size_t nul = name.find('\0'); if (nul != std::string::npos) name.resize(nul);
    off += nameLen;
    if (!read_u32(d, sz, off, ptr_size)) return false;
    if (ptr_size == 0) return false;
    uint32_t count; if (!read_u32(d, sz, off, count)) return false;
    entriesStart = off;

    uint64_t prevId=0, prevOffset=0;
    for (uint32_t i=0;i<count;i++) {
        uint8_t type; if (!read_u8(d, sz, off, type)) return false;
        uint8_t lo = type & 0xF, hi = type >> 4;
        uint64_t id;
        switch (lo) {
            case 0: { uint64_t v; if(!read_u64(d,sz,off,v)) return false; id=v; break; }
            case 1: id = prevId+1; break;
            case 2: { uint8_t v; if(!read_u8(d,sz,off,v)) return false; id=prevId+v; break; }
            case 3: { uint8_t v; if(!read_u8(d,sz,off,v)) return false; id=prevId-v; break; }
            case 4: { uint16_t v; if(!read_u16(d,sz,off,v)) return false; id=prevId+v; break; }
            case 5: { uint16_t v; if(!read_u16(d,sz,off,v)) return false; id=prevId-v; break; }
            case 6: { uint16_t v; if(!read_u16(d,sz,off,v)) return false; id=v; break; }
            case 7: { uint32_t v; if(!read_u32(d,sz,off,v)) return false; id=v; break; }
            default: return false;
        }
        uint64_t tmp = (hi & 8) ? (prevOffset / ptr_size) : prevOffset;
        uint64_t offset;
        switch (hi & 7) {
            case 0: { uint64_t v; if(!read_u64(d,sz,off,v)) return false; offset=v; break; }
            case 1: offset = tmp+1; break;
            case 2: { uint8_t v; if(!read_u8(d,sz,off,v)) return false; offset=tmp+v; break; }
            case 3: { uint8_t v; if(!read_u8(d,sz,off,v)) return false; offset=tmp-v; break; }
            case 4: { uint16_t v; if(!read_u16(d,sz,off,v)) return false; offset=tmp+v; break; }
            case 5: { uint16_t v; if(!read_u16(d,sz,off,v)) return false; offset=tmp-v; break; }
            case 6: { uint16_t v; if(!read_u16(d,sz,off,v)) return false; offset=v; break; }
            case 7: { uint32_t v; if(!read_u32(d,sz,off,v)) return false; offset=v; break; }
            default: return false;
        }
        if (hi & 8) offset *= ptr_size;
        entries.emplace_back(id, offset);
        prevId = id; prevOffset = offset;
    }
    return true;
}

int main(int argc, char** argv) {
    if (argc < 4) { fprintf(stderr, "usage: binpatch <bin> <oldbin...> <outbin>\n"); return 1; }
    const char* binPath = argv[1];
    const char* outPath = argv[argc-1];

    FILE* f = fopen(binPath, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", binPath); return 1; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> buf(sz);
    if (fread(buf.data(), 1, sz, f) != (size_t)sz) { fprintf(stderr, "read fail\n"); return 1; }
    fclose(f);

    std::vector<std::pair<uint64_t,uint64_t>> entries;
    uint32_t version[4]; std::string name; uint32_t ptr_size; size_t entriesStart;
    if (!parse_bin(buf.data(), buf.size(), entries, version, name, ptr_size, entriesStart)) {
        fprintf(stderr, "parse bin failed\n"); return 1;
    }
    std::map<uint64_t,uint64_t> have;
    for (auto& e : entries) have[e.first] = e.second;
    printf("bin: %zu entries\n", entries.size());

    // collect missing from old bins
    std::vector<std::pair<uint64_t,uint64_t>> missing;
    for (int a = 2; a < argc-1; a++) {
        f = fopen(argv[a], "rb");
        if (!f) { fprintf(stderr, "cannot open %s\n", argv[a]); continue; }
        fseek(f, 0, SEEK_END); long osz = ftell(f); fseek(f, 0, SEEK_SET);
        std::vector<uint8_t> obuf(osz);
        if (fread(obuf.data(), 1, osz, f) != (size_t)osz) { fclose(f); continue; }
        fclose(f);
        std::vector<std::pair<uint64_t,uint64_t>> oldEntries;
        uint32_t over[4]; std::string oname; uint32_t optr; size_t ostart;
        if (!parse_bin(obuf.data(), obuf.size(), oldEntries, over, oname, optr, ostart)) {
            fprintf(stderr, "parse old bin %s failed\n", argv[a]); continue;
        }
        int fromThis = 0;
        for (auto& e : oldEntries) {
            if (have.find(e.first) == have.end()) {
                have[e.first] = e.second;
                missing.push_back(e);
                fromThis++;
            }
        }
        printf("  %s: +%d IDs\n", argv[a], fromThis);
    }

    // append missing as absolute-encoded entries (type 0x00 + u64 id + u64 offset)
    std::vector<uint8_t> out = buf;
    for (auto& e : missing) {
        out.push_back(0x00);
        for (int i=0;i<8;i++) out.push_back((uint8_t)((e.first >> (8*i)) & 0xFF));
        for (int i=0;i<8;i++) out.push_back((uint8_t)((e.second >> (8*i)) & 0xFF));
    }
    // patch count in header: format(4) version(16) nameLen(4) name ptr_size(4) count(4)
    // nameLen from header includes the NUL; recompute from raw header
    size_t rawNameLen = (size_t)buf[20] | ((size_t)buf[21] << 8) | ((size_t)buf[22] << 16) | ((size_t)buf[23] << 24);
    size_t countOff = 24 + rawNameLen + 4;
    uint32_t newCount = (uint32_t)(entries.size() + missing.size());
    out[countOff]   = (uint8_t)(newCount & 0xFF);
    out[countOff+1] = (uint8_t)((newCount >> 8) & 0xFF);
    out[countOff+2] = (uint8_t)((newCount >> 16) & 0xFF);
    out[countOff+3] = (uint8_t)((newCount >> 24) & 0xFF);

    f = fopen(outPath, "wb");
    if (!f) { fprintf(stderr, "cannot write %s\n", outPath); return 1; }
    fwrite(out.data(), 1, out.size(), f);
    fclose(f);
    printf("wrote %s: %zu entries (+%zu added), %zu bytes\n", outPath, newCount, missing.size(), out.size());

    // verify
    {
        std::vector<std::pair<uint64_t,uint64_t>> dec;
        uint32_t dver[4]; std::string dname; uint32_t dptr; size_t dstart;
        if (parse_bin(out.data(), out.size(), dec, dver, dname, dptr, dstart)) {
            printf("verify: %zu entries parsed\n", dec.size());
            auto it1 = std::find_if(dec.begin(), dec.end(), [](auto& e){ return e.first == 0x371C; });
            auto it2 = std::find_if(dec.begin(), dec.end(), [](auto& e){ return e.first == 0x37DA; });
            printf("  0x371C: %s (0x%llX)\n", it1 != dec.end() ? "FOUND" : "MISSING",
                   it1 != dec.end() ? (unsigned long long)it1->second : 0);
            printf("  0x37DA: %s (0x%llX)\n", it2 != dec.end() ? "FOUND" : "MISSING",
                   it2 != dec.end() ? (unsigned long long)it2->second : 0);
        } else {
            printf("verify: parse FAILED\n");
        }
    }
    return 0;
}