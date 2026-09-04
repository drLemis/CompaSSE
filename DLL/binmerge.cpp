// binmerge.cpp - merge missing IDs from old bins into the current bin
// Usage: binmerge <newbin> <oldbin1> <oldbin2> ... <outbin>
// Reads current bin, adds any (id,offset) from old bins whose id is missing,
// writes patched bin (format 2, same header, entries appended).
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

// Parse bin into sorted entries. Returns header fields.
static bool parse_bin(const uint8_t* d, size_t sz,
                      std::vector<std::pair<uint64_t,uint64_t>>& entries,
                      uint32_t version[4], std::string& name, uint32_t& ptr_size) {
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
    // sort by id
    std::sort(entries.begin(), entries.end());
    return true;
}

// Encode entries back to format-2 delta encoding.
static bool encode_bin(std::vector<uint8_t>& out,
                       const uint32_t version[4], const std::string& name,
                       uint32_t ptr_size, const std::vector<std::pair<uint64_t,uint64_t>>& entries) {
    out.clear();
    auto put32 = [&out](uint32_t v) {
        out.push_back((uint8_t)(v&0xFF)); out.push_back((uint8_t)((v>>8)&0xFF));
        out.push_back((uint8_t)((v>>16)&0xFF)); out.push_back((uint8_t)((v>>24)&0xFF));
    };
    auto put64 = [&out](uint64_t v) {
        for (int i=0;i<8;i++) out.push_back((uint8_t)((v>>(8*i))&0xFF));
    };
    put32(2); // format 2
    for (int i=0;i<4;i++) put32(version[i]);
    put32((uint32_t)name.size()+1);
    out.insert(out.end(), name.begin(), name.end());
    out.push_back(0);
    put32(ptr_size);
    put32((uint32_t)entries.size());

    uint64_t prevId=0, prevOffset=0;
    for (auto& e : entries) {
        uint64_t id = e.first, offset = e.second;
        // id delta
        uint8_t type = 0;
        // choose encoding: try to fit in smallest
        int64_t idDelta = (int64_t)id - (int64_t)prevId;
        if (idDelta == 1) type |= 0x1;
        else if (idDelta > 0 && idDelta <= 0xFF) { type |= 0x2; }
        else if (idDelta < 0 && -idDelta <= 0xFF) { type |= 0x3; }
        else if (idDelta > 0 && idDelta <= 0xFFFF) { type |= 0x4; }
        else if (idDelta < 0 && -idDelta <= 0xFFFF) { type |= 0x5; }
        else if (id <= 0xFFFF) { type |= 0x6; }
        else if (id <= 0xFFFFFFFF) { type |= 0x7; }
        else { type |= 0x0; }

        // offset delta (in pointer units if divisible)
        int64_t offDelta = (int64_t)offset - (int64_t)prevOffset;
        uint8_t hiBits = 0;
        // hi nibble = offset encoding; bit 3 of hi (0x80) = pointer-units flag
        // try pointer-unit encoding if offset divisible by ptr_size
        if (ptr_size && (offset % ptr_size) == 0) {
            int64_t pu = (int64_t)(offset / ptr_size) - (int64_t)(prevOffset / ptr_size);
            if (pu == 1) { hiBits = 0x90; } // hi=9: +1 in pointer units
            else if (pu > 0 && pu <= 0xFF) { hiBits = 0xA0; }
            else if (pu < 0 && -pu <= 0xFF) { hiBits = 0xB0; }
            else if (pu > 0 && pu <= 0xFFFF) { hiBits = 0xC0; }
            else if (pu < 0 && -pu <= 0xFFFF) { hiBits = 0xD0; }
            else if ((offset/ptr_size) <= 0xFFFF) { hiBits = 0xE0; }
            else if ((offset/ptr_size) <= 0xFFFFFFFF) { hiBits = 0xF0; }
            else { hiBits = 0x80; }
        } else {
            if (offDelta == 1) hiBits = 0x10;
            else if (offDelta > 0 && offDelta <= 0xFF) hiBits = 0x20;
            else if (offDelta < 0 && -offDelta <= 0xFF) hiBits = 0x30;
            else if (offDelta > 0 && offDelta <= 0xFFFF) hiBits = 0x40;
            else if (offDelta < 0 && -offDelta <= 0xFFFF) hiBits = 0x50;
            else if (offset <= 0xFFFF) hiBits = 0x60;
            else if (offset <= 0xFFFFFFFF) hiBits = 0x70;
            else hiBits = 0x00;
        }
        type = (uint8_t)((type & 0x0F) | hiBits);
        out.push_back(type);

        // id payload
        switch (type & 0xF) {
            case 0: put64(id); break;
            case 2: out.push_back((uint8_t)idDelta); break;
            case 3: out.push_back((uint8_t)(-idDelta)); break;
            case 4: { uint16_t v=(uint16_t)idDelta; out.push_back((uint8_t)(v&0xFF)); out.push_back((uint8_t)(v>>8)); break; }
            case 5: { uint16_t v=(uint16_t)(-idDelta); out.push_back((uint8_t)(v&0xFF)); out.push_back((uint8_t)(v>>8)); break; }
            case 6: { uint16_t v=(uint16_t)id; out.push_back((uint8_t)(v&0xFF)); out.push_back((uint8_t)(v>>8)); break; }
            case 7: put32((uint32_t)id); break;
        }
        // offset payload
        uint8_t hi = type >> 4;
        bool pu = (hi & 8) != 0;
        uint8_t hiOff = hi & 7;
        uint64_t absVal = pu ? (offset/ptr_size) : offset;
        uint64_t deltaVal = pu ? ((offset/ptr_size) - (prevOffset/ptr_size)) : (uint64_t)offDelta;
        switch (hiOff) {
            case 0: put64(absVal); break;
            case 2: out.push_back((uint8_t)deltaVal); break;
            case 3: out.push_back((uint8_t)deltaVal); break;
            case 4: { uint16_t v=(uint16_t)deltaVal; out.push_back((uint8_t)(v&0xFF)); out.push_back((uint8_t)(v>>8)); break; }
            case 5: { uint16_t v=(uint16_t)deltaVal; out.push_back((uint8_t)(v&0xFF)); out.push_back((uint8_t)(v>>8)); break; }
            case 6: { uint16_t v=(uint16_t)absVal; out.push_back((uint8_t)(v&0xFF)); out.push_back((uint8_t)(v>>8)); break; }
            case 7: put32((uint32_t)absVal); break;
        }
        prevId = id; prevOffset = offset;
    }
    return true;
}

int main(int argc, char** argv) {
    if (argc < 4) { fprintf(stderr, "usage: binmerge <newbin> <oldbin...> <outbin>\n"); return 1; }
    const char* newPath = argv[1];
    const char* outPath = argv[argc-1];

    // read new bin
    FILE* f = fopen(newPath, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", newPath); return 1; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> nbuf(sz);
    if (fread(nbuf.data(), 1, sz, f) != (size_t)sz) { fprintf(stderr, "read fail\n"); return 1; }
    fclose(f);

    std::vector<std::pair<uint64_t,uint64_t>> newEntries;
    uint32_t version[4]; std::string name; uint32_t ptr_size;
    if (!parse_bin(nbuf.data(), nbuf.size(), newEntries, version, name, ptr_size)) {
        fprintf(stderr, "parse new bin failed\n"); return 1;
    }
    std::map<uint64_t,uint64_t> newMap;
    for (auto& e : newEntries) newMap[e.first] = e.second;
    printf("new bin: %zu entries\n", newEntries.size());

    // merge old bins
    int added = 0;
    for (int a = 2; a < argc-1; a++) {
        f = fopen(argv[a], "rb");
        if (!f) { fprintf(stderr, "cannot open %s\n", argv[a]); continue; }
        fseek(f, 0, SEEK_END); long osz = ftell(f); fseek(f, 0, SEEK_SET);
        std::vector<uint8_t> obuf(osz);
        if (fread(obuf.data(), 1, osz, f) != (size_t)osz) { fclose(f); continue; }
        fclose(f);
        std::vector<std::pair<uint64_t,uint64_t>> oldEntries;
        uint32_t over[4]; std::string oname; uint32_t optr;
        if (!parse_bin(obuf.data(), obuf.size(), oldEntries, over, oname, optr)) {
            fprintf(stderr, "parse old bin %s failed\n", argv[a]); continue;
        }
        int fromThis = 0;
        for (auto& e : oldEntries) {
            if (newMap.find(e.first) == newMap.end()) {
                newMap[e.first] = e.second;
                added++;
                fromThis++;
            }
        }
        printf("  %s: +%d IDs\n", argv[a], fromThis);
    }

    // rebuild entries sorted
    std::vector<std::pair<uint64_t,uint64_t>> merged;
    merged.reserve(newMap.size());
    for (auto& kv : newMap) merged.push_back(kv);
    std::sort(merged.begin(), merged.end());

    std::vector<uint8_t> out;
    if (!encode_bin(out, version, name, ptr_size, merged)) {
        fprintf(stderr, "encode failed\n"); return 1;
    }
    // self-verify: decode out and compare with merged
    {
        std::vector<std::pair<uint64_t,uint64_t>> dec;
        uint32_t dver[4]; std::string dname; uint32_t dptr;
        if (parse_bin(out.data(), out.size(), dec, dver, dname, dptr)) {
            int mismatches = 0;
            for (size_t i = 0; i < merged.size() && i < dec.size(); i++) {
                if (merged[i].first != dec[i].first || merged[i].second != dec[i].second) {
                    if (mismatches < 10)
                        printf("  MISMATCH[%zu]: want id=0x%llX off=0x%llX got id=0x%llX off=0x%llX\n",
                               i, (unsigned long long)merged[i].first, (unsigned long long)merged[i].second,
                               (unsigned long long)dec[i].first, (unsigned long long)dec[i].second);
                    mismatches++;
                }
            }
            printf("self-verify: %zu entries, %d mismatches\n", dec.size(), mismatches);
        } else {
            printf("self-verify: decode FAILED\n");
        }
    }
    f = fopen(outPath, "wb");
    if (!f) { fprintf(stderr, "cannot write %s\n", outPath); return 1; }
    fwrite(out.data(), 1, out.size(), f);
    fclose(f);
    printf("wrote %s: %zu entries (+%d added), %zu bytes\n", outPath, merged.size(), added, out.size());
    // verify specific IDs
    auto it1 = newMap.find(0x371C);
    auto it2 = newMap.find(0x37DA);
    printf("check 0x371C: %s (0x%llX)\n", it1 != newMap.end() ? "FOUND" : "MISSING",
           it1 != newMap.end() ? (unsigned long long)it1->second : 0);
    printf("check 0x37DA: %s (0x%llX)\n", it2 != newMap.end() ? "FOUND" : "MISSING",
           it2 != newMap.end() ? (unsigned long long)it2->second : 0);
    return 0;
}