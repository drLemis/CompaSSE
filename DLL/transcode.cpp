#include "transcode.h"

#include <algorithm>
#include <cstring>

namespace {

// Bounds-checked little-endian readers over a byte buffer.
struct Reader {
    const uint8_t* data;
    size_t size;
    size_t off = 0;

    bool u8(uint8_t& v) {
        if (off + 1 > size) return false;
        v = data[off++];
        return true;
    }
    bool u16(uint16_t& v) {
        if (off + 2 > size) return false;
        v = (uint16_t)data[off] | ((uint16_t)data[off + 1] << 8);
        off += 2;
        return true;
    }
    bool u32(uint32_t& v) {
        if (off + 4 > size) return false;
        v = (uint32_t)data[off] | ((uint32_t)data[off + 1] << 8) |
            ((uint32_t)data[off + 2] << 16) | ((uint32_t)data[off + 3] << 24);
        off += 4;
        return true;
    }
    bool u64(uint64_t& v) {
        if (off + 8 > size) return false;
        v = 0;
        for (int i = 0; i < 8; ++i) v |= (uint64_t)data[off + i] << (8 * i);
        off += 8;
        return true;
    }
};

} // namespace

bool parse_format2(const uint8_t* data, size_t size,
                   std::vector<std::pair<uint64_t, uint64_t>>& entries,
                   uint32_t version[4], std::string& name, uint32_t& ptr_size) {
    entries.clear();
    name.clear();

    Reader r{data, size};

    uint32_t format;
    if (!r.u32(format)) return false;
    if (format != 1 && format != 2) return false;

    for (int i = 0; i < 4; ++i)
        if (!r.u32(version[i])) return false;

    uint32_t nameLen;
    if (!r.u32(nameLen)) return false;
    if (nameLen == 0 || r.off + nameLen > r.size) return false; // name is NUL-terminated, len includes the NUL
    name.assign((const char*)r.data + r.off, nameLen);
    size_t nul = name.find('\0');
    if (nul != std::string::npos) name.resize(nul); // trim at NUL
    r.off += nameLen;

    if (!r.u32(ptr_size)) return false;
    if (ptr_size == 0) return false; // would divide by zero in delta decoding

    uint32_t count;
    if (!r.u32(count)) return false;

    uint64_t prev_id = 0, prev_offset = 0;
    for (uint32_t i = 0; i < count; ++i) {
        uint8_t type;
        if (!r.u8(type)) return false;

        // ---- id: low nibble ----
        uint8_t lo = type & 0xF;
        uint64_t id;
        switch (lo) {
            case 0: if (!r.u64(id)) return false; break;              // absolute u64
            case 1: id = prev_id + 1; break;                          // +1
            case 2: { uint8_t d; if (!r.u8(d)) return false; id = prev_id + d; break; }
            case 3: { uint8_t d; if (!r.u8(d)) return false; id = prev_id - d; break; }
            case 4: { uint16_t d; if (!r.u16(d)) return false; id = prev_id + d; break; }
            case 5: { uint16_t d; if (!r.u16(d)) return false; id = prev_id - d; break; }
            case 6: { uint16_t d; if (!r.u16(d)) return false; id = d; break; }   // absolute u16
            case 7: { uint32_t d; if (!r.u32(d)) return false; id = d; break; }   // absolute u32
            default: return false; // unknown id nibble
        }

        // ---- offset: high nibble ----
        uint8_t hi = type >> 4;
        // When bit 3 of the high nibble is set, the delta is applied to the
        // offset divided by pointer_size (i.e. in pointer units).
        uint64_t tmp = (hi & 8) ? (prev_offset / ptr_size) : prev_offset;
        uint8_t hiOff = hi & 7;
        uint64_t offset;
        switch (hiOff) {
            case 0: if (!r.u64(offset)) return false; break;          // absolute u64
            case 1: offset = tmp + 1; break;                          // +1
            case 2: { uint8_t d; if (!r.u8(d)) return false; offset = tmp + d; break; }
            case 3: { uint8_t d; if (!r.u8(d)) return false; offset = tmp - d; break; }
            case 4: { uint16_t d; if (!r.u16(d)) return false; offset = tmp + d; break; }
            case 5: { uint16_t d; if (!r.u16(d)) return false; offset = tmp - d; break; }
            case 6: { uint16_t d; if (!r.u16(d)) return false; offset = d; break; } // absolute u16
            case 7: { uint32_t d; if (!r.u32(d)) return false; offset = d; break; } // absolute u32
            default: return false; // unreachable (hiOff is 0..7)
        }
        if (hi & 8) offset *= ptr_size;

        entries.emplace_back(id, offset);
        prev_id = id;
        prev_offset = offset;
    }

    std::sort(entries.begin(), entries.end());
    return true;
}

bool format2_to_format5(const uint8_t* fmt2, size_t size, std::vector<uint8_t>& out, uint32_t& out_count) {
    std::vector<std::pair<uint64_t, uint64_t>> entries;
    uint32_t version[4];
    std::string name;
    uint32_t ptr_size = 0;
    if (!parse_format2(fmt2, size, entries, version, name, ptr_size)) return false;

    uint64_t maxId = 0;
    for (const auto& e : entries)
        if (e.first > maxId) maxId = e.first;
    uint64_t count64 = entries.empty() ? 0 : maxId + 1;
    if (count64 > 0xFFFFFFFFull) return false; // format 5 count is u32
    out_count = (uint32_t)count64;

    // Layout: format(4) + version(16) + name(64) + ptr_size(4) + data_fmt(4) + count(4) + dense[count]
    out.clear();
    out.reserve(96 + (size_t)out_count * 4);

    auto put32 = [&out](uint32_t v) {
        out.push_back((uint8_t)(v & 0xFF));
        out.push_back((uint8_t)((v >> 8) & 0xFF));
        out.push_back((uint8_t)((v >> 16) & 0xFF));
        out.push_back((uint8_t)((v >> 24) & 0xFF));
    };

    put32(5); // format
    for (int i = 0; i < 4; ++i) put32(version[i]); // copy version verbatim
    out.insert(out.end(), 64, 0);                  // name, zero-padded to 64
    size_t n = name.size() < 64 ? name.size() : 64;
    std::memcpy(out.data() + 20, name.data(), n);
    put32(ptr_size);
    put32(0); // data_fmt
    put32(out_count);

    out.resize(out.size() + (size_t)out_count * 4, 0);
    for (const auto& e : entries) {
        if (e.first >= out_count) continue; // defensive; ids are < max_id+1 by construction
        uint32_t v = (uint32_t)e.second;    // format 5 stores u32 offsets (RVAs, always < 4 GiB)
        size_t pos = 96 + (size_t)e.first * 4;
        out[pos] = (uint8_t)(v & 0xFF);
        out[pos + 1] = (uint8_t)((v >> 8) & 0xFF);
        out[pos + 2] = (uint8_t)((v >> 16) & 0xFF);
        out[pos + 3] = (uint8_t)((v >> 24) & 0xFF);
    }
    return true;
}

bool format2_to_format1(const uint8_t* fmt2, size_t size, std::vector<uint8_t>& out) {
    // Format-1 and format-2 use IDENTICAL header layout and entry encoding.
    // The ONLY difference is the 4-byte format version at offset 0 (1 vs 2).
    // So we just copy the data and patch the format byte.
    if (size < 4) return false;
    uint32_t fmt = fmt2[0] | ((uint32_t)fmt2[1] << 8) | ((uint32_t)fmt2[2] << 16) | ((uint32_t)fmt2[3] << 24);
    if (fmt != 1 && fmt != 2) return false; // source must be format 1 or 2

    out.assign(fmt2, fmt2 + size);
    out[0] = 0x01; // patch format version: 2 -> 1
    out[1] = 0x00;
    out[2] = 0x00;
    out[3] = 0x00;
    return true;
}

bool parse_format5(const uint8_t* data, size_t size,
                   std::vector<std::pair<uint64_t, uint64_t>>& entries,
                   uint32_t version[4], std::string& name, uint32_t& ptr_size) {
    entries.clear();
    name.clear();
    if (size < 96) return false;

    Reader r{data, size};
    uint32_t format;
    if (!r.u32(format)) return false;
    if (format != 5) return false;

    for (int i = 0; i < 4; ++i)
        if (!r.u32(version[i])) return false;

    // name: fixed 64 bytes, NUL-terminated
    if (r.off + 64 > r.size) return false;
    name.assign((const char*)r.data + r.off, 64);
    size_t nul = name.find('\0');
    if (nul != std::string::npos) name.resize(nul);
    r.off += 64;

    if (!r.u32(ptr_size)) return false;
    uint32_t data_fmt;
    if (!r.u32(data_fmt)) return false;
    uint32_t count;
    if (!r.u32(count)) return false;

    // dense u32 array: entry i = offset for id i
    if ((size_t)count > (size - r.off) / 4) return false;
    entries.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t off;
        if (!r.u32(off)) return false;
        entries.emplace_back((uint64_t)i, (uint64_t)off);
    }
    return true;
}

// Delta-encode entries into a format-2 bin (shared by fmt5->2 and fmt5->1).
// Uses absolute u64 encodings only (type 0x00) - valid format 1/2, just not
// compressed. Avoids the buggy delta encoder entirely.
bool encode_format2(std::vector<uint8_t>& out,
                           const uint32_t version[4], const std::string& name,
                           uint32_t ptr_size, const std::vector<std::pair<uint64_t, uint64_t>>& entries) {
    (void)ptr_size; // absolute encoding ignores pointer units
    out.clear();
    auto put32 = [&out](uint32_t v) {
        out.push_back((uint8_t)(v & 0xFF)); out.push_back((uint8_t)((v >> 8) & 0xFF));
        out.push_back((uint8_t)((v >> 16) & 0xFF)); out.push_back((uint8_t)((v >> 24) & 0xFF));
    };
    auto put64 = [&out](uint64_t v) {
        for (int i = 0; i < 8; i++) out.push_back((uint8_t)((v >> (8 * i)) & 0xFF));
    };
    put32(2); // format 2
    for (int i = 0; i < 4; i++) put32(version[i]);
    put32((uint32_t)name.size() + 1);
    out.insert(out.end(), name.begin(), name.end());
    out.push_back(0);
    put32(ptr_size);
    put32((uint32_t)entries.size());

    for (const auto& e : entries) {
        out.push_back(0x00); // type: id absolute u64 (lo=0), offset absolute u64 (hi=0)
        put64(e.first);
        put64(e.second);
    }
    return true;
}

bool format5_to_format2(const uint8_t* fmt5, size_t size, std::vector<uint8_t>& out) {
    std::vector<std::pair<uint64_t, uint64_t>> entries;
    uint32_t version[4];
    std::string name;
    uint32_t ptr_size = 0;
    if (!parse_format5(fmt5, size, entries, version, name, ptr_size)) return false;
    return encode_format2(out, version, name, ptr_size, entries);
}

bool format5_to_format1(const uint8_t* fmt5, size_t size, std::vector<uint8_t>& out) {
    std::vector<uint8_t> fmt2;
    if (!format5_to_format2(fmt5, size, fmt2)) return false;
    return format2_to_format1(fmt2.data(), fmt2.size(), out);
}

// Format 0: same header, but entries are fixed 16-byte {id:u64, offset:u64}.
// No type byte, no variable-length encoding.
bool encode_format0(std::vector<uint8_t>& out,
                           const uint32_t version[4], const std::string& name,
                           uint32_t ptr_size, const std::vector<std::pair<uint64_t, uint64_t>>& entries) {
    (void)ptr_size;
    out.clear();
    auto put32 = [&out](uint32_t v) {
        out.push_back((uint8_t)(v & 0xFF)); out.push_back((uint8_t)((v >> 8) & 0xFF));
        out.push_back((uint8_t)((v >> 16) & 0xFF)); out.push_back((uint8_t)((v >> 24) & 0xFF));
    };
    auto put64 = [&out](uint64_t v) {
        for (int i = 0; i < 8; i++) out.push_back((uint8_t)((v >> (8 * i)) & 0xFF));
    };
    put32(0); // format 0
    for (int i = 0; i < 4; i++) put32(version[i]);
    put32((uint32_t)name.size() + 1);
    out.insert(out.end(), name.begin(), name.end());
    out.push_back(0);
    put32(ptr_size);
    put32((uint32_t)entries.size());

    for (const auto& e : entries) {
        put64(e.first);   // id:u64
        put64(e.second);  // offset:u64
    }
    return true;
}

bool format5_to_format0(const uint8_t* fmt5, size_t size, std::vector<uint8_t>& out) {
    std::vector<std::pair<uint64_t, uint64_t>> entries;
    uint32_t version[4];
    std::string name;
    uint32_t ptr_size = 0;
    if (!parse_format5(fmt5, size, entries, version, name, ptr_size)) return false;
    return encode_format0(out, version, name, ptr_size, entries);
}