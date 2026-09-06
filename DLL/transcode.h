#pragma once
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

// Parse format-2 Address Library bin. Returns false on any parse error.
// entries = sorted {id, offset} pairs. version = 4 u32s. name = trimmed at NUL. ptr_size as read.
bool parse_format2(const uint8_t* data, size_t size,
                   std::vector<std::pair<uint64_t, uint64_t>>& entries,
                   uint32_t version[4], std::string& name, uint32_t& ptr_size);

// Transcode format-2 bytes to a complete format-5 bin (dense u32 array).
// count (max_id+1) is returned via out_count. Returns false on parse error.
bool format2_to_format5(const uint8_t* fmt2, size_t size, std::vector<uint8_t>& out, uint32_t& out_count);

// Transcode format-2 bytes to a complete format-1 bin (delta-encoded entries).
// For plugins compiled without SKYRIM_SUPPORT_AE that only accept format 1.
bool format2_to_format1(const uint8_t* fmt2, size_t size, std::vector<uint8_t>& out);

// Parse format-5 Address Library bin (dense u32 array after 96-byte header).
// entries = {id, offset} pairs; id == array index. Returns false on parse error.
bool parse_format5(const uint8_t* data, size_t size,
                   std::vector<std::pair<uint64_t, uint64_t>>& entries,
                   uint32_t version[4], std::string& name, uint32_t& ptr_size);

// Transcode format-5 bytes to a complete format-2 bin (delta-encoded entries).
bool format5_to_format2(const uint8_t* fmt5, size_t size, std::vector<uint8_t>& out);

// Transcode format-5 bytes to a complete format-1 bin (delta-encoded entries).
bool format5_to_format1(const uint8_t* fmt5, size_t size, std::vector<uint8_t>& out);

// Transcode format-5 bytes to a complete format-0 bin (fixed 16-byte entries).
bool format5_to_format0(const uint8_t* fmt5, size_t size, std::vector<uint8_t>& out);

// Encode entries into format-2 bin bytes. entries must be sorted by id.
bool encode_format2(std::vector<uint8_t>& out,
                    const uint32_t version[4], const std::string& name,
                    uint32_t ptr_size, const std::vector<std::pair<uint64_t, uint64_t>>& entries);

// Encode entries into format-0 bin bytes. entries must be sorted by id.
bool encode_format0(std::vector<uint8_t>& out,
                    const uint32_t version[4], const std::string& name,
                    uint32_t ptr_size, const std::vector<std::pair<uint64_t, uint64_t>>& entries);