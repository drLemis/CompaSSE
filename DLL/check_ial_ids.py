"""Check if the absent IDs from AIAgent correspond to valid SkyrimSE.exe offsets
by looking at what the 1.5.97 address library has for nearby IDs."""
import struct

# Read 1.5.97 format1
with open("D:/SteamLibrary/steamapps/common/Skyrim Special Edition/Data/SKSE/Plugins/version-1-5-97-0.bin", "rb") as f:
    fmt1 = f.read()

name_len = struct.unpack_from("<I", fmt1, 20)[0]
ptr_size = struct.unpack_from("<I", fmt1, 24 + name_len)[0]
count = struct.unpack_from("<I", fmt1, 28 + name_len)[0]
data_start = 32 + name_len

print(f"Format1 v1.5.97: {count} entries, ptr_size={ptr_size}")

# Parse format1 to extract all ID->offset pairs
entries = {}
off = data_start
cur_id = 0
cur_offset = 0
for i in range(count):
    if off >= len(fmt1):
        break
    type_byte = fmt1[off]
    id_mode = type_byte & 0x0F
    off_mode = (type_byte >> 4) & 0x0F
    
    # Decode ID delta
    if id_mode == 0:
        cur_id = struct.unpack_from("<Q", fmt1, off+1)[0]
        off += 9
    elif id_mode == 1:
        cur_id += 1
        off += 1
    elif id_mode == 2:
        cur_id += struct.unpack_from("<B", fmt1, off+1)[0]
        off += 2
    elif id_mode == 3:
        cur_id -= struct.unpack_from("<B", fmt1, off+1)[0]
        off += 2
    elif id_mode == 4:
        cur_id += struct.unpack_from("<H", fmt1, off+1)[0]
        off += 3
    elif id_mode == 5:
        cur_id -= struct.unpack_from("<H", fmt1, off+1)[0]
        off += 3
    elif id_mode == 6:
        cur_id = struct.unpack_from("<H", fmt1, off+1)[0]
        off += 3
    elif id_mode == 7:
        cur_id = struct.unpack_from("<I", fmt1, off+1)[0]
        off += 5
    
    # Decode offset
    if off_mode == 0:
        cur_offset = struct.unpack_from("<Q", fmt1, off)[0]
        off += 8
    elif off_mode == 1:
        cur_offset += 1
        off += 1
    elif off_mode == 2:
        cur_offset += struct.unpack_from("<B", fmt1, off)[0]
        off += 1
    elif off_mode == 3:
        cur_offset -= struct.unpack_from("<B", fmt1, off)[0]
        off += 1
    elif off_mode == 4:
        cur_offset += struct.unpack_from("<H", fmt1, off)[0]
        off += 2
    elif off_mode == 5:
        cur_offset -= struct.unpack_from("<H", fmt1, off)[0]
        off += 2
    elif off_mode == 6:
        cur_offset = struct.unpack_from("<H", fmt1, off)[0]
        off += 2
    elif off_mode == 7:
        cur_offset = struct.unpack_from("<I", fmt1, off)[0]
        off += 4
    
    entries[cur_id] = cur_offset

print(f"Parsed {len(entries)} entries from format1")

# Check the absent IDs
absent_ids = [0x02B25, 0x108EB, 0x5CF42, 0x7C36A, 0x7D92F, 0x7D938, 0x7DB8F, 0x7DD76]
print(f"\nAbsent IDs in 1.5.97 address library:")
for aid in absent_ids:
    if aid in entries:
        print(f"  0x{aid:05X} ({aid}): 1.5.97 offset=0x{entries[aid]:X}")
    else:
        print(f"  0x{aid:05X} ({aid}): NOT in 1.5.97 either")

# Also check format5
with open("D:/SteamLibrary/steamapps/common/Skyrim Special Edition/Data/SKSE/Plugins/versionlib-1-7-104-0.bin", "rb") as f:
    f5 = f.read()
f5_count = struct.unpack_from("<I", f5, 92)[0]

print(f"\nAbsent IDs in format5:")
for aid in absent_ids:
    if aid < f5_count:
        f5_off = struct.unpack_from("<I", f5, 96 + aid * 4)[0]
        print(f"  0x{aid:05X} ({aid}): format5 offset=0x{f5_off:X}")
    else:
        print(f"  0x{aid:05X} ({aid}): OUT OF RANGE")
