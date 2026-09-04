"""Parse format1 and check absent IDs."""
import struct

with open("D:/SteamLibrary/steamapps/common/Skyrim Special Edition/Data/SKSE/Plugins/version-1-5-97-0.bin", "rb") as f:
    data = f.read()

name_len = struct.unpack_from("<I", data, 20)[0]
count = struct.unpack_from("<I", data, 28+name_len)[0]
off = 32 + name_len

absent_ids = {0x02B25, 0x108EB, 0x5CF42, 0x7C36A, 0x7D92F, 0x7D938, 0x7DB8F, 0x7DD76}
found = {}
cur_id = 0
cur_offset = 0
parsed = 0

for i in range(count):
    if off >= len(data):
        break
    start = off
    type_byte = data[off]; off += 1
    id_mode = type_byte & 0x0F
    off_mode = (type_byte >> 4) & 0x0F
    
    if id_mode == 0: cur_id = struct.unpack_from("<Q", data, off)[0]; off += 8
    elif id_mode == 1: cur_id += 1
    elif id_mode == 2: cur_id += struct.unpack_from("<B", data, off)[0]; off += 1
    elif id_mode == 3: cur_id -= struct.unpack_from("<B", data, off)[0]; off += 1
    elif id_mode == 4: cur_id += struct.unpack_from("<H", data, off)[0]; off += 2
    elif id_mode == 5: cur_id -= struct.unpack_from("<H", data, off)[0]; off += 2
    elif id_mode == 6: cur_id = struct.unpack_from("<H", data, off)[0]; off += 2
    elif id_mode == 7: cur_id = struct.unpack_from("<I", data, off)[0]; off += 4
    
    if off_mode == 0: cur_offset = struct.unpack_from("<Q", data, off)[0]; off += 8
    elif off_mode == 1: cur_offset += 1
    elif off_mode == 2: cur_offset += struct.unpack_from("<B", data, off)[0]; off += 1
    elif off_mode == 3: cur_offset -= struct.unpack_from("<B", data, off)[0]; off += 1
    elif off_mode == 4: cur_offset += struct.unpack_from("<H", data, off)[0]; off += 2
    elif off_mode == 5: cur_offset -= struct.unpack_from("<H", data, off)[0]; off += 2
    elif off_mode == 6: cur_offset = struct.unpack_from("<H", data, off)[0]; off += 2
    elif off_mode == 7: cur_offset = struct.unpack_from("<I", data, off)[0]; off += 4
    
    parsed = i + 1
    if cur_id in absent_ids:
        found[cur_id] = cur_offset
        print(f"  Found absent ID: 0x{cur_id:05X} ({cur_id}) -> offset=0x{cur_offset:X} at entry {i}")
    
    if len(found) == len(absent_ids):
        break

print(f"\nParsed {parsed} entries, offset={off}")
print(f"\nAbsent IDs in 1.5.97 format1:")
for aid in sorted(found.keys()):
    print(f"  0x{aid:05X} ({aid}): offset=0x{found[aid]:X}")
missing = absent_ids - set(found.keys())
for aid in sorted(missing):
    print(f"  0x{aid:05X} ({aid}): NOT FOUND in file")
