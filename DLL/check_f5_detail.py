import struct

with open("D:/SteamLibrary/steamapps/common/Skyrim Special Edition/Data/SKSE/Plugins/versionlib-1-7-104-0.bin", "rb") as f:
    f5 = f.read()

# Print raw bytes in 16-byte rows
for i in range(0, min(256, len(f5)), 16):
    hexs = ' '.join(f'{f5[j]:02X}' for j in range(i, min(i+16, len(f5))))
    ascii_str = ''.join(chr(f5[j]) if 32 <= f5[j] < 127 else '.' for j in range(i, min(i+16, len(f5))))
    print(f'  {i:04X}: {hexs}  {ascii_str}')

# CommonLibSSE Header5: format(4) + version[4](16) + name(104 padded) + ptrSize(4) + count(4)
# The name "SkyrimSE.exe" starts at offset 20, padded to 104 bytes
# So name ends at offset 20+104=124
# ptrSize at offset 124, count at offset 128, data at offset 132

# Try header size = 20 + 104 + 4 + 4 = 132
ptr_off = 20 + 104  # 124
print(f"\nTrying header: name padded to 104 bytes")
print(f"  ptr_size at {ptr_off}: {struct.unpack_from('<I', f5, ptr_off)[0]}")
print(f"  count at {ptr_off+4}: {struct.unpack_from('<I', f5, ptr_off+4)[0]}")
data_start = ptr_off + 8
print(f"  data_start: {data_start}")
print(f"  remaining: {len(f5) - data_start}, entries: {(len(f5) - data_start) // 4}")

# Actually CommonLibSSE uses MAX_PATH=260 for name
ptr_off2 = 20 + 260  # 280
print(f"\nTrying header: name padded to MAX_PATH=260")
print(f"  ptr_size at {ptr_off2}: {struct.unpack_from('<I', f5, ptr_off2)[0]}")
print(f"  count at {ptr_off2+4}: {struct.unpack_from('<I', f5, ptr_off2+4)[0]}")
data_start2 = ptr_off2 + 8
print(f"  data_start: {data_start2}")
print(f"  remaining: {len(f5) - data_start2}, entries: {(len(f5) - data_start2) // 4}")
