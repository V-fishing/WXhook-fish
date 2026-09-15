# -*- coding: utf-8 -*-
# 从 minidump 的 MemoryList 流提取崩溃现场字节
import struct, sys
path = r'C:\Users\fish\AppData\Roaming\Tencent\xwechat\crashinfo\reports\Weixin_c4186904-65a7-4194-9f62-3d079c0f7601.dmp'
data = open(path, 'rb').read()
# MINIDUMP_HEADER: 'MDMP', version, NumberOfStreams, StreamDirectoryRva
assert data[:4] == b'MDMP'
nstreams = struct.unpack_from('<I', data, 8)[0]
dirrva = struct.unpack_from('<I', data, 12)[0]
for i in range(nstreams):
    st, sz, rva = struct.unpack_from('<III', data, dirrva + 12*i)
    if st == 5:  # MemoryListStream
        cnt = struct.unpack_from('<I', data, rva)[0]
        off = rva + 4
        ranges = []
        for j in range(cnt):
            start, dsz, drva = struct.unpack_from('<QII', data, off)
            off += 16
            ranges.append((start, dsz, drva))
        print(f"MemoryList: {cnt} ranges")
        TARGETS = [(0x7ff8800afcc0, 0x40), (0x7ff8800afcd0, 0x20)]
        for start, dsz, drva in ranges:
            for taddr, tlen in TARGETS:
                if start <= taddr < start + dsz:
                    o = taddr - start
                    chunk = data[drva+o: drva+o+tlen]
                    print(f"  @{taddr:#x} (range {start:#x}+{dsz:#x}):")
                    print("   ", chunk.hex(' '))
        break
