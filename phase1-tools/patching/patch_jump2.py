import os

files = [
    r'E:\weixin-hook-4.1.8\WeChat\[3.9.5.81]\WeChat.exe',
    r'E:\weixin-hook-4.1.8\WeChat\WeChat.exe',
]
off = 0x4556  # 'je rel32' at VA 0x140005156 (6 bytes: 0F 84 xx xx xx xx)

for path in files:
    data = bytearray(open(path, 'rb').read())
    name = os.path.basename(path)
    cur = bytes(data[off:off + 6])
    print('%s @0x%X: %s' % (name, off, cur.hex(' ')))
    if cur[0] == 0x0F and cur[1] == 0x84:
        rel = int.from_bytes(cur[2:6], 'little', signed=True)
        target = off + 6 + rel          # target file offset of the je
        # new jmp rel32 at same address: E9 <rel'> 90  (rel' = target - (off+5))
        rel2 = target - (off + 5)
        new = bytes([0xE9]) + rel2.to_bytes(4, 'little', signed=True) + b'\x90'
        data[off:off + 6] = new
        open(path, 'wb').write(bytes(data))
        print('  -> patched: E9 %s 90  (jmp to file 0x%X = success path)' % (rel2.to_bytes(4, 'little', signed=True).hex(' '), target))
    elif cur[0] == 0xE9:
        print('  -> already patched (E9)')
    else:
        print('  -> unexpected, abort')
