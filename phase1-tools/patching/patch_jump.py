import os

files = [
    r'E:\weixin-hook-4.1.8\WeChat\[3.9.5.81]\WeChat.exe',
    r'E:\weixin-hook-4.1.8\WeChat\WeChat.exe',
]
off = 0x4556   # file offset of the 'je 0x1400051fa' (VA 0x140005156)
for path in files:
    data = bytearray(open(path, 'rb').read())
    cur = data[off]
    name = os.path.basename(path)
    print('%s byte @0x%X = 0x%02X' % (name, off, cur))
    if cur == 0x74:
        data[off] = 0xEB  # je -> jmp (always take OK path)
        open(path, 'wb').write(bytes(data))
        print('  -> patched to 0xEB (jmp)')
    elif cur == 0xEB:
        print('  -> already patched')
    else:
        print('  -> UNEXPECTED byte 0x%02X, abort' % cur)
