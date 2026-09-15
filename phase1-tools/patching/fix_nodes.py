import re
import struct

FILES = [
    r'E:\weixin-hook-4.1.8\WeChat\[3.9.5.81]\WeChatWin.dll',
    r'E:\weixin-hook-4.1.8\WeChat\[3.9.5.81]\WeChat.exe',
    r'E:\weixin-hook-4.1.8\WeChat\WeChat.exe',
    r'E:\weixin-hook-4.1.8\WeChat\[3.9.5.81]\WeChatResource.dll',
    r'E:\weixin-hook-4.1.8\WeChat\[3.9.5.81]\WeUIResource.dll',
]

KEY_FV = 'FileVersion'.encode('utf-16le')
KEY_PV = 'ProductVersion'.encode('utf-16le')
NEW_VAL = '4.1.13.65'
ORIG_PRODUCT_MS = bytes.fromhex('09000300')   # 3.9
ORIG_PRODUCT_LS = bytes.fromhex('503e0500')   # 5.15952
SIG = bytes.fromhex('bd04effe')

for path in FILES:
    data = bytearray(open(path, 'rb').read())
    name = path.split('\\')[-1]
    changed = []

    # 1. fix FileVersion node wValueLength: node header is 6 bytes before key start
    for m in re.finditer(re.escape(KEY_FV), bytes(data)):
        key_off = m.start()
        node_off = key_off - 6
        wlen, vlen, wtype = struct.unpack_from('<HHH', data, node_off)
        if wtype != 1:
            continue
        # value starts after key + null + padding (to 4-byte alignment relative to node start)
        key_total = len(KEY_FV) + 2  # + null
        header_and_key = 6 + key_total
        pad = (4 - (header_and_key % 4)) % 4
        val_off = node_off + header_and_key + pad
        cur = data[val_off:val_off + 24].decode('utf-16le', errors='ignore').split('\x00')[0]
        if cur.startswith('4.1.13.65'):
            # set wValueLength = 10 words (9 chars + null)
            struct.pack_into('<H', data, node_off + 2, 10)
            changed.append('FileVersion node @0x%X: wValueLength %d->10 (value="%s", wLength=%d)' % (node_off, vlen, cur, wlen))

    # 2. restore product FIXEDINFO fields (keep product version original 3.9.5.15952)
    for m in re.finditer(re.escape(SIG), bytes(data)):
        i = m.start()
        data[i+16:i+20] = ORIG_PRODUCT_MS
        data[i+20:i+24] = ORIG_PRODUCT_LS
        changed.append('fixedinfo @0x%X: product version restored to 3.9.5.15952' % i)

    if changed:
        open(path, 'wb').write(bytes(data))
        print('FIXED', name)
        for c in changed:
            print('   ', c)
    else:
        print('no changes:', name)

print()
print('=== verify FileVersion reads ===')
