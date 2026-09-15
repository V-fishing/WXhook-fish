import shutil
import os
import re

BASE = r'E:\weixin-hook-4.1.8\WeChat'
files = [
    os.path.join(BASE, '[3.9.5.81]', 'WeChatWin.dll'),
    os.path.join(BASE, '[3.9.5.81]', 'WeChat.exe'),
    os.path.join(BASE, 'WeChat.exe'),
    os.path.join(BASE, '[3.9.5.81]', 'WeChatResource.dll'),
    os.path.join(BASE, '[3.9.5.81]', 'WeUIResource.dll'),
]

OLD_STR = '3.9.5.81'.encode('utf-16le')
NEW_STR = '4.1.13.65'.encode('utf-16le') + b'\x00\x00'   # 20 bytes: 9 chars + null
# old was 18 bytes: 8 chars + null
SIG = bytes.fromhex('bd04effe')
NEW_MS = (4 << 16 | 1).to_bytes(4, 'little')        # 01 00 04 00
NEW_LS = (13 << 16 | 65).to_bytes(4, 'little')      # 41 00 0d 00

for path in files:
    name = path.replace(BASE, '...')
    if not os.path.exists(path):
        print('MISSING:', name)
        continue
    bak = path + '.bak2'
    if not os.path.exists(bak):
        shutil.copy2(path, bak)
        print('backup ->', bak.replace(BASE, '...'))
    else:
        # already has a backup; refresh backup only if this is our first patch pass
        pass

    data = bytearray(open(path, 'rb').read())
    changes = []

    # 1. UTF-16 version strings
    for m in re.finditer(re.escape(OLD_STR), bytes(data)):
        off = m.start()
        # check we have room (2 extra bytes) and they are zero padding
        room = data[off+18:off+20]
        data[off:off+20] = NEW_STR
        changes.append('str@0x%X (pad was %s)' % (off, room.hex()))

    # 2. FIXEDFILEINFO
    for m in re.finditer(re.escape(SIG), bytes(data)):
        i = m.start()
        old = data[i+8:i+24].hex(' ')
        data[i+8:i+12] = NEW_MS      # file MS
        data[i+12:i+16] = NEW_LS     # file LS
        data[i+16:i+20] = NEW_MS     # product MS
        data[i+20:i+24] = NEW_LS     # product LS
        changes.append('fixedinfo@0x%X (was %s)' % (i, old))

    if changes:
        open(path, 'wb').write(bytes(data))
        print('PATCHED', name)
        for c in changes:
            print('   ', c)
    else:
        print('no changes needed:', name)

print()
print('=== verify ===')
for path in files:
    if not os.path.exists(path):
        continue
    d = open(path, 'rb').read()
    n_str = len(re.findall(re.escape('4.1.13.65'.encode('utf-16le')), d))
    n_old = len(re.findall(re.escape(OLD_STR), d))
    print(os.path.basename(path), ': new-string hits=', n_str, ' old-string hits=', n_old)
