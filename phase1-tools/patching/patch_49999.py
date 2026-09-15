import os
import re
import shutil
import struct

BASE = r'E:\weixin-hook-4.1.8\WeChat'

# target files: (path, backup_path or None)
FILES = [
    (os.path.join(BASE, '[4.1.13.65]', 'WeChatWin.dll'), os.path.join(BASE, '[4.1.13.65]', 'WeChatWin.dll.bak2')),
    (os.path.join(BASE, '[4.1.13.65]', 'WeChat.exe'), os.path.join(BASE, '[4.1.13.65]', 'WeChat.exe.bak2')),
    (os.path.join(BASE, 'WeChat.exe'), os.path.join(BASE, 'WeChat.exe.bak2')),
    (os.path.join(BASE, '[4.1.13.65]', 'WeChatResource.dll'), os.path.join(BASE, '[4.1.13.65]', 'WeChatResource.dll.bak2')),
    (os.path.join(BASE, '[4.1.13.65]', 'WeUIResource.dll'), os.path.join(BASE, '[4.1.13.65]', 'WeUIResource.dll.bak2')),
]

OLD_STR = '3.9.5.81'.encode('utf-16le')       # 18 bytes (8 chars + null)
NEW_STR_TXT = '4.9.9.99'                       # 8 chars! exactly same length as 3.9.5.81
NEW_STR = NEW_STR_TXT.encode('utf-16le') + b'\x00\x00'  # 18 bytes: 8 chars + null  (same total)
SIG = bytes.fromhex('bd04effe')
# 4.9.9.99: major=4 minor=9 patch=9 build=99 -> MS=(4<<16)|9, LS=(9<<16)|99
NEW_MS = ((4 << 16) | 9).to_bytes(4, 'little')
NEW_LS = ((9 << 16) | 99).to_bytes(4, 'little')
ORIG_PRODUCT_MS = bytes.fromhex('09000300')
ORIG_PRODUCT_LS = bytes.fromhex('503e0500')
KEY_FV = 'FileVersion'.encode('utf-16le')

for path, bak in FILES:
    if os.path.exists(bak):
        shutil.copy2(bak, path)
        print('restored', os.path.basename(path), 'from backup')
    else:
        print('WARNING: no backup for', path)

print()
for path, bak in FILES:
    data = bytearray(open(path, 'rb').read())
    name = path.split('\\')[-1] + '(' + path.split('\\')[-2][:6] + ')'
    changes = []

    # 1. strings: same length swap -> clean
    for m in re.finditer(re.escape(OLD_STR), bytes(data)):
        off = m.start()
        data[off:off + 18] = NEW_STR
        changes.append('str@0x%X' % off)

    # 2. node wValueLength stays 9 words (8 chars + null) -> NO change needed!
    #    (this is the advantage of a same-length version string)

    # 3. fixedinfo (product fields restored from pristine backup bytes at same offset)
    bak_data = open(bak, 'rb').read() if os.path.exists(bak) else None
    for m in re.finditer(re.escape(SIG), bytes(data)):
        i = m.start()
        data[i+8:i+12] = NEW_MS
        data[i+12:i+16] = NEW_LS
        if bak_data is not None:
            data[i+16:i+24] = bak_data[i+16:i+24]  # original product version
        changes.append('fixedinfo@0x%X' % i)

    if changes:
        open(path, 'wb').write(bytes(data))
        print('PATCHED', name, '->', ', '.join(changes))
    else:
        print('no changes:', name)

print()
print('=== verify ===')
for path, bak in FILES:
    if not os.path.exists(path):
        continue
    d = open(path, 'rb').read()
    n_new = len(re.findall(re.escape('4.9.9.99'.encode('utf-16le')), d))
    n_old = len(re.findall(re.escape(OLD_STR), d))
    print(os.path.basename(path), ':', path.split('\\')[-2][:6], '| new:', n_new, 'old:', n_old)
