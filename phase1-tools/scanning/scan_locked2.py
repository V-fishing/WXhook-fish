import ctypes
import ctypes.wintypes as wt
import os
import sys

GENERIC_READ = 0x80000000
FILE_SHARE_ALL = 0x00000001 | 0x00000002 | 0x00000004
OPEN_EXISTING = 3
INVALID_HANDLE = ctypes.c_void_p(-1).value
kernel32 = ctypes.windll.kernel32


def try_read(path, max_size=200 * 1024 * 1024):
    """returns (data, err) where err: None=ok, 'open:<code>' or 'read:<code>'"""
    h = kernel32.CreateFileW(path, GENERIC_READ, FILE_SHARE_ALL, None, OPEN_EXISTING, 0x80, None)
    if h == INVALID_HANDLE:
        return None, 'open:%d' % kernel32.GetLastError()
    try:
        size = kernel32.GetFileSize(h, None)
        if size == 0xFFFFFFFF:
            return None, 'size'
        if size > max_size:
            return None, 'toobig'
        buf = ctypes.create_string_buffer(size)
        read = wt.DWORD(0)
        ok = kernel32.ReadFile(h, buf, size, ctypes.byref(read), None)
        if not ok:
            return None, 'read:%d' % kernel32.GetLastError()
        return buf.raw[:read.value], None
    finally:
        kernel32.CloseHandle(h)


roots = [
    r'E:\weixin-hook-4.1.8\WeChat',
    os.path.expandvars(r'%APPDATA%\Tencent'),
    os.path.expandvars(r'%LOCALAPPDATA%\Tencent'),
    os.path.expandvars(r'%ProgramData%\Tencent'),
    os.path.expanduser(r'~\Documents\WeChat Files'),
    os.path.expanduser(r'~\Documents\xwechat_files'),
    os.path.expandvars(r'%TEMP%'),
]

pat_a = b'3.9.11.17'
pat_u = '3.9.11.17'.encode('utf-16le')
unreadable = []
hits = []
scanned = 0

for root in roots:
    if not os.path.isdir(root):
        continue
    for dp, dirs, files in os.walk(root):
        # skip deep temp junk
        if '\\Temp\\' in dp and 'Tencent' not in dp and 'WeChat' not in dp and 'wx' not in dp.lower():
            continue
        for fn in files:
            fp = os.path.join(dp, fn)
            try:
                sz = os.path.getsize(fp)
            except Exception as e:
                continue
            if sz < 16 or sz > 200 * 1024 * 1024:
                continue
            data, err = try_read(fp)
            scanned += 1
            if err:
                if err.startswith('open') or err.startswith('read'):
                    unreadable.append((fp, sz, err))
                continue
            if pat_a in data or pat_u in data:
                hits.append(fp)

print('scanned:', scanned)
print('=== HITS for 3.9.11.17 ===')
for h in hits:
    print(' ', h)
print('=== UNREADABLE (open/read failed) ===')
for fp, sz, err in unreadable[:60]:
    print(' ', err, sz, fp)
print('total unreadable:', len(unreadable))
