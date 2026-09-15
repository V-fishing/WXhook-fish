import ctypes
import ctypes.wintypes as wt
import os

GENERIC_READ = 0x80000000
FILE_SHARE_ALL = 0x00000001 | 0x00000002 | 0x00000004  # READ | WRITE | DELETE
OPEN_EXISTING = 3
INVALID_HANDLE = ctypes.c_void_p(-1).value

kernel32 = ctypes.windll.kernel32


def read_locked(path, max_size=200 * 1024 * 1024):
    """read a file that may be locked, with all share flags"""
    h = kernel32.CreateFileW(path, GENERIC_READ, FILE_SHARE_ALL, None, OPEN_EXISTING,
                             0x80, None)  # FILE_ATTRIBUTE_NORMAL
    if h == INVALID_HANDLE:
        return None
    try:
        size = kernel32.GetFileSize(h, None)
        if size == 0xFFFFFFFF or size > max_size:
            return None
        buf = ctypes.create_string_buffer(size)
        read = wt.DWORD(0)
        ok = kernel32.ReadFile(h, buf, size, ctypes.byref(read), None)
        if not ok:
            return None
        return buf.raw[:read.value]
    finally:
        kernel32.CloseHandle(h)


def scan_file(path):
    try:
        data = read_locked(path)
        if data is None:
            return None
    except Exception:
        return None
    hits = []
    if '3.9.11.17'.encode('utf-16le') in data:
        hits.append('utf16 3.9.11.17')
    if b'3.9.11.17' in data:
        hits.append('ascii 3.9.11.17')
    if '4.1.13.65'.encode('utf-16le') in data:
        hits.append('utf16 4.1.13.65')
    if '3.9.5.81'.encode('utf-16le') in data:
        hits.append('utf16 3.9.5.81')
    return hits if hits else None


roots = [
    r'E:\weixin-hook-4.1.8\WeChat',
    os.path.expandvars(r'%APPDATA%\Tencent'),
    os.path.expandvars(r'%LOCALAPPDATA%\Tencent'),
    os.path.expanduser(r'~\Documents\WeChat Files'),
    os.path.expanduser(r'~\Documents\xwechat_files'),
    os.path.expanduser(r'~\AppData\Roaming\Tencent\WeChat'),
]

total = 0
skipped = 0
for root in roots:
    if not os.path.isdir(root):
        print('missing root:', root)
        continue
    for dp, dirs, files in os.walk(root):
        for fn in files:
            fp = os.path.join(dp, fn)
            try:
                sz = os.path.getsize(fp)
            except Exception:
                skipped += 1
                continue
            if sz > 200 * 1024 * 1024 or sz < 16:
                continue
            hits = scan_file(fp)
            total += 1
            if hits:
                print('HIT', hits, fp)
print('scanned:', total, 'skipped:', skipped)
