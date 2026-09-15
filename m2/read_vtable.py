# -*- coding: utf-8 -*-
"""从活进程读取消息管理器 vtable (M2 关键步骤)"""
import ctypes
import ctypes.wintypes as wt
import struct
import sys

PID = 12048
VTABLE_VA = 0x7FF8929C6148
WX_BASE = 0x7FF889B60000
COUNT = 96

kernel32 = ctypes.windll.kernel32
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

h = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, PID)
if not h:
    print('OpenProcess failed', kernel32.GetLastError())
    sys.exit(1)

buf = ctypes.create_string_buffer(COUNT * 8)
read = ctypes.c_size_t(0)
ok = kernel32.ReadProcessMemory(h, ctypes.c_void_p(VTABLE_VA), buf, COUNT * 8, ctypes.byref(read))
if not ok:
    print('ReadProcessMemory failed', kernel32.GetLastError())
    sys.exit(1)

print('vtable @ 0x%X (Weixin.dll + 0x%X), %d entries read' % (VTABLE_VA, VTABLE_VA - WX_BASE, COUNT))
print()
for i in range(COUNT):
    entry = struct.unpack_from('<Q', buf.raw, i * 8)[0]
    rva = entry - WX_BASE if entry >= WX_BASE else None
    if rva is not None and rva < 0x10000000:
        print('[%02d] 0x%016X  rva=0x%X' % (i, entry, rva))
    else:
        print('[%02d] 0x%016X  (external)' % (i, entry))

kernel32.CloseHandle(h)
