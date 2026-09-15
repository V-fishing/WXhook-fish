# -*- coding: utf-8 -*-
# 把文件名字符串内容 (堆 0x27d90323f90) 补进 image_template.bin 的 +0x9A0
import ctypes, ctypes.wintypes as wt
k32 = ctypes.windll.kernel32
k32.ReadProcessMemory.argtypes = [wt.HANDLE, wt.LPCVOID, wt.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
h = k32.OpenProcess(0x410, False, 32624)
buf = (ctypes.c_ubyte*0x60)(); got = ctypes.c_size_t()
ok = k32.ReadProcessMemory(h, ctypes.c_void_p(0x27d90323f90), buf, 0x60, ctypes.byref(got))
k32.CloseHandle(h)
assert ok and got.value == 0x60, "read fail"
content = bytes(buf)
print("filename region:", content[:48])
p = r'E:\weixin-hook-4.1.8\hook-wx\m3\image_template.bin'
data = bytearray(open(p,'rb').read())
assert len(data) == 0xA00
data[0x9A0:0xA00] = content
open(p,'wb').write(bytes(data))
print("image_template.bin patched: tail now self-contained")
