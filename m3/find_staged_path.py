# -*- coding: utf-8 -*-
# 在活进程内存里找暂存图片的完整路径
import ctypes, ctypes.wintypes as wt, re
k32 = ctypes.windll.kernel32
k32.ReadProcessMemory.argtypes = [wt.HANDLE, wt.LPCVOID, wt.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
h = k32.OpenProcess(0x410, False, 32624)
class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD),("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD),("Protect", wt.DWORD),("Type", wt.DWORD)]
MEM_COMMIT=0x1000; PAGE_READABLE={0x02,0x04,0x20,0x40}
regions = []
addr = 0
while addr < 0x7ffffffeffff:
    mbi = MBI()
    r = ctypes.windll.kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
    if r == 0: break
    ba = mbi.BaseAddress or 0
    if mbi.State == MEM_COMMIT and mbi.Protect in PAGE_READABLE and mbi.RegionSize <= (1<<30):
        regions.append((ba, mbi.RegionSize))
    addr = ba + mbi.RegionSize
print(len(regions), "regions")
needle = b'ba84356d-9842-4597-87cb-3acb6f229fc4'
BS = chr(92)
hits = 0
for start, size in regions:
    CH = 1<<24; off = 0
    while off < size:
        n = min(CH, size-off)
        buf = (ctypes.c_ubyte*n)(); got = ctypes.c_size_t()
        ok = k32.ReadProcessMemory(h, ctypes.c_void_p(start+off), buf, n, ctypes.byref(got))
        if ok:
            data = bytes(buf[:got.value])
            for m in re.finditer(re.escape(needle), data):
                a = start+off+m.start()
                back = data[max(0,m.start()-300):m.start()].decode('latin1')
                idx = max(back.rfind(BS), back.rfind('/'))
                seg = back[idx+1:] if idx >= 0 else back[-60:]
                print(f"  hit {a:#x}: ...{seg[-80:]}")
                hits += 1
                if hits > 8: break
        off += n
        if hits > 8: break
    if hits > 8: break
print("done, hits:", hits)
k32.CloseHandle(h)
