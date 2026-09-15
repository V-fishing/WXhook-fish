# enum_dlls.py — enumerate all manually-mapped PE images in target; find one containing stub
import ctypes, struct
pid = 37940
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
h = k32.OpenProcess(0x0410, False, pid)  # QUERY_INFO | VM_READ
assert h

class MINFO(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),("__a1", ctypes.c_ulong),
        ("RegionSize", ctypes.c_size_t),("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),("Type", ctypes.c_ulong)]

def read(addr, n):
    buf = ctypes.create_string_buffer(n); got = ctypes.c_size_t()
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)): return None
    return buf.raw[:got.value]

MEM_COMMIT = 0x1000
addr = 0; imgs = []
while addr < 0x7FFFFFFF0000:
    mi = MINFO(); mi.RegionSize = 0
    if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mi), ctypes.sizeof(mi)): break
    if mi.State == MEM_COMMIT and mi.Type == 0x20000 and int(mi.AllocationBase or 0) == int(mi.BaseAddress or 0):
        # region start == allocation base: candidate image
        d = read(addr, 0x200)
        if d and d[:2] == b'MZ':
            e_lfanew = struct.unpack_from('<I', d, 0x3C)[0] if len(d) > 0x40 else 0
            sig = d[e_lfanew:e_lfanew+4] if e_lfanew and e_lfanew+4 <= len(d) else b''
            if sig == b'PE\0\0':
                imgs.append(addr)
    addr = int(mi.BaseAddress or 0) + int(mi.RegionSize)

print(f"private images: {len(imgs)}")
STUB = 0x1CC53531540
for b in imgs:
    hdr = read(b, 0x400) or b''
    if len(hdr) < 0x200: continue
    e_lfanew = struct.unpack_from('<I', hdr, 0x3C)[0]
    nsec = struct.unpack_from('<S', hdr, e_lfanew+6)[0]
    opt_size = struct.unpack_from('<H', hdr, e_lfanew+0x14)[0]
    secoff = e_lfanew + 0x18 + opt_size
    size_of_img = struct.unpack_from('<I', hdr, e_lfanew+0x18+56)[0]
    secs = []
    for i in range(nsec):
        sh = read(b + secoff + i*40, 40) or b''
        name = sh[:8].rstrip(b'\0').decode('ascii','replace')
        vsize, vaddr, rsize = struct.unpack_from('<III', sh, 8)
        chars = struct.unpack_from('<I', sh, 36)[0]
        secs.append((name, b+vaddr, vsize, chars))
    hit = b <= STUB < b + size_of_img
    print(f"  base={b:#x} imgsize={size_of_img:#x} {'<== contains STUB' if hit else ''}")
    for name, va, vs, ch in secs:
        mark = ' <== STUB' if va <= STUB < va+vs else ''
        print(f"     {name:8s} va={va:#x} vs={vs:#x} wr={'Y' if ch & 0x80000000 else 'N'}{mark}")
