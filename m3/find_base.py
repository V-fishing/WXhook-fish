# find_base.py — locate manually-mapped wx_send.dll base by walking down from known stub addr
import ctypes, struct, sys
pid = 37940
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
h = k32.OpenProcess(0x410, False, pid)
assert h

def read(addr, n):
    buf = ctypes.create_string_buffer(n); got = ctypes.c_size_t()
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)): return None
    return buf.raw[:got.value]

stub = 0x1CC53531540
base = None
page = stub & ~0xFFF
for i in range(1, 64):
    a = page - i*0x1000
    d = read(a, 2)
    if d == b'MZ':
        e = read(a + 0x3C, 4)
        if e:
            e_lfanew = struct.unpack('<I', e)[0]
            sig = read(a + e_lfanew, 4)
            if sig == b'PE\0\0':
                base = a; break
print(f"DLL base = {base:#x}" if base else "base not found")

if base:
    hdr = read(base, 0x400)
    nsec = struct.unpack_from('<S', hdr, base and e_lfanew+6)[0]
    secoff = e_lfanew + 0x18 + struct.unpack_from('<H', hdr, base and e_lfanew+0x14)[0]
    for i in range(nsec):
        sh = read(base + secoff + i*40, 40)
        name = sh[:8].rstrip(b'\0').decode('ascii','replace')
        vsize, vaddr = struct.unpack_from('<II', sh, 8)
        print(f"  sec {name:8s} va={base+vaddr:#x} size={vsize:#x}")
    # scan writable sections for u64 counters in [1,100000]
    for i in range(nsec):
        sh = read(base + secoff + i*40, 40)
        name = sh[:8].rstrip(b'\0').decode('ascii','replace')
        chars = struct.unpack_from('<I', sh, 36)[0]
        if not (chars & 0x80000000): continue  # not writable
        vsize, vaddr = struct.unpack_from('<II', sh, 8)
        blob = read(base+vaddr, min(vsize, 0x8000)) or b''
        hits = []
        for off in range(0, len(blob)-8, 8):
            v = struct.unpack_from('<Q', blob, off)[0]
            if 1 <= v <= 100000: hits.append((base+vaddr+off, v))
        print(f"  {name}: {len(hits)} counter candidates")
        for a,v in hits[:40]: print(f"    {a:#x} = {v}")
