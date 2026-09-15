import ctypes, ctypes.wintypes as wt, struct, sys

pid = 22572
kernel32 = ctypes.windll.kernel32
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
if not h:
    print('OpenProcess failed', kernel32.GetLastError()); sys.exit(1)

class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', wt.DWORD), ('RegionSize', ctypes.c_size_t),
                ('State', wt.DWORD), ('Protect', wt.DWORD), ('Type', wt.DWORD)]

pat = '3.9.'.encode('utf-16le')
addr = 0
buf = ctypes.create_string_buffer(1 << 20)
found = []
maxaddr = 0x7FFFFFFFFFFF
while addr < maxaddr:
    mbi = MBI()
    q = kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
    if not q:
        break
    if mbi.State == 0x1000 and (mbi.Protect & 0x100) == 0 and mbi.Protect not in (0x01, 0x00) and mbi.RegionSize <= (64 << 20):
        off = 0
        while off < mbi.RegionSize:
            chunk = min(len(buf), mbi.RegionSize - off)
            read = ctypes.c_size_t(0)
            ok = kernel32.ReadProcessMemory(h, ctypes.c_void_p(mbi.BaseAddress + off) if mbi.BaseAddress else ctypes.c_void_p(off), buf, chunk, ctypes.byref(read))
            if ok and read.value >= len(pat):
                data = buf.raw[:read.value]
                i = 0
                while True:
                    j = data.find(pat, i)
                    if j < 0:
                        break
                    s = data[j:j+24].decode('utf-16le', errors='ignore').split('\x00')[0]
                    found.append((mbi.BaseAddress + off + j, s))
                    i = j + 2
            off += chunk
    addr = mbi.BaseAddress + mbi.RegionSize

kernel32.CloseHandle(h)
seen = {}
for a, s in found:
    seen.setdefault(s, []).append(a)
for s in sorted(seen):
    addrs = seen[s]
    print('%-14s x%d  e.g. %s' % (repr(s), len(addrs), hex(addrs[0])))
