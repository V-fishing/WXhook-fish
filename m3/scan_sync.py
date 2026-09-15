# scan_sync.py — locate & read g_cntSync (SyncStage hit counter) inside remote wx_send.dll instances
# usage: python scan_sync.py          -> list wx_send.dll modules + candidate counters
#        python scan_sync.py <addr>   -> read u64 at addr (hex)
import ctypes, ctypes.wintypes as wt, sys, struct

pid = 37940
k32 = ctypes.WinDLL('kernel32', use_last_error=True)

PROCESS_VM_READ = 0x10; PROCESS_QUERY_INFORMATION = 0x400
TH32CS_SNAPMODULE = 0x8; TH32CS_SNAPMODULE32 = 0x10

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD),("th32ModuleID", wt.DWORD),("th32ProcessID", wt.DWORD),
        ("GlblcntUsage", wt.DWORD),("ProccntUsage", wt.DWORD),("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wt.DWORD),("hModule", wt.HMODULE),("szModule", ctypes.c_char*256),
       ("szExePath", ctypes.c_char*260)]

def modules(pid):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
    if snap == ctypes.c_void_p(-1).value: return []
    me = MODULEENTRY32(); me.dwSize = ctypes.sizeof(me)
    out = []
    ok = k32.Module32First(snap, ctypes.byref(me))
    while ok:
        out.append((me.szModule.decode('mbcs','replace'), ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value, me.modBaseSize))
        ok = k32.Module32Next(snap, ctypes.byref(me))
    k32.CloseHandle(snap)
    return out

h = k32.OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION, False, pid)
assert h, ctypes.get_last_error()

def read(addr, n):
    buf = ctypes.create_string_buffer(n); got = ctypes.c_size_t()
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)): return None
    return buf.raw[:got.value]

if len(sys.argv) > 1:
    a = int(sys.argv[1], 16)
    d = read(a, 8)
    print(f"{a:#x} -> {struct.unpack('<Q', d)[0] if d else None}")
    sys.exit(0)

wxs = [(n,b,s) for (n,b,s) in modules(pid) if n.lower() == 'wx_send.dll']
print(f"wx_send.dll instances: {len(wxs)}")
for n,b,s in wxs:
    print(f"  base={b:#x} size={s:#x}")
    # parse PE: find .data section, scan for plausible counters
    hdr = read(b, 0x400)
    if not hdr: print("   <unreadable>"); continue
    e_lfanew = struct.unpack_from('<I', hdr, 0x3C)[0]
    opt = b + e_lfanew + 0x18
    nsec = struct.unpack_from('<S', hdr, e_lfanew+6)[0]
    secoff = e_lfanew + 0x18 + struct.unpack_from('<H', hdr, e_lfanew+0x14)[0]
    for i in range(nsec):
        sh = read(b + secoff + i*40, 40)
        name = sh[:8].rstrip(b'\0').decode('ascii','replace')
        vsize, vaddr, rsize = struct.unpack_from('<I', sh, 8)[0], struct.unpack_from('<I', sh, 12)[0], struct.unpack_from('<I', sh, 16)[0]
        if name not in ('.data','.rdata','.bss'): continue
        blob = read(b+vaddr, min(vsize or rsize, 0x20000))
        if not blob: continue
        cands = []
        for off in range(0, len(blob)-8, 8):
            v = struct.unpack_from('<Q', blob, off)[0]
            if 1 <= v <= 100000: cands.append((b+vaddr+off, v))
        # only print first 12 candidates per section to keep output sane
        for a,v in cands[:12]:
            print(f"    cand {a:#x} = {v}")
        if cands: print(f"    ... {name}: {len(cands)} candidates total")
k32.CloseHandle(h)
