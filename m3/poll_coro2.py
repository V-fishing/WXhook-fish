# poll_coro2.py — wait for WeChat, catch live coroutine, dump FULL 0x510 fields
import ctypes, struct, time, sys, os
DURATION = float(sys.argv[1]) if len(sys.argv) > 1 else 300.0
OUT = r'E:\weixin-hook-4.1.8\hook-wx\m3\coro_dump'
os.makedirs(OUT, exist_ok=True)
nt = ctypes.WinDLL('ntdll')
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
class BB(ctypes.Structure):
    _fields_ = [("ExitStatus", ctypes.c_long),("TebBaseAddress", ctypes.c_void_p),
        ("ClientId", ctypes.c_ulong*2),("AffinityMask", ctypes.c_size_t),
        ("Priority", ctypes.c_long),("__p", ctypes.c_long),("BasePriority", ctypes.c_long)]
buf = ctypes.create_string_buffer(0x600)
def openproc(pid): return k32.OpenProcess(0x0410, False, pid)
def rpm(h, addr, n):
    got = ctypes.c_size_t()
    b = ctypes.create_string_buffer(n)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), b, n, ctypes.byref(got)): return None
    return b.raw[:got.value]
def rq(h, addr):
    d = rpm(h, addr, 8)
    return struct.unpack('<Q', d)[0] if d and len(d) == 8 else 0
def r32(h, addr):
    d = rpm(h, addr, 4)
    return struct.unpack('<i', d)[0] if d and len(d) == 4 else -1
TH32CS_SNAPTHREAD = 0x4; TH32CS_SNAPPROCESS = 0x2; TH32CS_SNAPMODULE = 0x8
class PE32(ctypes.Structure):
    _fields_=[("dwSize",ctypes.c_ulong),("cntUsage",ctypes.c_ulong),("th32ProcessID",ctypes.c_ulong),
       ("cntHeap",ctypes.c_ulong),("th32ModuleID",ctypes.c_ulong),("cntThreads",ctypes.c_ulong),
       ("th32ParentProcessID",ctypes.c_ulong),("pcPriClassBase",ctypes.c_long),("dwFlags",ctypes.c_ulong),
       ("szExeFile",ctypes.c_char*260)]
class TE32(ctypes.Structure):
    _fields_=[("dwSize",ctypes.c_ulong),("cntUsage",ctypes.c_ulong),("th32ThreadID",ctypes.c_ulong),
       ("th32OwnerProcessID",ctypes.c_ulong),("tpBasePri",ctypes.c_long),("tpDeltaPri",ctypes.c_long),("dwFlags",ctypes.c_ulong)]
class ME32(ctypes.Structure):
    _fields_=[("dwSize",ctypes.c_ulong),("th32ModuleID",ctypes.c_ulong),("th32ProcessID",ctypes.c_ulong),
       ("GlblcntUsage",ctypes.c_ulong),("ProccntUsage",ctypes.c_ulong),("modBaseAddr",ctypes.POINTER(ctypes.c_byte)),
       ("modBaseSize",ctypes.c_ulong),("hModule",ctypes.c_void_p),("szModule",ctypes.c_char*256),("szExePath",ctypes.c_char*260)]

def find_main():
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    pe = PE32(); pe.dwSize = ctypes.sizeof(pe)
    cands = []
    ok = k32.Process32First(snap, ctypes.byref(pe))
    while ok:
        if pe.szExeFile.decode('mbcs','replace').lower() == 'weixin.exe':
            cands.append(pe.th32ProcessID)
        ok = k32.Process32Next(snap, ctypes.byref(pe))
    k32.CloseHandle(snap)
    # return the candidate that actually has Weixin.dll loaded (most threads preferred)
    cands.sort(key=lambda p: 0)
    for p in cands:
        h = openproc(p)
        if not h: continue
        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, p)
        me = ME32(); me.dwSize = ctypes.sizeof(me)
        found = False
        ok = k32.Module32First(snap, ctypes.byref(me))
        while ok:
            if me.szModule.decode('mbcs','replace').lower() == 'weixin.dll':
                found = True; break
            ok = k32.Module32Next(snap, ctypes.byref(me))
        k32.CloseHandle(snap)
        k32.CloseHandle(h)
        if found: return p
    return 0

pid = int(sys.argv[2]) if len(sys.argv) > 2 else 0
wxbase = 0
t0 = time.time()
while time.time() - t0 < DURATION and not pid:
    p = find_main()
    if p:
        hProc = openproc(p)
        if hProc:
            # verify Weixin.dll loaded by checking a module read works: find base
            snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, p)
            me = ME32(); me.dwSize = ctypes.sizeof(me)
            wxbase = 0
            ok = k32.Module32First(snap, ctypes.byref(me))
            while ok:
                if me.szModule.decode('mbcs','replace').lower() == 'weixin.dll':
                    wxbase = ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value
                    break
                ok = k32.Module32Next(snap, ctypes.byref(me))
            k32.CloseHandle(snap)
            if wxbase:
                pid = p; break
        if hProc: k32.CloseHandle(hProc)
    time.sleep(2)
if not pid:
    print('no wechat found'); sys.exit(1)
hProc = openproc(pid)
if not wxbase:
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
    me = ME32(); me.dwSize = ctypes.sizeof(me)
    ok = k32.Module32First(snap, ctypes.byref(me))
    while ok:
        if me.szModule.decode('mbcs','replace').lower() == 'weixin.dll':
            wxbase = ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value
            break
        ok = k32.Module32Next(snap, ctypes.byref(me))
    k32.CloseHandle(snap)
print(f'pid {pid} wxbase {wxbase:#x}', flush=True)

# enumerate threads + resolve TLS slots
snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
te = TE32(); te.dwSize = ctypes.sizeof(te)
tids = []
ok = k32.Thread32First(snap, ctypes.byref(te))
while ok:
    if te.th32OwnerProcessID == pid: tids.append(te.th32ThreadID)
    ok = k32.Thread32Next(snap, ctypes.byref(te))
k32.CloseHandle(snap)
tls_index_d = rpm(hProc, wxbase + 0xB5D6A70, 4)
tls_index = struct.unpack('<I', tls_index_d)[0] if tls_index_d else 12
slots = {}
for tid in tids:
    h = k32.OpenThread(0x0040, False, tid)
    if not h: continue
    bb = BB()
    if nt.NtQueryInformationThread(ctypes.c_void_p(h), 0, ctypes.byref(bb), ctypes.sizeof(bb), None) != 0:
        k32.CloseHandle(h); continue
    teb = bb.TebBaseAddress
    tlsarr = rq(h, teb + 0x58) if teb else 0
    blk = rq(h, tlsarr + tls_index*8) if tlsarr else 0
    if blk: slots[tid] = blk + 0x1F0
    k32.CloseHandle(h)
print(f'{len(slots)} tls slots, _tls_index={tls_index}', flush=True)

saved = 0
seen = set()
t1 = time.time()
reads = 0
while time.time() - t1 < DURATION and saved < 2:
    for tid, slot in slots.items():
        d = rpm(hProc, slot, 16)
        reads += 1
        if d and len(d) == 16:
            coro, ctrl = struct.unpack('<QQ', d)
            if coro and coro not in seen:
                seen.add(coro)
                state = r32(hProc, coro + 0x388)
                print(f'T+{time.time()-t1:.2f}s tid {tid}: coro={coro:#x} state={state} dumping', flush=True)
                if saved < 2:
                    body = rpm(hProc, coro, 0x510)
                    if body:
                        open(os.path.join(OUT, f'real_coro_{saved}_st{state}.bin'),'wb').write(body)
                        exec_ = struct.unpack_from('<Q', body, 0x368)[0]
                        eb = rpm(hProc, exec_, 0x60)
                        if eb: open(os.path.join(OUT, f'real_exec_{saved}.bin'),'wb').write(eb)
                        saved += 1
print(f'reads {reads}, dumped {saved}')
