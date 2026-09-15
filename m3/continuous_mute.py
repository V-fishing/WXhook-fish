# continuous_mute.py — continuously re-apply the TLS+0x360 log-mute to all WeChat threads
import ctypes, struct, time, sys
nt = ctypes.WinDLL('ntdll')
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
TH32CS_SNAPPROCESS = 0x2; TH32CS_SNAPTHREAD = 0x4; TH32CS_SNAPMODULE = 0x8
class PE32(ctypes.Structure):
    _fields_=[("dwSize",ctypes.c_ulong),("cntUsage",ctypes.c_ulong),("th32ProcessID",ctypes.c_ulong),
       ("th32DefaultHeapID",ctypes.c_size_t),("th32ModuleID",ctypes.c_ulong),("cntThreads",ctypes.c_ulong),
       ("th32ParentProcessID",ctypes.c_ulong),("pcPriClassBase",ctypes.c_long),("dwFlags",ctypes.c_ulong),
       ("szExeFile",ctypes.c_char*260)]
class TE32(ctypes.Structure):
    _fields_=[("dwSize",ctypes.c_ulong),("cntUsage",ctypes.c_ulong),("th32ThreadID",ctypes.c_ulong),
       ("th32OwnerProcessID",ctypes.c_ulong),("tpBasePri",ctypes.c_long),("tpDeltaPri",ctypes.c_long),("dwFlags",ctypes.c_ulong)]
class ME32(ctypes.Structure):
    _fields_=[("dwSize",ctypes.c_ulong),("th32ModuleID",ctypes.c_ulong),("th32ProcessID",ctypes.c_ulong),
       ("GlblcntUsage",ctypes.c_ulong),("ProccntUsage",ctypes.c_ulong),("modBaseAddr",ctypes.POINTER(ctypes.c_byte)),
       ("modBaseSize",ctypes.c_ulong),("hModule",ctypes.c_void_p),("szModule",ctypes.c_char*256),("szExePath",ctypes.c_char*260)]
class BB(ctypes.Structure):
    _fields_ = [("ExitStatus", ctypes.c_long),("TebBaseAddress", ctypes.c_void_p),
        ("ClientId", ctypes.c_ulong*2),("AffinityMask", ctypes.c_size_t),
        ("Priority", ctypes.c_long),("__p", ctypes.c_long),("BasePriority", ctypes.c_long)]
rpm_buf = ctypes.create_string_buffer(64)
def find_main():
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    pe = PE32(); pe.dwSize = ctypes.sizeof(pe)
    best = (0, 0)
    ok = k32.Process32First(snap, ctypes.byref(pe))
    while ok:
        if pe.szExeFile.decode('mbcs','replace').lower() == 'weixin.exe' and pe.cntThreads > best[1]:
            best = (pe.th32ProcessID, pe.cntThreads)
        ok = k32.Process32Next(snap, ctypes.byref(pe))
    k32.CloseHandle(snap)
    return best[0]
pid = 0
hProc = None
wxbase = 0
t0 = time.time()
DURATION = float(sys.argv[1]) if len(sys.argv) > 1 else 600.0
# wait for a logged-in WeChat
while time.time() - t0 < DURATION:
    p = find_main()
    if p:
        h = k32.OpenProcess(0x0410 | 0x0020, False, p)
        if h:
            snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, p)
            me = ME32(); me.dwSize = ctypes.sizeof(me)
            ok = k32.Module32First(snap, ctypes.byref(me))
            while ok:
                if me.szModule.decode('mbcs','replace').lower() == 'weixin.dll':
                    wxbase = ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value
                    break
                ok = k32.Module32Next(snap, ctypes.byref(me))
            k32.CloseHandle(snap)
            if wxbase:
                pid = p; hProc = h; break
            k32.CloseHandle(h)
        if h: k32.CloseHandle(h)
    time.sleep(1)
if not pid:
    print('no wechat'); sys.exit(1)
print(f'watching pid {pid} wxbase {wxbase:#x}', flush=True)
rpm_buf = ctypes.create_string_buffer(64)
def rpm(addr, n):
    got = ctypes.c_size_t()
    if not k32.ReadProcessMemory(hProc, ctypes.c_void_p(addr), rpm_buf, n, ctypes.byref(got)): return None
    return rpm_buf.raw[:got.value]
def wp(addr, data):
    return bool(k32.WriteProcessMemory(hProc, ctypes.c_void_p(addr), data, len(data), None))
tls_index_d = rpm(wxbase + 0xB5D6A70, 4)
tls_index = struct.unpack('<I', tls_index_d)[0] if tls_index_d else 12
rounds = 0
total = 0
while time.time() - t0 < DURATION:
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    te = TE32(); te.dwSize = ctypes.sizeof(te)
    tids = []
    ok = k32.Thread32First(snap, ctypes.byref(te))
    while ok:
        if te.th32OwnerProcessID == pid: tids.append(te.th32ThreadID)
        ok = k32.Thread32Next(snap, ctypes.byref(te))
    k32.CloseHandle(snap)
    muted = 0
    for tid in tids:
        h = k32.OpenThread(0x0040, False, tid)
        if not h: continue
        bb = BB()
        if nt.NtQueryInformationThread(ctypes.c_void_p(h), 0, ctypes.byref(bb), ctypes.sizeof(bb), None) != 0:
            k32.CloseHandle(h); continue
        teb = bb.TebBaseAddress
        d = rpm(teb + 0x58, 8) if teb else None
        tlsarr = struct.unpack('<Q', d)[0] if d and len(d) == 8 else 0
        d = rpm(tlsarr + tls_index*8, 8) if tlsarr else None
        blk = struct.unpack('<Q', d)[0] if d and len(d) == 8 else 0
        if blk:
            d = rpm(blk + 0x360, 4)
            if d and len(d) == 4:
                cur = struct.unpack('<I', d)[0]
                if not (cur & 1):
                    if wp(blk + 0x360, struct.pack('<I', cur | 1)): muted += 1
        k32.CloseHandle(h)
    rounds += 1
    total += muted
    if muted: print(f'round {rounds}: muted {muted} new threads', flush=True)
    time.sleep(0.4)
print(f'done: rounds={rounds} total-muted={total}')
