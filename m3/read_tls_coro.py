# read_tls_coro.py — read per-thread current-coroutine state from live WeChat
# TLS+0x1F0 = &shared_ptr{coro, ctrl}; coro+0x388 = state; coro+0x368 = exec_;
# exec_+0x00 = exec vtable; exec vtable[1] (+8) = submit fn
import ctypes, struct, sys

pid = int(sys.argv[1]) if len(sys.argv) > 1 else 0
if not pid:
    import ctypes.wintypes as wt
    # find largest Weixin process
    k32 = ctypes.WinDLL('kernel32', use_last_error=True)
    TH32CS_SNAPPROCESS = 0x2
    class PE32(ctypes.Structure):
        _fields_=[("dwSize",ctypes.c_ulong),("cntUsage",ctypes.c_ulong),("th32ProcessID",ctypes.c_ulong),
           ("cntHeap",ctypes.c_ulong),("th32ModuleID",ctypes.c_ulong),("cntThreads",ctypes.c_ulong),
           ("th32ParentProcessID",ctypes.c_ulong),("pcPriClassBase",ctypes.c_long),("dwFlags",ctypes.c_ulong),
           ("szExeFile",ctypes.c_char*260)]
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    pe = PE32(); pe.dwSize = ctypes.sizeof(pe)
    best = (0, 0)
    ok = k32.Process32First(snap, ctypes.byref(pe))
    while ok:
        if pe.szExeFile.decode('mbcs','replace').lower() == 'weixin.exe' and pe.cntThreads > best[1]:
            best = (pe.th32ProcessID, pe.cntThreads)
        ok = k32.Process32Next(snap, ctypes.byref(pe))
    pid = best[0]
print('pid', pid)

nt = ctypes.WinDLL('ntdll')
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
hProc = k32.OpenProcess(0x0410, False, pid)

class BB(ctypes.Structure):
    _fields_ = [("ExitStatus", ctypes.c_long),("TebBaseAddress", ctypes.c_void_p),
        ("ClientId", ctypes.c_ulong*2),("AffinityMask", ctypes.c_ulong),
        ("Priority", ctypes.c_long),("BasePriority", ctypes.c_long)]

rpm_buf = ctypes.create_string_buffer(64)
def rpm(addr, n):
    got = ctypes.c_size_t()
    if not k32.ReadProcessMemory(hProc, ctypes.c_void_p(addr), rpm_buf, min(n,64), ctypes.byref(got)): return None
    return rpm_buf.raw[:got.value]

def rq(addr):
    d = rpm(addr, 8)
    return struct.unpack('<Q', d)[0] if d and len(d) == 8 else 0

# Weixin.dll base + _tls_index via toolhelp
TH32CS_SNAPMODULE = 0x8
class ME32(ctypes.Structure):
    _fields_=[("dwSize",ctypes.c_ulong),("th32ModuleID",ctypes.c_ulong),("th32ProcessID",ctypes.c_ulong),
       ("GlblcntUsage",ctypes.c_ulong),("ProccntUsage",ctypes.c_ulong),("modBaseAddr",ctypes.POINTER(ctypes.c_byte)),
       ("modBaseSize",ctypes.c_ulong),("hModule",ctypes.c_void_p),("szModule",ctypes.c_char*256),("szExePath",ctypes.c_char*260)]
snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
me = ME32(); me.dwSize = ctypes.sizeof(me)
wxbase = 0
ok = k32.Module32First(snap, ctypes.byref(me))
while ok:
    if me.szModule.decode('mbcs','replace').lower() == 'weixin.dll':
        wxbase = ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value
        break
    ok = k32.Module32Next(snap, ctypes.byref(me))
k32.CloseHandle(snap)
print(f'Weixin base {wxbase:#x}')

tls_index_d = rpm(wxbase + 0xB5D6A70, 4)
tls_index = struct.unpack('<I', tls_index_d)[0] if tls_index_d else 12
print(f'_tls_index = {tls_index}')

TH32CS_SNAPTHREAD = 0x4
class TE32(ctypes.Structure):
    _fields_=[("dwSize",ctypes.c_ulong),("cntUsage",ctypes.c_ulong),("th32ThreadID",ctypes.c_ulong),
       ("th32OwnerProcessID",ctypes.c_ulong),("tpBasePri",ctypes.c_long),("tpDeltaPri",ctypes.c_long),("dwFlags",ctypes.c_ulong)]
snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
te = TE32(); te.dwSize = ctypes.sizeof(te)
tids = []
ok = k32.Thread32First(snap, ctypes.byref(te))
while ok:
    if te.th32OwnerProcessID == pid: tids.append(te.th32ThreadID)
    ok = k32.Thread32Next(snap, ctypes.byref(te))
k32.CloseHandle(snap)

results = []
for tid in tids:
    h = k32.OpenThread(0x0040|8, False, tid)   # QUERY_INFORMATION | GET_CONTEXT? just query
    if not h: continue
    bb = BB()
    nt.NtQueryInformationThread(ctypes.c_void_p(h), 0, ctypes.byref(bb), ctypes.sizeof(bb), None)
    teb = bb.TebBaseAddress
    if not teb:
        k32.CloseHandle(h); continue
    tlsarr = rq(teb + 0x58)
    if not tlsarr:
        k32.CloseHandle(h); continue
    blk = rq(tlsarr + tls_index*8)
    if not blk:
        k32.CloseHandle(h); continue
    spptr = rq(blk + 0x1F0)
    info = (tid, spptr)
    if spptr:
        coro = rq(spptr)
        ctrl = rq(spptr + 8)
        state = 0
        exec_ = 0
        execvt = 0
        submit = 0
        if coro:
            d = rpm(coro + 0x388, 4)
            state = struct.unpack('<i', d)[0] if d else -1
            exec_ = rq(coro + 0x368)
            if exec_:
                execvt = rq(exec_)
                if execvt:
                    s = rpm(execvt + 8, 8)
                    submit = struct.unpack('<Q', s)[0] if s else 0
        results.append((tid, spptr, coro, ctrl, state, exec_, execvt, submit))
    k32.CloseHandle(h)

for tid, spptr, coro, ctrl, state, exec_, execvt, submit in results:
    if spptr:
        print(f'tid {tid}: SP@{spptr:#x} coro={coro:#x} ctrl={ctrl:#x} state={state} exec={exec_:#x} execvt={execvt:#x} submit={submit - wxbase:#x}' if execvt else f'tid {tid}: SP@{spptr:#x} coro={coro:#x} ctrl={ctrl:#x} state={state} exec={exec_:#x}')
    else:
        print(f'tid {tid}: SP=NULL')
print(f'threads with SP: {len(results)}')
