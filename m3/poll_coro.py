# poll_coro.py — high-frequency poll of all threads' TLS+0x1F0 to catch live coroutines
import ctypes, struct, time, sys
pid = 2160
DURATION = float(sys.argv[1]) if len(sys.argv) > 1 else 40.0
nt = ctypes.WinDLL('ntdll')
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
hProc = k32.OpenProcess(0x0410, False, pid)
class BB(ctypes.Structure):
    _fields_ = [("ExitStatus", ctypes.c_long),("TebBaseAddress", ctypes.c_void_p),
        ("ClientId", ctypes.c_ulong*2),("AffinityMask", ctypes.c_size_t),
        ("Priority", ctypes.c_long),("__p", ctypes.c_long),("BasePriority", ctypes.c_long)]
rpm_buf = ctypes.create_string_buffer(64)
def rpm(addr, n):
    got = ctypes.c_size_t()
    if not k32.ReadProcessMemory(hProc, ctypes.c_void_p(addr), rpm_buf, n, ctypes.byref(got)): return None
    return rpm_buf.raw[:got.value]
def rq(addr):
    d = rpm(addr, 8)
    return struct.unpack('<Q', d)[0] if d and len(d) == 8 else 0
def r32(addr):
    d = rpm(addr, 4)
    return struct.unpack('<i', d)[0] if d and len(d) == 4 else -1
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

# pre-resolve per-thread TLS slot addresses (they don't change)
slots = {}
for tid in tids:
    h = k32.OpenThread(0x0040, False, tid)
    if not h: continue
    bb = BB()
    if nt.NtQueryInformationThread(ctypes.c_void_p(h), 0, ctypes.byref(bb), ctypes.sizeof(bb), None) != 0:
        k32.CloseHandle(h); continue
    teb = bb.TebBaseAddress
    tlsarr = rq(teb + 0x58) if teb else 0
    blk = rq(tlsarr + 12*8) if tlsarr else 0
    if blk: slots[tid] = blk + 0x1F0
    k32.CloseHandle(h)
print(f'polling {len(slots)} tls slots for {DURATION}s')

seen = {}
t0 = time.time()
reads = 0
while time.time() - t0 < DURATION:
    for tid, slot in slots.items():
        d = rpm(slot, 8)
        reads += 1
        if d and len(d) == 8:
            v = struct.unpack('<Q', d)[0]
            if v and v not in seen:
                seen[v] = (time.time() - t0, tid)
                # dump fields at first sighting
                coro = rq(v)
                ctrl = rq(v + 8)
                state = r32(coro + 0x388) if coro else -1
                exec_ = rq(coro + 0x368) if coro else 0
                i0 = rq(coro) if coro else 0
                i1 = rq(coro + 8) if coro else 0
                execvt = rq(exec_) if exec_ else 0
                print(f'T+{time.time()-t0:.2f}s tid {tid}: SP={v:#x} coro={coro:#x} ctrl={ctrl:#x} inner0={i0:#x} inner1={i1:#x} state={state} exec={exec_:#x} execvt={execvt:#x}', flush=True)
print(f'total reads {reads}, distinct coroutines {len(seen)}')
