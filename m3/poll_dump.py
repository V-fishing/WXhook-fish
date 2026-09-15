# poll_dump.py — catch a live coroutine and dump its full memory for offline analysis
import ctypes, struct, time, sys, os
pid = 2160
if len(sys.argv) > 1 and sys.argv[1].isdigit(): pid = int(sys.argv[1])
DURATION = float(sys.argv[2]) if len(sys.argv) > 2 else 60.0
OUT = r'E:\weixin-hook-4.1.8\hook-wx\m3\coro_dump'
os.makedirs(OUT, exist_ok=True)
nt = ctypes.WinDLL('ntdll')
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
hProc = k32.OpenProcess(0x0410, False, pid)
class BB(ctypes.Structure):
    _fields_ = [("ExitStatus", ctypes.c_long),("TebBaseAddress", ctypes.c_void_p),
        ("ClientId", ctypes.c_ulong*2),("AffinityMask", ctypes.c_size_t),
        ("Priority", ctypes.c_long),("__p", ctypes.c_long),("BasePriority", ctypes.c_long)]
rpm_buf = ctypes.create_string_buffer(0x600)
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
print(f'polling {len(slots)} slots for {DURATION}s, dumping first 3 live coroutines', flush=True)

saved = 0
seen = set()
t0 = time.time()
reads = 0
while time.time() - t0 < DURATION and saved < 3:
    for tid, slot in slots.items():
        d = rpm(slot, 16)
        reads += 1
        if d and len(d) == 16:
            coro, ctrl = struct.unpack('<QQ', d)
            if coro and coro not in seen:
                seen.add(coro)
                state = r32(coro + 0x388)
                print(f'T+{time.time()-t0:.2f}s tid {tid}: coro={coro:#x} ctrl={ctrl:#x} state={state} — dumping', flush=True)
                if saved < 3:
                    body = rpm(coro, 0x510)
                    cbody = rpm(ctrl, 0x20) if ctrl else None
                    if body:
                        open(os.path.join(OUT, f'coro_{saved}_state{state}.bin'),'wb').write(body)
                        if cbody: open(os.path.join(OUT, f'ctrl_{saved}.bin'),'wb').write(cbody)
                        exec_ = rq(coro + 0x368)
                        if exec_:
                            eb = rpm(exec_, 0x60)
                            if eb: open(os.path.join(OUT, f'exec_{saved}.bin'),'wb').write(eb)
                        saved += 1
print(f'reads {reads}, dumped {saved}')
