# cntsnap.py — snapshot u64 counters in the stub allocation; diff mode identifies g_hits2/g_cntSync
# usage: python cntsnap.py snap  -> write candidates to cntsnap_a.txt
#        python cntsnap.py diff  -> compare with saved, print changed
import ctypes, struct, sys
pid = 37940
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
h = k32.OpenProcess(0x0410, False, pid)
STUB_ALLOC_LO, STUB_ALLOC_HI = 0x1CC53C20000, 0x1CC53C3F000

def read(addr, n):
    buf = ctypes.create_string_buffer(n); got = ctypes.c_size_t()
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)): return None
    return buf.raw[:got.value]

def snapshot():
    out = {}
    for page in range(STUB_ALLOC_LO, STUB_ALLOC_HI, 0x1000):
        blob = read(page, 0x1000)
        if not blob: continue
        for off in range(0, 0x1000-8, 8):
            v = struct.unpack_from('<Q', blob, off)[0]
            if 1 <= v <= 1000000: out[page+off] = v
    return out

mode = sys.argv[1] if len(sys.argv) > 1 else 'snap'
if mode == 'snap':
    s = snapshot()
    with open('cntsnap_a.txt','w') as f:
        for a,v in sorted(s.items()): f.write(f'{a:x} {v}\n')
    print(f'snapped {len(s)} candidates')
else:
    prev = {}
    with open('cntsnap_a.txt') as f:
        for line in f:
            a,v = line.split(); prev[int(a,16)] = int(v)
    cur = snapshot()
    chg = [(a, prev[a], cur.get(a)) for a in prev if cur.get(a) != prev[a]]
    # also new values that appeared
    newv = [(a, cur[a]) for a in cur if a not in prev and 1 <= cur[a] <= 100]
    print(f'changed: {len(chg)}')
    for a,ov,nv in chg[:60]: print(f'  {a:#x} {ov} -> {nv}')
    print(f'new in [1,100]: {len(newv)}')
    for a,v in newv[:20]: print(f'  {a:#x} = {v}')
