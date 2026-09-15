# parse_dmp.py — parse WeChat minidump: exception, context, module mapping, stack walk
import struct, sys

path = sys.argv[1]
d = open(path, 'rb').read()
assert d[:4] == b'MDMP', d[:4]
version, nstreams, dirrva = struct.unpack_from('<III', d, 4)
print(f'MDMP v{version:#x} streams={nstreams}')

streams = {}
for i in range(nstreams):
    t, sz, rva = struct.unpack_from('<III', d, dirrva + i*12)
    streams.setdefault(t, []).append((sz, rva))

STREAM = {0:'Unused',3:'ThreadList',4:'ModuleList',5:'MemoryList',6:'Exception',
          7:'SystemInfo',9:'Memory64List',16:'ThreadNames',21:'SystemMemoryInfo',
          22:'ProcessVmCounters',0x47670003:'MiscInfo'}

for t, lst in sorted(streams.items()):
    name = STREAM.get(t, f'type{t}')
    print(f'  stream {name}: {len(lst)} x {lst[0][0]}B')

# ---- exception stream (type 6) ----
if 6 in streams:
    sz, rva = streams[6][0]
    buf = d[rva:rva+sz]
    tid, = struct.unpack_from('<I', buf, 0)
    code, flags = struct.unpack_from('<II', buf, 8)
    record, addr = struct.unpack_from('<QQ', buf, 16)
    nparams, = struct.unpack_from('<I', buf, 32)
    params = struct.unpack_from('<15Q', buf, 40)
    # ThreadContext: MINIDUMP_LOCATION_DESCRIPTOR at +8+152 = +160
    ctx_size, ctx_rva = struct.unpack_from('<II', buf, 160)
    print(f'exception: tid={tid} code={code:#x} flags={flags:#x} addr={addr:#x} nparams={nparams}')
    for i in range(min(nparams, 4)):
        print(f'  param[{i}] = {params[i]:#x}')
    # x64 CONTEXT: Rip at 0xF8
    ctx = d[ctx_rva:ctx_rva+ctx_size]
    rip = struct.unpack_from('<Q', ctx, 0xF8)[0]
    rsp = struct.unpack_from('<Q', ctx, 0x98)[0]
    rbp = struct.unpack_from('<Q', ctx, 0xA0)[0]
    rax = struct.unpack_from('<Q', ctx, 0x78)[0]
    rcx = struct.unpack_from('<Q', ctx, 0x80)[0]
    rdx = struct.unpack_from('<Q', ctx, 0x88)[0]
    r8  = struct.unpack_from('<Q', ctx, 0x98-0x20)[0]
    print(f'context: rip={rip:#x} rsp={rsp:#x} rbp={rbp:#x} rax={rax:#x} rcx={rcx:#x} rdx={rdx:#x}')

    # ---- module list (type 4) ----
    mods = []
    if 4 in streams:
        sz, rva = streams[4][0]
        nmod, = struct.unpack_from('<I', d, rva)
        off = rva + 4
        for i in range(nmod):
            base, msize, cksum, tstamp, namesz, name_rva = struct.unpack_from('<QIIIII', d, off)
            nstr = d[name_rva:name_rva+namesz*2].decode('utf-16-le', 'replace')
            nstr = nstr.rstrip('\0')
            mods.append((base, msize, nstr))
            off += 108  # MINIDUMP_MODULE size
        for base, msize, nstr in mods:
            if base <= addr < base + msize:
                print(f'  faulting module: {nstr} base={base:#x} -> RVA {addr-base:#x}')
            if base <= rip < base + msize:
                print(f'  RIP in module: {nstr} -> RVA {rip-base:#x}')

    # stack scan for Weixin return addresses
    WX = [m for m in mods if m[2].endswith('Weixin.dll')]
    if WX and 3 in streams:
        wbase, wsize, _ = WX[0][0], WX[0][1], WX[0][2]
        # thread list: find the crashing thread's stack
        if 3 in streams:
            sz, rva = streams[3][0]
            nthreads, = struct.unpack_from('<I', d, rva)
            toff = rva + 4
            TSZ = 48  # MINIDUMP_THREAD size x64
            for i in range(nthreads):
                o2 = toff + i*TSZ
                t_tid, = struct.unpack_from('<I', d, o2)
                if t_tid != tid: continue
                stack_start, = struct.unpack_from('<Q', d, o2+24)
                stack_size, stack_rva = struct.unpack_from('<II', d, o2+32)
                print(f'  thread {t_tid}: stack {stack_start:#x} size {stack_size:#x}')
                st = d[stack_rva:stack_rva+stack_size]
                rets = []
                for off2 in range(0, len(st)-8, 8):
                    v = struct.unpack_from('<Q', st, off2)[0]
                    if wbase <= v < wbase + 0x7400000:
                        rets.append((stack_start+off2, v - wbase))
                print(f'  weixin stack frames ({len(rets)}):')
                for sa, rva2 in rets[:30]:
                    print(f'    rsp {sa:#x}: Weixin+{rva2:#x}')
                break
print('DONE')
