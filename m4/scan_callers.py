# -*- coding: utf-8 -*-
# 扫描 Weixin.dll .text 中对目标函数的直接调用 (E8 rel32) 和 rip 相对引用
import pefile, struct, sys

DLL = r'E:\weixin-hook-4.1.8\weixin-4.1.8\Weixin\4.1.13.65\Weixin.dll'
TARGETS = {
    'composer':  0x19D14C0,
    'sched':     0x45FF50,
    'cocreate':  0x45FCC0,
    'arg1ctor':  0x185E570,
    'tasksubmit': 0x35DFE0,
}

pe = pefile.PE(DLL, fast_load=True)
text = next(s for s in pe.sections if s.Name.startswith(b'.text'))
data = text.get_data()
text_rva = text.VirtualAddress
print(f'.text RVA={text_rva:#x} size={len(data):#x}')

for name, trva in TARGETS.items():
    hits = []
    n = len(data)
    i = 0
    while i < n - 5:
        if data[i] == 0xE8:   # call rel32
            disp = struct.unpack_from('<i', data, i + 1)[0]
            tgt = text_rva + i + 5 + disp
            if tgt == trva:
                hits.append(('call', text_rva + i))
        i += 1
    print(f'== {name} {trva:#x}: {len(hits)} direct callers ==')
    for kind, rva in hits[:20]:
        print(f'   {kind} @{rva:#x}')
