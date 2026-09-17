# -*- coding: utf-8 -*-
# 定位 0x389db0 返回地址所在函数的起始边界, 并用 objdump 反汇编
import pefile, subprocess, os

DLL = r'E:\weixin-hook-4.1.8\weixin-4.1.8\Weixin\4.1.13.65\Weixin.dll'
OUT = r'E:\weixin-hook-4.1.8\hook-wx\m4\sender_disasm.txt'
pe = pefile.PE(DLL, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.startswith(b'.text'))
data = text.get_data()
trva = 0x389db0
off = trva - text.VirtualAddress

# 向回找函数起始: 连续 >=6 字节 0xCC (int3 padding) 之后即是函数入口
start = off
i = off
while i > off - 0x8000:
    if data[i] == 0xCC and data[i-1] == 0xCC and data[i-2] == 0xCC and data[i-3] == 0xCC \
       and data[i-4] == 0xCC and data[i-5] == 0xCC:
        start = i + 1
        break
    i -= 1
else:
    start = off - 0x2000
fun_rva = text.VirtualAddress + start
print(f'ret@{trva:#x} -> function start ~{fun_rva:#x} (size ~{trva - fun_rva + 0x200:#x})')

# objdump 反汇编该函数区域 (VA)
va_s = base + fun_rva
va_e = base + trva + 0x400
r = subprocess.run([r'E:\weixin-hook-4.1.8\hook-wx\toolchain\mingw64\bin\objdump.exe',
                    '-d', '-M', 'intel',
                    '--start-address=' + hex(va_s), '--stop-address=' + hex(va_e), DLL],
                   capture_output=True, text=True, timeout=300)
out = r.stdout
# 只保留该范围
with open(OUT, 'w', encoding='utf-8') as f:
    f.write(out)
print('disasm lines:', out.count('\n'), '->', OUT)
# 打印 ret 附近
for line in out.splitlines():
    if 'call' in line and hex(base + trva)[2:] in line.replace('0x',''):
        print('CALLSITE:', line)
