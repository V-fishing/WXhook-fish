import struct
import re
import capstone

PATH = r'E:\weixin-hook-4.1.8\WeChat\[3.9.5.81]\WeChat.exe'
data = open(PATH, 'rb').read()

# --- parse PE ---
e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
assert data[e_lfanew:e_lfanew+4] == b'PE\x00\x00'
coff = e_lfanew + 4
num_sections = struct.unpack_from('<H', data, coff + 2)[0]
opt_size = struct.unpack_from('<H', data, coff + 16)[0]
opt_off = coff + 20
magic = struct.unpack_from('<H', data, opt_off)[0]
assert magic == 0x20b, hex(magic)
image_base = struct.unpack_from('<Q', data, opt_off + 24)[0]
print('image_base: 0x%X  sections: %d' % (image_base, num_sections))

secs = []
sec_off = opt_off + opt_size
for i in range(num_sections):
    o = sec_off + i * 40
    name = data[o:o+8].rstrip(b'\x00').decode()
    vsize, vaddr, rsize, rptr = struct.unpack_from('<IIII', data, o + 8)
    secs.append((name, vaddr, vsize, rptr, rsize))
    print('  %-10s VA=0x%X VS=0x%X raw=0x%X rs=0x%X' % (name, vaddr, vsize, rptr, rsize))

def off2va(off):
    for name, vaddr, vsize, rptr, rsize in secs:
        if rptr <= off < rptr + rsize:
            return image_base + vaddr + (off - rptr)
    return None

def va2off(va):
    rva = va - image_base
    for name, vaddr, vsize, rptr, rsize in secs:
        if vaddr <= rva < vaddr + max(vsize, rsize):
            return rptr + (rva - vaddr)
    return None

# --- target string ranges (file offsets in .rdata) ---
# dialog text near 0x2c8bc ("环境异常"), verify log near 0x2ca88 ("verifyDlls faild.")
ranges = []
for (lo, hi, label) in [(0x2c880, 0x2c980, 'dialog-text'), (0x2ca70, 0x2cab0, 'verify-log')]:
    va_lo = off2va(lo); va_hi = off2va(hi)
    ranges.append((va_lo, va_hi, label))
    print('%s: VA 0x%X - 0x%X' % (label, va_lo, va_hi))

# --- xref scan in .text ---
text = [s for s in secs if s[0] == '.text'][0]
tname, tvaddr, tvsize, trptr, trsize = text
print('scanning .text: file 0x%X - 0x%X' % (trptr, trptr + trsize))

xrefs = []
for i in range(trptr, trptr + trsize - 4):
    d = struct.unpack_from('<i', data, i)[0]
    # candidate: RIP-relative disp whose target = VA(i+4)+d
    insn_end_va = off2va(i + 4)
    if insn_end_va is None:
        continue
    tgt = insn_end_va + d
    for va_lo, va_hi, label in ranges:
        if va_lo <= tgt <= va_hi:
            xrefs.append((i, tgt, label, data[i-4:i+4].hex(' ')))

print('xref candidates:', len(xrefs))
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
seen = set()
for i, tgt, label, ctx in xrefs[:40]:
    # disassemble a small window ending at the disp to identify the instruction
    start = i - 4
    va = off2va(start)
    code = data[start:i+8]
    insns = list(md.disasm(code, va))
    line = '; '.join(('%s %s' % (x.mnemonic, x.op_str)) for x in insns[:3])
    key = (i, tgt)
    if key in seen:
        continue
    seen.add(key)
    print('  @file 0x%X -> text VA 0x%X [%s] bytes: %s | %s' % (i, off2va(i-3), label, ctx, line))
