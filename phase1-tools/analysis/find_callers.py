import struct
import capstone

PATH = r'E:\weixin-hook-4.1.8\WeChat\[3.9.5.81]\WeChat.exe'
data = open(PATH, 'rb').read()

e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
coff = e_lfanew + 4
num_sections = struct.unpack_from('<H', data, coff + 2)[0]
opt_size = struct.unpack_from('<H', data, coff + 16)[0]
opt_off = coff + 20
image_base = struct.unpack_from('<Q', data, opt_off + 24)[0]

secs = []
sec_off = opt_off + opt_size
for i in range(num_sections):
    o = sec_off + i * 40
    name = data[o:o+8].rstrip(b'\x00').decode()
    vsize, vaddr, rsize, rptr = struct.unpack_from('<IIII', data, o + 8)
    secs.append((name, vaddr, vsize, rptr, rsize))

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

text = [s for s in secs if s[0] == '.text'][0]
tname, tvaddr, tvsize, trptr, trsize = text

TARGETS = {
    0x140004DF0: 'dialog-fn',
    0x140004F00: 'verify-fn?',
}

print('=== call sites (E8 rel32) ===')
for i in range(trptr, trptr + trsize - 5):
    if data[i] != 0xE8:
        continue
    rel = struct.unpack_from('<i', data, i + 1)[0]
    va_i = off2va(i)
    tgt = va_i + 5 + rel
    for t, tname2 in TARGETS.items():
        if tgt == t:
            print('call at file 0x%X (VA 0x%X) -> %s' % (i, va_i, tname2))

print()
print('=== also try indirect (FF 15) — skip; print data refs to IAT-like slots ===')
# print code window around each call site found above (done separately)

# Let's dump the function that CONTAINS specific file offsets mentioned earlier:
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

def disasm(file_lo, file_hi, label):
    print('===== %s =====' % label)
    va = off2va(file_lo)
    for insn in md.disasm(data[file_lo:file_hi], va):
        print('%X: %s %s' % (insn.address, insn.mnemonic, insn.op_str))

# caller region: find who calls dialog-fn and what precedes it
