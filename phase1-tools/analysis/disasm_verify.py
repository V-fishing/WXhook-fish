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

def va2off(va):
    rva = va - image_base
    for name, vaddr, vsize, rptr, rsize in secs:
        if vaddr <= rva < vaddr + max(vsize, rsize):
            return rptr + (rva - vaddr)
    return None

def off2va(off):
    for name, vaddr, vsize, rptr, rsize in secs:
        if rptr <= off < rptr + rsize:
            return image_base + vaddr + (off - rptr)
    return None

# --- parse imports ---
# data directories: opt_off + 112 for import dir (PE32+)
imp_rva, imp_size = struct.unpack_from('<II', data, opt_off + 112)
imports = {}
off = va2off(image_base + imp_rva)
while True:
    ilt, ts, fc, nrva, fthunk = struct.unpack_from('<IIIII', data, off)
    if nrva == 0 and fthunk == 0 and ilt == 0:
        break
    # dll name
    dll_off = va2off(image_base + nrva)
    dll = data[dll_off:dll_off+64].split(b'\x00')[0].decode()
    thunk_rva = ilt or fthunk
    t_off = va2off(image_base + thunk_rva)
    iat_rva = fthunk
    idx = 0
    while True:
        entry = struct.unpack_from('<Q', data, t_off + idx * 8)[0]
        if entry == 0:
            break
        iat_va = image_base + iat_rva + idx * 8
        if entry & 0x8000000000000000:
            imports[iat_va] = '%s!ord_%d' % (dll, entry & 0xFFFF)
        else:
            fn_off = va2off(image_base + (entry & 0x7FFFFFFF))
            fname = data[fn_off+2:fn_off+64].split(b'\x00')[0].decode()
            imports[iat_va] = '%s!%s' % (dll, fname)
        idx += 1
    off += 20

print('imports parsed:', len(imports))

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

def disasm_range(file_lo, file_hi, label):
    print('===== %s (file 0x%X-0x%X) =====' % (label, file_lo, file_hi))
    va = off2va(file_lo)
    code = data[file_lo:file_hi]
    for insn in md.disasm(code, va):
        note = ''
        # resolve rip-relative memory operands (IAT calls)
        if 'rip' in insn.op_str:
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    target = insn.address + insn.size + op.mem.disp
                    if target in imports:
                        note = '   ; -> %s' % imports[target]
                    else:
                        off_t = va2off(target)
                        if off_t is not None:
                            # peek at string there
                            raw = data[off_t:off_t+80]
                            if raw[:2] not in (b'\x00\x00', b'MZ'):
                                try:
                                    s = raw.decode('utf-16le', errors='ignore').split('\x00')[0]
                                    a = raw.split(b'\x00')[0].decode('latin1')
                                    show = s if any(c > 0x7f for c in s) else a
                                    if show and len(show) >= 3:
                                        note = '   ; -> 0x%X "%s"' % (target, show[:60])
                                except Exception:
                                    pass
        print('  0x%X: %-28s %s%s' % (insn.address, '%s %s' % (insn.mnemonic, insn.op_str), '', note))

disasm_range(0x41E0, 0x43E0, 'verify-area-1')
disasm_range(0x4960, 0x4A80, 'verify-area-2')
disasm_range(0x5100, 0x5180, 'verify-area-3')
disasm_range(0x6540, 0x65E0, 'dialog-area')
