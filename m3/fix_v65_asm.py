# fix_v65_asm.py — rebuild the cocreate_cap_stub asm block with proper \n escapes
src = open('src/wx_send.c', encoding='utf-8').read()

# Find and replace the broken cocreate_cap_stub __asm__ block
# The block starts with '__asm__(' before '.globl cocreate_cap_stub' 
# and ends with the closing ');' before 'static void __fastcall C_CoCapP5'
start_marker = '__asm__(\n".text'
end_marker = 'static void __fastcall C_CoCapP5'

# find the cocreate_cap_stub asm block (the second __asm__ containing cocreate_cap_stub)
# search from the first occurrence of 'cocreate_cap_stub' backwards for '__asm__'
idx = src.find('cocreate_cap_stub')
if idx < 0:
    print('cocreate_cap_stub not found')
    exit(1)

# find the '__asm__(' before this
asm_start = src.rfind('__asm__(', 0, idx)
if asm_start < 0:
    print('no __asm__ before cocreate_cap_stub')
    exit(1)

# find the closing ');' after the cocreate_cap_stub block
# look for the pattern '\n);' after the last string in the block
# the block ends with 'jmp *%rax\n"\n);' or similar
# find the C_CoCapP5 that follows
ccp5 = src.find('C_CoCapP5', idx)
if ccp5 < 0:
    print('no C_CoCapP5 after')
    exit(1)
# find the ');' before C_CoCapP5's function body
# actually, find the last ');' before 'static void __fastcall C_CoCapP5'
fn_start = src.find('static void __fastcall C_CoCapP5', idx)
if fn_start < 0:
    fn_start = src.find('void __fastcall C_CoCapP5', idx)
if fn_start < 0:
    print('no C_CoCapP5 function')
    exit(1)

# find the ');' that ends the __asm__ block (before the C_CoCapP5 function)
# search backwards from fn_start for ');'
close_pos = src.rfind('\n);', asm_start, fn_start)
if close_pos < 0:
    print('no closing ); found')
    exit(1)
close_pos += 1  # include the \n before );

# the old block = src[asm_start:close_pos]
old_block = src[asm_start:close_pos]
print(f'old block: {len(old_block)} chars, starts at {asm_start}')

# build the new block with proper \n escapes
lines = [
    '__asm__(',
    '".text\\n"',
    '".globl cocreate_cap_stub\\n"',
    '"cocreate_cap_stub:\\n"',
    '"  push %rax\\n"',
    '"  mov 0x30(%rsp), %rax\\n"',
    '"  mov %rax, g_capOpts(%rip)\\n"',
    '"  mov %rax, %rcx\\n"',
    '"  sub $0x28, %rsp\\n"',
    '"  xor %ecx, %ecx\\n"',
    '"  call C_CoCapP5\\n"',
    '"  add $0x28, %rsp\\n"',
    '"  pop %rcx\\n"',
    '"  mov g_cocreateTramp(%rip), %rax\\n"',
    '"  jmp *%rax\\n"',
    ');',
    '',
]
new_block = '\n'.join(lines) + '\n'

src = src[:asm_start] + new_block + src[close_pos+1:]
open('src/wx_send.c', 'w', encoding='utf-8').write(src)
print('asm block rebuilt with proper escapes')
