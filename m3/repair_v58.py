# repair_v58_asm.py — rebuild the hijack asm block with proper \n escapes
src = open('src/wx_send.c', encoding='utf-8').read()

# locate the broken block: from 'extern void hijack_stub(void);' through the closing ');' before HijackThread
start_marker = 'extern void hijack_stub(void);'
end_marker = '// 劫持注入线程'
si = src.find(start_marker)
ei = src.find(end_marker)
assert si >= 0 and ei > si, (si, ei)

good = '''extern void hijack_stub(void);
__asm__(
".text\\n"
".globl hijack_stub\\n"
"hijack_stub:\\n"
"  pushfq\\n"
"  push %rax\\n"
"  push %rcx\\n"
"  push %rdx\\n"
"  push %rbx\\n"
"  push %rbp\\n"
"  push %rsi\\n"
"  push %rdi\\n"
"  push %r8\\n"
"  push %r9\\n"
"  push %r10\\n"
"  push %r11\\n"
"  push %r12\\n"
"  push %r13\\n"
"  push %r14\\n"
"  push %r15\\n"
"  mov %rsp, %r15\\n"
"  and $-16, %rsp\\n"
"  sub $0x20, %rsp\\n"
"  xor %ecx, %ecx\\n"
"  call C_HijackFlush\\n"
"  mov %rsp, %r15\\n"
"  pop %r15\\n"
"  pop %r14\\n"
"  pop %r13\\n"
"  pop %r12\\n"
"  pop %r11\\n"
"  pop %r10\\n"
"  pop %r9\\n"
"  pop %r8\\n"
"  pop %rdi\\n"
"  pop %rsi\\n"
"  pop %rbp\\n"
"  pop %rbx\\n"
"  pop %rdx\\n"
"  pop %rcx\\n"
"  pop %rax\\n"
"  popfq\\n"
"  jmp *g_hijackRet(%rip)\\n"
);

'''
src = src[:si] + good + src[ei:]
open('src/wx_send.c', 'w', encoding='utf-8').write(src)
print('asm block rebuilt')
