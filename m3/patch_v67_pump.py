# -*- coding: utf-8 -*-
# v67: 注入被动武装泵钩子 (0x17F1F70 会话队列泵入口)
import io, sys
P = r'E:\weixin-hook-4.1.8\hook-wx\m3\src\wx_send_v65.c'
src = io.open(P, encoding='utf-8').read()
assert 'PUMP_RVA' not in src, 'already applied'

BS = chr(92)  # backslash
NL2 = BS + 'r' + BS + 'n'      # literal \r\n as in C source
NLN = BS + 'n'                 # literal \n   as in asm strings

old = '#define WAIT_RVA        0x7329A7CULL  // ' + '线程池等待函数 (worker 空闲必经)'
assert old in src
src = src.replace(old, old + '''
#define PUMP_RVA        0x17F1F70ULL  // 会话队列泵 (mgr=arg1, 调度器任务驱动)
#define STOLENP         17''', 1)

old = [l for l in src.splitlines() if 'g_waitTramp = 0;' in l][0]
asm_lines = NLN.join([
    '".text', '"\n'.join([]) or '',  # placeholder no-op
])
# 构造 asm 块: 每行 C 字符串以 "\n" 结尾
ins = ['".text' + NLN + '"',
       '".globl pump_stub' + NLN + '"',
       '"pump_stub:' + NLN + '"']
body = ['  mov %rcx, g_mgr2(%rip)', '  push %rcx', '  push %rdx', '  push %r8', '  push %r9',
        '  sub $0x28, %rsp', '  mov %r8, %rcx', '  mov %r9, %rdx', '  call C_pump',
        '  add $0x28, %rsp', '  pop %r9', '  pop %r8', '  pop %rdx', '  pop %rcx',
        '  mov g_pumpTramp(%rip), %rax', '  jmp *%rax']
for b in body:
    ins.append('"' + b + NLN + '"')
asm_block = '__asm__(\n' + '\n'.join(ins) + '\n);'

block = '''// ==== v67: 被动武装 —— 队列泵入口钩 (微信自身调度驱动, 无需用户消息) ====
volatile u64 g_pumpHits = 0;
unsigned char* g_pumpTramp = 0;
extern void pump_stub(void);
''' + asm_block + '''

void C_pump(void* p3, u64 flag) {
    (void)p3; (void)flag;
    u64 n = InterlockedIncrement((volatile LONG*)&g_pumpHits);
    {
        u64 tlsarr = 0, blk = 0;
        __asm__ volatile("movq %%gs:0x58, %0" : "=r"(tlsarr));
        u32 ti = *(u32*)((unsigned char*)g_base + TLS_INDEX_RVA);
        blk = *(u64*)(tlsarr + (u64)ti * 8);
        if (blk) {
            u64 spptr = *(u64*)(blk + TLS_CURCORO_OFF);
            if (spptr && !g_savedSPPtr) g_savedSPPtr = spptr;
            if (spptr) {
                u64 scoro = *(u64*)spptr;
                if (scoro && !g_sessExec) {
                    u64 sexec = *(u64*)(scoro + 0x368);
                    if (sexec) { g_sessExec = sexec; LogL("[PUMP] exec captured (passive)"); }
                }
            }
        }
    }
    if (n <= 3 || (n % 50) == 0) { LogHex("[PUMP] hit #", n); LogHex("[PUMP] mgr=", (u64)(ULONG_PTR)g_mgr2); }
}

static BOOL InstallPumpHook(void) {
    unsigned char* fn = (unsigned char*)g_base + PUMP_RVA;
    static const unsigned char exp[STOLENP] = {
        0x55,0x56,0x57,0x53, 0x48,0x81,0xEC,0xB8,0x00,0x00,0x00,
        0x48,0x8D,0x6C,0x24,0x80};
    unsigned char orig[STOLENP+3];
    for (int i = 0; i < STOLENP; i++) orig[i] = fn[i];
    for (int i = 0; i < STOLENP; i++) {
        if (orig[i] != exp[i]) { LogBytes("[PUMPHOOK] bytes: ", orig, STOLENP); return FALSE; }
    }
    g_pumpTramp = (unsigned char*)VirtualAlloc(NULL, 64, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_pumpTramp) return FALSE;
    for (int i = 0; i < STOLENP; i++) g_pumpTramp[i] = orig[i];
    g_pumpTramp[STOLENP] = 0xFF; g_pumpTramp[STOLENP+1] = 0x25;
    for (int i = 0; i < 4; i++) g_pumpTramp[STOLENP+2+i] = 0;
    u64 back = (u64)(fn + STOLENP);
    for (int i = 0; i < 8; i++) g_pumpTramp[STOLENP+6+i] = (unsigned char)(back >> (i*8));
    DWORD old;
    if (!VirtualProtect(fn, STOLENP, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    unsigned char pat[12];
    pat[0] = 0x48; pat[1] = 0xB8;
    u64 s = (u64)(ULONG_PTR)&pump_stub;
    for (int i = 0; i < 8; i++) pat[2+i] = (unsigned char)(s >> (i*8));
    pat[10] = 0xFF; pat[11] = 0xE0;
    for (int i = 0; i < 12; i++) fn[i] = pat[i];
    DWORD t2; VirtualProtect(fn, STOLENP, old, &t2);
    FlushInstructionCache(GetCurrentProcess(), fn, STOLENP);
    LogL("[PUMPHOOK] installed");
    return TRUE;
}

''' + old
src = src.replace(old, block, 1)

old = '    if (!InstallWaitHook()) LogL("[INIT] waithook failed (idle trigger off)");'
assert old in src
src = src.replace(old, old + '''
    if (!InstallPumpHook()) LogL("[INIT] pumphook failed (passive arming off)");''', 1)

old = 'aq=%ld' + NL2 + '", g_hits, g_rw, (g_qSH-g_qST+QCAP)%QCAP, (g_qAH-g_qAT+QCAP)%QCAP);'
assert old in src, 'status anchor'
src = src.replace(old, 'aq=%ld pump=%I64u exec=%I64u mgr=%I64u' + NL2 + '", g_hits, g_rw, (g_qSH-g_qST+QCAP)%QCAP, (g_qAH-g_qAT+QCAP)%QCAP, g_pumpHits, g_sessExec, g_mgr2);', 1)

io.open(P, 'w', encoding='utf-8').write(src)
print('v67 pump hook applied OK')
