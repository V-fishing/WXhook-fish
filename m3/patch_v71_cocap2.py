# -*- coding: utf-8 -*-
# v71: CoCreate 捕获钩子迁址 fn+17 (避开 +10..16 诱雷窗), rax 直传 P5, 无栈计算
import io, re
P = r'E:\weixin-hook-4.1.8\hook-wx\m3\src\wx_send_v65.c'
src = io.open(P, encoding='utf-8').read()
assert 'COCAP2_RVA' not in src, 'already applied'
B = chr(92)
NLN = B + 'n'

# 1) 常量
old = '#define EXEC_VT_RVA     0x8D4CDE8ULL  // 会话 exec 对象 vtable (coro+0x368 处对象)'
assert old in src
src = src.replace(old, old + '''
#define COCAP2_RVA      0x45FCD1ULL   // CoCreate+0x11: 诱雷窗(+10..16)之外; 此处 rax=P5
#define COCAP2_STOLEN   15''', 1)

# 2) 新 stub + 新安装函数 (替换旧 InstallCoCapHook 调用点之前先加新函数)
anchor = 'static DWORD WINAPI CocapRetryThread(LPVOID p) {'
assert anchor in src
g = 'volatile u64 g_cocapRax = 0;   // asm 可见 (非 static)\nextern void cocreate_cap2_stub(void);\n__asm__(\n".text' + NLN + '"\n".globl cocreate_cap2_stub' + NLN + '"\n"cocreate_cap2_stub:' + NLN + '"'
body = ['  mov %rax, g_cocapRax(%rip)', '  push %rcx', '  push %rdx', '  push %r8', '  push %r9',
        '  mov %rax, %rcx', '  call C_cocap', '  mov g_cocapRax(%rip), %rax',
        '  mov g_cap2Tramp(%rip), %r10', '  jmp *%r10']
for b in body:
    g += '"' + b + NLN + '"\n'
g += ');\n\nunsigned char* g_cap2Tramp = 0;\n\n'
g += '''static BOOL InstallCoCapHook2(void) {
    unsigned char* fn = (unsigned char*)g_base + COCAP2_RVA;
    static const unsigned char exp[COCAP2_STOLEN] = {
        0x4C,0x89,0x4C,0x24,0x50, 0x4C,0x89,0x44,0x24,0x48, 0x48,0x89,0x54,0x24,0x40};
    unsigned char orig[COCAP2_STOLEN];
    for (int i = 0; i < COCAP2_STOLEN; i++) {
        orig[i] = fn[i];
        if (orig[i] != exp[i]) { LogBytes("[COCAP2] bytes: ", orig, COCAP2_STOLEN); return FALSE; }
    }
    g_cap2Tramp = (unsigned char*)VirtualAlloc(NULL, 64, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_cap2Tramp) return FALSE;
    for (int i = 0; i < COCAP2_STOLEN; i++) g_cap2Tramp[i] = orig[i];
    g_cap2Tramp[COCAP2_STOLEN] = 0xFF; g_cap2Tramp[COCAP2_STOLEN+1] = 0x25;
    for (int i = 0; i < 4; i++) g_cap2Tramp[COCAP2_STOLEN+2+i] = 0;
    u64 back = (u64)(ULONG_PTR)(fn + COCAP2_STOLEN);
    for (int i = 0; i < 8; i++) g_cap2Tramp[COCAP2_STOLEN+6+i] = (unsigned char)(back >> (i*8));
    DWORD old;
    if (!VirtualProtect(fn, COCAP2_STOLEN, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    unsigned char pat[12];
    pat[0] = 0x48; pat[1] = 0xB8;
    u64 s = (u64)(ULONG_PTR)&cocreate_cap2_stub;
    for (int i = 0; i < 8; i++) pat[2+i] = (unsigned char)(s >> (i*8));
    pat[10] = 0xFF; pat[11] = 0xE0;
    for (int i = 0; i < 12; i++) fn[i] = pat[i];
    DWORD t2; VirtualProtect(fn, COCAP2_STOLEN, old, &t2);
    FlushInstructionCache(GetCurrentProcess(), fn, COCAP2_STOLEN);
    LogL("[COCAP2] installed (fn+17, rax=P5)");
    return TRUE;
}

''' + anchor
src = src.replace(anchor, g, 1)

# 3) InitThread: 用 v2 替换旧 COCAPH (旧的不再装)
old = '''    if (!InstallCoCapHook()) {
        LogL("[INIT] cocap deferred -> retry thread (WeChat warmup transient)");
        HANDLE t2 = CreateThread(NULL, 0, CocapRetryThread, NULL, 0, NULL);
        if (t2) CloseHandle(t2);
    }'''
assert old in src
src = src.replace(old, '''    if (!InstallCoCapHook2()) LogL("[INIT] cocap2 failed");
    {   // v71: 旧 COCAPH 补丁若在 (残留会话), 不再安装; 全新进程 fn+0 永不补丁
    }''', 1)

io.open(P, 'w', encoding='utf-8').write(src)
print('v71 applied OK')
