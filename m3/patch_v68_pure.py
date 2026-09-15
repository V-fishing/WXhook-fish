# -*- coding: utf-8 -*-
# v68: 纯自主三件套 — mgr 构造钩子 ×2 + CoCreate 参数验证捕获 + 模板磁盘存取
import io
P = r'E:\weixin-hook-4.1.8\hook-wx\m3\src\wx_send_v65.c'
src = io.open(P, encoding='utf-8').read()
assert 'MGRCTOR1_RVA' not in src, 'already applied'
BS = chr(92)
NLN = BS + 'n'

# ---- 1) 常量 ----
old = '#define STOLENP         19'
assert old in src
src = src.replace(old, old + '''
#define MGRCTOR1_RVA    0x1788920ULL  // mgr 类构造 A (写 vtable 0x8E66148)
#define MGRCTOR2_RVA    0x178B5B0ULL  // mgr 类构造 B (写 vtable + 初始化 +0xe00 子对象)
#define STOLENC         17
#define EXEC_VT_RVA     0x8D4CDE8ULL  // 会话 exec 对象 vtable (coro+0x368 处对象)
#define TEMPLATE_PATH   "E:" BS BS "weixin-hook-4.1.8" BS BS "hook-wx" BS BS "m3" BS BS "template.bin"''', 1)

# ---- 2) C_cocap (验证式 exec 捕获) + 两个 mgr 构造钩子, 插在 C_pump 定义之前 ----
anchor = 'void C_pump(void* p3, u64 flag) {'
assert anchor in src
pre = '''// ==== v68: CoCreate P5 验证捕获 (exec) ====
volatile u64 g_capOptsRaw2 = 0;
void C_cocap(void* p5) {
    if (!p5) return;
    u64 cand = *(u64*)((unsigned char*)p5 + 0x20);
    if (cand) {
        u64 vt = *(u64*)cand;
        if (vt == (u64)(ULONG_PTR)g_base + EXEC_VT_RVA) {
            g_capOptsRaw2 = (u64)(ULONG_PTR)p5;
            if (g_sessExec != cand) {
                g_sessExec = cand;
                LogL("[COCAP] exec captured (validated, passive)");
            }
        }
    }
}

// ==== v68: mgr 构造钩子 (登录瞬间被动捕获 mgr) ====
extern void mgrc1_stub(void);
extern void mgrc2_stub(void);
unsigned char* g_mgrc1Tramp = 0;
unsigned char* g_mgrc2Tramp = 0;

__asm__(
".text''' + NLN + '''"
".globl mgrc1_stub''' + NLN + '''"
"mgrc1_stub:''' + NLN + '''"
"  mov %rcx, g_mgr2(%rip)''' + NLN + '''"
"  push %rcx''' + NLN + '''"
"  push %rdx''' + NLN + '''"
"  push %r8''' + NLN + '''"
"  push %r9''' + NLN + '''"
"  sub $0x28, %rsp''' + NLN + '''"
"  xor %ecx, %ecx''' + NLN + '''"
"  xor %edx, %edx''' + NLN + '''"
"  call C_pump''' + NLN + '''"
"  add $0x28, %rsp''' + NLN + '''"
"  pop %r9''' + NLN + '''"
"  pop %r8''' + NLN + '''"
"  pop %rdx''' + NLN + '''"
"  pop %rcx''' + NLN + '''"
"  mov g_mgrc1Tramp(%rip), %rax''' + NLN + '''"
"  jmp *%rax''' + NLN + '''"
);

__asm__(
".text''' + NLN + '''"
".globl mgrc2_stub''' + NLN + '''"
"mgrc2_stub:''' + NLN + '''"
"  mov %rcx, g_mgr2(%rip)''' + NLN + '''"
"  push %rcx''' + NLN + '''"
"  push %rdx''' + NLN + '''"
"  push %r8''' + NLN + '''"
"  push %r9''' + NLN + '''"
"  sub $0x28, %rsp''' + NLN + '''"
"  xor %ecx, %ecx''' + NLN + '''"
"  xor %edx, %edx''' + NLN + '''"
"  call C_pump''' + NLN + '''"
"  add $0x28, %rsp''' + NLN + '''"
"  pop %r9''' + NLN + '''"
"  pop %r8''' + NLN + '''"
"  pop %rdx''' + NLN + '''"
"  pop %rcx''' + NLN + '''"
"  mov g_mgrc2Tramp(%rip), %rax''' + NLN + '''"
"  jmp *%rax''' + NLN + '''"
);

static BOOL InstallMgrCtorHook(unsigned rva, const unsigned char* exp, void* stub,
                               unsigned char** tramp, const char* tag) {
    unsigned char* fn = (unsigned char*)g_base + rva;
    unsigned char orig[STOLENC];
    for (int i = 0; i < STOLENC; i++) {
        orig[i] = fn[i];
        if (orig[i] != exp[i]) { LogBytes(tag, orig, STOLENC); return FALSE; }
    }
    *tramp = (unsigned char*)VirtualAlloc(NULL, 64, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!*tramp) return FALSE;
    for (int i = 0; i < STOLENC; i++) (*tramp)[i] = orig[i];
    (*tramp)[STOLENC] = 0xFF; (*tramp)[STOLENC+1] = 0x25;
    for (int i = 0; i < 4; i++) (*tramp)[STOLENC+2+i] = 0;
    u64 back = (u64)(ULONG_PTR)(fn + STOLENC);
    for (int i = 0; i < 8; i++) (*tramp)[STOLENC+6+i] = (unsigned char)(back >> (i*8));
    DWORD old;
    if (!VirtualProtect(fn, STOLENC, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    unsigned char pat[12];
    pat[0] = 0x48; pat[1] = 0xB8;
    u64 s = (u64)(ULONG_PTR)stub;
    for (int i = 0; i < 8; i++) pat[2+i] = (unsigned char)(s >> (i*8));
    pat[10] = 0xFF; pat[11] = 0xE0;
    for (int i = 0; i < 12; i++) fn[i] = pat[i];
    DWORD t2; VirtualProtect(fn, STOLENC, old, &t2);
    FlushInstructionCache(GetCurrentProcess(), fn, STOLENC);
    LogL(tag);
    LogL("[MGRCTOR] installed");
    return TRUE;
}

static BOOL InstallMgrCtors(void) {
    static const unsigned char e1[STOLENC] = {
        0x55,0x41,0x57,0x41,0x56,0x41,0x54,0x56,0x57,0x53,
        0x48,0x81,0xEC,0x90,0x02,0x00,0x00};
    static const unsigned char e2[STOLENC] = {
        0x56,0x57,0x53, 0x48,0x83,0xEC,0x20, 0x48,0x89,0xCE,
        0x48,0x8D,0x05,0x87,0xAB,0x6D,0x07};
    BOOL a = InstallMgrCtorHook(MGRCTOR1_RVA, e1, (void*)&mgrc1_stub, &g_mgrc1Tramp, "[MGRCTOR1]");
    BOOL b = InstallMgrCtorHook(MGRCTOR2_RVA, e2, (void*)&mgrc2_stub, &g_mgrc2Tramp, "[MGRCTOR2]");
    return a || b;
}

''' + anchor
src = src.replace(anchor, pre, 1)

# ---- 3) cocreate_cap_stub 改为调用 C_cocap ----
old = '''__asm__(
".text\\n"
".globl cocreate_cap_stub\\n"
"cocreate_cap_stub:\\n"
"  push %rax\\n"
"  mov 0x30(%rsp), %rax\\n"
"  mov %rax, g_capOptsRaw(%rip)\\n"
"  pop %rax\\n"
"  mov g_capTramp(%rip), %rax\\n"
"  jmp *%rax\\n"
);'''
# 上面字符串里的 \\n 实际是文件中的 \n 两字符; 用动态构造避免工具层转义问题
g = chr(92)+'n'   # 反斜杠+n 两个字符
old = '__asm__(\n".text' + g + '"\n".globl cocreate_cap_stub' + g + '"\n"cocreate_cap_stub:' + g + '"\n"  push %rax' + g + '"\n"  mov 0x30(%rsp), %rax' + g + '"\n"  mov %rax, g_capOptsRaw(%rip)' + g + '"\n"  pop %rax' + g + '"\n"  mov g_capTramp(%rip), %rax' + g + '"\n"  jmp *%rax' + g + '"\n);'
assert old in src, 'cocreate stub anchor'
newstub_lines = [
    '__asm__(',
    '".text' + g + '"',
    '".globl cocreate_cap_stub' + g + '"',
    '"cocreate_cap_stub:' + g + '"',
    '"  push %rcx' + g + '"',
    '"  push %rdx' + g + '"',
    '"  push %r8' + g + '"',
    '"  push %r9' + g + '"',
    '"  push %r10' + g + '"',
    '"  mov 0x50(%rsp), %rcx' + g + '"',
    '"  call C_cocap' + g + '"',
    '"  pop %r10' + g + '"',
    '"  pop %r9' + g + '"',
    '"  pop %r8' + g + '"',
    '"  pop %rdx' + g + '"',
    '"  pop %rcx' + g + '"',
    '"  mov g_capTramp(%rip), %rax' + g + '"',
    '"  jmp *%rax' + g + '"',
    ');',
]
src = src.replace(old, '\n'.join(newstub_lines), 1)

# ---- 4) InitThread: 构造钩子安装 + 模板磁盘加载 ----
old = '    if (!InstallPumpHook()) LogL("[INIT] pumphook failed (passive arming off)");'
assert old in src
src = src.replace(old, old + '''
    if (!InstallMgrCtors()) LogL("[INIT] mgrctor failed (passive mgr off)");
    {
        HANDLE f = CreateFileA(TEMPLATE_PATH, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            g_templateObj = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, 0x798);
            DWORD r = 0;
            ReadFile(f, g_templateObj, 0x798, &r, NULL);
            CloseHandle(f);
            LogL("[TPL] loaded from disk");
        }
    }''', 1)

# ---- 5) C_helper 模板捕获后存盘 ----
old = '''            if (g_templateObj) { memcpy(g_templateObj, obj, 0x798); LogL("[TPL] template obj saved"); }'''
assert old in src
new5 = '''            if (g_templateObj) {
                memcpy(g_templateObj, obj, 0x798); LogL("[TPL] template obj saved");
                HANDLE f = CreateFileA(TEMPLATE_PATH, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
                if (f != INVALID_HANDLE_VALUE) { DWORD w = 0; WriteFile(f, g_templateObj, 0x798, &w, NULL); CloseHandle(f); LogL("[TPL] saved to disk"); }
            }'''
src = src.replace(old, new5, 1)

io.open(P, 'w', encoding='utf-8').write(src)
print('v68 applied OK')
