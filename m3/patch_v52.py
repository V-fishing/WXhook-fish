# patch_v52.py - hook ucrtbase!abort to log the abort caller
src = open('src/wx_send.c', encoding='utf-8').read()

# 1. globals + stub + install (insert before g_hookBusy)
anchor = 'static volatile LONG g_hookBusy = 0;'
assert anchor in src
block = '''unsigned char* g_abortTramp = 0;

// v52: ucrtbase!abort 钩子 — 记录 fastfail 的调用者返回地址 (0xC0000409 无 dump, 只有这样能定位)
void __fastcall C_AbortLog(void* dummy, u64 retaddr);

extern void abort_stub(void);
__asm__(
".text\\n"
".globl abort_stub\\n"
"abort_stub:\\n"
"  mov (%rsp), %rax\\n"
"  push %rcx\\n"
"  push %rdx\\n"
"  push %r8\\n"
"  push %r9\\n"
"  sub $0x28, %rsp\\n"
"  mov %rax, %rdx\\n"
"  xor %ecx, %ecx\\n"
"  call C_AbortLog\\n"
"  add $0x28, %rsp\\n"
"  pop %r9\\n"
"  pop %r8\\n"
"  pop %rdx\\n"
"  pop %rcx\\n"
"  mov g_abortTramp(%rip), %rax\\n"
"  jmp *%rax\\n"
);

void __fastcall C_AbortLog(void* dummy, u64 retaddr) {
    (void)dummy;
    char buf[128];
    if (g_base && retaddr >= (u64)g_base && retaddr < (u64)g_base + 0x7400000) {
        wsprintfA(buf, "[ABORT] caller Weixin+0x%I64x", retaddr - (u64)g_base);
    } else {
        wsprintfA(buf, "[ABORT] caller abs 0x%I64x", retaddr);
    }
    LogL(buf);
}

static BOOL InstallAbortHook(void) {
    HMODULE h = GetModuleHandleW(L"ucrtbase.dll");
    if (!h) { LogL("[ABORTHOOK] no ucrtbase"); return FALSE; }
    void* pa = (void*)GetProcAddress(h, "abort");
    if (!pa) { LogL("[ABORTHOOK] no abort export"); return FALSE; }
    unsigned char* fn = (unsigned char*)pa;
    static const unsigned char exp[18] = {
        0x48,0x8B,0xC4, 0x48,0x83,0xEC,0x28, 0x4C,0x8D,0x48,0x08,
        0xC7,0x40,0x08,0x03,0x00,0x00,0x00};
    unsigned char orig[18];
    for (int i = 0; i < 18; i++) {
        orig[i] = fn[i];
        if (orig[i] != exp[i]) { LogBytes("[ABORTHOOK] actual bytes: ", orig, 18); return FALSE; }
    }
    g_abortTramp = (unsigned char*)VirtualAlloc(NULL, 64, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_abortTramp) return FALSE;
    for (int i = 0; i < 18; i++) g_abortTramp[i] = orig[i];
    g_abortTramp[18] = 0xFF; g_abortTramp[19] = 0x25;
    for (int i = 0; i < 4; i++) g_abortTramp[18+2+i] = 0;
    u64 back = (u64)(fn + 18);
    for (int i = 0; i < 8; i++) g_abortTramp[18+6+i] = (unsigned char)(back >> (i*8));
    DWORD old;
    if (!VirtualProtect(fn, 18, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    unsigned char pat[12];
    pat[0] = 0x48; pat[1] = 0xB8;
    u64 sv = (u64)(ULONG_PTR)&abort_stub;
    for (int i = 0; i < 8; i++) pat[2+i] = (unsigned char)(sv >> (i*8));
    pat[10] = 0xFF; pat[11] = 0xE0;
    for (int i = 0; i < 12; i++) fn[i] = pat[i];
    DWORD t2; VirtualProtect(fn, 18, old, &t2);
    FlushInstructionCache(GetCurrentProcess(), fn, 18);
    LogL("[ABORTHOOK] installed");
    return TRUE;
}

''' + anchor
src = src.replace(anchor, block, 1)

# 2. install in InitThread
old3 = '    if (!InstallThrowHook()) LogL("[INIT] throw hook failed");\n'
assert old3 in src
src = src.replace(old3, old3 + '    if (!InstallAbortHook()) LogL("[INIT] abort hook failed");\n', 1)

open('src/wx_send.c', 'w', encoding='utf-8').write(src)
print('v52 patched')
