# patch_v51.py - hook the throw helper to log throw sites
src = open('src/wx_send.c', encoding='utf-8').read()

# 1. defines
old = '#define STOLEN4      17'
assert old in src
src = src.replace(old, old + '\n#define THROW_RVA    0x72DD144ULL   // C++ throw 助手 (MSVC EH magic 0x19930520)\n#define STOLEN5      13', 1)

# 2. globals + stub + install (before C_coHook block)
old2 = 'static volatile LONG g_hookBusy = 0;'
assert old2 in src
src = src.replace(old2, '''unsigned char* g_throwTramp = 0;
static volatile LONG g_throwLogN = 0;

extern void throw_stub(void);
__asm__(
".text\\n"
".globl throw_stub\\n"
"throw_stub:\\n"
"  mov (%rsp), %rax\\n"
"  push %rcx\\n"
"  push %rdx\\n"
"  push %r8\\n"
"  push %r9\\n"
"  sub $0x28, %rsp\\n"
"  mov %rax, %rdx\\n"
"  xor %ecx, %ecx\\n"
"  call C_ThrowLog\\n"
"  add $0x28, %rsp\\n"
"  pop %r9\\n"
"  pop %r8\\n"
"  pop %rdx\\n"
"  pop %rcx\\n"
"  mov g_throwTramp(%rip), %rax\\n"
"  jmp *%rax\\n"
);

static void __fastcall C_ThrowLog(void* dummy, u64 retaddr) {
    (void)dummy;
    LONG n = InterlockedIncrement(&g_throwLogN);
    if (n <= 30 && g_base) {
        char buf[96];
        char* p = buf; const char* hx = "0123456789abcdef";
        const char* s = "[THROW] from rva 0x";
        for (int i = 0; s[i]; i++) p[i] = s[i]; p += 19;
        u64 v = retaddr - (u64)g_base;
        for (int i = 15; i >= 0; i--) *p++ = hx[(v >> (i*4)) & 0xF];
        *p = 0;
        LogL(buf);
    }
}

static BOOL InstallThrowHook(void) {
    unsigned char* fn = g_base + THROW_RVA;
    static const unsigned char exp[STOLEN5] = {
        0x48,0x89,0x5C,0x24,0x18, 0x48,0x89,0x74,0x24,0x20, 0x57,
        0x48,0x83,0xEC,0x50};
    unsigned char orig[STOLEN5];
    for (int i = 0; i < STOLEN5; i++) {
        orig[i] = fn[i];
        if (orig[i] != exp[i]) { LogBytes("[THROWHOOK] actual bytes: ", orig, STOLEN5); return FALSE; }
    }
    g_throwTramp = (unsigned char*)VirtualAlloc(NULL, 64, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_throwTramp) return FALSE;
    for (int i = 0; i < STOLEN5; i++) g_throwTramp[i] = orig[i];
    g_throwTramp[STOLEN5] = 0xFF; g_throwTramp[STOLEN5+1] = 0x25;
    for (int i = 0; i < 4; i++) g_throwTramp[STOLEN5+2+i] = 0;
    u64 back = (u64)(fn + STOLEN5);
    for (int i = 0; i < 8; i++) g_throwTramp[STOLEN5+6+i] = (unsigned char)(back >> (i*8));
    DWORD old;
    if (!VirtualProtect(fn, STOLEN5, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    unsigned char pat[12];
    pat[0] = 0x48; pat[1] = 0xB8;
    u64 sv = (u64)(ULONG_PTR)&throw_stub;
    for (int i = 0; i < 8; i++) pat[2+i] = (unsigned char)(sv >> (i*8));
    pat[10] = 0xFF; pat[11] = 0xE0;
    for (int i = 0; i < 12; i++) fn[i] = pat[i];
    DWORD t2; VirtualProtect(fn, STOLEN5, old, &t2);
    FlushInstructionCache(GetCurrentProcess(), fn, STOLEN5);
    LogL("[THROWHOOK] installed");
    return TRUE;
}

static volatile LONG g_hookBusy = 0;''' , 1)

# 3. install in InitThread
old3 = '    if (!InstallCoHook()) LogL("[INIT] co hook failed");\n'
assert old3 in src
src = src.replace(old3, old3 + '    if (!InstallThrowHook()) LogL("[INIT] throw hook failed");\n', 1)

open('src/wx_send.c', 'w', encoding='utf-8').write(src)
print('v51 patched')
