// ==== wx_boot.c: bootstrap —— 常驻层 (v98) ====
// 职责: 钩子安装与桩、全部持久状态、队列、管道服务 (含 RELOAD 热重载)
// 业务逻辑在 wx_payload.dll, 通过 WxApi 读写状态; 旧 payload 永不卸载
#include "wx_api.h"
#include <stdio.h>

static void LogL(const char* s);
static void LogHex(const char* label, u64 v);
static void LogBytes(const char* label, const unsigned char* b, int n);

// ==== 常量 (与 m3 单体一致, 实测值勿改) ====
#define UP1_RVA         0x1790970ULL
#define STOLEN          17
#define LOG_PATH        "E:\\weixin-hook-4.1.8\\hook-wx\\m2\\wx_send.log"
#define PIPE_NAME       "\\\\.\\pipe\\wxsend"
#define WAIT_RVA        0x7329A7CULL
#define PUMP_RVA        0x17F1F70ULL
#define STOLENP         19
#define MGRCTOR1_RVA    0x1788920ULL
#define MGRCTOR2_RVA    0x178B5B0ULL
#define STOLENC         17
#define EXEC_VT_RVA     0x8D4CDE8ULL
#define STOLEN3         18
#define POOL_WAIT_RET   0x73225D1ULL
#define POOL_WAIT_RET2  0x732D872ULL
#define LOGOFF_RVA      0xD9E810ULL
#define TLS_CURCORO_OFF 0x1F0
#define TLS_INDEX_RVA   0xB5D6A70
#define TPL_PATH        "E:\\weixin-hook-4.1.8\\hook-wx\\m4\\template.bin"
#define IMG_TPL_PATH    "E:\\weixin-hook-4.1.8\\hook-wx\\m4\\image_template.bin"
#define PAYLOAD_DIR     L"E:\\weixin-hook-4.1.8\\wxbot\\bin\\"
#define PAYLOAD_IN      L"E:\\weixin-hook-4.1.8\\wxbot\\bin\\wx_payload_incoming.dll"
#define TPL_SIZE        0x798

// ==== 状态 (全部 bootstrap 持有) ====
static unsigned char* g_base = 0;
static unsigned char* g_up1 = 0;
unsigned char* g_tramp = 0;
static unsigned char g_orig[STOLEN];
static volatile u64 g_hits = 0, g_rw = 0;
static volatile DWORD g_tid2 = 0;
static void* volatile g_mgr2 = 0;
static CRITICAL_SECTION g_cs;
static Cmd g_ringA[QCAP];
static volatile LONG g_qAH = 0, g_qAT = 0;
static Cmd g_ringS[QCAP];
static volatile LONG g_qSH = 0, g_qST = 0;
static volatile u64 g_savedSPPtr = 0;
static volatile u64 g_sessExec = 0;
static volatile u64 g_up1Tick = 0;
static volatile LONG g_busy2 = 0;
static volatile u64 g_stubRsp = 0;
static volatile u64 g_pumpHits = 0;
unsigned char* g_templateObj = 0;
unsigned char* g_imgTemplate = 0;
static unsigned char* g_tplBuf = 0;
static unsigned char* g_imgTplBuf = 0;
volatile u64 g_imgVtRva = 0;

// payload 代际
static WxApi* volatile g_curApi = 0;
static volatile LONG g_gen = -1;
static HMODULE g_payMods[8] = {0};
static WxApi* g_apis[8] = {0};

// VEH 取证: 代码段范围表 (boot + 各代 payload)
static struct { u64 lo, hi; } g_codeRanges[12];
static volatile LONG g_codeRangeN = 0;
static void AddCodeRange(u64 lo, u64 hi) {
    LONG i = InterlockedIncrement(&g_codeRangeN) - 1;
    if (i < 12) { g_codeRanges[i].lo = lo; g_codeRanges[i].hi = hi; }
}
static LONG WINAPI SanityVEH(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != 0xC0000005) return EXCEPTION_CONTINUE_SEARCH;
    u64 rip = ep->ContextRecord->Rip;
    for (int i = 0; i < 12; i++) {
        if (rip >= g_codeRanges[i].lo && rip < g_codeRanges[i].hi) {
            LogL("[VEH] access violation in our code");
            LogHex("  rip=", rip);
            LogHex("  fault-addr=", ep->ExceptionRecord->ExceptionInformation[1]);
            LogHex("  op(0=r,1=w,8=dep)=", ep->ExceptionRecord->ExceptionInformation[0]);
            LogHex("  rcx=", ep->ContextRecord->Rcx);
            LogHex("  rdx=", ep->ContextRecord->Rdx);
            break;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// ==== 日志 (bootstrap 服务, payload 经 api 调用) ====
static void LogL(const char* s) {
    HANDLE f = CreateFileA(LOG_PATH, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 128, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME t; GetLocalTime(&t);
    char ts[32]; int n = wsprintfA(ts, "[%02d:%02d:%02d] ", t.wHour, t.wMinute, t.wSecond);
    DWORD w; WriteFile(f, ts, n, &w, NULL);
    WriteFile(f, s, lstrlenA(s), &w, NULL);
    WriteFile(f, "\r\n", 2, &w, NULL);
    CloseHandle(f);
}
static void LogHex(const char* label, u64 v) {
    char buf[128]; char* p = buf; const char* hx = "0123456789abcdef";
    int n = lstrlenA(label); if (n > 80) n = 80;
    for (int i = 0; i < n; i++) p[i] = label[i]; p += n;
    *p++ = '0'; *p++ = 'x';
    for (int i = 15; i >= 0; i--) *p++ = hx[(v >> (i*4)) & 0xF];
    *p = 0; LogL(buf);
}
// 前置声明已在文件头, 此处直接定义
static void LogBytes(const char* label, const unsigned char* b, int n) {
    char buf[256]; char* p = buf; const char* hx = "0123456789abcdef";
    int k = lstrlenA(label); if (k > 100) k = 100;
    for (int i = 0; i < k; i++) p[i] = label[i]; p += k;
    for (int i = 0; i < n && p < buf + 240; i++) { *p++ = hx[b[i] >> 4]; *p++ = hx[b[i] & 0xF]; *p++ = ' '; }
    *p = 0; LogL(buf);
}

// ==== 队列 (bootstrap 持锁) ====
static BOOL QPushA(const Cmd* c) { BOOL ok=FALSE; EnterCriticalSection(&g_cs); LONG n=(g_qAH+1)%QCAP; if(n!=g_qAT){g_ringA[g_qAH]=*c;g_qAH=n;ok=TRUE;} LeaveCriticalSection(&g_cs); return ok; }
static BOOL QPopA(Cmd* o) { BOOL ok=FALSE; EnterCriticalSection(&g_cs); if(g_qAT!=g_qAH){*o=g_ringA[g_qAT];g_qAT=(g_qAT+1)%QCAP;ok=TRUE;} LeaveCriticalSection(&g_cs); return ok; }
static BOOL QPushS(const Cmd* c) { BOOL ok=FALSE; EnterCriticalSection(&g_cs); LONG n=(g_qSH+1)%QCAP; if(n!=g_qST){g_ringS[g_qSH]=*c;g_qSH=n;ok=TRUE;} LeaveCriticalSection(&g_cs); return ok; }
static BOOL QPopS(Cmd* o) { BOOL ok=FALSE; EnterCriticalSection(&g_cs); if(g_qST!=g_qSH){*o=g_ringS[g_qST];g_qST=(g_qST+1)%QCAP;ok=TRUE;} LeaveCriticalSection(&g_cs); return ok; }
static BOOL QEmptyA(void) { BOOL empty; EnterCriticalSection(&g_cs); empty = (g_qAH == g_qAT); LeaveCriticalSection(&g_cs); return empty; }

static int B64V(char c) {
    if (c>='A'&&c<='Z') return c-'A'; if (c>='a'&&c<='z') return c-'a'+26;
    if (c>='0'&&c<='9') return c-'0'+52; if (c=='+') return 62; if (c=='/') return 63; return -1;
}
static int B64D(const char* in, int n, char* out, int cap) {
    int o=0, acc=0, bits=0;
    for (int i=0;i<n;i++){int v=B64V(in[i]);if(v<0)continue;acc=(acc<<6)|v;bits+=6;
        if(bits>=8){bits-=8;if(o>=cap)return -1;out[o++]=(char)((acc>>bits)&0xFF);}}
    return o;
}

// ==== thunk: stub -> 当前 payload ====
void BootOnUp1(void* p3, u64 flag) {
    WxApi* a = g_curApi;
    if (a && a->onUp1) a->onUp1(a, p3, flag);
}
void BootOnIdle(void* dummy, u64 retaddr) {
    WxApi* a = g_curApi;
    if (a && a->onIdle) a->onIdle(a, retaddr);
    (void)dummy;
}

// ==== stubs (asm, 与 m3 一致) ====
extern void hook_stub(void);
__asm__(
".text\n"
".globl hook_stub\n"
"hook_stub:\n"
"  mov %rsp, g_stubRsp(%rip)\n"
"  mov %rcx, g_mgr2(%rip)\n"
"  push %rcx\n"
"  push %rdx\n"
"  push %r8\n"
"  push %r9\n"
"  sub $0x28, %rsp\n"
"  mov %r8, %rcx\n"
"  mov %r9, %rdx\n"
"  call BootOnUp1\n"
"  add $0x28, %rsp\n"
"  pop %r9\n"
"  pop %r8\n"
"  pop %rdx\n"
"  pop %rcx\n"
"  mov g_tramp(%rip), %rax\n"
"  jmp *%rax\n"
);

extern void wait_stub(void);
unsigned char* g_waitTramp = 0;
__asm__(
".text\n"
".globl wait_stub\n"
"wait_stub:\n"
"  mov (%rsp), %r11\n"
"  push %rcx\n"
"  push %rdx\n"
"  push %r8\n"
"  push %r9\n"
"  push %r10\n"
"  sub $0x30, %rsp\n"
"  xor %ecx, %ecx\n"
"  mov %r11, %rdx\n"
"  call BootOnIdle\n"
"  add $0x30, %rsp\n"
"  pop %r10\n"
"  pop %r9\n"
"  pop %r8\n"
"  pop %rdx\n"
"  pop %rcx\n"
"  mov g_waitTramp(%rip), %rax\n"
"  jmp *%rax\n"
);

extern void pump_stub(void);
unsigned char* g_pumpTramp = 0;
__asm__(
".text\n"
".globl pump_stub\n"
"pump_stub:\n"
"  mov %rcx, g_mgr2(%rip)\n"
"  push %rcx\n"
"  push %rdx\n"
"  push %r8\n"
"  push %r9\n"
"  sub $0x28, %rsp\n"
"  mov %r8, %rcx\n"
"  mov %r9, %rdx\n"
"  call C_pump\n"
"  add $0x28, %rsp\n"
"  pop %r9\n"
"  pop %r8\n"
"  pop %rdx\n"
"  pop %rcx\n"
"  mov g_pumpTramp(%rip), %rax\n"
"  jmp *%rax\n"
);

extern void mgrc1_stub(void);
extern void mgrc2_stub(void);
unsigned char* g_mgrc1Tramp = 0;
unsigned char* g_mgrc2Tramp = 0;
__asm__(
".text\n"
".globl mgrc1_stub\n"
"mgrc1_stub:\n"
"  mov %rcx, g_mgr2(%rip)\n"
"  push %rcx\n"
"  push %rdx\n"
"  push %r8\n"
"  push %r9\n"
"  sub $0x28, %rsp\n"
"  xor %ecx, %ecx\n"
"  xor %edx, %edx\n"
"  call C_pump\n"
"  add $0x28, %rsp\n"
"  pop %r9\n"
"  pop %r8\n"
"  pop %rdx\n"
"  pop %rcx\n"
"  mov g_mgrc1Tramp(%rip), %rax\n"
"  jmp *%rax\n"
);
__asm__(
".text\n"
".globl mgrc2_stub\n"
"mgrc2_stub:\n"
"  mov %rcx, g_mgr2(%rip)\n"
"  push %rcx\n"
"  push %rdx\n"
"  push %r8\n"
"  push %r9\n"
"  sub $0x28, %rsp\n"
"  xor %ecx, %ecx\n"
"  xor %edx, %edx\n"
"  call C_pump\n"
"  add $0x28, %rsp\n"
"  pop %r9\n"
"  pop %r8\n"
"  pop %rdx\n"
"  pop %rcx\n"
"  mov g_mgrc2Tramp(%rip), %rax\n"
"  jmp *%rax\n"
);


// ==== 泵处理 (武装: TLS SES 捕获) —— 常驻 bootstrap ====
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

// ==== 钩子安装器 (字节表 = m3 实测值) ====
static BOOL InstallHook(void) {
    g_up1 = (unsigned char*)g_base + UP1_RVA;
    for (int i = 0; i < STOLEN; i++) g_orig[i] = g_up1[i];
    static const unsigned char exp[STOLEN] = {
        0x55,0x41,0x57,0x41,0x56,0x56,0x57,0x53,0x48,0x83,0xEC,0x78,0x48,0x8D,0x6C,0x24,0x70};
    for (int i = 0; i < STOLEN; i++) { if (g_orig[i] != exp[i]) { LogBytes("[HOOK] bytes: ", g_orig, STOLEN); return FALSE; } }
    g_tramp = (unsigned char*)VirtualAlloc(NULL, 64, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_tramp) return FALSE;
    for (int i = 0; i < STOLEN; i++) g_tramp[i] = g_orig[i];
    g_tramp[STOLEN] = 0xFF; g_tramp[STOLEN+1] = 0x25;
    for (int i = 0; i < 4; i++) g_tramp[STOLEN+2+i] = 0;
    u64 back = (u64)(g_up1 + STOLEN);
    for (int i = 0; i < 8; i++) g_tramp[STOLEN+6+i] = (unsigned char)(back >> (i*8));
    DWORD old;
    if (!VirtualProtect(g_up1, STOLEN, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    unsigned char pat[12];
    pat[0] = 0x48; pat[1] = 0xB8;
    u64 sv = (u64)(ULONG_PTR)&hook_stub;
    for (int i = 0; i < 8; i++) pat[2+i] = (unsigned char)(sv >> (i*8));
    pat[10] = 0xFF; pat[11] = 0xE0;
    for (int i = 0; i < 12; i++) g_up1[i] = pat[i];
    DWORD t2; VirtualProtect(g_up1, STOLEN, old, &t2);
    FlushInstructionCache(GetCurrentProcess(), g_up1, STOLEN);
    return TRUE;
}

static BOOL InstallLogOff2(void) {
    unsigned char* fn = (unsigned char*)g_base + LOGOFF_RVA;
    DWORD old;
    if (!VirtualProtect(fn, 3, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    unsigned char pat[3] = {0x31, 0xC0, 0xC3};
    for (int i = 0; i < 3; i++) fn[i] = pat[i];
    DWORD t2; VirtualProtect(fn, 3, old, &t2);
    FlushInstructionCache(GetCurrentProcess(), fn, 3);
    LogL("[LOGOFF2] installed");
    return TRUE;
}

static BOOL InstallWaitHook(void) {
    unsigned char* fn = (unsigned char*)g_base + WAIT_RVA;
    static const unsigned char exp[STOLEN3] = {
        0x48,0x89,0x7C,0x24,0x10, 0x41,0xBA,0x40,0x80,0x00,0x00,
        0x33,0xD2, 0x0F,0xAE,0x5C,0x24,0x08};
    unsigned char orig[STOLEN3];
    for (int i = 0; i < STOLEN3; i++) {
        orig[i] = fn[i];
        if (orig[i] != exp[i]) { LogBytes("[WAITHOOK] bytes: ", orig, STOLEN3); return FALSE; }
    }
    g_waitTramp = (unsigned char*)VirtualAlloc(NULL, 64, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_waitTramp) return FALSE;
    for (int i = 0; i < STOLEN3; i++) g_waitTramp[i] = orig[i];
    g_waitTramp[STOLEN3] = 0xFF; g_waitTramp[STOLEN3+1] = 0x25;
    for (int i = 0; i < 4; i++) g_waitTramp[STOLEN3+2+i] = 0;
    u64 back = (u64)(fn + STOLEN3);
    for (int i = 0; i < 8; i++) g_waitTramp[STOLEN3+6+i] = (unsigned char)(back >> (i*8));
    DWORD old;
    if (!VirtualProtect(fn, STOLEN3, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    unsigned char pat[12];
    pat[0] = 0x48; pat[1] = 0xB8;
    u64 s = (u64)(ULONG_PTR)&wait_stub;
    for (int i = 0; i < 8; i++) pat[2+i] = (unsigned char)(s >> (i*8));
    pat[10] = 0xFF; pat[11] = 0xE0;
    for (int i = 0; i < 12; i++) fn[i] = pat[i];
    DWORD t2; VirtualProtect(fn, STOLEN3, old, &t2);
    FlushInstructionCache(GetCurrentProcess(), fn, STOLEN3);
    LogL("[WAITHOOK] installed");
    return TRUE;
}

static BOOL InstallPumpHook(void) {
    unsigned char* fn = (unsigned char*)g_base + PUMP_RVA;
    static const unsigned char exp[STOLENP] = {
        0x55,0x56,0x57,0x53, 0x48,0x81,0xEC,0xB8,0x00,0x00,0x00,
        0x48,0x8B,0x41,0x10, 0x48,0x8B,0x71,0x08};
    unsigned char orig[STOLENP];
    for (int i = 0; i < STOLENP; i++) {
        orig[i] = fn[i];
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

// ==== payload 加载 / 热重载 ====
typedef BOOL (*PayloadMainFn)(WxApi* api);
static WxApi* MakeApi(DWORD gen) {
    WxApi* a = (WxApi*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WxApi));
    if (!a) return 0;
    a->gen = gen;
    a->stopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    a->Log = LogL; a->LogHex = LogHex; a->LogBytes = LogBytes;
    a->ppBase = &g_base;
    a->pSessExec = &g_sessExec;
    a->ppMgr2 = &g_mgr2;
    a->pSavedSPPtr = &g_savedSPPtr;
    a->ppTemplateObj = &g_templateObj;
    a->ppImgTemplate = &g_imgTemplate;
    a->pImgVtRva = &g_imgVtRva;
    a->pUp1Tick = &g_up1Tick;
    a->pTid2 = &g_tid2;
    a->pHits = &g_hits;
    a->pRw = &g_rw;
    a->pBusy2 = &g_busy2;
    a->pStubRsp = &g_stubRsp;
    a->pTplBuf = g_tplBuf;
    a->pImgTplBuf = g_imgTplBuf;
    a->QPushA = QPushA; a->QPopA = QPopA; a->QPopS = QPopS; a->QPushS = QPushS; a->QEmptyA = QEmptyA;
    return a;
}
static BOOL LoadPayloadGen(DWORD gen, BOOL forceFresh) {
    wchar_t path[512];
    wsprintfW(path, L"%swx_payload_g%u.dll", PAYLOAD_DIR, gen);
    if (gen == 0 || forceFresh) {
        wchar_t src0[512];
        wsprintfW(src0, L"%swx_payload.dll", PAYLOAD_DIR);
        if (!CopyFileW(src0, path, FALSE)) { LogL("[RELOAD] copy base payload fail"); return FALSE; }
    } else if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
        // 该代文件不存在: 从基础 payload 拷贝 (首次部署)
        wchar_t src[512];
        wsprintfW(src, L"%swx_payload.dll", PAYLOAD_DIR);
        if (!CopyFileW(src, path, FALSE)) { LogL("[RELOAD] no base payload file"); return FALSE; }
    }
    HMODULE h = LoadLibraryW(path);
    if (!h) { LogL("[RELOAD] LoadLibraryW fail"); return FALSE; }
    PayloadMainFn pfn = (PayloadMainFn)(void*)GetProcAddress(h, "WxPayloadMain");
    if (!pfn) { LogL("[RELOAD] no WxPayloadMain export"); return FALSE; }
    WxApi* a = MakeApi(gen);
    if (!a) return FALSE;
    if (!pfn(a)) { LogL("[RELOAD] payload init failed"); return FALSE; }
    // 注册代码段范围 (VEH 取证)
    {   IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)h;
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((u64)(ULONG_PTR)h + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE)
                AddCodeRange((u64)(ULONG_PTR)h, (u64)(ULONG_PTR)h + nt->OptionalHeader.SizeOfImage);
        }
    }
    int slot = gen % 8;
    g_payMods[slot] = h; g_apis[slot] = a;
    InterlockedExchangePointer((volatile PVOID*)&g_curApi, a);   // 原子换表
    char buf[64]; wsprintfA(buf, "[RELOAD] payload gen %u active", gen);
    LogL(buf);
    return TRUE;
}
static void DoReload(char* resp, int respCap) {
    LONG gen = InterlockedIncrement(&g_gen);
    // 1) 通知旧 payload 线程停止 (代码不卸载, 在途调用安全)
    WxApi* old = g_curApi;
    if (old && old->stopEvent) SetEvent(old->stopEvent);
    // 2) 非强制路径: 优先 incoming 热替换, 否则沿用已有代文件
    if (!LoadPayloadGen((DWORD)gen, FALSE)) {
        lstrcpynA(resp, "ERR load fail\r\n", respCap);
        InterlockedDecrement(&g_gen);
        return;
    }
    wsprintfA(resp, "OK reload gen=%ld\r\n", gen);
}

// ==== 管道服务 ====
static void HandleClient(HANDLE pipe) {
    char req[4352]; DWORD got = 0;
    int pos = 0; char ch;
    while (pos < (int)sizeof(req) - 1) {
        if (!ReadFile(pipe, &ch, 1, &got, NULL) || got == 0) break;
        if (ch == '\n') break;
        req[pos++] = ch;
    }
    req[pos] = 0;
    char resp[160] = "ERR\n";
    if (pos >= 6 && req[0]=='A' && req[1]=='U' && req[2]=='T' && req[3]=='O' && req[4]=='|') {
        char* p2 = req + 5;
        char* sep = p2; while (*sep && *sep != '|') sep++;
        if (*sep == '|') {
            *sep = 0;
            char* b64 = sep + 1;
            Cmd cmd; cmd.targetLen = 0; cmd.flags = 2;
            for (char* s = p2; *s && cmd.targetLen < (int)sizeof(cmd.target)-1; s++) cmd.target[cmd.targetLen++] = *s;
            cmd.target[cmd.targetLen] = 0;
            cmd.contentLen = B64D(b64, lstrlenA(b64), cmd.content, (int)sizeof(cmd.content)-1);
            if (cmd.contentLen >= 0) { cmd.content[cmd.contentLen] = 0; if (QPushA(&cmd)) lstrcpyA(resp, "OK auto\n"); else lstrcpyA(resp, "ERR full\n"); }
            else lstrcpyA(resp, "ERR b64\n");
        }
    } else if (pos >= 6 && req[0]=='S' && req[1]=='E' && req[2]=='N' && req[3]=='D' && (req[4]=='|' || req[4]=='2')) {
        char* p2 = req + (req[4] == '2' ? 6 : 5);
        char* sep = p2; while (*sep && *sep != '|') sep++;
        if (*sep == '|') {
            *sep = 0;
            char* b64 = sep + 1;
            Cmd cmd; cmd.targetLen = 0; cmd.flags = (req[4] == '2') ? 1 : 0;
            for (char* s = p2; *s && cmd.targetLen < (int)sizeof(cmd.target)-1; s++) cmd.target[cmd.targetLen++] = *s;
            cmd.target[cmd.targetLen] = 0;
            cmd.contentLen = B64D(b64, lstrlenA(b64), cmd.content, (int)sizeof(cmd.content)-1);
            if (cmd.contentLen >= 0) { cmd.content[cmd.contentLen] = 0; if (QPushS(&cmd)) lstrcpyA(resp, "OK\n"); else lstrcpyA(resp, "ERR full\n"); }
            else lstrcpyA(resp, "ERR b64\n");
        }
    } else if (pos >= 6 && req[0]=='A' && req[1]=='I' && req[2]=='M' && req[3]=='G' && req[4]=='|') {
        char* p2 = req + 5;
        char* sep = p2; while (*sep && *sep != '|') sep++;
        Cmd cmd; cmd.targetLen = 0; cmd.flags = 4; cmd.contentLen = -1;
        char* b64p = 0;
        if (*sep == '|') {
            *sep = 0;
            b64p = sep + 1;
            for (char* s = p2; *s && cmd.targetLen < (int)sizeof(cmd.target)-1; s++) cmd.target[cmd.targetLen++] = *s;
        }
        cmd.target[cmd.targetLen] = 0;
        if (b64p) {
            cmd.contentLen = B64D(b64p, lstrlenA(b64p), cmd.content, (int)sizeof(cmd.content) - 1);
            if (cmd.contentLen < 0) { lstrcpyA(resp, "ERR b64\n"); }
        }
        if (cmd.contentLen >= 0) {
            cmd.content[cmd.contentLen] = 0;
            if (QPushA(&cmd)) lstrcpyA(resp, "OK aimg\n"); else lstrcpyA(resp, "ERR full\n");
        }
    } else if (pos == 6 && req[0]=='S') {
        wsprintfA(resp, "OK gen=%ld hits=%I64u rw=%I64u q=%ld aq=%ld pump=%I64u exec=%I64u mgr=%I64u img=%I64u\r\n",
            g_gen, g_hits, g_rw, (g_qSH-g_qST+QCAP)%QCAP, (g_qAH-g_qAT+QCAP)%QCAP, g_pumpHits, g_sessExec, (u64)(ULONG_PTR)g_mgr2, g_imgVtRva);
    } else if (pos == 6 && req[0]=='R' && req[1]=='E') {
        DoReload(resp, (int)sizeof(resp));
    }
    DWORD w; WriteFile(pipe, resp, lstrlenA(resp), &w, NULL);
    FlushFileBuffers(pipe);
}

static DWORD WINAPI PipeThread(LPVOID p) {
    (void)p;
    for (;;) {
        HANDLE pipe = CreateNamedPipeA(PIPE_NAME, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE|PIPE_READMODE_BYTE, 1, 4096, 4096, 0, NULL);
        if (pipe == INVALID_HANDLE_VALUE) { Sleep(1000); continue; }
        BOOL ok = ConnectNamedPipe(pipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (ok) HandleClient(pipe);
        FlushFileBuffers(pipe); DisconnectNamedPipe(pipe); CloseHandle(pipe);
    }
    return 0;
}

// ==== 初始化 ====
static DWORD WINAPI InitThread(LPVOID p) {
    (void)p;
    LogL("=== wx_boot.dll loaded ===");
    for (int i = 0; i < 120; i++) {
        HMODULE h = GetModuleHandleW(L"Weixin.dll");
        if (h) { g_base = (unsigned char*)h; break; }
        Sleep(500);
    }
    if (!g_base) { LogL("[INIT] no Weixin.dll"); return 1; }
    LogHex("[INIT] base=", (u64)(ULONG_PTR)g_base);
    InitializeCriticalSection(&g_cs);
    if (!InstallHook()) { LogL("[INIT] hook failed"); return 1; }
    LogHex("[INIT] UP1 hooked @", (u64)g_up1);
    if (!InstallLogOff2()) LogL("[INIT] logoff failed");
    if (!InstallWaitHook()) LogL("[INIT] waithook failed (idle trigger off)");
    if (!InstallPumpHook()) LogL("[INIT] pumphook failed (passive arming off)");
    if (!InstallMgrCtors()) LogL("[INIT] mgrctor failed (passive mgr off)");
    // 磁盘模板 -> bootstrap 状态
    {
        HANDLE f2 = CreateFileA(IMG_TPL_PATH, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (f2 != INVALID_HANDLE_VALUE) {
            g_imgTemplate = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, IMG_CAP_SIZE);
            DWORD r2 = 0;
            ReadFile(f2, g_imgTemplate, IMG_CAP_SIZE, &r2, NULL);
            CloseHandle(f2);
            LogL("[IMG] template loaded from disk");
        }
        HANDLE f = CreateFileA(TPL_PATH, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            g_tplBuf = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, TPL_SIZE);
            g_templateObj = g_tplBuf;
            DWORD r = 0;
            ReadFile(f, g_tplBuf, TPL_SIZE, &r, NULL);
            CloseHandle(f);
            LogL("[TPL] loaded from disk");
        }
    }
    HANDLE t = CreateThread(NULL, 0, PipeThread, NULL, 0, NULL);
    if (t) CloseHandle(t);
    // payload gen0
    if (!LoadPayloadGen(0, TRUE)) LogL("[INIT] payload load FAILED");
    else InterlockedExchange(&g_gen, 0);
    LogL("[INIT] ready");
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInst);
        AddVectoredExceptionHandler(1, SanityVEH);
        AddCodeRange((u64)(ULONG_PTR)hInst, (u64)(ULONG_PTR)hInst + 0x400000);
        HANDLE t = CreateThread(NULL, 0, InitThread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
