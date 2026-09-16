// wx_send.c — v65 clean rebuild: M3 rewrite + v62 clone batch + CoCreate spawn + LOGOFF
#include <windows.h>
#include <string.h>

// ==== constants ====
#define UP1_RVA         0x1790970ULL
#define VT_RVA          0x8BDF0F8ULL
#define IMGVT_RVA       0x8E6BCE8ULL  // 图片消息对象 vtable
#define RXCTOR_RVA      0x758821ULL   // v96d: 文本消息对象构造函数入口 (push rsi; sub rsp,20h; mov rsi,rcx)
#define RXCTOR_STOLEN   8
#define STOLEN          17
#define LOG_PATH        "E:\\weixin-hook-4.1.8\\hook-wx\\m2\\wx_send.log"
#define PIPE_NAME       "\\\\.\\pipe\\wxsend"
#define COCREATE_RVA    0x45FCC0ULL
#define SCHED_RVA       0x45FF50ULL
#define COCAP_RVA       0x45FCC0ULL
#define WAIT_RVA        0x7329A7CULL  // 线程池等待函数 (worker 空闲必经)
#define PUMP_RVA        0x17F1F70ULL  // 会话队列泵 (mgr=arg1, 调度器任务驱动)
#define STOLENP         19
#define MGRCTOR1_RVA    0x1788920ULL  // mgr 类构造 A (写 vtable 0x8E66148)
#define MGRCTOR2_RVA    0x178B5B0ULL  // mgr 类构造 B (写 vtable + 初始化 +0xe00 子对象)
#define STOLENC         17
#define EXEC_VT_RVA     0x8D4CDE8ULL  // 会话 exec 对象 vtable (coro+0x368 处对象)
#define COCAP2_RVA      0x45FCD1ULL   // CoCreate+0x11: 诱雷窗(+10..16)之外; 此处 rax=P5
#define COCAP2_STOLEN   15
#define TEMPLATE_PATH   "E:\\weixin-hook-4.1.8\\hook-wx\\m3\\template.bin"
#define IMG_TEMPLATE_PATH   "E:\\weixin-hook-4.1.8\\hook-wx\\m3\\image_template.bin"
#define IMG_CAP_SIZE    0x1400
#define ARG1_CTOR_RVA   0x185E570ULL   // arg1 类构造函数 (vtable 0x8EA3198)
#define COMPOSER_RVA    0x19D14C0ULL   // 组装器
#define STOLEN3         18
#define POOL_WAIT_RET   0x73225D1ULL  // 池空闲调用点 A (v62 原值, 12412 实测复现)
#define POOL_WAIT_RET2  0x732D872ULL  // 池空闲调用点 B (12412 实测诊断日志)
#define COCAP_STOLEN    17
#define LOGOFF_RVA      0xD9E810ULL
#define TLS_LOCALE_OFF  0x360
#define TLS_CURCORO_OFF 0x1F0
#define TLS_INDEX_RVA   0xB5D6A70

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;
typedef void (*UP1_fn)(void*, void*, void*, int);
typedef struct { void* obj; void* ctrl; } SP;
typedef void (*CoCreateFn)(SP* out, void* P2, void* P3, void* P4, void* P5);
typedef void (*SchedFn)(SP* sp, u64 val);

// ==== globals ====
static unsigned char* g_base = 0;
static unsigned char* g_up1 = 0;
unsigned char* g_tramp = 0;
static unsigned char g_orig[STOLEN];
static volatile u64 g_hits = 0, g_rw = 0;
static volatile DWORD g_tid2 = 0;
static void* volatile g_mgr2 = 0;
static CRITICAL_SECTION g_cs;

// AUTO queue (v62 clone batch)
typedef struct { int targetLen, contentLen, flags; char target[128], content[2048]; } Cmd;
#define QCAP 16
static Cmd g_ringA[QCAP];
static volatile LONG g_qAH = 0, g_qAT = 0;
// SEND queue (M3 rewrite)
static Cmd g_ringS[QCAP];
static volatile LONG g_qSH = 0, g_qST = 0;

static BOOL QPushA(const Cmd* c) { BOOL ok=FALSE; EnterCriticalSection(&g_cs); LONG n=(g_qAH+1)%QCAP; if(n!=g_qAT){g_ringA[g_qAH]=*c;g_qAH=n;ok=TRUE;} LeaveCriticalSection(&g_cs); return ok; }
static BOOL QPopA(Cmd* o) { BOOL ok=FALSE; EnterCriticalSection(&g_cs); if(g_qAT!=g_qAH){*o=g_ringA[g_qAT];g_qAT=(g_qAT+1)%QCAP;ok=TRUE;} LeaveCriticalSection(&g_cs); return ok; }
static BOOL QPushS(const Cmd* c) { BOOL ok=FALSE; EnterCriticalSection(&g_cs); LONG n=(g_qSH+1)%QCAP; if(n!=g_qST){g_ringS[g_qSH]=*c;g_qSH=n;ok=TRUE;} LeaveCriticalSection(&g_cs); return ok; }
static BOOL QPopS(Cmd* o) { BOOL ok=FALSE; EnterCriticalSection(&g_cs); if(g_qST!=g_qSH){*o=g_ringS[g_qST];g_qST=(g_qST+1)%QCAP;ok=TRUE;} LeaveCriticalSection(&g_cs); return ok; }

// CoCreate options capture (v65)
static volatile u64 g_capOpts = 0;       // CoCreate P5 (options ptr, captured)
static volatile LONG g_capValid = 0;     // capture valid flag
static unsigned char* g_cocreateTramp = 0;
// LOGOFF patch state
static BOOL g_logOff = FALSE;

// ==== logging ====
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
static void LogBytes(const char* label, const unsigned char* b, int n) {
    char buf[256]; char* p = buf; const char* hx = "0123456789abcdef";
    int k = lstrlenA(label); if (k > 100) k = 100;
    for (int i = 0; i < k; i++) p[i] = label[i]; p += k;
    for (int i = 0; i < n && p < buf + 240; i++) { *p++ = hx[b[i] >> 4]; *p++ = hx[b[i] & 0xF]; *p++ = ' '; }
    *p = 0; LogL(buf);
}

// ==== string ops ====
static int RdStr(unsigned char* obj, u64 off, char* out, int cap) {
    unsigned char* p = obj + off;
    u64 size = *(u64*)(p + 0x10);
    if (size > (u64)cap - 1) size = (u64)(cap - 1);
    unsigned char* src = (*(u64*)(p + 0x18) > 15) ? *(unsigned char**)p : p;
    if (!src) { out[0] = 0; return 0; }
    for (u64 i = 0; i < size; i++) out[i] = (char)src[i];
    out[size] = 0;
    return (int)size;
}
static int WrFresh(unsigned char* obj, u64 off, const char* data, int len) {
    unsigned char* p = obj + off;
    if (len > 4000) return 0;
    u64 newCap = (u64)len | 0xF;
    if (newCap < 0x16) newCap = 0x16;
    unsigned char* nb = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)(newCap + 1));
    if (!nb) return 0;
    for (int i = 0; i < len; i++) nb[i] = (unsigned char)data[i];
    nb[len] = 0;
    *(unsigned char**)p = nb;
    *(u64*)(p + 0x10) = (u64)len;
    *(u64*)(p + 0x18) = newCap;
    return 2;
}

// v90: 宽字符字符串写入 (WeChatString/wstring: UTF-16LE)
static int WrWide(unsigned char* obj, u64 off, const wchar_t* data, int wlen) {
    unsigned char* p = obj + off;
    u64 newCap = (u64)wlen | 0xF;
    if (newCap < 0x16) newCap = 0x16;
    unsigned char* nb = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)(newCap * 2 + 2));
    if (!nb) return 0;
    for (int i = 0; i < wlen; i++) {
        nb[i*2] = (unsigned char)(data[i] & 0xFF);
        nb[i*2+1] = (unsigned char)(data[i] >> 8);
    }
    nb[wlen*2] = 0; nb[wlen*2+1] = 0;
    *(unsigned char**)p = nb;
    *(u64*)(p + 0x10) = (u64)wlen;
    *(u64*)(p + 0x18) = newCap;
    return 2;
}

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
static unsigned int g_rnd = 0;
static void GenUuid(char out[37]) {
    if (!g_rnd) g_rnd = (unsigned int)GetTickCount64() ^ 0x9E3779B9u;
    unsigned char b[16];
    for (int i = 0; i < 16; i++) { g_rnd ^= g_rnd << 13; g_rnd ^= g_rnd >> 17; g_rnd ^= g_rnd << 5; b[i] = (unsigned char)g_rnd; }
    b[6] = (unsigned char)((b[6] & 0x0F) | 0x40); b[8] = (unsigned char)((b[8] & 0x3F) | 0x80);
    static const char hx[] = "0123456789abcdef";
    static const int dash[16] = {0,0,0,0,1,0,0,0,2,0,0,0,3,0,0,0};
    int p = 0;
    for (int i = 0; i < 16; i++) { if (dash[i]) out[p++] = '-'; out[p++] = hx[b[i] >> 4]; out[p++] = hx[b[i] & 0xF]; }
    out[p] = 0;
}

// ==== v65: CoCreate options capture hook ====
unsigned char* g_capTramp = 0;
volatile u64 g_capOptsRaw = 0;    // P5 pointer

extern void cocreate_cap_stub(void);
__asm__(
".text\n"
".globl cocreate_cap_stub\n"
"cocreate_cap_stub:\n"
"  push %rcx\n"
"  push %rdx\n"
"  push %r8\n"
"  push %r9\n"
"  push %r10\n"
"  mov 0x50(%rsp), %rcx\n"
"  call C_cocap\n"
"  pop %r10\n"
"  pop %r9\n"
"  pop %r8\n"
"  pop %rdx\n"
"  pop %rcx\n"
"  mov g_capTramp(%rip), %rax\n"
"  jmp *%rax\n"
);

static BOOL InstallCoCap(void) {
    unsigned char* fn = (unsigned char*)g_base + COCAP_RVA;
    // v65b: 运行时字节 (WeChat 启动后可能已修改 CoCreate 入口)
    static const unsigned char exp[COCAP_STOLEN] = {
        0x56,0x57,0x48,0x83,0xEC,0x58,0x48,0x89,0xCE,
        0x48,0x8B,0x84,0x24,0x90,0x00,0x00,0x00};  // 磁盘原文 (pid34988 实测=磁盘)
    unsigned char orig[COCAP_STOLEN];
    for (int i = 0; i < COCAP_STOLEN; i++) {
        orig[i] = fn[i];
        if (orig[i] != exp[i]) { LogBytes("[COCAP] bytes: ", orig, COCAP_STOLEN); return FALSE; }
    }
    g_capTramp = (unsigned char*)VirtualAlloc(NULL, 64, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_capTramp) return FALSE;
    for (int i = 0; i < COCAP_STOLEN; i++) g_capTramp[i] = orig[i];
    g_capTramp[COCAP_STOLEN] = 0xFF; g_capTramp[COCAP_STOLEN+1] = 0x25;
    for (int i = 0; i < 4; i++) g_capTramp[COCAP_STOLEN+2+i] = 0;
    u64 back = (u64)(fn + COCAP_STOLEN);
    for (int i = 0; i < 8; i++) g_capTramp[COCAP_STOLEN+6+i] = (unsigned char)(back >> (i*8));
    DWORD old;
    if (!VirtualProtect(fn, COCAP_STOLEN, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    unsigned char pat[12];
    pat[0] = 0x48; pat[1] = 0xB8;
    u64 sv = (u64)(ULONG_PTR)&cocreate_cap_stub;
    for (int i = 0; i < 8; i++) pat[2+i] = (unsigned char)(sv >> (i*8));
    pat[10] = 0xFF; pat[11] = 0xE0;
    for (int i = 0; i < 12; i++) fn[i] = pat[i];
    DWORD t2; VirtualProtect(fn, COCAP_STOLEN, old, &t2);
    FlushInstructionCache(GetCurrentProcess(), fn, COCAP_STOLEN);
    LogL("[COCAP] installed");
    return TRUE;
}

// ==== v65: LOGOFF patch (FUN_180d9e810 → xor eax,eax; ret) ====
static BOOL InstallLogOff(void) {
    unsigned char* fn = (unsigned char*)g_base + LOGOFF_RVA;
    DWORD old;
    if (!VirtualProtect(fn, 3, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    unsigned char pat[3] = {0x31, 0xC0, 0xC3};  // xor eax,eax; ret
    for (int i = 0; i < 3; i++) fn[i] = pat[i];
    DWORD t2; VirtualProtect(fn, 3, old, &t2);
    FlushInstructionCache(GetCurrentProcess(), fn, 3);
    LogL("[LOGOFF] installed");
    return TRUE;
}

// ==== v66b: 协程体改走克隆路线 (工厂路线实测 PC-only/无达; 克隆路线 v62 验证双达) ====
// 定义移至 FactoryFlush 之后 (依赖克隆实现); 此处仅前向声明供 SpawnAutoFlush 取址。
static BOOL CloneSanityText(unsigned char* clone, const char* tag);
static BOOL CloneSanityImg(unsigned char* clone, const char* tag);

static void __fastcall FlushBodyForCo(void* arg);
static void FactoryFlush(Cmd* a);   // v90 前置声明
static unsigned char g_compBuf[0x1800];   // v90: 组装器 arg1 全图
static volatile LONG g_compArmed = 0;     // v90: 捕获完成标志
volatile u64 g_stubRsp = 0;   // v90: UP1 入口 rsp
static char g_stagedDir[] = "D:/xwechat_files/wxid_yahr9o9txwt722_1cda/temp/RWTemp/2026-09/9e20f478899dc29eb19741386f9343c8";

// ==== v70: 图片自主发送 ====
extern unsigned char* g_imgTemplate;   // 定义在 C_helper 区 (v69)
static void ImageFlush(Cmd* a) {
    if (!g_mgr2) { LogL("[IMG] not armed"); return; }
    // 1) 暂存覆盖: 我们的图 → RWTemp/<uuid>.png
    char name[48];
    for (int i = 0; i < 44; i++) name[i] = (char)g_imgTemplate[0x9A0 + i];
    name[44] = 0;
    {   // 目录链
        CreateDirectoryA("D:/xwechat_files/wxid_yahr9o9txwt722_1cda/temp/RWTemp", NULL);
        char d2[300]; wsprintfA(d2, "D:/xwechat_files/wxid_yahr9o9txwt722_1cda/temp/RWTemp/2026-09");
        CreateDirectoryA(d2, NULL);
        char d3[400]; wsprintfA(d3, "%s/9e20f478899dc29eb19741386f9343c8", d2);
        CreateDirectoryA(d3, NULL);
    }
    char staged[600];
    wsprintfA(staged, "%s/%s", g_stagedDir, name);
    if (!CopyFileA(a->content, staged, FALSE)) { LogL("[IMG] stage copy fail"); return; }
    LogL("[IMG] staged overwritten");
    // 2) clone = 模板 + 修 self/引用计数 + 新 clientMsgId + +0x120 = 我们的路径
    unsigned char* abase = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1400 + 0x20);
    if (!abase) return;
    unsigned char* clone = abase + 0x10;
    memcpy(clone, g_imgTemplate, 0x1400);
    *(u64*)(clone + 0x00) = (u64)(ULONG_PTR)g_base + IMGVT_RVA;  // v96c: vtable 重定基址
    *(u32*)(abase + 0x08) = 0x10000;   // _Uses
    *(u32*)(abase + 0x0C) = 0x10000;   // _Weaks
    *(u64*)(clone + 0x08) = (u64)(ULONG_PTR)clone;
    *(u64*)(clone + 0x10) = (u64)(ULONG_PTR)abase;
    {   // +0x120 = 我们的图片路径 (UTF-16)
        int wlen = MultiByteToWideChar(CP_UTF8, 0, a->content, a->contentLen, NULL, 0);
        if (wlen > 0 && wlen < 1024) {
            wchar_t* wp = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)(wlen * 2 + 2));
            if (wp) {
                MultiByteToWideChar(CP_UTF8, 0, a->content, a->contentLen, wp, wlen);
                WrWide(clone, 0x120, wp, wlen);
                HeapFree(GetProcessHeap(), 0, wp);
            }
        }
    }
    {   // 新 clientMsgId (+0x6F8)
        char au[37]; GenUuid(au);
        WrFresh(clone, 0x6F8, au, 36);
    }
    // +0x1A8 名字字段: ptr → 模板尾部缓冲 (全局稳定)
    *(u64*)(clone + 0x1A8) = (u64)(ULONG_PTR)(g_imgTemplate + 0x9A0);
    if (!CloneSanityImg(clone, "[IMGFLUSH] sanity")) { HeapFree(GetProcessHeap(), 0, abase); return; }
    // 3) 构造 arg1 对象 (调图片类 ctor)
    unsigned char* arg1 = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x100);
    if (!arg1) return;
    typedef void (*Arg1CtorFn)(void*);
    Arg1CtorFn ctorfn = (Arg1CtorFn)(g_base + ARG1_CTOR_RVA);
    LogL("[IMG] calling arg1 ctor");
    ctorfn(arg1);
    LogL("[IMG] arg1 ctor ok");
    // 4) 设置 arg1 vector: +0x08 = begin, +0x10 = end, +0x18 = current
    void* elem[2] = {clone, abase};
    *(u64*)(arg1 + 0x08) = (u64)(ULONG_PTR)elem;
    *(u64*)(arg1 + 0x10) = (u64)(ULONG_PTR)(elem + 2);
    *(u64*)(arg1 + 0x18) = (u64)(ULONG_PTR)(elem + 2);
    LogL("[IMG] arg1 vector set");
    // 5) 调组装器 (内部: 取 mgr → UP2 → 任务 → 提交)
    typedef void (*CompFn)(void*);
    CompFn comp = (CompFn)(g_base + COMPOSER_RVA);
    LogL("[IMG] calling composer");
    comp(arg1);
    LogL("[IMG] composer returned");
    g_rw++;
}
// ==== v66: 空闲自主冲刷 —— 池等待钩子 + CoCreate 派生 (异步, 无内联冲刷) ====
static volatile u64 g_savedSPPtr = 0;
static volatile u64 g_up1Tick = 0;      // 最近一次 UP1 触发时刻 (静默闸)
static volatile LONG g_busy2 = 0;       // 空闲冲刷互斥
static volatile u64 g_sessExec = 0;
unsigned char* g_templateObj = 0;
// v69: 图片(非文本vtable)模板捕获
unsigned char* g_imgTemplate = 0;
volatile u64 g_imgVtRva = 0;
static void SpawnAutoFlush(void) {
    CoCreateFn cocreate = (CoCreateFn)(g_base + COCREATE_RVA);
    SchedFn sched = (SchedFn)(g_base + SCHED_RVA);
    Cmd a;
    while (QPopA(&a)) {
        if (!g_sessExec) { LogL("[SPAWN] no exec"); break; }
        Cmd* hc = (Cmd*)HeapAlloc(GetProcessHeap(), 0, sizeof(Cmd));
        if (!hc) break;
        *hc = a;
        static void* bh = 0; if (!bh) bh = (void*)&FlushBodyForCo;
        void* ah = (void*)hc;
        static void* ch = 0;
        SP sp2;
        // options: 会话 exec_ 在 +0x20 (resume_if 断言非空)
        unsigned char opts[0x40];
        memset(opts, 0, sizeof(opts));
        *(u64*)(opts + 0x20) = g_sessExec;
        *(int*)(opts + 0x38) = -1;
        cocreate(&sp2, (void*)bh, (void*)ah, (void*)ch, opts);
        if (!sp2.obj) { LogL("[SPAWN] fail"); HeapFree(GetProcessHeap(),0,hc); continue; }
        sched(&sp2, 0);
        LogL("[SPAWN] scheduled");
        g_rw++;
    }
}

void C_idle(void* dummy, u64 retaddr) {
    (void)dummy;
    if (g_qAH == g_qAT) return;                       // 热路径: AUTO 队列空
    if (!g_base || !g_mgr2 || !g_sessExec) return;    // 未武装
    if (g_tid2 && GetCurrentThreadId() != g_tid2) return;  // 仅 UP1 线程
    u64 roff = retaddr - (u64)g_base;
    if (roff != POOL_WAIT_RET && roff != POOL_WAIT_RET2) {  // 仅两个池空闲调用点
        static volatile LONG n = 0;
        if (InterlockedExchangeAdd(&n, 1) < 5) LogHex("[IDLE] site retaddr=", retaddr);
        return;
    }
    if (GetTickCount64() - g_up1Tick < 10000) return; // 10s 静默闸
    if (InterlockedExchange(&g_busy2, 1)) return;
    LogL("[IDLE] autonomous flush begin");
    SpawnAutoFlush();
    InterlockedExchange(&g_busy2, 0);
}

// ==== v67: 被动武装 —— 队列泵入口钩 (微信自身调度驱动, 无需用户消息) ====
volatile u64 g_pumpHits = 0;
unsigned char* g_pumpTramp = 0;
extern void pump_stub(void);
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

// ==== v68: CoCreate P5 验证捕获 (exec) ====
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

// ==== v96f: 登录窗口密钥捕获线程 (进程内原生速度扫 x'...' 字面量) ====
static DWORD WINAPI KeyCatchThread(LPVOID p) {
    (void)p;
    // 等武装 (登录完成) —— DB 打开在武装时刻前后数秒
    for (int i = 0; i < 1200 && !g_sessExec; i++) Sleep(100);
    if (!g_sessExec) return 1;
    LogL("[KEYCATCH] armed, scanning...");
    char outpath[128];
    lstrcpyA(outpath, "E:\\weixin-hook-4.1.8\\wxbot\\keycands.txt");
    u64 t0 = GetTickCount64();
    LONG total = 0;
    HANDLE out = CreateFileA(outpath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    if (out == INVALID_HANDLE_VALUE) { LogL("[KEYCATCH] out file fail"); return 1; }
    DWORD written = 0;
    while (GetTickCount64() - t0 < 45000) {
        // 枚举自身可读区域
        SYSTEM_INFO si; GetSystemInfo(&si);
        u64 addr = (u64)(ULONG_PTR)si.lpMinimumApplicationAddress;
        u64 maxa = (u64)(ULONG_PTR)si.lpMaximumApplicationAddress;
        MEMORY_BASIC_INFORMATION mbi;
        while (addr < maxa) {
            if (VirtualQuery((LPCVOID)(ULONG_PTR)addr, &mbi, sizeof(mbi)) == 0) break;
            u64 rsz = mbi.RegionSize;
            DWORD prot = mbi.Protect & 0xFF;
            BOOL readable = (prot == PAGE_READONLY || prot == PAGE_READWRITE ||
                             prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READ ||
                             prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY);
            if (mbi.State == MEM_COMMIT && readable && rsz > 0 && rsz < 0x40000000) {
                const u8* base = (const u8*)(ULONG_PTR)mbi.BaseAddress;
                if (IsBadReadPtr((const void*)(ULONG_PTR)base, 1) || IsBadReadPtr((const void*)(ULONG_PTR)(base + rsz - 1), 1)) {
                    addr += rsz;
                    if (rsz == 0) addr += 0x1000;
                    continue;
                }
                for (u64 i = 0; i + 70 < rsz; i++) {
                    if (base[i] != 'x' || base[i+1] != '\'') continue;
                    u64 j = i + 2;
                    while (j < rsz && (((base[j]>='0'&&base[j]<='9')||(base[j]>='a'&&base[j]<='f')||(base[j]>='A'&&base[j]<='F')))) j++;
                    u64 len = j - (i + 2);
                    if (len >= 64 && len <= 192 && j < rsz && base[j] == '\'') {
                        // 记录: hex + \n
                        char buf[200];
                        for (u64 k = 0; k < len; k++) {
                            char c = (char)base[i+2+k];
                            buf[k] = (c >= 'A' && c <= 'F') ? (char)(c + 32) : c;
                        }
                        buf[len] = '\n';
                        WriteFile(out, buf, (DWORD)(len + 1), &written, NULL);
                        total++;
                    }
                    i = j;
                }
            }
            addr += rsz;
            if (rsz == 0) addr += 0x1000;
        }
        Sleep(120);
    }
    CloseHandle(out);
    LogL("[KEYCATCH] done");
    LogHex("[KEYCATCH] candidates=", total);
    return 0;
}

// ==== v96d: 接收侧捕获 —— 文本消息对象构造函数钩 (收到的消息也走此构造) ====
#define RXRING_N 64
struct RxEnt { volatile u64 obj; volatile u64 tick; volatile LONG done; };
static struct RxEnt g_rxRing[RXRING_N];
static volatile LONG g_rxIdx = 0;

void __fastcall C_rxctor(void* obj) {
    if (!obj) return;
    LONG i = InterlockedIncrement(&g_rxIdx) - 1;
    struct RxEnt* e = &g_rxRing[i % RXRING_N];
    e->obj = (u64)(ULONG_PTR)obj;
    e->tick = GetTickCount64();
    e->done = 0;
}

// SSO 兼容读取 std::string 形态 {union buf/ptr @0, size @0x10, cap @0x18}
static int RxReadStr(unsigned char* obj, u64 off, char* out, int cap) {
    if (IsBadReadPtr((const void*)(ULONG_PTR)obj, 0x800)) return -1;
    u64 sptr = *(u64*)(obj + off);
    u64 ssize = *(u64*)(obj + off + 0x10);
    u64 scap = *(u64*)(obj + off + 0x18);
    if (ssize == 0 || ssize >= (u64)cap) return -1;
    const char* data = (const char*)(ULONG_PTR)sptr;
    char sso[16];
    if (scap < ssize || scap <= 15) {
        for (int i = 0; i < 16; i++) sso[i] = *(unsigned char*)(obj + off + i);
        data = sso;
    }
    if (IsBadReadPtr((const void*)(ULONG_PTR)data, (SIZE_T)ssize)) return -1;
    for (u64 i = 0; i < ssize; i++) out[i] = data[i];
    out[ssize] = 0;
    return (int)ssize;
}

static DWORD WINAPI RxDrainThread(LPVOID p) {
    (void)p;
    char content[2048]; char target[256];
    for (;;) {
        Sleep(30);
        if (!g_base) continue;
        u64 now = GetTickCount64();
        for (int i = 0; i < RXRING_N; i++) {
            struct RxEnt* e = &g_rxRing[i];
            if (e->done || !e->obj) continue;
            u64 obj = e->obj;
            if (now - e->tick < 60) continue;          // 等构造完成
            if (now - e->tick > 10000) { e->done = 1; continue; }  // 超时放弃
            if (IsBadReadPtr((const void*)(ULONG_PTR)obj, 8)) { e->done = 1; continue; }
            if (*(u64*)(ULONG_PTR)obj != (u64)(ULONG_PTR)g_base + VT_RVA) { e->done = 1; continue; }
            if (RxReadStr((unsigned char*)(ULONG_PTR)obj, 0x758, content, sizeof(content)-1) < 0) continue;  // 内容未填, 下轮再试
            target[0] = 0;
            RxReadStr((unsigned char*)(ULONG_PTR)obj, 0xB0, target, sizeof(target)-1);
            e->done = 1;
            LogL("[RX] msg captured");
            LogL(target);
            LogL(content);
            {   // 写文件供 bot 读取
                HANDLE f = CreateFileA("E:\\weixin-hook-4.1.8\\wxbot\\received_text.txt",
                    GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
                if (f != INVALID_HANDLE_VALUE) {
                    DWORD w = 0;
                    WriteFile(f, target, lstrlenA(target), &w, NULL);
                    WriteFile(f, "|", 1, &w, NULL);
                    WriteFile(f, content, lstrlenA(content), &w, NULL);
                    CloseHandle(f);
                }
            }
        }
    }
    return 0;
}

extern void rxctor_stub(void);
unsigned char* g_rxctorTramp = 0;
volatile u64 g_rxctorBack = 0;   // fn+8 (构造函数 stolen 尾部回跳)
__asm__(
".text\n"
".globl rxctor_stub\n"
"rxctor_stub:\n"
"  push %rcx\n"
"  sub $0x28, %rsp\n"
"  call C_rxctor\n"
"  add $0x28, %rsp\n"
"  pop %rcx\n"
"  push %rsi\n"
"  sub $0x20, %rsp\n"
"  mov %rcx, %rsi\n"
"  mov g_rxctorBack(%rip), %rax\n"
"  jmp *%rax\n"
);

static BOOL InstallRxctor(void) {
    unsigned char* fn = (unsigned char*)g_base + RXCTOR_RVA;
    static const unsigned char exp[RXCTOR_STOLEN] = {0x56,0x48,0x83,0xEC,0x20,0x48,0x89,0xCE};
    unsigned char orig[RXCTOR_STOLEN];
    for (int i = 0; i < RXCTOR_STOLEN; i++) {
        orig[i] = fn[i];
        if (orig[i] != exp[i]) { LogBytes("[RXCTOR] bytes: ", orig, RXCTOR_STOLEN); return FALSE; }
    }
    g_rxctorTramp = (unsigned char*)VirtualAlloc(NULL, 64, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_rxctorTramp) return FALSE;
    for (int i = 0; i < RXCTOR_STOLEN; i++) g_rxctorTramp[i] = orig[i];
    g_rxctorTramp[RXCTOR_STOLEN] = 0xFF; g_rxctorTramp[RXCTOR_STOLEN+1] = 0x25;
    for (int i = 0; i < 4; i++) g_rxctorTramp[RXCTOR_STOLEN+2+i] = 0;
    u64 back = (u64)(ULONG_PTR)(fn + RXCTOR_STOLEN);
    for (int i = 0; i < 8; i++) g_rxctorTramp[RXCTOR_STOLEN+6+i] = (unsigned char)(back >> (i*8));
    g_rxctorBack = back;   // stub 尾部回跳
    DWORD old;
    if (!VirtualProtect(fn, RXCTOR_STOLEN, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    unsigned char pat[12];
    pat[0] = 0x48; pat[1] = 0xB8;
    u64 s = (u64)(ULONG_PTR)&rxctor_stub;
    for (int i = 0; i < 8; i++) pat[2+i] = (unsigned char)(s >> (i*8));
    pat[10] = 0xFF; pat[11] = 0xE0;
    for (int i = 0; i < 12; i++) fn[i] = pat[i];
    DWORD t2; VirtualProtect(fn, RXCTOR_STOLEN, old, &t2);
    FlushInstructionCache(GetCurrentProcess(), fn, RXCTOR_STOLEN);
    LogL("[RXCTOR] installed");
    return TRUE;
}

// ==== v68: mgr 构造钩子 (登录瞬间被动捕获 mgr) ====
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
        0x48,0x8D,0xAC,0x24,0x80,0x00,0x00,0x00};  // lea rbp,[rsp+0x80] 是 disp32 长形式
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

unsigned char* g_waitTramp = 0;   // 非 static: asm 符号可见性 (同 g_capOptsRaw)
extern void wait_stub(void);
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
"  call C_idle\n"
"  add $0x30, %rsp\n"
"  pop %r10\n"
"  pop %r9\n"
"  pop %r8\n"
"  pop %rdx\n"
"  pop %rcx\n"
"  mov g_waitTramp(%rip), %rax\n"
"  jmp *%rax\n"
);

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

static BOOL CloneSanityText(unsigned char* clone, const char* tag);
static BOOL CloneSanityImg(unsigned char* clone, const char* tag);

// ==== v97: 预检器 —— 克隆体进 UP1 前校验, 把崩溃变成报错 ====
static BOOL StrFieldOk(unsigned char* obj, u64 off) {
    if (IsBadReadPtr((const void*)(ULONG_PTR)obj, off + 0x20)) return FALSE;
    u64 sptr = *(u64*)(obj + off);
    u64 ssize = *(u64*)(obj + off + 0x10);
    u64 scap = *(u64*)(obj + off + 0x18);
    if (ssize == 0 || ssize > 0x4000) return FALSE;
    const void* p;
    if (scap < ssize || scap <= 15) p = (const void*)(ULONG_PTR)obj;      // SSO 内联
    else { if (sptr < 0x10000) return FALSE; p = (const void*)(ULONG_PTR)sptr; }
    return !IsBadReadPtr(p, (SIZE_T)ssize);
}

static BOOL CloneSanity(unsigned char* clone, u64 vtExpect, const char* tag) {
    u64 vt = *(u64*)(ULONG_PTR)clone;
    BOOL vtOk = (vt == vtExpect);
    BOOL b0   = StrFieldOk(clone, 0xB0);
    BOOL c758 = StrFieldOk(clone, 0x758);
    BOOL u6f8 = StrFieldOk(clone, 0x6F8);
    BOOL ok = vtOk && b0 && c758 && u6f8;
    if (ok) { LogL(tag); LogL("[PRECHECK] ok"); return TRUE; }
    LogL(tag); LogL("[PRECHECK] FAIL - refuse UP1");
    LogHex("  vtable=", vt); LogHex("  expect=", vtExpect);
    LogL(b0 ? "  +0xB0 ok" : "  +0xB0 BAD");
    LogL(c758 ? "  +0x758 ok" : "  +0x758 BAD");
    LogL(u6f8 ? "  +0x6F8 ok" : "  +0x6F8 BAD");
    return FALSE;
}

static BOOL CloneSanityText(unsigned char* clone, const char* tag) {
    return CloneSanity(clone, (u64)(ULONG_PTR)g_base + VT_RVA, tag);
}
static BOOL CloneSanityImg(unsigned char* clone, const char* tag) {
    return CloneSanity(clone, (u64)(ULONG_PTR)g_base + IMGVT_RVA, tag);
}

// ==== UP1 hook (M3 + AUTO flush) ====
static void FactoryFlush(Cmd* a) {
    // v62 clone: HeapAlloc + memcpy + the deep string copies + UP1(flag=1)
    unsigned char* clone = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x798);
    if (!clone) { LogL("[CLONE] alloc fail"); return; }
    // the template obj = the real message obj passed to C_helper
    // (g_templateObj = the saved copy from the arming send)
    extern unsigned char* g_templateObj;
    if (!g_templateObj) { HeapFree(GetProcessHeap(), 0, clone); return; }
    memcpy(clone, g_templateObj, 0x798);
    // v96c: 跨会话磁盘模板的 vtable 是旧基址指针 -> 重定基址 (其余内部指针
    // 由活体刷新保证同会话有效, 见 C_helper 的 TPL 活体优先捕获)
    *(u64*)(ULONG_PTR)clone = (u64)(ULONG_PTR)g_base + VT_RVA;
    WrFresh(clone, 0x758, a->content, a->contentLen);
    if (a->targetLen > 0) WrFresh(clone, 0xB0, a->target, a->targetLen);
    char au[37]; GenUuid(au);
    WrFresh(clone, 0x6F8, au, 36);
    if (!CloneSanityText(clone, "[CLONE] sanity")) { HeapFree(GetProcessHeap(), 0, clone); return; }
    void* csp[2] = {clone, NULL};
    UP1_fn up1f = (UP1_fn)(g_base + UP1_RVA);
    u64 fout[2] = {0, 0};
    up1f(g_mgr2, fout, (void*)csp, 1);
    LogL("[CLONE] UP1 returned");
    g_rw++;
}

// ==== v66b: 协程体定义 —— 克隆路线 (依赖上方 FactoryFlush) ====
static void __fastcall FlushBodyForCo(void* arg) {
    Cmd* a = (Cmd*)arg;
    if (!a) return;
    if (a->flags == 4) { LogL("[CORO] image flush begin"); ImageFlush(a); LogL("[CORO] image flush done"); return; }
    LogL("[CORO] clone flush begin");
    FactoryFlush(a);
    LogL("[CORO] clone flush done");
}
// (v66: 全局声明已上移至 SpawnAutoFlush 之前)

void C_helper(void* p3, u64 flag) {
    g_hits++;
    g_tid2 = GetCurrentThreadId();
    g_up1Tick = GetTickCount64();
    void** sp = (void**)p3;
    if (!sp) return;
    unsigned char* obj = (unsigned char*)sp[0];
    if (!obj) return;
    {   // v92b: vt trace
        static LONG vtn = 0;
        if (InterlockedIncrement((volatile LONG*)&vtn) <= 10) {
            LogHex("[VT] obj=", (u64)(ULONG_PTR)obj);
            LogHex("[VT] vt=", *(u64*)obj);
        }
    }
    if (*(void**)obj != (void*)((u64)g_base + VT_RVA)) {
        // v69: 非文本 vtable (图片等) -> 捕获模板一次
        if (!g_compArmed) {
                {   // v90: 栈扫描定位组装器 arg1 (vtable 0x8EF3198) 并捕获全图
                    u64 w = g_stubRsp;
                    if (w) {
                        MEMORY_BASIC_INFORMATION mbi90;
                        u64 limit = w + 0x6000;
                        if (VirtualQuery((LPCVOID)w, &mbi90, sizeof(mbi90))) {
                            u64 stop = (u64)(ULONG_PTR)mbi90.BaseAddress + mbi90.RegionSize;
                            if (w + 0x6000 > stop - 0x40) limit = stop - 0x40;
                        }
                        u64 vtTarget = (u64)(ULONG_PTR)g_base + 0x8EF3198ULL;
                        u64 arg1 = 0;
                        for (u64 off = 0; w + off < limit && !arg1; off += 8) {
                            u64 v = *(u64*)(w + off);
                            if (v > 0x10000 && v < 0x7fffffffffff && (v & 7) == 0 &&
                                !IsBadReadPtr((const void*)(ULONG_PTR)v, 0x40)) {
                                if (*(u64*)(ULONG_PTR)v == vtTarget) arg1 = v;
                            }
                        }
                        if (arg1) {
                            unsigned char* B = g_compBuf;
                            for (int i = 0; i < 0x40; i++) B[i] = ((unsigned char*)(ULONG_PTR)arg1)[i];
                            u64 begin = *(u64*)(B + 8);
                            u64 end = *(u64*)(B + 0x10);
                            u64 span = (end > begin && end - begin <= 0x100) ? (end - begin) : 0x10;
                            if (!IsBadReadPtr((const void*)(ULONG_PTR)begin, (SIZE_T)span)) {
                                for (u64 i = 0; i < span; i++) B[0x40 + i] = ((unsigned char*)(ULONG_PTR)begin)[i];
                            }
                            u64 obj2 = *(u64*)(B + 0x40);
                            u64 ctrl2 = *(u64*)(B + 0x48);
                            if (obj2 && !IsBadReadPtr((const void*)(ULONG_PTR)obj2, 0x1400)) {
                                for (int i = 0; i < 0x1400; i++) B[0x140 + i] = ((unsigned char*)(ULONG_PTR)obj2)[i];
                            }
                            if (ctrl2 && !IsBadReadPtr((const void*)(ULONG_PTR)ctrl2, 0x20)) {
                                for (int i = 0; i < 0x20; i++) B[0x1540 + i] = ((unsigned char*)(ULONG_PTR)ctrl2)[i];
                            }
                            u64 nptr = *(u64*)(B + 0x140 + 0x1A8);
                            if (nptr && !IsBadReadPtr((const void*)(ULONG_PTR)nptr, 0x30)) {
                                for (int i = 0; i < 0x30; i++) B[0x1760 + i] = ((unsigned char*)(ULONG_PTR)nptr)[i];
                            }
                            InterlockedExchange((volatile LONG*)&g_compArmed, 1);
                            LogL("[CAP] arg1 graph armed");
                        } else {
                            LogL("[CAP] arg1 not found on stack");
                            if (!IsBadReadPtr((const void*)(ULONG_PTR)w, 0x400)) {
                                for (int off = 0; off < 0x400; off += 0x40) {
                                    LogBytes("[STACK] ", (const unsigned char*)(ULONG_PTR)(w + off), 0x40);
                                }
                            }
                        }
                    }
                }
        }
        {   // v96c: 活体优先 (磁盘兜底 -> 首次图片发送用活体覆盖)
            static BOOL g_imgArmed = FALSE;
            if (!g_imgArmed) {
            u64 vt = *(u64*)obj;
            g_imgVtRva = vt - (u64)(ULONG_PTR)g_base;
            if (!g_imgTemplate) g_imgTemplate = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, IMG_CAP_SIZE);
            if (g_imgTemplate) {
                g_imgArmed = TRUE;
                memcpy(g_imgTemplate, obj, IMG_CAP_SIZE);
                LogL("[IMG] template captured");
                LogHex("[IMG] vtable RVA=", g_imgVtRva);
                LogHex("[IMG] obj=", (u64)(ULONG_PTR)obj);
                {   // v70: 文件名字符串内容内嵌到模板尾部 (跨会话自包含)
                    u64 fnptr = *(u64*)(obj + 0x1A8);
                    if (fnptr) memcpy(g_imgTemplate + 0x9A0, (const void*)fnptr, 0x60);
                }
                HANDLE f = CreateFileA(IMG_TEMPLATE_PATH, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
                if (f != INVALID_HANDLE_VALUE) { DWORD w = 0; WriteFile(f, g_imgTemplate, IMG_CAP_SIZE, &w, NULL); CloseHandle(f); LogL("[IMG] saved to disk"); }
            }
            }
        }
        return;
    }

    // v96b: 捕获文本消息内容 (兼容 SSO 内联与堆分配两种字符串形态)
    {
        static LONG diagN = 0;
        u64 cptr = *(u64*)(obj + 0x758);
        u64 csize = *(u64*)(obj + 0x758 + 0x10);
        u64 ccap = *(u64*)(obj + 0x758 + 0x18);
        if (InterlockedIncrement((volatile LONG*)&diagN) <= 3)
            LogHex("[TXT] ptr=", cptr), LogHex("[TXT] size=", csize), LogHex("[TXT] cap=", ccap);
        if (csize > 0 && csize < 0x2000) {
            const char* data = (const char*)(ULONG_PTR)cptr;
            char ssoBuf[16];
            if (ccap < csize || ccap <= 15) {          // SSO: 数据内联在对象里
                for (int i = 0; i < 16; i++) ssoBuf[i] = *(unsigned char*)(obj + 0x758 + i);
                data = ssoBuf;
            }
            if (!IsBadReadPtr((const void*)(ULONG_PTR)data, (SIZE_T)csize)) {
                HANDLE f = CreateFileA("E:\\weixin-hook-4.1.8\\wxbot\\last_text.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
                if (f != INVALID_HANDLE_VALUE) { DWORD w = 0; WriteFile(f, data, csize, &w, NULL); CloseHandle(f); }
            }
        }
    }

    // v65: capture the session SP (TLS+0x1F0 → &{coro,ctrl}) and the template obj
    {
        u64 tlsarr = 0, blk = 0;
        __asm__ volatile("movq %%gs:0x58, %0" : "=r"(tlsarr));
        u32 ti = *(u32*)((unsigned char*)g_base + TLS_INDEX_RVA);
        blk = *(u64*)(tlsarr + (u64)ti * 8);
        if (blk) {
            u64 spptr = *(u64*)(blk + TLS_CURCORO_OFF);
            if (spptr && !g_savedSPPtr) {
                g_savedSPPtr = spptr;
                LogL("[SES] session SP captured");
                u64 scoro = *(u64*)spptr;
                if (scoro) {
                    u64 sexec = *(u64*)(scoro + 0x368);
                    if (sexec) { g_sessExec = sexec; LogL("[SES] exec captured"); }
                }
            }
        }
        {   // v96c: 活体优先 —— 磁盘模板只是跨会话兜底, 本次会话首次真实发送必须
            // 用活体对象覆盖 (内部指针/ vtable 均为当前基址, 消除悬空风险)
            static BOOL g_tplLive = FALSE;
            if (!g_tplLive) {
                if (!g_templateObj) g_templateObj = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, 0x798);
                if (g_templateObj) {
                    memcpy(g_templateObj, obj, 0x798); g_tplLive = TRUE; LogL("[TPL] template obj captured (live)");
                    HANDLE f = CreateFileA(TEMPLATE_PATH, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
                    if (f != INVALID_HANDLE_VALUE) { DWORD w = 0; WriteFile(f, g_templateObj, 0x798, &w, NULL); CloseHandle(f); LogL("[TPL] saved to disk"); }
                }
            }
        }
    }

    // v65/v66: AUTO 队列 → CoCreate 派生协程 (当前线程 = UP1 线程 = 完整 CRT/locale ✓)
    SpawnAutoFlush();

    // the M3 rewrite: the SEND queue → the last item via the rewrite
    Cmd tmp;
    if (!QPopS(&tmp)) return;
    WrFresh(obj, 0x758, tmp.content, tmp.contentLen);
    if (tmp.targetLen > 0) WrFresh(obj, 0xB0, tmp.target, tmp.targetLen);
    if (tmp.flags) { char u[37]; GenUuid(u); WrFresh(obj, 0x6F8, u, 36); }
    g_rw++;
    LogL("[FLUSH] dispatched");
}

// ==== v65: capture the options from the live CoCreate ====

// the CoCreate capture stub reads P5 and stores it
// (called on every CoCreate in the process — the options are stable after the first capture)
void __fastcall C_CoCapP5(void* dummy, u64 optsPtr) {
    (void)dummy;
    if (optsPtr && !g_capOptsRaw) g_capOptsRaw = optsPtr;
}


static BOOL InstallCoCapHook(void) {
    unsigned char* fn = (unsigned char*)g_base + COCAP_RVA;
    static const unsigned char exp[COCAP_STOLEN] = {
        0x56,0x57,0x48,0x83,0xEC,0x58,0x48,0x89,0xCE,
        0x48,0x8B,0x84,0x24,0x90,0x00,0x00,0x00};  // 磁盘原文 17 字节 (v65e: 修复截断表)
    unsigned char orig[COCAP_STOLEN];
    for (int i = 0; i < COCAP_STOLEN; i++) orig[i] = fn[i];
    // v65d: CoCreate 页开启反读虚拟化 —— 进程内数据读看到诱饵 (前9字节=原文, +10..16=零填充),
    // RPM/执行看到磁盘原文. 诱饵专破 prologue 校验. 识别诱饵 -> 盲装: trampoline 用磁盘原文.
    int decoy = 0;
    for (int i = 0; i < COCAP_STOLEN; i++) {
        if (orig[i] != exp[i]) {
            decoy = 1;
            for (int j = 0; j < 9; j++) if (orig[j] != exp[j]) { LogBytes("[COCAPH] bytes: ", orig, COCAP_STOLEN); return FALSE; }
            for (int j = 10; j < COCAP_STOLEN; j++) if (orig[j] != 0x00) { LogBytes("[COCAPH] bytes: ", orig, COCAP_STOLEN); return FALSE; }
            LogL("[COCAPH] anti-read decoy -> blind install");
            break;
        }
    }
    g_capTramp = (unsigned char*)VirtualAlloc(NULL, 64, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_capTramp) return FALSE;
    for (int i = 0; i < COCAP_STOLEN; i++) g_capTramp[i] = exp[i];
    g_capTramp[COCAP_STOLEN] = 0xFF; g_capTramp[COCAP_STOLEN+1] = 0x25;
    for (int i = 0; i < 4; i++) g_capTramp[COCAP_STOLEN+2+i] = 0;
    u64 back = (u64)(fn + COCAP_STOLEN);
    for (int i = 0; i < 8; i++) g_capTramp[COCAP_STOLEN+6+i] = (unsigned char)(back >> (i*8));
    DWORD old;
    if (!VirtualProtect(fn, COCAP_STOLEN, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    unsigned char pat[12];
    pat[0] = 0x48; pat[1] = 0xB8;
    u64 sv = (u64)(ULONG_PTR)&cocreate_cap_stub;
    for (int i = 0; i < 8; i++) pat[2+i] = (unsigned char)(sv >> (i*8));
    pat[10] = 0xFF; pat[11] = 0xE0;
    for (int i = 0; i < 12; i++) fn[i] = pat[i];
    DWORD t2; VirtualProtect(fn, COCAP_STOLEN, old, &t2);
    FlushInstructionCache(GetCurrentProcess(), fn, COCAP_STOLEN);
    LogL("[COCAPH] installed");
    return TRUE;
}

// ==== v65: LOGOFF (FUN_180d9e810 → xor eax,eax; ret) ====
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

// ==== UP1 hook install ====
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
"  call C_helper\n"
"  add $0x28, %rsp\n"
"  pop %r9\n"
"  pop %r8\n"
"  pop %rdx\n"
"  pop %rcx\n"
"  mov g_tramp(%rip), %rax\n"
"  jmp *%rax\n"
);

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

// ==== pipe server ====
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
        wsprintfA(resp, "OK hits=%I64u rw=%I64u q=%ld aq=%ld pump=%I64u exec=%I64u mgr=%I64u img=%I64u\r\n", g_hits, g_rw, (g_qSH-g_qST+QCAP)%QCAP, (g_qAH-g_qAT+QCAP)%QCAP, g_pumpHits, g_sessExec, g_mgr2, g_imgVtRva);
    }
    DWORD w; WriteFile(pipe, resp, lstrlenA(resp), &w, NULL);
    FlushFileBuffers(pipe);
}

static DWORD WINAPI PipeThread(LPVOID p) {
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

// v65c: CoCreate 入口在微信启动预热期是临时自钩子 (48 ff e0...), 预热完成后恢复磁盘原文.
// 注入发生在预热期内时一次性检查必失败 -> 每 3s 重试, 最长 4 分钟.
volatile u64 g_cocapRax = 0;   // asm 可见 (非 static)
extern void cocreate_cap2_stub(void);
__asm__(
".text\n"
".globl cocreate_cap2_stub\n"
"cocreate_cap2_stub:\n""  mov %rax, g_cocapRax(%rip)\n"
"  push %rcx\n"
"  push %rdx\n"
"  push %r8\n"
"  push %r9\n"
"  mov %rax, %rcx\n"
"  call C_cocap\n"
"  mov g_cocapRax(%rip), %rax\n"
"  mov g_cap2Tramp(%rip), %r10\n"
"  jmp *%r10\n"
);

unsigned char* g_cap2Tramp = 0;

static BOOL InstallCoCapHook2(void) {
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

static DWORD WINAPI CocapRetryThread(LPVOID p) {
    (void)p;
    for (int i = 1; i <= 80; i++) {
        if (InstallCoCapHook()) return 0;
        if (i % 10 == 0) LogL("[COCAP] retrying...");
        Sleep(3000);
    }
    LogL("[COCAP] retry exhausted");
    return 1;
}

static DWORD WINAPI InitThread(LPVOID p) {
    (void)p;
    LogL("=== wx_send.dll v65 loaded ===");
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
    // v71b: COCAP 捕获移除 — CoCreate 页零接触 (保护者会对补丁页去执行化)。
    // exec 由 mgr 构造钩子的 TLS 链在登录时被动捕获, 冗余且安全。

    {   // v71: 旧 COCAPH 补丁若在 (残留会话), 不再安装; 全新进程 fn+0 永不补丁
    }
    if (!InstallLogOff2()) LogL("[INIT] logoff failed");
    if (!InstallWaitHook()) LogL("[INIT] waithook failed (idle trigger off)");
    if (!InstallPumpHook()) LogL("[INIT] pumphook failed (passive arming off)");
    if (!InstallMgrCtors()) LogL("[INIT] mgrctor failed (passive mgr off)");
    if (!InstallRxctor()) LogL("[INIT] rxctor failed (receive capture off)");
    CreateThread(NULL, 0, RxDrainThread, NULL, 0, NULL);
    CreateThread(NULL, 0, KeyCatchThread, NULL, 0, NULL);
    {
        {
            HANDLE f2 = CreateFileA(IMG_TEMPLATE_PATH, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (f2 != INVALID_HANDLE_VALUE) {
                g_imgTemplate = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, IMG_CAP_SIZE);
                DWORD r2 = 0;
                ReadFile(f2, g_imgTemplate, IMG_CAP_SIZE, &r2, NULL);
                CloseHandle(f2);
                LogL("[IMG] template loaded from disk");
            }
        }
        HANDLE f = CreateFileA(TEMPLATE_PATH, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            g_templateObj = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, 0x798);
            DWORD r = 0;
            ReadFile(f, g_templateObj, 0x798, &r, NULL);
            CloseHandle(f);
            LogL("[TPL] loaded from disk");
        }
    }
    HANDLE t = CreateThread(NULL, 0, PipeThread, NULL, 0, NULL);
    if (t) CloseHandle(t);
    LogL("[INIT] ready");
    return 0;
}

// ==== v97: VEH 取证 —— 我们代码段内的 AV 精确记录 (RIP/出错地址/读写) ====
static u64 g_selfLo = 0, g_selfHi = 0;   // 本 DLL 映像范围
static LONG WINAPI SanityVEH(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != 0xC0000005) return EXCEPTION_CONTINUE_SEARCH;
    u64 rip = ep->ContextRecord->Rip;
    if (g_selfLo && rip >= g_selfLo && rip < g_selfHi) {
        LogL("[VEH] access violation in our code");
        LogHex("  rip=", rip);
        LogHex("  fault-addr=", ep->ExceptionRecord->ExceptionInformation[1]);
        LogHex("  op(0=r,1=w,8=dep)=", ep->ExceptionRecord->ExceptionInformation[0]);
        LogHex("  rcx=", ep->ContextRecord->Rcx);
        LogHex("  rdx=", ep->ContextRecord->Rdx);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInst);
        // v97: 记录自身映像范围 (VEH 取证用)
        {
            g_selfLo = (u64)(ULONG_PTR)hInst;
            IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hInst;
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((u64)(ULONG_PTR)hInst + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE)
                    g_selfHi = g_selfLo + nt->OptionalHeader.SizeOfImage;
            }
            if (!g_selfHi) g_selfHi = g_selfLo + 0x400000;
            AddVectoredExceptionHandler(1, SanityVEH);
        }
        HANDLE t = CreateThread(NULL, 0, InitThread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
