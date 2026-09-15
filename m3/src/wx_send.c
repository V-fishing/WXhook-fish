// wx_send.c — M3 精简版
#include <windows.h>

#define UP1_RVA     0x1790970ULL
#define VT_RVA      0x8BDF0F8ULL
#define PROC_RVA    0x19D14C0ULL   // 派发处理器 (UP1 祖先帧, 同线程, 上下文合法)
#define WAIT_RVA    0x7329A7CULL   // 线程池等待函数 (worker 空闲必经, 实测栈采样定位)
#define COCREATE_RVA 0x45FCC0ULL   // CoCreate: 创建协程 (body@+0x350, arg@+0x360)
#define SCHED_RVA    0x45FF50ULL   // resume_if: 投递协程到 worker 池
#define STOLEN4      17
#define THROW_RVA    0x72DD144ULL   // C++ throw 助手 (MSVC EH magic 0x19930520)
#define STOLEN5      15
#define PARK_RET     0x731D6CCULL
#define COCREATE_HOOK_RVA 0x45FCC0ULL  // CoCreate 入口 (捕获 P5 options 指针)
#define COCREATE_STOLEN   17            // push rsi; push rdi; sub rsp,0x58; mov rsi,rcx   // 池等待返回地址 (实测 park 诊断确认, 原 0x73225D1 错误)
#define FAC_RVA     0x6EC830ULL    // 消息对象工厂 (v10 已验证)
#define STOLEN      17
#define STOLEN2     26
#define STOLEN3     18
#define LOG_PATH    "E:\\weixin-hook-4.1.8\\hook-wx\\m2\\wx_send.log"
#define PIPE_NAME   "\\\\.\\pipe\\wxsend"

typedef unsigned int u32;
typedef unsigned long long u64;
typedef void (*UP1_fn)(void*, void*, void*, int);
typedef struct { void* obj; void* ctrl; } SP;
typedef SP (*FactoryFn)(void);



static volatile u64 g_hits, g_rw;
static unsigned char* g_base;
static unsigned char* g_up1;
static unsigned char* g_tramp;
static unsigned char g_orig[STOLEN];
void* volatile g_mgr2;
static DWORD volatile g_tid2;
static CRITICAL_SECTION g_cs;

typedef struct { int targetLen, contentLen, flags; char target[128], content[2048]; } Cmd;
#define QCAP 16
static Cmd g_ring[QCAP];
static volatile LONG g_qH, g_qT;
static BOOL QPush(const Cmd* c) {
    BOOL ok = FALSE;
    EnterCriticalSection(&g_cs);
    LONG n = (g_qH + 1) % QCAP;
    if (n != g_qT) { g_ring[g_qH] = *c; g_qH = n; ok = TRUE; }
    LeaveCriticalSection(&g_cs);
    return ok;
}
static BOOL QPop(Cmd* o) {
    BOOL ok = FALSE;
    EnterCriticalSection(&g_cs);
    if (g_qT != g_qH) { *o = g_ring[g_qT]; g_qT = (g_qT + 1) % QCAP; ok = TRUE; }
    LeaveCriticalSection(&g_cs);
    return ok;
}
// AUTO 专用队列 (独立冲刷路径: 派发线程处理器钩子, 无需用户触发)
static Cmd g_ringA[QCAP];
static volatile LONG g_qAH, g_qAT;
static BOOL QPushA(const Cmd* c) {
    BOOL ok = FALSE;
    EnterCriticalSection(&g_cs);
    LONG n = (g_qAH + 1) % QCAP;
    if (n != g_qAT) { g_ringA[g_qAH] = *c; g_qAH = n; ok = TRUE; }
    LeaveCriticalSection(&g_cs);
    return ok;
}
static BOOL QPopA(Cmd* o) {
    BOOL ok = FALSE;
    EnterCriticalSection(&g_cs);
    if (g_qAT != g_qAH) { *o = g_ringA[g_qAT]; g_qAT = (g_qAT + 1) % QCAP; ok = TRUE; }
    LeaveCriticalSection(&g_cs);
    return ok;
}

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
    char buf[128]; char* p = buf; const char* hx = "0123456789abcdef";
    int k = lstrlenA(label); if (k > 60) k = 60;
    for (int i = 0; i < k; i++) p[i] = label[i]; p += k;
    for (int i = 0; i < n && p < buf + 120; i++) { *p++ = hx[b[i] >> 4]; *p++ = hx[b[i] & 0xF]; *p++ = ' '; }
    *p = 0; LogL(buf);
}

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
static int WrFresh(unsigned char* obj, u64 off, const char* data, int len);
static int WrStr(unsigned char* obj, u64 off, const char* data, int len) {
    unsigned char* p = obj + off;
    u64 cap = *(u64*)(p + 0x18);
    if ((u64)len <= cap) {
        unsigned char* buf = (*(u64*)(p + 0x18) > 15) ? *(unsigned char**)p : p;
        if (!buf) return 0;
        for (int i = 0; i < len; i++) buf[i] = (unsigned char)data[i];
        buf[len] = 0;
        *(u64*)(p + 0x10) = (u64)len;
        return 1;
    }
    // len > cap: 分配新堆缓冲区 (UCRT 同堆, 微信 operator delete 兼容)
    return WrFresh(obj, off, data, len);
}
// 总是分配全新堆缓冲, 不读不写旧缓冲 (冲刷路径专用: 嵌套管线可能已接管旧缓冲)
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

// UUIDv4 生成 (36 字符含连字符, 小写) — 嵌套发送用全新 clientMsgId, 避免与外层真实消息去重冲突
static unsigned int g_rnd = 0;
static void GenUuid(char out[37]) {
    if (!g_rnd) g_rnd = (unsigned int)GetTickCount64() ^ 0x9E3779B9u;
    unsigned char b[16];
    for (int i = 0; i < 16; i++) {
        g_rnd ^= g_rnd << 13; g_rnd ^= g_rnd >> 17; g_rnd ^= g_rnd << 5;
        b[i] = (unsigned char)g_rnd;
    }
    b[6] = (unsigned char)((b[6] & 0x0F) | 0x40);   // version 4
    b[8] = (unsigned char)((b[8] & 0x3F) | 0x80);   // variant 10
    static const char hx[] = "0123456789abcdef";
    static const int dash[16] = {0,0,0,0,1,0,0,0,2,0,0,0,3,0,0,0};
    int p = 0;
    for (int i = 0; i < 16; i++) {
        if (dash[i]) out[p++] = '-';
        out[p++] = hx[b[i] >> 4];
        out[p++] = hx[b[i] & 0xF];
    }
    out[p] = 0;
}

static volatile u64 g_hits2;
void* volatile g_mgr2;
static DWORD volatile g_tid2;
unsigned char* g_tramp2;
unsigned char* g_procTramp;
unsigned char* g_waitTramp;

static void ReleaseSp(SP* sp);
static volatile u64 g_autoN = 0;
static volatile u64 g_factTest = 0;  // FACTTEST: 单次工厂路径分步诊断
static volatile u64 g_busy = 0;      // 冲刷重入保护
static volatile u64 g_up1Tick = 0;   // 最近一次 UP1 命中时刻 (10s 静默闸)
static volatile u64 g_sendOpts = 0;   // UP1 命中瞬间捕获的 options (发送协程执行器, 持久)
static volatile u64 g_engine = 0;
static volatile u64 g_savedSPPtr = 0;  // v63: 会话协程 SP 槽指针
static void* g_bodyFn = 0;             // v63: 协程 body 函数指针 (CoCreate P2)
static void* g_cleanupFn = 0;          // v63: cleanup 函数指针 (CoCreate P4, null=无)
typedef void (*CoCreateFn)(SP* out, void* P2, void* P3, void* P4, void* P5);
typedef void (*SchedFn)(SP* sp, u64 val);
#define COCREATE_RVA 0x45FCC0ULL
#define SCHED_RVA    0x45FF50ULL

static void FactoryFlush(Cmd* a);
// v64: 协程 body — 在框架调度的协程上下文中执行 FactoryFlush
static void FlushBodyForCo(void* arg) {
    Cmd* a = (Cmd*)arg;
    if (!a) return;
    FactoryFlush(a);
    HeapFree(GetProcessHeap(), 0, a);
}     // UP1 线程当前协程的引擎指针 (coro+0x370)
extern volatile u64 g_capOpts;
extern volatile u64 g_capValid;

volatile u64 g_flagLast = 0;   // 最近一次真实 UP1 调用的 flag (r9)

void C_helper(void* p3, u64 flag) {
    g_hits2++;
    g_up1Tick = GetTickCount64();
    // v61: v54 静默标志移除 — TLS+0x360 bit0 = "使用线程本地 locale" 标志,
    // 置位后时间戳格式化读到空 locale → 故意陷阱 (0xFEA90) = v54-v56 崩溃真因!
    // v63: 捕获会话协程的 SP 槽指针 (TLS+0x1F0) — 劫持时恢复给 UP1 管线的 GetCtx
    {
        u64 tlsarr2 = 0, blk2 = 0;
        __asm__ volatile("movq %%gs:0x58, %0" : "=r"(tlsarr2));
        u32 ti2 = *(u32*)(g_base + 0xB5D6A70);
        blk2 = *(u64*)(tlsarr2 + (u64)ti2 * 8);
        if (blk2) g_savedSPPtr = *(u64*)(blk2 + 0x1F0);   // &{coro, ctrl} = 会话协程 SP
    }
    // v65: 读取 CoCreate 钩子捕获的 options 指针
    if (g_capValid && g_capOpts) g_sendOpts = g_capOpts;
    // v46: UP1 命中瞬间, 最近一次 CoCreate 的 options 就是发送协程的 (执行器持久)
    if (g_capValid) g_sendOpts = g_capOpts;
    g_flagLast = flag;
    g_tid2 = GetCurrentThreadId();
    void** sp = (void**)p3;
    if (!sp) return;
    unsigned char* obj = (unsigned char*)sp[0];
    if (!obj) return;
    if (*(void**)obj != (void*)((u64)g_base + VT_RVA)) return;

    // v64: AUTO 队列 → CoCreate 派生协程 (在当前线程的 CRT/locale 上下文中创建)
    // 协程排队后由执行器在管线完成后运行 = 完全无触发自主发送
    CoCreateFn cocreate = (CoCreateFn)(g_base + COCREATE_RVA);
    SchedFn sched = (SchedFn)(g_base + SCHED_RVA);
    UP1_fn up1_n = (UP1_fn)(g_base + UP1_RVA);
    Cmd a;
    while (QPopA(&a)) {
        // CoCreate: 创建协程, body = FlushBodyForCo, arg = heapCmd, options = 捕获的
        Cmd* heapCmd = (Cmd*)HeapAlloc(GetProcessHeap(), 0, sizeof(Cmd));
        if (!heapCmd) { LogL("[SPAWN] alloc fail"); continue; }
        *heapCmd = a;
        static void* bodyHolder = 0;
        if (!bodyHolder) bodyHolder = (void*)&FlushBodyForCo;
        void* argHolder = (void*)heapCmd;
        static void* cleanupHolder = 0;   // null = 无清理 (协程完成后泄漏 Cmd, 可接受)
        SP sp2;
        // v65: 使用 CoCreate 钩子捕获的真实 options 指针 (正确初始化协程 ✓)
        if (!g_sendOpts) { LogL("[SPAWN] no captured opts"); HeapFree(GetProcessHeap(),0,heapCmd); continue; }
        cocreate(&sp2, &bodyHolder, &argHolder, &cleanupHolder, (void*)g_sendOpts);
        if (!sp2.obj) { LogL("[SPAWN] cocreate fail"); HeapFree(GetProcessHeap(),0,heapCmd); continue; }
        LogL("[SPAWN] cocreate ok, scheduling");
        sched(&sp2, 0);                   // resume_if → 排队 → 执行器线程在管线完成后运行
        LogL("[SPAWN] scheduled");
        // sp2 不释放 (框架持有引用, 我们泄漏以防过早析构)
    }

    // v62: SEND/AUTO 队列克隆嵌套发送 (触发式批量, 与 CoCreate 派生并行的备用路径)
    Cmd a2;
    while (QPopA(&a2)) {
        unsigned char* clone = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x798);
        if (!clone) { LogL("[CLONE] alloc fail"); continue; }
        memcpy(clone, obj, 0x798);
        // 深拷贝已知字符串 (内容/目标/UUID), 其余内部指针共享原始对象 (引用安全)
        WrFresh(clone, 0x758, a2.content, a2.contentLen);
        if (a2.targetLen > 0) WrFresh(clone, 0xB0, a2.target, a2.targetLen);
        char au[37]; GenUuid(au);
        WrFresh(clone, 0x6F8, au, 36);
        void* csp[2] = {clone, NULL};   // ctrl=NULL → 框架跳过引用计数, 克隆由管线管理
        LogL("[CLONE] calling UP1 flag=1");
        u64 aout[2] = {0, 0};
        up1_n(g_mgr2, aout, (void*)csp, (int)(g_flagLast & 1));
        LogL("[CLONE] UP1 returned");
        g_rw++;
    }

    // SEND 搭车改写 (M3 语义)
    Cmd tmp;
    if (!QPop(&tmp)) return;   // 无搭车命令 → 用户消息原样发送
    WrFresh(obj, 0x758, tmp.content, tmp.contentLen);
    if (tmp.targetLen > 0) WrFresh(obj, 0xB0, tmp.target, tmp.targetLen);
    if (tmp.flags) {           // SEND2 语义: 替换 clientMsgId
        char u[37]; GenUuid(u);
        WrFresh(obj, 0x6F8, u, 36);
    }
    g_rw++;
    LogL("[FLUSH] rewrite dispatched");
}

// ==== AUTO: 派发线程处理器钩子 — 微信自发任务(心跳/收消息)触发, 无需用户发送 ====



// shared_ptr 释放 (镜像反编译中的 ctrl block 模式: dec strong@+8 → dtor → dec weak@+0xC → dtor ctrl)
static void ReleaseSp(SP* sp) {
    void* ctrl = sp->ctrl;
    if (!ctrl) return;
    long* strong = (long*)((unsigned char*)ctrl + 8);
    long* weak = (long*)((unsigned char*)ctrl + 0xC);
    void** vt = *(void***)ctrl;
    if (--(*strong) == 0) {
        ((void(*)(void*))vt[0])(ctrl);
        if (--(*weak) == 0) ((void(*)(void*))vt[1])(ctrl);
    }
}

// v39: 等待钩子空闲冲刷 —— 仅当线程 park 在池空闲循环 (retaddr == 0x73225D1)
// 且为 UP1 线程时才冲刷; 管线中途的等待一律跳过 (v32 深重入教训)
// UP1 入口冲刷也废除 (v38: 外层 body 紧随嵌套调用后必崩) → 用户消息零接触
#define POOL_WAIT_RET 0x73225D1ULL

static void FactoryFlush(Cmd* a);
static void SpawnFlush(Cmd* a);
static void SpawnFlushWith(Cmd* a, u64 optsP5);
static void FactoryFlush(Cmd* a) {
    LogL("[AUTO] step1: calling factory");
    FactoryFn fac = (FactoryFn)(g_base + FAC_RVA);
    UP1_fn up1f = (UP1_fn)(g_base + UP1_RVA);
    SP fsp; memset(&fsp, 0, sizeof(fsp));
    fsp = fac();
    LogHex("[AUTO] step2: factory obj=", (u64)fsp.obj);
    if (!fsp.obj) { LogL("[AUTO] factory null"); return; }
    unsigned char* fo = (unsigned char*)fsp.obj;
    if (*(void**)fo != (void*)((u64)g_base + VT_RVA)) { LogL("[AUTO] vtable mismatch"); ReleaseSp(&fsp); return; }
    LogL("[AUTO] step3: vtable ok");
    WrFresh(fo, 0xB0, a->target, a->targetLen);
    WrFresh(fo, 0x758, a->content, a->contentLen);
    char fu[37]; GenUuid(fu);
    WrFresh(fo, 0x6F8, fu, 36);
    LogL("[AUTO] step4: filled, calling UP1 flag=1");
    u64 fout[2] = {0, 0};
    up1f(g_mgr2, fout, (void*)&fsp, 1);
    LogL("[AUTO] step5: UP1 returned");
    ReleaseSp(&fsp);
    g_autoN++;
    g_rw++;
}

// ==== v41: 协程派生 —— 把冲刷包装成协程任务, worker 线程以合法上下文执行 ====
// CoCreate(out, &body, &arg, &cleanup, &options): body→coro+0x350, arg→coro+0x360, cleanup(可空)→+0x358
// resume_if(&sp, 0): 把协程投递到 worker 池; 协程内 TLS+0x1F0 = 本协程, 管线上下文合法
typedef void (*CoCreateFn)(SP* out, void* P2, void* P3, void* P4, void* P5);
typedef void (*SchedFn)(SP* sp, u64 val);

// ==== v42: CoCreate 捕获钩子 — 纯 asm 记录微信自己传的 P5 (合法 options, 含 executor) ====
volatile u64 g_capOpts = 0;      // 最近一次 CoCreate 的第5参 (options 指针)
volatile u64 g_capValid = 0;
unsigned char* g_coTramp = 0;

void __fastcall C_coHook(void* dummy, u64 retaddr);
extern void cocreate_stub(void);
__asm__(
".text\n"
".globl cocreate_stub\n"
"cocreate_stub:\n"
"  mov 0x28(%rsp), %rax\n"        // 第5参 (P5/options) 在栈上
"  mov %rax, g_capOpts(%rip)\n"
"  movq $1, g_capValid(%rip)\n"
"  push %rcx\n"
"  push %rdx\n"
"  push %r8\n"
"  push %r9\n"
"  sub $0x28, %rsp\n"
"  mov %rax, %rdx\n"
"  xor %ecx, %ecx\n"
"  call C_coHook\n"
"  add $0x28, %rsp\n"
"  pop %r9\n"
"  pop %r8\n"
"  pop %rdx\n"
"  pop %rcx\n"
"  mov g_coTramp(%rip), %rax\n"
"  jmp *%rax\n"
);

// v57b: 日志开关总闸 — FUN_180d9e810 永远返回 0 (所有 co 框架日志跳过)
static BOOL InstallLogOff(void) {
    unsigned char* fn = g_base + 0xD9E810ULL;
    unsigned char exp[3] = {0x8B, 0x44, 0x24};  // 占位, 实际下面动态验证前3字节
    unsigned char orig[3];
    for (int i = 0; i < 3; i++) orig[i] = fn[i];
    DWORD old;
    if (!VirtualProtect(fn, 3, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    unsigned char pat[3] = {0x31, 0xC0, 0xC3};  // xor eax,eax; ret
    for (int i = 0; i < 3; i++) fn[i] = pat[i];
    DWORD t2; VirtualProtect(fn, 3, old, &t2);
    FlushInstructionCache(GetCurrentProcess(), fn, 3);
    LogL("[LOGOFF] installed");
    return TRUE;
}

static BOOL InstallCoHook(void) {
    unsigned char* fn = g_base + COCREATE_RVA;
    static const unsigned char exp[STOLEN4] = {
        0x56,0x57,0x48,0x83,0xEC,0x58,
        0x48,0x89,0xCE,
        0x48,0x8B,0x84,0x24,0x90,0x00,0x00,0x00};
    unsigned char orig[STOLEN4];
    for (int i = 0; i < STOLEN4; i++) {
        orig[i] = fn[i];
        if (orig[i] != exp[i]) { LogBytes("[COHOOK] actual bytes: ", orig, STOLEN4); return FALSE; }
    }
    g_coTramp = (unsigned char*)VirtualAlloc(NULL, 64, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_coTramp) return FALSE;
    for (int i = 0; i < STOLEN4; i++) g_coTramp[i] = orig[i];
    g_coTramp[STOLEN4] = 0xFF; g_coTramp[STOLEN4+1] = 0x25;
    for (int i = 0; i < 4; i++) g_coTramp[STOLEN4+2+i] = 0;
    u64 back = (u64)(fn + STOLEN4);
    for (int i = 0; i < 8; i++) g_coTramp[STOLEN4+6+i] = (unsigned char)(back >> (i*8));
    DWORD old;
    if (!VirtualProtect(fn, STOLEN4, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    unsigned char pat[12];
    pat[0] = 0x48; pat[1] = 0xB8;
    u64 s = (u64)(ULONG_PTR)&cocreate_stub;
    for (int i = 0; i < 8; i++) pat[2+i] = (unsigned char)(s >> (i*8));
    pat[10] = 0xFF; pat[11] = 0xE0;
    for (int i = 0; i < 12; i++) fn[i] = pat[i];
    DWORD t2; VirtualProtect(fn, STOLEN4, old, &t2);
    FlushInstructionCache(GetCurrentProcess(), fn, STOLEN4);
    LogL("[COHOOK] installed");
    return TRUE;
}

static void FlushBody(void* arg) {
    Cmd* a = (Cmd*)arg;
    FactoryFlush(a);
    HeapFree(GetProcessHeap(), 0, a);
}

unsigned char* g_throwTramp = 0;
static volatile LONG g_throwLogN = 0;

void __fastcall C_ThrowLog(void* dummy, u64 retaddr);
extern void throw_stub(void);
__asm__(
".text\n"
".globl throw_stub\n"
"throw_stub:\n"
"  mov (%rsp), %rax\n"
"  push %rcx\n"
"  push %rdx\n"
"  push %r8\n"
"  push %r9\n"
"  sub $0x28, %rsp\n"
"  mov %rax, %rdx\n"
"  xor %ecx, %ecx\n"
"  call C_ThrowLog\n"
"  add $0x28, %rsp\n"
"  pop %r9\n"
"  pop %r8\n"
"  pop %rdx\n"
"  pop %rcx\n"
"  mov g_throwTramp(%rip), %rax\n"
"  jmp *%rax\n"
);

void __fastcall C_ThrowLog(void* dummy, u64 retaddr) {
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

unsigned char* g_abortTramp = 0;

// v52: ucrtbase!abort 钩子 — 记录 fastfail 的调用者返回地址 (0xC0000409 无 dump, 只有这样能定位)
void __fastcall C_AbortLog(void* dummy, u64 retaddr);

extern void abort_stub(void);
__asm__(
".text\n"
".globl cocreate_cap_stub\n"
"cocreate_cap_stub:\n"
"  push %rax\n"
"  mov 0x30(%rsp), %rax\n"
"  mov %rax, g_capOpts(%rip)\n"
"  mov %rax, %rcx\n"
"  sub $0x28, %rsp\n"
"  xor %ecx, %ecx\n"
"  call C_CoCapP5\n"
"  add $0x28, %rsp\n"
"  pop %rcx\n"
"  mov g_cocreateTramp(%rip), %rax\n"
"  jmp *%rax\n"
);

;

static void __fastcall C_CoCapP5(void* dummy) {
    (void)dummy;
    if (!g_capValid) {
        g_capValid = 1;
        LogL("[COCAP] options captured");
    }
}

static BOOL InstallCoCreateCap(void) {static BOOL InstallCoCreateCap(void) {
    unsigned char* fn = g_base + COCREATE_HOOK_RVA;
    static const unsigned char exp[COCREATE_STOLEN] = {
        0x56,0x57,0x48,0x83,0xEC,0x58,0x48,0x89,0xCE,
        0x48,0x8B,0x84,0x24,0x90,0x00,0x00,0x00};
    unsigned char orig[COCREATE_STOLEN];
    for (int i = 0; i < COCREATE_STOLEN; i++) {
        orig[i] = fn[i];
        if (orig[i] != exp[i]) { LogBytes("[COCAP] actual bytes: ", orig, COCREATE_STOLEN); return FALSE; }
    }
    g_cocreateTramp = (unsigned char*)VirtualAlloc(NULL, 64, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_cocreateTramp) return FALSE;
    for (int i = 0; i < COCREATE_STOLEN; i++) g_cocreateTramp[i] = orig[i];
    g_cocreateTramp[COCREATE_STOLEN] = 0xFF; g_cocreateTramp[COCREATE_STOLEN+1] = 0x25;
    for (int i = 0; i < 4; i++) g_cocreateTramp[COCREATE_STOLEN+2+i] = 0;
    u64 back = (u64)(fn + COCREATE_STOLEN);
    for (int i = 0; i < 8; i++) g_cocreateTramp[COCREATE_STOLEN+6+i] = (unsigned char)(back >> (i*8));
    DWORD old;
    if (!VirtualProtect(fn, COCREATE_STOLEN, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    unsigned char pat[12];
    pat[0] = 0x48; pat[1] = 0xB8;
    u64 sv = (u64)(ULONG_PTR)&cocreate_cap_stub;
    for (int i = 0; i < 8; i++) pat[2+i] = (unsigned char)(sv >> (i*8));
    pat[10] = 0xFF; pat[11] = 0xE0;
    for (int i = 0; i < 12; i++) fn[i] = pat[i];
    DWORD t2; VirtualProtect(fn, COCREATE_STOLEN, old, &t2);
    FlushInstructionCache(GetCurrentProcess(), fn, COCREATE_STOLEN);
    LogL("[COCAP] installed");
    return TRUE;
}

void __fastcall C_HijackFlush(void* dummy) {
    (void)dummy;
    // v63: 会话上下文移植 — UP1 管线的 GetCtx 读 TLS+0x1F0 (当前协程),
    // park 时 = 0 → GetCtx NULL 崩溃 (0x462C1E)。设为会话协程的 SP 槽指针
    // → GetCtx 返回会话协程 ✓ 管线在合法上下文中运行 ✓
    u64 tlsarr = 0, blk = 0, orig = 0;
    __asm__ volatile("movq %%gs:0x58, %0" : "=r"(tlsarr));
    u32 ti = *(u32*)(g_base + 0xB5D6A70);
    blk = *(u64*)(tlsarr + (u64)ti * 8);
    if (blk && g_savedSPPtr) {
        orig = *(u64*)(blk + 0x1F0);                    // save (likely 0)
        *(u64*)(blk + 0x1F0) = g_savedSPPtr;            // ★ 会话协程 SP 注入!
        LogL("[HIJACK-TLS] session SP injected");
    }
    Cmd t;
    while (QPopA(&t)) FactoryFlush(&t);     // 工厂造对象 + flag=1 全管线发送
    if (blk) *(u64*)(blk + 0x1F0) = orig;           // restore
    InterlockedExchange(&g_hijackPending, 0);
}

extern void hijack_stub(void);
__asm__(
".text\n"
".globl hijack_stub\n"
"hijack_stub:\n"
"  pushfq\n"
"  push %rax\n"
"  push %rcx\n"
"  push %rdx\n"
"  push %rbx\n"
"  push %rbp\n"
"  push %rsi\n"
"  push %rdi\n"
"  push %r8\n"
"  push %r9\n"
"  push %r10\n"
"  push %r11\n"
"  push %r12\n"
"  push %r13\n"
"  push %r14\n"
"  push %r15\n"
"  mov %rsp, %r15\n"
"  and $-16, %rsp\n"
"  sub $0x20, %rsp\n"
"  xor %ecx, %ecx\n"
"  call C_HijackFlush\n"
"  mov %rsp, %r15\n"
"  pop %r15\n"
"  pop %r14\n"
"  pop %r13\n"
"  pop %r12\n"
"  pop %r11\n"
"  pop %r10\n"
"  pop %r9\n"
"  pop %r8\n"
"  pop %rdi\n"
"  pop %rsi\n"
"  pop %rbp\n"
"  pop %rbx\n"
"  pop %rdx\n"
"  pop %rcx\n"
"  pop %rax\n"
"  popfq\n"
"  jmp *g_hijackRet(%rip)\n"
);

// 劫持注入线程: AUTO 队列有货时反复尝试劫持 UP1 线程
static DWORD WINAPI HijackThread(LPVOID p) {
    (void)p;
    for (;;) {
        if (g_qAH != g_qAT && g_mgr2 && g_tid2 && !g_hijacking) {   // 队列有货即触发 (不依赖 CoCreate 钩子)
            HANDLE h = OpenThread(THREAD_ALL_ACCESS, FALSE, g_tid2);
            if (h) {
                if (SuspendThread(h) != (DWORD)-1) {
                    CONTEXT ctx;
                    memset(&ctx, 0, sizeof(ctx));
                    ctx.ContextFlags = 0x100005;   // CONTEXT_FULL
                    if (GetThreadContext(h, &ctx)) {
                        // v64: 移除 park 位置检查 — SuspendThread 已确保线程一致性,
                        // 会话 SP 注入解决 GetCtx NULL, LOGOFF 解决日志崩溃
                        u64 found = 1;
                        static LONG parkDbg = 0;
                        if (InterlockedIncrement(&parkDbg) <= 3) {
                            char b2[128]; char* p2 = b2; const char* hx = "0123456789abcdef";
                            const char* s2 = "[PARK] rsp0=";
                            for (int k = 0; s2[k]; k++) p2[k] = s2[k]; p2 += 12;
                            u64 rv = ctx.Rsp - (u64)g_base;
                            for (int k = 15; k >= 0; k--) *p2++ = hx[(rv >> (k*4)) & 0xF];
                            *p2++ = ' ';
                            for (int i = 0; i < 16; i++) {
                                u64 v = *(u64*)(ctx.Rsp + i*8);
                                u64 r2 = (v >= (u64)g_base && v < (u64)g_base + 0x7400000) ? v - (u64)g_base : 0xFFFFFFFFFFFFFFFFULL;
                                for (int k = 7; k >= 0; k--) *p2++ = hx[(r2 >> (k*4)) & 0xF];
                                *p2++ = ' ';
                            }
                            *p2 = 0;
                            LogL(b2);
                        }
                        if (found) {
                            g_hijackRet = ctx.Rip;           // 跳回目标
                            ctx.Rip = (u64)&hijack_stub;      // RIP → 桩
                            if (SetThreadContext(h, &ctx)) {
                                LogL("[HIJACK] dispatched");
                                ResumeThread(h);
                                // 桩执行完自动跳回, 线程继续; 等刷完再允许下一轮
                                while (g_hijackPending) Sleep(50);
                            } else {
                                ResumeThread(h);
                                LogL("[HIJACK] setctx fail");
                            }
                        } else {
                            ResumeThread(h);   // 未 park 在等待点 → 稍后重试
                        }
                    } else {
                        ResumeThread(h);
                    }
                }
                CloseHandle(h);
            }
        }
        Sleep(150);
    }
    return 0;
}

static volatile LONG g_hookBusy = 0;

// CoCreate 钩子回调: 微信每次派生协程时, 借同线程同状态派生我们自己的冲刷协程
void __fastcall C_coHook(void* dummy, u64 optsP5) {
    (void)dummy;
    if (!g_base || !g_tid2) return;
    // v49: 仅当 CoCreate 发生在 UP1 线程时捕获 options —— 执行器与派生线程亲和一致
    // (v45/v46 用随机后台线程的 options → 线程亲和断言 abort)
    if (GetCurrentThreadId() == g_tid2 && optsP5) g_sendOpts = optsP5;
    if (g_qAH == g_qAT) return;                 // 热路径快速退出
    if (!g_mgr2) return;                        // mgr 未武装
    if (!g_sendOpts) return;                    // 尚无 UP1 线程执行器
    if (GetCurrentThreadId() != g_tid2) return; // 派发仅限 UP1 线程
    if (GetTickCount64() - g_up1Tick < 10000) return;      // 10s 静默闸: 杜绝管线中途派生 (v44 红感叹号教训)
    // v58: 不再在 CoCreate 钩子里 spawn — 改由 HijackThread 劫持 UP1 线程执行
    if (g_tid2 && GetCurrentThreadId() == g_tid2) InterlockedExchange(&g_hijackPending, 1);
}

static void SpawnFlushWith(Cmd* a, u64 optsP5) {
    static void* bodyHolder = (void*)&FlushBody;  // *P2 → coro+0x350 (body)
    void* argHolder = (void*)a;                    // *P3 → coro+0x360 (arg)
    static void* cleanupHolder = 0;                // *P4 → coro+0x358 (可空清理回调)
    SP sp;
    CoCreateFn cocreate = (CoCreateFn)(g_base + COCREATE_RVA);
    // v47: P5 = 本次 CoCreate 调用的实参 (微信此刻正在用它, 执行器必然有效)
    cocreate(&sp, &bodyHolder, &argHolder, &cleanupHolder, (void*)optsP5);
    if (!sp.obj) { LogL("[SPAWN] cocreate fail"); return; }
    // v56: 全量转储派生协程 (0x510) → 与真实协程 diff 找缺失字段
    {
        HANDLE f = CreateFileA("E:\weixin-hook-4.1.8\hook-wx\m3\spawned_coro.bin",
            GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            DWORD w = 0;
            WriteFile(f, sp.obj, 0x510, &w, NULL);
            CloseHandle(f);
            LogL("[SPAWN] coro dumped 0x510 bytes");
        }
    }
    // v48: 自填协程自引用 SP (inner[0]=inner, inner[1]=ctrl)
    // CoroutineSpawn 清零了 inner+0x00/+0x08, 微信自己的流程后续会填 {inner, outer};
    // 我们不填 → resume_if 读 inner[1]==0 abort(静默闪退), 或 TLS 槽悬挂 → GetCtx AV(0x462C1E)
    // 借用 CoCreate 返回的那份引用(我们不释放) = 自引用计数成立
    *(void**)sp.obj = sp.obj;
    *(void**)((unsigned char*)sp.obj + 8) = sp.ctrl;
    // v57: 移植引擎指针 (真实协程 +0x370) — 派生协程缺它 = do_resume_now 引擎虚表调用 NULL 崩溃
    if (g_engine) *(u64*)((unsigned char*)sp.obj + 0x370) = g_engine;
    // v50: 协程状态初值 — 真实协程 state 只见 1(排队)/2(运行)/3(结束), spawn 清零为 0 = 非法
    // 执行器处理 resume-item 时对非法 state 抛 co_exception → 未捕获 → terminate
    *(int*)((unsigned char*)sp.obj + 0x388) = 1;
    SchedFn sched = (SchedFn)(g_base + SCHED_RVA);
    sched(&sp, 0);
    LogL("[SPAWN] coroutine scheduled");
    // 不释放引用: 防队列中协程被过早析构 (v42 延时崩教训); 每条泄漏 ~1.3KB
}

void C_auto(void* dummy, u64 retaddr) {
    (void)dummy; (void)retaddr;  // v44: 等待钩子已撤除

}

extern void auto_stub(void);
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
"  call C_auto\n"
"  add $0x30, %rsp\n"
"  pop %r10\n"
"  pop %r9\n"
"  pop %r8\n"
"  pop %rdx\n"
"  pop %rcx\n"
"  mov g_waitTramp(%rip), %rax\n"
"  jmp *%rax\n"
);
__asm__(
".text\n"
".globl auto_stub\n"
"auto_stub:\n"
"  push %rcx\n"
"  push %rdx\n"
"  push %r8\n"
"  push %r9\n"
"  sub $0x28, %rsp\n"
"  xor %ecx, %ecx\n"
"  call C_auto\n"
"  add $0x28, %rsp\n"
"  pop %r9\n"
"  pop %r8\n"
"  pop %rdx\n"
"  pop %rcx\n"
"  mov g_procTramp(%rip), %rax\n"
"  jmp *%rax\n"
);

static BOOL InstallProcHook(void) {
    unsigned char* fn = g_base + PROC_RVA;
    static const unsigned char exp[STOLEN2] = {
        0x55,0x56,0x57,0x48,0x81,0xEC,0xD0,0x00,0x00,0x00,
        0x48,0x8D,0xAC,0x24,0x80,0x00,0x00,0x00,
        0x48,0xC7,0x45,0x48,0xFE,0xFF,0xFF,0xFF};
    unsigned char orig[STOLEN2];
    for (int i = 0; i < STOLEN2; i++) {
        orig[i] = fn[i];
        if (orig[i] != exp[i]) { LogBytes("[PROCHOOK] actual bytes: ", orig, STOLEN2); return FALSE; }
    }
    g_procTramp = (unsigned char*)VirtualAlloc(NULL, 64, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_procTramp) return FALSE;
    for (int i = 0; i < STOLEN2; i++) g_procTramp[i] = orig[i];
    g_procTramp[STOLEN2] = 0xFF; g_procTramp[STOLEN2+1] = 0x25;
    for (int i = 0; i < 4; i++) g_procTramp[STOLEN2+2+i] = 0;
    u64 back = (u64)(fn + STOLEN2);
    for (int i = 0; i < 8; i++) g_procTramp[STOLEN2+6+i] = (unsigned char)(back >> (i*8));
    DWORD old;
    if (!VirtualProtect(fn, STOLEN2, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    unsigned char pat[12];
    pat[0] = 0x48; pat[1] = 0xB8;
    u64 s = (u64)(ULONG_PTR)&auto_stub;
    for (int i = 0; i < 8; i++) pat[2+i] = (unsigned char)(s >> (i*8));
    pat[10] = 0xFF; pat[11] = 0xE0;
    for (int i = 0; i < 12; i++) fn[i] = pat[i];
    DWORD t2; VirtualProtect(fn, STOLEN2, old, &t2);
    FlushInstructionCache(GetCurrentProcess(), fn, STOLEN2);
    LogL("[PROCHOOK] installed");
    return TRUE;
}

static BOOL InstallWaitHook(void) {
    unsigned char* fn = g_base + WAIT_RVA;
    static const unsigned char exp[STOLEN3] = {
        0x48,0x89,0x7C,0x24,0x10, 0x41,0xBA,0x40,0x80,0x00,0x00,
        0x33,0xD2, 0x0F,0xAE,0x5C,0x24,0x08};
    unsigned char orig[STOLEN3];
    for (int i = 0; i < STOLEN3; i++) {
        orig[i] = fn[i];
        if (orig[i] != exp[i]) { LogBytes("[WAITHOOK] actual bytes: ", orig, STOLEN3); return FALSE; }
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

extern void hook_stub(void);
__asm__(
".text\n"
".globl hook_stub\n"
"hook_stub:\n"
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
"  mov g_tramp2(%rip), %rax\n"
"  jmp *%rax\n"
);

static BOOL InstallHook(void) {
    g_up1 = g_base + UP1_RVA;
    for (int i = 0; i < STOLEN; i++) g_orig[i] = g_up1[i];
    static const unsigned char exp[STOLEN] = {
        0x55,0x41,0x57,0x41,0x56,0x56,0x57,0x53,0x48,0x83,0xEC,0x78,0x48,0x8D,0x6C,0x24,0x70};
    for (int i = 0; i < STOLEN; i++) { if (g_orig[i] != exp[i]) { LogBytes("[HOOK] actual UP1 bytes: ", g_orig, STOLEN); return FALSE; } }
    g_tramp2 = (unsigned char*)VirtualAlloc(NULL, 64, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_tramp2) return FALSE;
    for (int i = 0; i < STOLEN; i++) g_tramp2[i] = g_orig[i];
    g_tramp2[STOLEN] = 0xFF; g_tramp2[STOLEN+1] = 0x25;
    g_tramp2[STOLEN+2] = 0; g_tramp2[STOLEN+3] = 0; g_tramp2[STOLEN+4] = 0; g_tramp2[STOLEN+5] = 0;
    u64 back = (u64)(g_up1 + STOLEN);
    for (int i = 0; i < 8; i++) g_tramp2[STOLEN+6+i] = (unsigned char)(back >> (i*8));
    DWORD old;
    if (!VirtualProtect(g_up1, STOLEN, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    unsigned char pat[12];
    pat[0] = 0x48; pat[1] = 0xB8;
    u64 s = (u64)(ULONG_PTR)&hook_stub;
    for (int i = 0; i < 8; i++) pat[2+i] = (unsigned char)(s >> (i*8));
    pat[10] = 0xFF; pat[11] = 0xE0;
    for (int i = 0; i < 12; i++) g_up1[i] = pat[i];
    DWORD t2; VirtualProtect(g_up1, STOLEN, old, &t2);
    FlushInstructionCache(GetCurrentProcess(), g_up1, STOLEN);
    return TRUE;
}

// v27: SyncStage 钩子已移除 —— 双补丁触发保护器击杀 (15:05 崩溃), 只保留已验证稳定的单 UP1 补丁

static void HandleClient(HANDLE pipe) {
    char req[4352]; DWORD got = 0;
    int pos = 0; char ch;
    while (pos < (int)sizeof(req) - 1) {
        if (!ReadFile(pipe, &ch, 1, &got, NULL) || got == 0) break;
        if (ch == '\n') break;
        req[pos++] = ch;
    }
    req[pos] = 0;
    char resp[64] = "ERR\n";
    if (pos >= 6 && req[0]=='A' && req[1]=='U' && req[2]=='T' && req[3]=='O' && req[4]=='|') {
        // AUTO|target|b64 — 自主发送: 无需用户触发, 由派发线程处理器钩子冲刷
        char* p2 = req + 5;
        char* sep = p2; while (*sep && *sep != '|') sep++;
        if (*sep == '|') {
            *sep = 0;
            char* b64 = sep + 1;
            Cmd cmd; cmd.targetLen = 0; cmd.flags = 2;
            for (char* s = p2; *s && cmd.targetLen < (int)sizeof(cmd.target)-1; s++) cmd.target[cmd.targetLen++] = *s;
            cmd.target[cmd.targetLen] = 0;
            cmd.contentLen = B64D(b64, lstrlenA(b64), cmd.content, (int)sizeof(cmd.content)-1);
            if (cmd.contentLen >= 0) {
                cmd.content[cmd.contentLen] = 0;
                if (QPushA(&cmd)) lstrcpyA(resp, "OK auto queued (hook drains)\n");
                else lstrcpyA(resp, "ERR full\n");
            } else lstrcpyA(resp, "ERR b64\n");
        }
    } else if (pos >= 6 && req[0]=='S' && req[1]=='E' && req[2]=='N' && req[3]=='D' && (req[4]=='|' || req[4]=='2')) {
        char* p2 = req + (req[4] == '2' ? 6 : 5);   // SEND2|target|b64 → flags=1 (全新 clientMsgId)
        char* sep = p2; while (*sep && *sep != '|') sep++;
        if (*sep == '|') {
            *sep = 0;
            char* b64 = sep + 1;
            Cmd cmd; cmd.targetLen = 0; cmd.flags = (req[4] == '2') ? 1 : 0;
            for (char* s = p2; *s && cmd.targetLen < (int)sizeof(cmd.target)-1; s++) cmd.target[cmd.targetLen++] = *s;
            cmd.target[cmd.targetLen] = 0;
            cmd.contentLen = B64D(b64, lstrlenA(b64), cmd.content, (int)sizeof(cmd.content)-1);
            if (cmd.contentLen >= 0) { cmd.content[cmd.contentLen] = 0; if (QPush(&cmd)) lstrcpyA(resp, "OK\n"); else lstrcpyA(resp, "ERR full\n"); }
            else lstrcpyA(resp, "ERR b64\n");
        }
    } else if (pos == 4 && req[0]=='F' && req[1]=='A' && req[2]=='C' && req[3]=='T') {
        g_factTest = 1;
        lstrcpyA(resp, "OK facttest armed\n");
    } else if (pos == 6 && req[0]=='S') {
        wsprintfA(resp, "OK hits=%I64u rw=%I64u q=%ld\r\n", g_hits2, g_rw, (g_qH-g_qT+QCAP)%QCAP);
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

static DWORD WINAPI InitThread(LPVOID p) {
    (void)p;
    LogL("=== wx_send.dll loaded ===");
    for (int i = 0; i < 120; i++) {
        HMODULE h = GetModuleHandleW(L"Weixin.dll");
        if (h) { g_base = (unsigned char*)h; break; }
        Sleep(500);
    }
    if (!g_base) { LogL("[INIT] no Weixin.dll"); return 1; }
    LogHex("[INIT] base=", (u64)g_base);
    InitializeCriticalSection(&g_cs);
    if (!InstallHook()) { LogL("[INIT] hook failed"); return 1; }
    LogHex("[INIT] UP1 hooked @", (u64)g_up1);
    // v60b: 仅保留 UP1 单补丁 (M3 稳定配置) — 多补丁触发保护器 .text 完整性查杀
    // CoCreate 钩子移除 (FactoryFlush 路径不需要); 日志总闸移除 (与崩溃无关)
// v54: Throw/Abort 诊断钩子移除 (零触发 + 保护器诱饵)
    {
        void* pv = (void*)&C_Veh;
        if (!AddVectoredExceptionHandler(1, pv)) LogL("[INIT] veh failed");
    if (!InstallCoHook()) LogL("[INIT] co hook failed");
    if (!InstallLogOff()) LogL("[INIT] logoff failed");
    if (!InstallThrowHook()) LogL("[INIT] throw hook failed");
    if (!InstallAbortHook()) LogL("[INIT] abort hook failed");

        else LogL("[VEH] installed");
    }
    // v32: 处理器钩子撤除 (0x19D14C0 非热路径无触发价值, 且 3 补丁触发保护器)

    // v63: HijackThread 启动 (v61 误删, 现恢复)
    {
        HANDLE ht = CreateThread(NULL, 0, HijackThread, NULL, 0, NULL);
        if (ht) CloseHandle(ht);
    }
    HANDLE t = CreateThread(NULL, 0, PipeThread, NULL, 0, NULL);
    if (t) CloseHandle(t);
    LogL("[INIT] ready");
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInst);
        HANDLE t = CreateThread(NULL, 0, InitThread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
