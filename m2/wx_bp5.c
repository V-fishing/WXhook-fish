// wx_bp5.c — M2 四断点消息管线测绘
// DR0: SaveSendMessagesAtOnce xref   (发送)
// DR1: CoAddMessageListToDB xref     (入库)
// DR2: SendMsgFailed xref            (发送失败)
// DR3: GetAddSendMessageToDb xref    (服务端同步)
// 每个命中: 记录寄存器 + 栈上返回地址链
// 编译: gcc -O2 -shared -o wx_bp5.dll wx_bp5.c

#include <windows.h>
#include <tlhelp32.h>

#define CTX_FLAGS (0x0010001B)

// 四个 xref 点的 RVA (.text: file + 0xC00)
static DWORD64 g_rvas[4] = {
    0x17A1575ULL,   // DR0 SaveSendMessagesAtOnce
    0x17A012EULL,   // DR1 CoAddMessageListToDB
    0x17CA6F9ULL,   // DR2 SendMsgFailed
    0x17F5237ULL,   // DR3 GetAddSendMessageToDb
};
static const char* g_names[4] = {
    "DR0 SaveSendMessagesAtOnce",
    "DR1 CoAddMessageListToDB",
    "DR2 SendMsgFailed",
    "DR3 GetAddSendMessageToDb",
};
static DWORD64 g_targets[4] = {0, 0, 0, 0};

static HANDLE g_logFile = NULL;
static LONG volatile g_totalHits = 0;
static LONG volatile g_done = 0;
static PVOID g_veh = NULL;
static DWORD g_myPid = 0;
static DWORD g_myTid = 0;
static DWORD g_armed[1024];
static int g_armedCount = 0;
static DWORD64 g_wxBase = 0;

static void LogLine(const char* text)
{
    if (!g_logFile) return;
    DWORD w;
    WriteFile(g_logFile, text, lstrlenA(text), &w, NULL);
}

static void LogHex64(const char* label, DWORD64 v)
{
    if (!g_logFile) return;
    DWORD w;
    WriteFile(g_logFile, label, lstrlenA(label), &w, NULL);
    char buf[19];
    buf[0]='0'; buf[1]='x';
    for (int i=0;i<16;i++){int n=(int)((v>>((15-i)*4))&0xF);buf[2+i]=(char)(n<10?'0'+n:'A'+n-10);}
    buf[18]=0;
    WriteFile(g_logFile, buf, 18, &w, NULL);
    WriteFile(g_logFile, "\r\n", 2, &w, NULL);
}

static void LogStackAndRegs(PCONTEXT ctx, int which)
{
    char line[160];
    int p;
    LogLine("---- HIT ----");
    p = wsprintfA(line, "  src: %s", g_names[which]);
    LogLine(line);
    LogHex64("  rip = 0x", (DWORD64)ctx->Rip);
    LogHex64("  rcx = 0x", (DWORD64)ctx->Rcx);
    LogHex64("  rdx = 0x", (DWORD64)ctx->Rdx);
    LogHex64("  r8  = 0x", (DWORD64)ctx->R8);
    LogHex64("  r9  = 0x", (DWORD64)ctx->R9);
    LogHex64("  rsp = 0x", (DWORD64)ctx->Rsp);

    // 栈上返回地址链 (标出 Weixin.dll 范围内的值)
    DWORD64 rsp = ctx->Rsp;
    DWORD64 wxBase = g_wxBase;
    LogLine("  ---- stack return-address chain ----");
    for (DWORD off = 0; off < 0x400; off += 8) {
        DWORD64 val = *(DWORD64*)(rsp + off);
        if (val >= wxBase && val < wxBase + 0xC800000) {
            // 可能是返回地址: 检查前一字节是否 E8/FF (调用痕迹) — 简化: 只标记范围
            char l2[128];
            p = wsprintfA(l2, "  rsp+0x%03X: Weixin+0x%llX", off, (unsigned long long)(val - wxBase));
            LogLine(l2);
        }
    }
}

static LONG CALLBACK VehHandler(PEXCEPTION_POINTERS ep)
{
    PEXCEPTION_RECORD rec = ep->ExceptionRecord;
    PCONTEXT ctx = ep->ContextRecord;

    if (rec->ExceptionCode != 0x80000004) return EXCEPTION_CONTINUE_SEARCH;
    DWORD64 dr6 = ctx->Dr6 & 0xF;
    if (dr6 == 0) return EXCEPTION_CONTINUE_SEARCH;

    // 命中! 找出是哪个断点
    int which = -1;
    for (int i = 0; i < 4; i++) if (dr6 & (1ULL << i)) { which = i; break; }

    g_totalHits++;

    // 单次记录: 每个断点只记录前 3 次 (防止热函数刷屏)
    static int hitCount[4] = {0, 0, 0, 0};
    if (hitCount[which] < 3) {
        hitCount[which]++;
        LogStackAndRegs(ctx, which);
    } else if (hitCount[which] == 3) {
        hitCount[which]++;
        LogLine("  ...(更多命中省略)...");
    }

    // 清 DR6 标志 + 设 RF 防重触发
    ctx->Dr6 &= ~dr6;
    ctx->EFlags |= 0x10000;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void ArmAllThreads(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te; te.dwSize = sizeof(te);
    int newly = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != g_myPid) continue;
            if (te.th32ThreadID == g_myTid) continue;
            int dup = 0;
            for (int i = 0; i < g_armedCount; i++) if (g_armed[i] == (int)te.th32ThreadID) { dup = 1; break; }
            if (dup) continue;
            HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
            if (!h) continue;
            if (SuspendThread(h) != (DWORD)-1) {
                CONTEXT ctx; memset(&ctx, 0, sizeof(ctx));
                ctx.ContextFlags = CTX_FLAGS;
                if (GetThreadContext(h, &ctx)) {
                    ctx.Dr0 = g_targets[0];
                    ctx.Dr1 = g_targets[1];
                    ctx.Dr2 = g_targets[2];
                    ctx.Dr3 = g_targets[3];
                    // DR7: L0-L1 全部使能, RW/LEN = 00 (执行断点)
                    ULONG64 dr7 = ctx.Dr7;
                    dr7 &= ~((0xFULL << 16) | (0xFULL << 20) | (0xFULL << 24) | (0xFULL << 28));
                    dr7 |= (1ULL << 0) | (1ULL << 2) | (1ULL << 4) | (1ULL << 6);
                    ctx.Dr7 = (DWORD64)dr7;
                    SetThreadContext(h, &ctx);
                    if (g_armedCount < 1024) g_armed[g_armedCount++] = te.th32ThreadID;
                    newly++;
                }
                ResumeThread(h);
            }
            CloseHandle(h);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    if (newly) {
        char line[64];
        wsprintfA(line, "[arm] newly=%d total=%d", newly, g_armedCount);
        LogLine(line);
    }
}

static DWORD WINAPI BpThread(LPVOID param)
{
    (void)param;
    g_myTid = GetCurrentThreadId();
    g_logFile = CreateFileA("C:\\Users\\fish\\ZCodeProject\\wx_bp5_log.txt",
        FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_logFile == INVALID_HANDLE_VALUE) { g_logFile = NULL; return 0; }
    LogLine("=== wx_bp5 4-BP message pipeline mapper ===");

    HMODULE wx = GetModuleHandleW(L"Weixin.dll");
    if (!wx) { LogLine("Weixin.dll NOT FOUND"); return 0; }
    g_wxBase = (DWORD64)(ULONG_PTR)wx;
    LogHex64("Weixin.dll base = 0x", g_wxBase);
    for (int i = 0; i < 4; i++) {
        g_targets[i] = g_wxBase + g_rvas[i];
        char line[128];
        wsprintfA(line, "  %s => 0x%llX", g_names[i], (unsigned long long)g_targets[i]);
        LogLine(line);
    }

    g_veh = AddVectoredExceptionHandler(1, VehHandler);
    if (!g_veh) { LogLine("AddVectoredExceptionHandler FAILED"); return 0; }

    ArmAllThreads();
    LogLine("all armed. waiting for message activity (send/receive)...");

    DWORD start = GetTickCount();
    DWORD lastArm = 0;
    while (!g_done && (GetTickCount() - start) < 600000) {
        Sleep(150);
        if (GetTickCount() - lastArm > 500) { ArmAllThreads(); lastArm = GetTickCount(); }
    }

    // 清理
    for (int i = 0; i < g_armedCount; i++) {
        HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, (DWORD)g_armed[i]);
        if (!h) continue;
        if (SuspendThread(h) != (DWORD)-1) {
            CONTEXT ctx; memset(&ctx, 0, sizeof(ctx));
            ctx.ContextFlags = CTX_FLAGS;
            if (GetThreadContext(h, &ctx)) {
                ctx.Dr7 &= ~((1ULL << 0) | (1ULL << 2) | (1ULL << 4) | (1ULL << 6));
                SetThreadContext(h, &ctx);
            }
            ResumeThread(h);
        }
        CloseHandle(h);
    }
    if (g_veh) RemoveVectoredExceptionHandler(g_veh);
    char line[128];
    wsprintfA(line, "=== done, total hits = %d ===", (int)g_totalHits);
    LogLine(line);
    if (g_logFile) { CloseHandle(g_logFile); g_logFile = NULL; }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r)
{
    (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        g_myPid = GetCurrentProcessId();
        g_myTid = GetCurrentThreadId();
        HANDLE t = CreateThread(NULL, 0, BpThread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
