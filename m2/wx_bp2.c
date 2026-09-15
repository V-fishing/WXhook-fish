// wx_bp2.c — M2 硬件断点探针 (DR0-DR3, 零字节修改, CRC 不可见)
// 对所有线程(含新建)设置 DR0/DR1 执行断点, VEH 捕获命中并记录寄存器
// 编译: gcc -O2 -shared -o wx_bp2.dll wx_bp2.c

#include <windows.h>
#include <tlhelp32.h>

// 目标: Weixin.dll 内 RVA (运行时自动加上实际基址)
static DWORD64 g_rva1 = 0x24CAC63ULL;
static DWORD64 g_rva2 = 0x544C885ULL;
static DWORD64 g_t1 = 0, g_t2 = 0;

static HANDLE g_logFile = NULL;
static LONG volatile g_hits = 0;
static PVOID g_veh = NULL;
static DWORD volatile g_myPid = 0;
static CRITICAL_SECTION g_tls;

#define CTX_FLAGS (0x00100001B)  // FULL | DEBUG_REGISTERS

static void LogLine(const char* text)
{
    if (!g_logFile) return;
    DWORD written = 0;
    WriteFile(g_logFile, text, lstrlenA(text), &written, NULL);
}

static void LogHex64(const char* label, DWORD64 value)
{
    if (!g_logFile) return;
    DWORD written = 0;
    WriteFile(g_logFile, label, lstrlenA(label), &written, NULL);
    char buf[19];
    buf[0] = '0'; buf[1] = 'x';
    for (int i = 0; i < 16; i++) {
        int nib = (int)((value >> ((15 - i) * 4)) & 0xF);
        buf[2 + i] = (char)(nib < 10 ? '0' + nib : 'A' + nib - 10);
    }
    buf[18] = '\0';
    WriteFile(g_logFile, buf, 18, &written, NULL);
    WriteFile(g_logFile, "\r\n", 2, &written, NULL);
}

// VEH: 捕获 DR0/DR1 命中 (EXCEPTION_SINGLE_STEP 且 DR6 标记)
static LONG CALLBACK VehHandler(PEXCEPTION_POINTERS ep)
{
    PEXCEPTION_RECORD rec = ep->ExceptionRecord;
    PCONTEXT ctx = ep->ContextRecord;

    if (rec->ExceptionCode != 0x80000004) return EXCEPTION_CONTINUE_SEARCH;
    if ((ctx->Dr6 & 0xF) == 0) return EXCEPTION_CONTINUE_SEARCH; // 不是我们的断点

    g_hits++;
    LogLine("---- HW-BP HIT ----");
    if (ctx->Dr6 & 1) LogLine("  src: DR0 (delmsg cand #1)");
    if (ctx->Dr6 & 2) LogLine("  src: DR1 (delmsg cand #2)");
    LogHex64("  rip = 0x", (DWORD64)ctx->Rip);
    LogHex64("  rcx = 0x", (DWORD64)ctx->Rcx);
    LogHex64("  rdx = 0x", (DWORD64)ctx->Rdx);
    LogHex64("  r8  = 0x", (DWORD64)ctx->R8);
    LogHex64("  r9  = 0x", (DWORD64)ctx->R9);
    LogHex64("  rsp = 0x", (DWORD64)ctx->Rsp);
    // 清 DR6 标记位 (写回 context, 继续执行时生效)
    ctx->Dr6 &= ~0xFULL;
    // DR 命中不改变执行流: 直接继续 (硬件断点在指令执行前触发, 清标志后重执行该指令)
    return EXCEPTION_CONTINUE_EXECUTION;
}

// 对单个线程设置 DR0/DR1 + DR7
static BOOL ArmThread(DWORD tid)
{
    HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
    if (!h) return FALSE;
    BOOL ok = FALSE;
    if (SuspendThread(h) != (DWORD)-1) {
        CONTEXT ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CTX_FLAGS;
        if (GetThreadContext(h, &ctx)) {
            // 已有别的 DR0/DR1 占用则跳过 (保护微信自用场景)
            ctx.Dr0 = g_t1;
            ctx.Dr1 = g_t2;
            ULONG64 dr7 = ctx.Dr7;
            dr7 |= (1ULL << 0);            // L0
            dr7 |= (1ULL << 2);            // L1
            // RW0/RW1 = 00 (执行断点), LEN = 00 (1字节) —— 位 16-19 / 20-23 保持 0
            dr7 &= ~((0xFULL << 16) | (0xFULL << 20));
            ctx.Dr7 = (DWORD64)dr7;
            ok = SetThreadContext(h, &ctx);
        }
        ResumeThread(h);
    }
    CloseHandle(h);
    return ok;
}

// 枚举本进程所有线程, 对未武装的线程武装
static DWORD g_armed[512];
static int g_armedCount = 0;

static int IsArmed(DWORD tid)
{
    for (int i = 0; i < g_armedCount; i++) if (g_armed[i] == (int)tid) return 1;
    return 0;
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
            if (IsArmed(te.th32ThreadID)) continue;
            if (ArmThread(te.th32ThreadID)) {
                if (g_armedCount < 512) g_armed[g_armedCount++] = te.th32ThreadID;
                newly++;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    if (newly) {
        LogLine("[arm] threads total = ");
        LogHex64("", (DWORD64)g_armedCount);
    }
}

static DWORD WINAPI BpThread(LPVOID param)
{
    (void)param;
    g_logFile = CreateFileA("C:\\Users\\fish\\ZCodeProject\\wx_bp2_log.txt",
        FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_logFile == INVALID_HANDLE_VALUE) { g_logFile = NULL; return 0; }
    LogLine("=== wx_bp2 HW-BP probe loaded ===");

    g_myPid = GetCurrentProcessId();
    LogLine("pid = "); LogHex64("", g_myPid);

    HMODULE wx = GetModuleHandleW(L"Weixin.dll");
    if (!wx) { LogLine("Weixin.dll NOT FOUND"); return 0; }
    DWORD64 wxBase = (DWORD64)(ULONG_PTR)wx;
    LogHex64("Weixin.dll base = 0x", wxBase);
    g_t1 = wxBase + g_rva1;
    g_t2 = wxBase + g_rva2;
    LogHex64("target1 = base+0x24CAC63 = 0x", g_t1);
    LogHex64("target2 = base+0x544C885 = 0x", g_t2);

    g_veh = AddVectoredExceptionHandler(1, VehHandler);
    if (!g_veh) { LogLine("AddVectoredExceptionHandler FAILED"); return 0; }

    ArmAllThreads();
    LogLine("all existing threads armed. watching for new threads + hits...");

    DWORD start = GetTickCount();
    DWORD lastArm = 0;
    while ((GetTickCount() - start) < 300000 && g_hits < 10) {
        Sleep(100);
        if (GetTickCount() - lastArm > 500) {   // 每 0.5 秒武装新线程
            ArmAllThreads();
            lastArm = GetTickCount();
        }
    }

    // 清理: 清所有线程的 DR7
    for (int i = 0; i < g_armedCount; i++) {
        HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, (DWORD)g_armed[i]);
        if (!h) continue;
        if (SuspendThread(h) != (DWORD)-1) {
            CONTEXT ctx; memset(&ctx, 0, sizeof(ctx));
            ctx.ContextFlags = CTX_FLAGS;
            if (GetThreadContext(h, &ctx)) {
                ctx.Dr7 &= ~((1ULL << 0) | (1ULL << 2));
                SetThreadContext(h, &ctx);
            }
            ResumeThread(h);
        }
        CloseHandle(h);
    }
    if (g_veh) RemoveVectoredExceptionHandler(g_veh);
    LogLine("=== wx_bp2 done, DR7 cleared, cleaned up ===");
    if (g_logFile) { CloseHandle(g_logFile); g_logFile = NULL; }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInstance);
        InitializeCriticalSection(&g_tls);
        g_myPid = GetCurrentProcessId();
        HANDLE t = CreateThread(NULL, 0, BpThread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    } else if (reason == DLL_PROCESS_DETACH) {
        DeleteCriticalSection(&g_tls);
    }
    return TRUE;
}
