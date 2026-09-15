// wx_bp3.c — M2 V3 探针: 一次性断点捕获 mgr 实例 + vtable 转储
// DR0 命中一次后立即自禁用 → 抓 mgr(rcx) → 转储 [mgr] vtable 前 64 项 → 完成
// 微信零负担 (无热循环日志)
// 编译: gcc -O2 -shared -o wx_bp3.dll wx_bp3.c

#include <windows.h>
#include <tlhelp32.h>

#define CTX_FLAGS (0x0010001B)  // FULL | DEBUG_REGISTERS

static DWORD64 g_rva = 0x24CAC63ULL;   // 热函数 (RevokeHook sig2 命中, mgr 方法)
static DWORD64 g_t1 = 0;
static HANDLE g_logFile = NULL;
static LONG volatile g_done = 0;
static PVOID g_veh = NULL;
static DWORD g_myPid = 0;

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

// 内存 hex dump (mgr 对象头)
static void LogDump(DWORD64 addr, DWORD size)
{
    if (!g_logFile) return;
    DWORD written = 0;
    for (DWORD off = 0; off < size; off += 16) {
        char line[120];
        int p = 0;
        // 地址
        p += wsprintfA(line + p, "  +0x%04X: ", off);
        for (int k = 0; k < 16 && off + k < size; k++) {
            BYTE b = *(BYTE*)(addr + off + k);
            p += wsprintfA(line + p, "%02X ", b);
        }
        p += wsprintfA(line + p, "\r\n");
        WriteFile(g_logFile, line, p, &written, NULL);
    }
}

// VEH: DR0 一次性命中
static LONG CALLBACK VehHandler(PEXCEPTION_POINTERS ep)
{
    PEXCEPTION_RECORD rec = ep->ExceptionRecord;
    PCONTEXT ctx = ep->ContextRecord;

    if (rec->ExceptionCode != 0x80000004) return EXCEPTION_CONTINUE_SEARCH;
    if ((ctx->Dr6 & 1) == 0) return EXCEPTION_CONTINUE_SEARCH;
    if (InterlockedExchange(&g_done, 1) == 1) {
        // 已处理过: 直接清标志继续 (防御性)
        ctx->Dr6 &= ~1ULL;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    LogLine("==== ONE-SHOT HIT ====");
    LogHex64("  rip = 0x", (DWORD64)ctx->Rip);
    LogHex64("  rcx (mgr?) = 0x", (DWORD64)ctx->Rcx);
    LogHex64("  rdx = 0x", (DWORD64)ctx->Rdx);
    LogHex64("  r8  = 0x", (DWORD64)ctx->R8);
    LogHex64("  r9  = 0x", (DWORD64)ctx->R9);

    DWORD64 mgr = (DWORD64)ctx->Rcx;
    if (mgr) {
        LogLine("  ---- mgr object dump [0x00..0x80] ----");
        LogDump(mgr, 0x80);
        // vtable
        DWORD64 vtable = *(DWORD64*)mgr;
        LogHex64("  vtable ptr = 0x", vtable);
        LogLine("  ---- vtable entries [0..63] ----");
        for (int i = 0; i < 64; i++) {
            DWORD64 entry = ((DWORD64*)vtable)[i];
            DWORD64 rva = (entry >= (DWORD64)0x180000000) ? (entry - 0x180000000) : 0;
            char line[128];
            wsprintfA(line, "  [%02d] 0x%016llX  rva=0x%llX", i, (unsigned long long)entry, (unsigned long long)rva);
            LogLine(line);
        }
    }

    // 自禁用: 关闭 DR0 使能 + 清 DR6 → 微信恢复零开销
    ctx->Dr7 &= ~(1ULL << 0);
    ctx->Dr6 &= ~1ULL;
    LogLine("==== DR0 disabled, capture complete ====");
    return EXCEPTION_CONTINUE_EXECUTION;
}

static DWORD g_armed[512];
static int g_armedCount = 0;

static void ArmAllThreads(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te; te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != g_myPid) continue;
            int dup = 0;
            for (int i = 0; i < g_armedCount; i++) if (g_armed[i] == (int)te.th32ThreadID) { dup = 1; break; }
            if (dup) continue;
            HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
            if (!h) continue;
            if (SuspendThread(h) != (DWORD)-1) {
                CONTEXT ctx; memset(&ctx, 0, sizeof(ctx));
                ctx.ContextFlags = CTX_FLAGS;
                if (GetThreadContext(h, &ctx)) {
                    ctx.Dr0 = g_t1;
                    ULONG64 dr7 = ctx.Dr7 | (1ULL << 0);
                    ctx.Dr7 = (DWORD64)dr7;
                    SetThreadContext(h, &ctx);
                    if (g_armedCount < 512) g_armed[g_armedCount++] = te.th32ThreadID;
                }
                ResumeThread(h);
            }
            CloseHandle(h);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

static DWORD WINAPI BpThread(LPVOID param)
{
    (void)param;
    g_logFile = CreateFileA("C:\\Users\\fish\\ZCodeProject\\wx_bp3_log.txt",
        FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_logFile == INVALID_HANDLE_VALUE) { g_logFile = NULL; return 0; }
    LogLine("=== wx_bp3 one-shot probe loaded ===");
    LogLine("pid = "); LogHex64("", g_myPid);

    HMODULE wx = GetModuleHandleW(L"Weixin.dll");
    if (!wx) { LogLine("Weixin.dll NOT FOUND"); return 0; }
    DWORD64 wxBase = (DWORD64)(ULONG_PTR)wx;
    LogHex64("Weixin.dll base = 0x", wxBase);
    g_t1 = wxBase + g_rva;
    LogHex64("DR0 target = 0x", g_t1);

    g_veh = AddVectoredExceptionHandler(1, VehHandler);
    if (!g_veh) { LogLine("AddVectoredExceptionHandler FAILED"); return 0; }

    // 等待微信就绪 (Weixin.dll 已加载即可武装; 命中可能要等登录后热函数开跑)
    ArmAllThreads();
    LogLine("threads armed (one-shot). waiting for first hit...");

    DWORD start = GetTickCount();
    while (!g_done && (GetTickCount() - start) < 600000) {  // 10 分钟窗口
        Sleep(200);
        ArmAllThreads();  // 持续武装新线程 (登录过程会创建大量线程)
    }

    if (!g_done) {
        // 超时: 清理
        for (int i = 0; i < g_armedCount; i++) {
            HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, (DWORD)g_armed[i]);
            if (!h) continue;
            if (SuspendThread(h) != (DWORD)-1) {
                CONTEXT ctx; memset(&ctx, 0, sizeof(ctx));
                ctx.ContextFlags = CTX_FLAGS;
                if (GetThreadContext(h, &ctx)) {
                    ctx.Dr7 &= ~(1ULL << 0);
                    SetThreadContext(h, &ctx);
                }
                ResumeThread(h);
            }
            CloseHandle(h);
        }
        LogLine("=== TIMEOUT, no hit. cleaned up ===");
    } else {
        LogLine("=== capture complete, DR0 disabled, WeChat running normally ===");
    }
    if (g_veh) RemoveVectoredExceptionHandler(g_veh);
    if (g_logFile) { CloseHandle(g_logFile); g_logFile = NULL; }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInstance);
        g_myPid = GetCurrentProcessId();
        HANDLE t = CreateThread(NULL, 0, BpThread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
