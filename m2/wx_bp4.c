// wx_bp4.c — M2 终极探针: DR0 埋伏在发送管线必经点 + 捕获调用栈
// 目标: Weixin.dll + 0x17F5237 ("GetAddSendMessageToDb" 日志引用点, 发送必经)
// 命中后记录: 全部寄存器 + RSP 起 0x200 字节栈数据 (含返回地址链)
// 编译: gcc -O2 -shared -o wx_bp4.dll wx_bp4.c

#include <windows.h>
#include <tlhelp32.h>

#define CTX_FLAGS (0x0010001B)
static DWORD64 g_rva = 0x17F5237ULL;   // "GetAddSendMessageToDb" 引用点 (发送必经)
static DWORD64 g_t1 = 0;
static HANDLE g_logFile = NULL;
static LONG volatile g_done = 0;
static PVOID g_veh = NULL;
static DWORD g_myPid = 0;
static DWORD g_myTid = 0;

static void LogLine(const char* text)
{
    if (!g_logFile) return;
    DWORD written = 0;
    WriteFile(g_logFile, text, lstrlenA(text), &written, NULL);
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

// 栈转储: 标记哪些 8 字节值看起来像 Weixin.dll 内的返回地址
static void LogStack(PCONTEXT ctx)
{
    if (!g_logFile) return;
    DWORD w;
    DWORD64 rsp = ctx->Rsp;
    // Weixin.dll 运行时范围 (从模块基址推断)
    HMODULE wx = GetModuleHandleW(L"Weixin.dll");
    DWORD64 wxBase = (DWORD64)(ULONG_PTR)wx;
    // .text 大约 48MB; 返回地址应在 [base, base+200MB)
    LogLine("  ---- stack dump (0x200 bytes, * = Weixin.dll range) ----");
    for (DWORD off = 0; off < 0x200; off += 8) {
        DWORD64 val = *(DWORD64*)(rsp + off);
        char line[128];
        int p = wsprintfA(line, "  rsp+0x%03X: 0x%016llX", off, (unsigned long long)val);
        if (val >= wxBase && val < wxBase + 0xC800000) {  // 200MB 内
            p += wsprintfA(line + p, "  *<-Weixin+0x%llX", (unsigned long long)(val - wxBase));
        }
        p += wsprintfA(line + p, "\r\n");
        WriteFile(g_logFile, line, p, &w, NULL);
    }
}

static LONG CALLBACK VehHandler(PEXCEPTION_POINTERS ep)
{
    PEXCEPTION_RECORD rec = ep->ExceptionRecord;
    PCONTEXT ctx = ep->ContextRecord;

    if (rec->ExceptionCode != 0x80000004) return EXCEPTION_CONTINUE_SEARCH;
    if ((ctx->Dr6 & 1) == 0) return EXCEPTION_CONTINUE_SEARCH;
    if (InterlockedExchange(&g_done, 1) == 1) {
        ctx->EFlags |= 0x10000;
        ctx->Dr6 &= ~1ULL;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    LogLine("==== SEND-PIPELINE HIT ====");
    LogHex64("  rip = 0x", (DWORD64)ctx->Rip);
    LogHex64("  rcx = 0x", (DWORD64)ctx->Rcx);
    LogHex64("  rdx = 0x", (DWORD64)ctx->Rdx);
    LogHex64("  r8  = 0x", (DWORD64)ctx->R8);
    LogHex64("  r9  = 0x", (DWORD64)ctx->R9);
    LogHex64("  rsp = 0x", (DWORD64)ctx->Rsp);
    LogHex64("  rbx = 0x", (DWORD64)ctx->Rbx);
    LogHex64("  rdi = 0x", (DWORD64)ctx->Rdi);
    LogHex64("  rsi = 0x", (DWORD64)ctx->Rsi);
    LogStack(ctx);

    // 一次性: 关 DR0, 清 DR6, 设 RF
    ctx->Dr7 &= ~(1ULL << 0);
    ctx->Dr6 &= ~1ULL;
    ctx->EFlags |= 0x10000;
    LogLine("==== capture complete, DR0 disabled ====");
    return EXCEPTION_CONTINUE_EXECUTION;
}

static DWORD g_armed[1024];
static int g_armedCount = 0;

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
                    ctx.Dr0 = g_t1;
                    ctx.Dr7 = (DWORD64)(ctx.Dr7 | (1ULL << 0));
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
    g_logFile = CreateFileA("C:\\Users\\fish\\ZCodeProject\\wx_bp4_log.txt",
        FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_logFile == INVALID_HANDLE_VALUE) { g_logFile = NULL; return 0; }
    LogLine("=== wx_bp4 send-pipeline probe loaded ===");

    HMODULE wx = GetModuleHandleW(L"Weixin.dll");
    if (!wx) { LogLine("Weixin.dll NOT FOUND"); return 0; }
    DWORD64 wxBase = (DWORD64)(ULONG_PTR)wx;
    LogHex64("Weixin.dll base = 0x", wxBase);
    g_t1 = wxBase + g_rva;
    LogHex64("DR0 target (GetAddSendMessageToDb xref) = 0x", g_t1);

    g_veh = AddVectoredExceptionHandler(1, VehHandler);
    if (!g_veh) { LogLine("AddVectoredExceptionHandler FAILED"); return 0; }

    ArmAllThreads();
    LogLine("armed. waiting for user to send a message...");

    DWORD start = GetTickCount();
    while (!g_done && (GetTickCount() - start) < 600000) {
        Sleep(200);
        ArmAllThreads();
    }
    if (!g_done) {
        LogLine("=== TIMEOUT 10min ===");
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
    } else {
        LogLine("=== capture complete ===");
    }
    if (g_veh) RemoveVectoredExceptionHandler(g_veh);
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
