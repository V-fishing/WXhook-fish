// wx_freeze.c — M2 回车触发冻结 + 全线程栈转储
#include <windows.h>
#include <tlhelp32.h>

#define CTX_FLAGS (0x0010001B)
#define FREEZE_HOLD_MS  10000

static HANDLE g_logFile = NULL;
static DWORD g_myPid = 0;
static DWORD g_myTid = 0;
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

static BOOL IsEnterPressed(void)
{
    static BOOL wasDown = FALSE;
    SHORT state = GetAsyncKeyState(VK_RETURN);
    BOOL isDown = (state & 0x8000) != 0;
    BOOL pressed = isDown && !wasDown;
    wasDown = isDown;
    return pressed;
}

static void DumpThreadStack(DWORD tid, HANDLE hThread)
{
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CTX_FLAGS;
    if (!GetThreadContext(hThread, &ctx)) return;

    char line[160];
    LogLine("");
    wsprintfA(line, "==== TID %lu ====", (unsigned long)tid);
    LogLine(line);
    LogHex64("  rip = ", (DWORD64)ctx.Rip);
    LogHex64("  rsp = ", (DWORD64)ctx.Rsp);
    LogHex64("  rcx = ", (DWORD64)ctx.Rcx);
    LogHex64("  rdx = ", (DWORD64)ctx.Rdx);
    LogHex64("  r8  = ", (DWORD64)ctx.R8);
    LogHex64("  r9  = ", (DWORD64)ctx.R9);
    LogHex64("  rax = ", (DWORD64)ctx.Rax);
    LogHex64("  rbx = ", (DWORD64)ctx.Rbx);
    LogHex64("  rbp = ", (DWORD64)ctx.Rbp);
    LogHex64("  rsi = ", (DWORD64)ctx.Rsi);
    LogHex64("  rdi = ", (DWORD64)ctx.Rdi);
    LogHex64("  r12 = ", (DWORD64)ctx.R12);
    LogHex64("  r13 = ", (DWORD64)ctx.R13);
    LogHex64("  r14 = ", (DWORD64)ctx.R14);
    LogHex64("  r15 = ", (DWORD64)ctx.R15);

    // 栈上返回地址链
    DWORD64 rsp = (DWORD64)ctx.Rsp;
    LogLine("  ---- stack (Weixin.dll code addrs) ----");
    for (DWORD off = 0; off < 0x800; off += 8) {
        DWORD64 val = *(DWORD64*)(rsp + off);
        if (val >= g_wxBase && val < g_wxBase + 0xC800000) {
            wsprintfA(line, "  rsp+%03X: Weixin+0x%llX", off, (unsigned long long)(val - g_wxBase));
            LogLine(line);
        }
    }
}

static void FreezeAndDump(void)
{
    LogLine("========== FREEZE ==========");

    DWORD myTid = GetCurrentThreadId();
    DWORD tids[1024];
    HANDLE handles[1024];
    int threadCount = 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te; te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != g_myPid) continue;
            if (te.th32ThreadID == myTid) continue;
            HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (!h) continue;
            SuspendThread(h);
            if (threadCount < 1024) {
                tids[threadCount] = te.th32ThreadID;
                handles[threadCount] = h;
                threadCount++;
            } else { ResumeThread(h); CloseHandle(h); }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    char line[128];
    wsprintfA(line, "frozen %d threads", threadCount);
    LogLine(line);

    // 需要更高权限来 GetContext
    for (int i = 0; i < threadCount; i++) {
        CloseHandle(handles[i]);
        handles[i] = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tids[i]);
    }

    for (int i = 0; i < threadCount; i++) {
        DumpThreadStack(tids[i], handles[i]);
    }

    LogLine("========== DUMP DONE, holding 10s ==========");
    Sleep(FREEZE_HOLD_MS);
    for (int i = 0; i < threadCount; i++) {
        ResumeThread(handles[i]);
        CloseHandle(handles[i]);
    }
    LogLine("========== RESUMED ==========");
}

static DWORD WINAPI FreezeWatchThread(LPVOID param)
{
    (void)param;
    g_logFile = CreateFileA("C:\\Users\\fish\\ZCodeProject\\wx_freeze_log.txt",
        FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_logFile == INVALID_HANDLE_VALUE) { g_logFile = NULL; return 0; }
    LogLine("=== wx_freeze loaded ===");
    HMODULE wx = GetModuleHandleW(L"Weixin.dll");
    if (wx) g_wxBase = (DWORD64)(ULONG_PTR)wx;
    LogHex64("Weixin.dll base = 0x", g_wxBase);
    LogLine("watching for ENTER...");

    DWORD start = GetTickCount();
    while ((GetTickCount() - start) < 600000) {
        if (IsEnterPressed()) {
            LogLine("ENTER detected!");
            FreezeAndDump();
            break;
        }
        Sleep(1);
    }
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
        HMODULE wx = GetModuleHandleW(L"Weixin.dll");
        if (wx) g_wxBase = (DWORD64)(ULONG_PTR)wx;
        HANDLE t = CreateThread(NULL, 0, FreezeWatchThread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
