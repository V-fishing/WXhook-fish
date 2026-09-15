// wx_diag.c — 诊断: DR 寄存器武装后是否真的生效/被清除
// 编译: gcc -O2 -shared -o wx_diag.dll wx_diag.c
#include <windows.h>
#include <tlhelp32.h>

#define CTX_FLAGS (0x0010001B)
static DWORD64 g_rva = 0x24CAC63ULL;
static HANDLE g_logFile = NULL;
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

static DWORD g_armed[1024];
static int g_armedCount = 0;

static void ArmAll(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te; te.dwSize = sizeof(te);
    int failSet = 0, failGet = 0, okSet = 0, skipSelf = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != g_myPid) continue;
            if (te.th32ThreadID == g_myTid) { skipSelf++; continue; }
            HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
            if (!h) { failSet++; continue; }
            if (SuspendThread(h) == (DWORD)-1) { CloseHandle(h); failSet++; continue; }
            CONTEXT ctx; memset(&ctx, 0, sizeof(ctx));
            ctx.ContextFlags = CTX_FLAGS;
            int got = GetThreadContext(h, &ctx);
            if (!got) { failGet++; ResumeThread(h); CloseHandle(h); continue; }
            DWORD64 oldDr0 = ctx.Dr0, oldDr7 = ctx.Dr7;
            ctx.Dr0 = g_rva ? 0 : 0; // placeholder
            ctx.Dr0 = 0;
            // 目标地址 = Weixin.dll base + rva, 由调用方传入 —— 这里直接用模块基址+常量
            HMODULE wx = GetModuleHandleW(L"Weixin.dll");
            DWORD64 base = (DWORD64)(ULONG_PTR)wx;
            ctx.Dr0 = base + 0x24CAC63;
            ctx.Dr7 = (DWORD64)(ctx.Dr7 | (1ULL << 0));
            BOOL set = SetThreadContext(h, &ctx);
            int serr = set ? 0 : (int)GetLastError();
            // 回读验证
            CONTEXT chk; memset(&chk, 0, sizeof(chk));
            chk.ContextFlags = CTX_FLAGS;
            BOOL got2 = GetThreadContext(h, &chk);
            DWORD64 dr0now = chk.Dr0;
            DWORD64 dr7now = chk.Dr7;
            ResumeThread(h);
            CloseHandle(h);
            if (set && got2 && dr0now == base + 0x24CAC63 && (dr7now & 1)) {
                okSet++;
                if (g_armedCount < 1024) g_armed[g_armedCount++] = te.th32ThreadID;
                if (okSet <= 3) {
                    LogHex64("  [sample] tid=0x", (DWORD64)te.th32ThreadID);
                    LogHex64("    oldDr0=0x", oldDr0);
                    LogHex64("    oldDr7=0x", oldDr7);
                    LogHex64("    newDr0=0x", base + 0x24CAC63);
                    LogHex64("    readbackDr0=0x", dr0now);
                    LogHex64("    readbackDr7=0x", dr7now);
                }
            } else {
                failSet++;
                if (failSet <= 3) {
                    char line[128];
                    wsprintfA(line, "  [FAIL] tid=0x%X set=%d err=%d dr0now=0x%llX dr7now=0x%llX",
                        te.th32ThreadID, set, serr, (unsigned long long)dr0now, (unsigned long long)dr7now);
                    LogLine(line);
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    char line[128];
    wsprintfA(line, "[summary] ok=%d failSet=%d failGet=%d skipSelf=%d", okSet, failSet, failGet, skipSelf);
    LogLine(line);
}

static DWORD WINAPI DiagThread(LPVOID param)
{
    (void)param;
    g_logFile = CreateFileA("C:\\Users\\fish\\ZCodeProject\\wx_diag_log.txt",
        FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_logFile == INVALID_HANDLE_VALUE) { g_logFile = NULL; return 0; }
    LogLine("=== wx_diag ===");
    LogLine("pid = "); LogHex64("", g_myPid);
    HMODULE wx = GetModuleHandleW(L"Weixin.dll");
    if (!wx) { LogLine("Weixin.dll NOT FOUND"); return 0; }
    LogHex64("Weixin.dll base = 0x", (DWORD64)(ULONG_PTR)wx);
    ArmAll();
    LogLine("=== pass1 done ===");
    // 10 秒后再读一次, 检测是否有东西在清 DR
    Sleep(10000);
    LogLine("=== pass2 (10s later) readback of armed threads ===");
    int checked = 0, cleared = 0;
    for (int i = 0; i < g_armedCount && checked < 10; i++) {
        HANDLE h = OpenThread(THREAD_GET_CONTEXT, FALSE, (DWORD)g_armed[i]);
        if (!h) continue;
        CONTEXT ctx; memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CTX_FLAGS;
        if (GetThreadContext(h, &ctx)) {
            checked++;
            if ((ctx.Dr7 & 1) == 0) cleared++;
            if (checked <= 5) {
                LogHex64("  tid-armed Dr0=0x", ctx.Dr0);
                LogHex64("             Dr7=0x", ctx.Dr7);
            }
        }
        CloseHandle(h);
    }
    char line[128];
    wsprintfA(line, "[pass2] checked=%d dr_cleared=%d", checked, cleared);
    LogLine(line);
    LogLine("=== diag done ===");
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
        HANDLE t = CreateThread(NULL, 0, DiagThread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
