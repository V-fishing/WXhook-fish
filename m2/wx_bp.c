// wx_bp.c — M2 进程内 VEH 断点探针 (移植自 RevokeHook vehbp.cpp 思路)
// 功能: 在指定运行时地址安装 INT3, 命中时记录全部寄存器到日志, 自动单步恢复
// 注入后自动工作, 不需要外部调试器 (规避反调试)
// 编译: gcc -O2 -shared -o wx_bp.dll wx_bp.c

#include <windows.h>

#define TARGET_VA        0x7FF88C02AC63ULL   // DelMsg 候选 #1 (sig2 命中点)
#define TARGET_VA2       0x7FF88EFAC885ULL   // DelMsg 候选 #2
#define MAX_HITS         6
#define TIMEOUT_MS       240000              // 4 分钟观察窗口

static HANDLE g_logFile = NULL;
static LONG volatile g_hits = 0;
static LONG volatile g_done = 0;
static BYTE g_orig1 = 0, g_orig2 = 0;
static PVOID g_veh = NULL;

static void LogLine(const char* text)
{
    if (!g_logFile) return;
    DWORD written = 0;
    WriteFile(g_logFile, text, lstrlenA(text), &written, NULL);
}

static void LogLine2(const char* a, const char* b)
{
    LogLine(a); LogLine(b);
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

static void WriteByteAt(DWORD64 addr, BYTE val)
{
    DWORD oldProt = 0;
    if (!VirtualProtect((LPVOID)addr, 1, PAGE_EXECUTE_READWRITE, &oldProt)) return;
    *(volatile BYTE*)addr = val;
    FlushInstructionCache(GetCurrentProcess(), (LPVOID)addr, 1);
    VirtualProtect((LPVOID)addr, 1, oldProt, &oldProt);
}

static BYTE ReadByteAt(DWORD64 addr)
{
    return *(volatile BYTE*)addr;
}

// VEH 回调: 捕获 INT3, 记录寄存器, 恢复原字节 + 单步, 下次单步再装回
static LONG CALLBACK VehHandler(PEXCEPTION_POINTERS ep)
{
    PEXCEPTION_RECORD rec = ep->ExceptionRecord;
    PCONTEXT ctx = ep->ContextRecord;

    if (rec->ExceptionCode == 0x80000004) { // STATUS_SINGLE_STEP: 我们的单步
        // 恢复 INT3 (单步执行完原字节后重新安装)
        WriteByteAt(TARGET_VA, 0xCC);
        WriteByteAt(TARGET_VA2, 0xCC);
        ctx->EFlags &= ~0x100; // 清 TF
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (rec->ExceptionCode == 0x80000003 && // STATUS_BREAKPOINT
        (DWORD64)ctx->Rip == TARGET_VA + 1) {
        g_hits++;
        LogLine("---- HIT (candidate #1) ----");
        LogHex64("  rip(after int3)=0x", (DWORD64)ctx->Rip);
        LogHex64("  rcx=0x", (DWORD64)ctx->Rcx);
        LogHex64("  rdx=0x", (DWORD64)ctx->Rdx);
        LogHex64("  r8 =0x", (DWORD64)ctx->R8);
        LogHex64("  r9 =0x", (DWORD64)ctx->R9);
        LogHex64("  rsp=0x", (DWORD64)ctx->Rsp);
        // 恢复原字节, 回退 RIP 到 INT3 位置, 设 TF 单步
        WriteByteAt(TARGET_VA, g_orig1);
        ctx->Rip = TARGET_VA;
        ctx->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (rec->ExceptionCode == 0x80000003 &&
        (DWORD64)ctx->Rip == TARGET_VA2 + 1) {
        g_hits++;
        LogLine("---- HIT (candidate #2) ----");
        LogHex64("  rip(after int3)=0x", (DWORD64)ctx->Rip);
        LogHex64("  rcx=0x", (DWORD64)ctx->Rcx);
        LogHex64("  rdx=0x", (DWORD64)ctx->Rdx);
        LogHex64("  r8 =0x", (DWORD64)ctx->R8);
        LogHex64("  r9 =0x", (DWORD64)ctx->R9);
        LogHex64("  rsp=0x", (DWORD64)ctx->Rsp);
        WriteByteAt(TARGET_VA2, g_orig2);
        ctx->Rip = TARGET_VA2;
        ctx->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static DWORD WINAPI BpThread(LPVOID param)
{
    (void)param;
    g_logFile = CreateFileA("C:\\Users\\fish\\ZCodeProject\\wx_bp_log.txt",
        FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_logFile == INVALID_HANDLE_VALUE) { g_logFile = NULL; return 0; }
    LogLine("=== wx_bp VEH probe loaded ===");
    LogLine("target1 = 0x7FF88C02AC63");
    LogLine("target2 = 0x7FF88EFAC885");

    // 保存原字节
    g_orig1 = ReadByteAt(TARGET_VA);
    g_orig2 = ReadByteAt(TARGET_VA2);
    LogHex64("orig1 = 0x", g_orig1);
    LogHex64("orig2 = 0x", g_orig2);

    // 安装 VEH (排在链表最前, 优先于微信自己的异常处理)
    g_veh = AddVectoredExceptionHandler(1, VehHandler);
    if (!g_veh) { LogLine("AddVectoredExceptionHandler FAILED"); return 0; }

    // 装 INT3
    WriteByteAt(TARGET_VA, 0xCC);
    WriteByteAt(TARGET_VA2, 0xCC);
    LogLine("INT3 installed at both targets. waiting for hits (revoke a message!)");

    DWORD start = GetTickCount();
    while ((GetTickCount() - start) < TIMEOUT_MS && g_hits < MAX_HITS) {
        Sleep(200);
    }

    // 清理
    WriteByteAt(TARGET_VA, g_orig1);
    WriteByteAt(TARGET_VA2, g_orig2);
    if (g_veh) RemoveVectoredExceptionHandler(g_veh);
    LogLine("=== wx_bp done, cleaned up ===");
    if (g_logFile) { CloseHandle(g_logFile); g_logFile = NULL; }
    g_done = 1;
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInstance);
        HANDLE t = CreateThread(NULL, 0, BpThread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
