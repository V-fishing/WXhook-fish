// wx_probe.c — M1 验证用测试 DLL (反射加载安全)
// 被注入后写日志文件(含 Weixin.dll 基址), 并持续心跳
// 编译: gcc -O2 -shared -o wx_probe.dll wx_probe.c ReflectiveLoader.c

#include <windows.h>

static HANDLE g_logFile = NULL;

static void WriteDec(DWORD value)
{
    DWORD written = 0;
    char tmp[12]; int j = 0;
    if (value == 0) tmp[j++] = '0';
    while (value > 0) { tmp[j++] = (char)('0' + (value % 10)); value /= 10; }
    char buf[12]; int i = 0;
    while (j > 0) buf[i++] = tmp[--j];
    WriteFile(g_logFile, buf, (DWORD)i, &written, NULL);
}

static void LogLine(const char* text, DWORD value)
{
    if (!g_logFile) return;
    DWORD written = 0;
    WriteFile(g_logFile, text, lstrlenA(text), &written, NULL);
    WriteDec(value);
    WriteFile(g_logFile, "\r\n", 2, &written, NULL);
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

static DWORD WINAPI ProbeThread(LPVOID param)
{
    (void)param;
    g_logFile = CreateFileA("C:\\Users\\fish\\ZCodeProject\\wx_probe_log.txt",
        FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_logFile == INVALID_HANDLE_VALUE) { g_logFile = NULL; return 0; }

    LogLine("=== wx_probe DLL injected! ===", 0);
    LogLine("pid = ", (DWORD)GetCurrentProcessId());

    HMODULE wx = GetModuleHandleW(L"Weixin.dll");
    LogHex64("Weixin.dll base = ", (DWORD64)(ULONG_PTR)wx);

    HMODULE self = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR)&LogLine, &self);
    LogHex64("probe dll base = ", (DWORD64)(ULONG_PTR)self);

    // 心跳: 每 15 秒一条, 共 40 次 = 10 分钟观察窗口
    for (DWORD i = 1; i <= 40; i++) {
        Sleep(15000);
        LogLine("heartbeat #", i);
    }
    LogLine("=== probe exiting (40 heartbeats done) ===", 0);
    if (g_logFile) { CloseHandle(g_logFile); g_logFile = NULL; }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInstance);
        HANDLE t = CreateThread(NULL, 0, ProbeThread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
