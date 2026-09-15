// inject_lib.c — M1 LoadLibrary 注入器(经典方式, 稳定可靠)
// 用法: wx_inject.exe <pid> <dll绝对路径>
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

static DWORD FindMainWeixinPid(void)
{
    // 取内存最大的 Weixin.exe = 主进程(简化: 取第一个能打开的)
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    DWORD best = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (lstrcmpiA(pe.szExeFile, "Weixin.exe") == 0) { best = pe.th32ProcessID; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return best;
}

int main(int argc, char** argv)
{
    if (argc < 3) { printf("usage: wx_inject.exe <pid|auto> <dll_abs_path>\n"); return 1; }

    DWORD pid = 0;
    if (lstrcmpiA(argv[1], "auto") == 0) {
        pid = FindMainWeixinPid();
        if (!pid) { printf("[-] Weixin.exe not found\n"); return 1; }
        printf("[+] auto-detected Weixin.exe pid=%lu\n", (unsigned long)pid);
    } else {
        pid = (DWORD)strtoul(argv[1], NULL, 10);
    }

    // 路径转宽字符
    wchar_t wpath[MAX_PATH];
    int n = MultiByteToWideChar(CP_UTF8, 0, argv[2], -1, wpath, MAX_PATH);
    if (!n) { printf("[-] path convert failed\n"); return 1; }

    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                               PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                               FALSE, pid);
    if (!hProc) { printf("[-] OpenProcess failed: %lu\n", GetLastError()); return 1; }
    printf("[+] process opened: %lu\n", (unsigned long)pid);

    // 1. 在目标进程分配内存写入 DLL 路径
    SIZE_T pathBytes = (SIZE_T)n * sizeof(wchar_t);
    LPVOID remotePath = VirtualAllocEx(hProc, NULL, pathBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remotePath) { printf("[-] VirtualAllocEx failed: %lu\n", GetLastError()); return 1; }
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, remotePath, wpath, pathBytes, &written)) {
        printf("[-] WriteProcessMemory failed: %lu\n", GetLastError()); return 1;
    }
    printf("[+] path written to 0x%p\n", remotePath);

    // 2. 拿 LoadLibraryW 地址(kernel32 所有进程同基址)
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLib =
        (LPTHREAD_START_ROUTINE)GetProcAddress(k32, "LoadLibraryW");
    if (!pLoadLib) { printf("[-] LoadLibraryW not found\n"); return 1; }

    // 3. 远程线程调用 LoadLibraryW(路径)
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, pLoadLib, remotePath, 0, NULL);
    if (!hThread) { printf("[-] CreateRemoteThread failed: %lu\n", GetLastError()); return 1; }
    printf("[+] remote thread started, waiting...\n");
    WaitForSingleObject(hThread, 10000);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);
    printf("[+] LoadLibraryW returned 0x%08lX %s\n", (unsigned long)exitCode,
           exitCode ? "(success, module loaded)" : "(FAILED = 0)");

    VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
    CloseHandle(hProc);
    printf("[+] done. check log: C:\\Users\\fish\\ZCodeProject\\wx_probe_log.txt\n");
    return 0;
}
