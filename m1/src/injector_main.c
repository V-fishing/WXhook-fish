// injector_main.c — M1 精简反射注入器
// 用法: wx_inject.exe <pid> <dll路径>
// 复用 RevokeHook 的 ReflectiveInject.c (GetReflectiveLoaderOffset + LoadRemoteLibraryR)

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "ReflectiveInject.h"

static DWORD FindMainWeixinPid(void)
{
    // 枚举 Weixin.exe, 取工作集最大的(主进程)
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    DWORD best = 0;
    // 工作集需要 psapi; 这里用线程数+父进程不可靠 —— 改为: 由调用者传 pid, 此函数仅返回第一个
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
    if (argc < 3) {
        printf("usage: wx_inject.exe <pid|auto> <dll_path>\n");
        return 1;
    }

    DWORD pid = 0;
    if (lstrcmpiA(argv[1], "auto") == 0) {
        pid = FindMainWeixinPid();
        if (!pid) { printf("[-] Weixin.exe not found\n"); return 1; }
        printf("[+] auto-detected Weixin.exe pid=%lu\n", (unsigned long)pid);
    } else {
        pid = (DWORD)strtoul(argv[1], NULL, 10);
    }

    HANDLE hFile = CreateFileA(argv[2], GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { printf("[-] open dll failed: %lu\n", GetLastError()); return 1; }
    DWORD size = GetFileSize(hFile, NULL);
    BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size);
    DWORD read = 0;
    ReadFile(hFile, buf, size, &read, NULL);
    CloseHandle(hFile);
    printf("[+] dll size: %lu bytes\n", size);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { printf("[-] OpenProcess failed: %lu\n", GetLastError()); return 1; }
    printf("[+] process opened: %lu\n", pid);

    HANDLE hThread = LoadRemoteLibraryR(hProc, buf, size, NULL);
    if (!hThread) { printf("[-] LoadRemoteLibraryR failed: %lu\n", GetLastError()); return 1; }
    printf("[+] remote thread started, waiting for ReflectiveLoader...\n");
    WaitForSingleObject(hThread, 15000);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    printf("[+] remote thread exit code: 0x%08lX\n", (unsigned long)exitCode);
    CloseHandle(hThread);
    CloseHandle(hProc);
    HeapFree(GetProcessHeap(), 0, buf);
    printf("[+] done. check log: C:\\Users\\fish\\ZCodeProject\\wx_probe_log.txt\n");
    return 0;
}
