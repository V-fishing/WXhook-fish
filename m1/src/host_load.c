// host_load.c — DLL 本机 LoadLibrary 自检(验证 DLL 本身能否正常加载运行)
#include <windows.h>
#include <stdio.h>

int main(int argc, char** argv)
{
    if (argc < 2) { printf("usage: host_load.exe <dll>\n"); return 1; }
    printf("[+] LoadLibraryW(%s)...\n", argv[1]);
    HMODULE h = LoadLibraryA(argv[1]);
    if (!h) { printf("[-] LoadLibrary failed: %lu\n", GetLastError()); return 1; }
    printf("[+] loaded at 0x%p, waiting 5s for probe thread...\n", (void*)h);
    Sleep(5000);
    FreeLibrary(h);
    printf("[+] done\n");
    return 0;
}
