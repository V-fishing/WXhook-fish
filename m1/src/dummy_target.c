// dummy_target.c — 无害注入测试靶子(纯 Sleep 循环进程)
// 崩了也不心疼, 专门用来调试反射注入
#include <windows.h>
#include <stdio.h>

int main(void)
{
    printf("[dummy target] pid=%lu running, Ctrl+C to stop...\n", (unsigned long)GetCurrentProcessId());
    for (;;) {
        Sleep(1000);
    }
    return 0;
}
