# patch_v49.py - capture executor only from UP1-thread spawns (thread affinity)
src = open('src/wx_send.c', encoding='utf-8').read()

old = '''void __fastcall C_coHook(void* dummy, u64 optsP5) {
    (void)dummy;
    if (g_qAH == g_qAT) return;                 // 热路径快速退出
    if (!g_base || !g_mgr2) return;             // mgr 未武装
    if (g_tid2 && GetCurrentThreadId() != g_tid2) return;  // 仅 UP1 线程 (上下文链完备)
    if (GetTickCount64() - g_up1Tick < 10000) return;      // 10s 静默闸: 杜绝管线中途派生 (v44 红感叹号教训)
    if (!optsP5) return;
    if (InterlockedExchange(&g_hookBusy, 1)) return;  // 重入保护 (我们的 CoCreate 会再次进钩子)
    Cmd t;
    while (QPopA(&t)) SpawnFlushWith(&t, optsP5);  // v47: 复用"本次调用"的 P5 — 微信此刻正在用它, 必然有效
    InterlockedExchange(&g_hookBusy, 0);
}'''
assert old in src, 'C_coHook not found'
new = '''void __fastcall C_coHook(void* dummy, u64 optsP5) {
    (void)dummy;
    if (!g_base || !g_tid2) return;
    // v49: 仅当 CoCreate 发生在 UP1 线程时捕获 options —— 执行器与派生线程亲和一致
    // (v45/v46 用随机后台线程的 options → 线程亲和断言 abort)
    if (GetCurrentThreadId() == g_tid2 && optsP5) g_sendOpts = optsP5;
    if (g_qAH == g_qAT) return;                 // 热路径快速退出
    if (!g_mgr2) return;                        // mgr 未武装
    if (!g_sendOpts) return;                    // 尚无 UP1 线程执行器
    if (GetCurrentThreadId() != g_tid2) return; // 派发仅限 UP1 线程
    if (GetTickCount64() - g_up1Tick < 10000) return;      // 10s 静默闸: 杜绝管线中途派生 (v44 红感叹号教训)
    if (InterlockedExchange(&g_hookBusy, 1)) return;  // 重入保护 (我们的 CoCreate 会再次进钩子)
    Cmd t;
    while (QPopA(&t)) SpawnFlushWith(&t, g_sendOpts);
    InterlockedExchange(&g_hookBusy, 0);
}'''
src = src.replace(old, new, 1)

open('src/wx_send.c', 'w', encoding='utf-8').write(src)
print('v49 patched')
