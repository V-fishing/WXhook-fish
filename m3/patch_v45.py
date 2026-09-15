# patch_v45.py - silence gate + UP1-thread gate + leak coroutine ref
src = open('src/wx_send.c', encoding='utf-8').read()

# 1. C_coHook gates: UP1 thread + 10s silence
old = (
'    if (g_qAH == g_qAT) return;                 // 热路径快速退出\n'
'    if (!g_base || !g_mgr2) return;             // mgr 未武装\n'
'    if (InterlockedExchange(&g_hookBusy, 1)) return;  // 重入保护 (我们的 CoCreate 会再次进钩子)\n')
assert old in src, 'cohook gates not found'
new = (
'    if (g_qAH == g_qAT) return;                 // 热路径快速退出\n'
'    if (!g_base || !g_mgr2) return;             // mgr 未武装\n'
'    if (g_tid2 && GetCurrentThreadId() != g_tid2) return;  // 仅 UP1 线程 (上下文链完备)\n'
'    if (GetTickCount64() - g_up1Tick < 10000) return;      // 10s 静默闸: 杜绝管线中途派生 (v44 红感叹号教训)\n'
'    if (InterlockedExchange(&g_hookBusy, 1)) return;  // 重入保护 (我们的 CoCreate 会再次进钩子)\n')
src = src.replace(old, new, 1)

# 2. SpawnFlush: leak our coroutine ref (v42: premature free killed the queued coroutine)
old2 = '''    SchedFn sched = (SchedFn)(g_base + SCHED_RVA);
    sched(&sp, 0);
    LogL("[SPAWN] coroutine scheduled");
    ReleaseSp(&sp);
}'''
assert old2 in src, 'sched tail not found'
new2 = '''    SchedFn sched = (SchedFn)(g_base + SCHED_RVA);
    sched(&sp, 0);
    LogL("[SPAWN] coroutine scheduled");
    // v45: 不释放引用 —— resume_if 若只持弱引用, 过早释放 = 队列中协程被析构 (v42 延时崩教训)
    // 每条消息泄漏 ~1.3KB, 可接受
}'''
src = src.replace(old2, new2, 1)

open('src/wx_send.c', 'w', encoding='utf-8').write(src)
print('v45 patched')
