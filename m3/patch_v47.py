# patch_v47.py - piggyback the CURRENT CoCreate call's P5 (guaranteed valid)
src = open('src/wx_send.c', encoding='utf-8').read()

# 1. asm: pass current P5 (in rax) as 2nd arg to C_coHook
old = '"  sub $0x28, %rsp\\n"\n"  call C_coHook\\n"'
assert old in src, 'call site not found'
new = '"  sub $0x28, %rsp\\n"\n"  mov %rax, %rdx\\n"\n"  xor %ecx, %ecx\\n"\n"  call C_coHook\\n"'
src = src.replace(old, new, 1)

# 2. C_coHook: use the CURRENT call's P5 (valid right now), with gates
old2 = '''static void __fastcall C_coHook(void* dummy, u64 retaddr) {
    (void)dummy; (void)retaddr;
    if (g_qAH == g_qAT) return;                 // 热路径快速退出
    if (!g_base || !g_mgr2) return;             // mgr 未武装
    if (g_tid2 && GetCurrentThreadId() != g_tid2) return;  // 仅 UP1 线程 (上下文链完备)
    if (GetTickCount64() - g_up1Tick < 10000) return;      // 10s 静默闸: 杜绝管线中途派生 (v44 红感叹号教训)
    if (InterlockedExchange(&g_hookBusy, 1)) return;  // 重入保护 (我们的 CoCreate 会再次进钩子)
    Cmd t;
    while (QPopA(&t)) SpawnFlush(&t);
    InterlockedExchange(&g_hookBusy, 0);
}'''
assert old2 in src, 'C_coHook not found'
new2 = '''static void __fastcall C_coHook(void* dummy, u64 optsP5) {
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
src = src.replace(old2, new2, 1)

# 3. SpawnFlush -> SpawnFlushWith(opts)
old3 = '''static void SpawnFlush(Cmd* a) {
    static void* bodyHolder = (void*)&FlushBody;  // *P2 → coro+0x350 (body)
    void* argHolder = (void*)a;                    // *P3 → coro+0x360 (arg)
    static void* cleanupHolder = 0;                // *P4 → coro+0x358 (可空清理回调)
    SP sp;
    if (!g_sendOpts) { LogL("[SPAWN] no send-executor options yet"); return; }
    CoCreateFn cocreate = (CoCreateFn)(g_base + COCREATE_RVA);
    // v42: P5 复用 CoCreate 捕获钩子存下的微信真实 options (含合法 executor)
    // resume_if 断言 coro+0x368(executor=options+0x20) 非空, 自造 options 缺件即 abort (v41 教训)
    cocreate(&sp, &bodyHolder, &argHolder, &cleanupHolder, (void*)g_sendOpts);
    if (!sp.obj) { LogL("[SPAWN] cocreate fail"); return; }
    SchedFn sched = (SchedFn)(g_base + SCHED_RVA);
    sched(&sp, 0);
    LogL("[SPAWN] coroutine scheduled");
    // v45: 不释放引用 —— resume_if 若只持弱引用, 过早释放 = 队列中协程被析构 (v42 延时崩教训)
    // 每条消息泄漏 ~1.3KB, 可接受
}'''
assert old3 in src, 'SpawnFlush not found'
new3 = '''static void SpawnFlushWith(Cmd* a, u64 optsP5) {
    static void* bodyHolder = (void*)&FlushBody;  // *P2 → coro+0x350 (body)
    void* argHolder = (void*)a;                    // *P3 → coro+0x360 (arg)
    static void* cleanupHolder = 0;                // *P4 → coro+0x358 (可空清理回调)
    SP sp;
    CoCreateFn cocreate = (CoCreateFn)(g_base + COCREATE_RVA);
    // v47: P5 = 本次 CoCreate 调用的实参 (微信此刻正在用它, 执行器必然有效)
    cocreate(&sp, &bodyHolder, &argHolder, &cleanupHolder, (void*)optsP5);
    if (!sp.obj) { LogL("[SPAWN] cocreate fail"); return; }
    SchedFn sched = (SchedFn)(g_base + SCHED_RVA);
    sched(&sp, 0);
    LogL("[SPAWN] coroutine scheduled");
    // 不释放引用: 防队列中协程被过早析构 (v42 延时崩教训); 每条泄漏 ~1.3KB
}'''
src = src.replace(old3, new3, 1)

open('src/wx_send.c', 'w', encoding='utf-8').write(src)
print('v47 patched')
