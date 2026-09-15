# patch_v63.py — session context transplant: TLS+0x1F0 = the captured session coro SP
src = open('src/wx_send.c', encoding='utf-8').read()

# 1. global for the captured session SP pointer
old = 'u64 g_hijackRet = 0;                 // 保存的原 RIP (跳回目标, asm 引用)'
assert old in src
src = src.replace(old, old + '\nstatic volatile u64 g_savedSPPtr = 0;  // 会话协程的 SP 槽指针 (C_helper 捕获, GetCtx 用)', 1)

# 2. C_helper: capture TLS+0x1F0's value (the SP slot pointer) at the UP1 entry
old2 = '''    // v61: v54 静默标志移除 — TLS+0x360 bit0 = "使用线程本地 locale" 标志,
    // 置位后时间戳格式化读到空 locale → 故意陷阱 (0xFEA90) = v54-v56 崩溃真因!'''
assert old2 in src
new2 = '''    // v61: v54 静默标志移除 — TLS+0x360 bit0 = "使用线程本地 locale" 标志,
    // 置位后时间戳格式化读到空 locale → 故意陷阱 (0xFEA90) = v54-v56 崩溃真因!
    // v63: 捕获会话协程的 SP 槽指针 (TLS+0x1F0) — 劫持时恢复给 UP1 管线的 GetCtx
    {
        u64 tlsarr2 = 0, blk2 = 0;
        __asm__ volatile("movq %%gs:0x58, %0" : "=r"(tlsarr2));
        u32 ti2 = *(u32*)(g_base + 0xB5D6A70);
        blk2 = *(u64*)(tlsarr2 + (u64)ti2 * 8);
        if (blk2) g_savedSPPtr = *(u64*)(blk2 + 0x1F0);   // &{coro, ctrl} = 会话协程 SP
    }'''
src = src.replace(old2, new2, 1)

# 3. C_HijackFlush: set TLS+0x1F0 = the session SP before the flush, restore after
old3 = '''void __fastcall C_HijackFlush(void* dummy) {
    (void)dummy;
    Cmd t;
    while (QPopA(&t)) FactoryFlush(&t);     // 工厂造对象 + flag=1 全管线发送
    InterlockedExchange(&g_hijackPending, 0);
}'''
assert old3 in src
new3 = '''void __fastcall C_HijackFlush(void* dummy) {
    (void)dummy;
    // v63: 会话上下文移植 — UP1 管线的 GetCtx 读 TLS+0x1F0 (当前协程),
    // park 时 = 0 → GetCtx NULL 崩溃 (0x462C1E)。设为会话协程的 SP 槽指针
    // → GetCtx 返回会话协程 ✓ 管线在合法上下文中运行 ✓
    u64 tlsarr = 0, blk = 0, orig = 0;
    __asm__ volatile("movq %%gs:0x58, %0" : "=r"(tlsarr));
    u32 ti = *(u32*)(g_base + 0xB5D6A70);
    blk = *(u64*)(tlsarr + (u64)ti * 8);
    if (blk && g_savedSPPtr) {
        orig = *(u64*)(blk + 0x1F0);                    // save (likely 0)
        *(u64*)(blk + 0x1F0) = g_savedSPPtr;            // ★ 会话协程 SP 注入!
        LogL("[HIJACK-TLS] session SP injected");
    }
    Cmd t;
    while (QPopA(&t)) FactoryFlush(&t);     // 工厂造对象 + flag=1 全管线发送
    if (blk) *(u64*)(blk + 0x1F0) = orig;           // restore
    InterlockedExchange(&g_hijackPending, 0);
}'''
src = src.replace(old3, new3, 1)

# 4. re-enable the HijackThread install
old4 = '// v61: HijackThread 移除 — park 上下文的 FactoryFlush 触发框架自毁陷阱'
assert old4 in src
src = src.replace(old4, '', 1)

open('src/wx_send.c', 'w', encoding='utf-8').write(src)
print('v63 patched')
