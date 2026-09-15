# patch_v46.py - capture send-executor options at UP1 hit time
src = open('src/wx_send.c', encoding='utf-8').read()

# 1. global for send-executor options
old = 'static volatile u64 g_up1Tick = 0;   // 最近一次 UP1 命中时刻 (10s 静默闸)'
assert old in src
src = src.replace(old, old + '\nstatic volatile u64 g_sendOpts = 0;   // UP1 命中瞬间捕获的 options (发送协程执行器, 持久)', 1)

# 2. C_helper: refresh g_sendOpts = g_capOpts at every UP1 hit
old2 = 'void C_helper(void* p3, u64 flag) {\n    g_hits2++;\n    g_up1Tick = GetTickCount64();'
assert old2 in src
src = src.replace(old2, '''void C_helper(void* p3, u64 flag) {
    g_hits2++;
    g_up1Tick = GetTickCount64();
    // v46: UP1 命中瞬间, 最近一次 CoCreate 的 options 就是发送协程的 (执行器持久)
    if (g_capValid) g_sendOpts = g_capOpts;''', 1)

# 3. SpawnFlush: use g_sendOpts instead of g_capOpts
old3 = '''    if (!g_capValid) { LogL("[SPAWN] no captured options yet"); return; }'''
assert old3 in src
src = src.replace(old3, '''    if (!g_sendOpts) { LogL("[SPAWN] no send-executor options yet"); return; }''', 1)
old4 = '    cocreate(&sp, &bodyHolder, &argHolder, &cleanupHolder, (void*)g_capOpts);'
assert old4 in src
src = src.replace(old4, '    cocreate(&sp, &bodyHolder, &argHolder, &cleanupHolder, (void*)g_sendOpts);', 1)

open('src/wx_send.c', 'w', encoding='utf-8').write(src)
print('v46 patched')
