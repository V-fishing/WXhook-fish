# patch_v48.py - fill the coroutine self-SP after CoCreate
src = open('src/wx_send.c', encoding='utf-8').read()

old = '''    cocreate(&sp, &bodyHolder, &argHolder, &cleanupHolder, (void*)optsP5);
    if (!sp.obj) { LogL("[SPAWN] cocreate fail"); return; }
    SchedFn sched = (SchedFn)(g_base + SCHED_RVA);'''
assert old in src, 'spawn core not found'
new = '''    cocreate(&sp, &bodyHolder, &argHolder, &cleanupHolder, (void*)optsP5);
    if (!sp.obj) { LogL("[SPAWN] cocreate fail"); return; }
    // v48: 自填协程自引用 SP (inner[0]=inner, inner[1]=ctrl)
    // CoroutineSpawn 清零了 inner+0x00/+0x08, 微信自己的流程后续会填 {inner, outer};
    // 我们不填 → resume_if 读 inner[1]==0 abort(静默闪退), 或 TLS 槽悬挂 → GetCtx AV(0x462C1E)
    // 借用 CoCreate 返回的那份引用(我们不释放) = 自引用计数成立
    *(void**)sp.obj = sp.obj;
    *(void**)((unsigned char*)sp.obj + 8) = sp.ctrl;
    SchedFn sched = (SchedFn)(g_base + SCHED_RVA);'''
src = src.replace(old, new, 1)

open('src/wx_send.c', 'w', encoding='utf-8').write(src)
print('v48 patched')
