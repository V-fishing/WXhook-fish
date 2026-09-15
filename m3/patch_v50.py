# patch_v50.py - set coroutine state = 1 (queued) after CoCreate
src = open('src/wx_send.c', encoding='utf-8').read()

old = '''    *(void**)sp.obj = sp.obj;
    *(void**)((unsigned char*)sp.obj + 8) = sp.ctrl;'''
assert old in src, 'self-SP fill not found'
new = '''    *(void**)sp.obj = sp.obj;
    *(void**)((unsigned char*)sp.obj + 8) = sp.ctrl;
    // v50: 协程状态初值 — 真实协程 state 只见 1(排队)/2(运行)/3(结束), spawn 清零为 0 = 非法
    // 执行器处理 resume-item 时对非法 state 抛 co_exception → 未捕获 → terminate
    *(int*)((unsigned char*)sp.obj + 0x388) = 1;'''
src = src.replace(old, new, 1)

open('src/wx_send.c', 'w', encoding='utf-8').write(src)
print('v50 patched')
