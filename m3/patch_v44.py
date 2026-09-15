# patch_v44.py - C_coHook + AUTO queue mode + gut C_auto
src = open('src/wx_send.c', encoding='utf-8').read()

# 1. C_coHook before SpawnFlush definition
anchor = 'static void SpawnFlush(Cmd* a) {'
assert anchor in src, 'SpawnFlush def not found'
hook = (
'static volatile LONG g_hookBusy = 0;\n'
'\n'
'// CoCreate 钩子回调: 微信每次派生协程时, 借同线程同状态派生我们自己的冲刷协程\n'
'static void __fastcall C_coHook(void* dummy, u64 retaddr) {\n'
'    (void)dummy; (void)retaddr;\n'
'    if (g_qAH == g_qAT) return;                 // 热路径快速退出\n'
'    if (!g_base || !g_mgr2) return;             // mgr 未武装\n'
'    if (InterlockedExchange(&g_hookBusy, 1)) return;  // 重入保护 (我们的 CoCreate 会再次进钩子)\n'
'    Cmd t;\n'
'    while (QPopA(&t)) SpawnFlush(&t);\n'
'    InterlockedExchange(&g_hookBusy, 0);\n'
'}\n'
'\n') + anchor
src = src.replace(anchor, hook, 1)

# 2. HandleClient AUTO: always queue (hook drains when WeChat spawns on veteran thread)
old_auto = (
'                if (g_mgr2) {\n'
'                    Cmd* hc = (Cmd*)HeapAlloc(GetProcessHeap(), 0, sizeof(Cmd));\n'
'                    if (hc) { *hc = cmd; SpawnFlush(hc); lstrcpyA(resp, "OK auto spawned\\n"); }\n'
'                    else lstrcpyA(resp, "ERR alloc\\n");\n'
'                } else if (QPushA(&cmd)) lstrcpyA(resp, "OK auto queued\\n");\n'
'                else lstrcpyA(resp, "ERR full\\n");')
assert old_auto in src, 'auto branch v42 not found'
new_auto = (
'                if (QPushA(&cmd)) lstrcpyA(resp, "OK auto queued (hook drains)\\n");\n'
'                else lstrcpyA(resp, "ERR full\\n");')
src = src.replace(old_auto, new_auto, 1)

# 3. gut C_auto (wait hook removed; no callers)
i = src.find('void C_auto(void* dummy, u64 retaddr) {')
assert i >= 0, 'C_auto not found'
j = src.find('\n}\n', i)
assert j > i
src = src[:i] + 'void C_auto(void* dummy, u64 retaddr) {\n    (void)dummy; (void)retaddr;  // v44: 等待钩子已撤除\n' + src[j:]

open('src/wx_send.c', 'w', encoding='utf-8').write(src)
print('v44 patched')
