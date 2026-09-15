# -*- coding: utf-8 -*-
# v70: 图片自主发送 — AIMG 队列 + ImageFlush (克隆图片模板, 自包含文件名, 新 UUID)
import io, re
P = r'E:\weixin-hook-4.1.8\hook-wx\m3\src\wx_send_v65.c'
src = io.open(P, encoding='utf-8').read()
assert 'ImageFlush' not in src, 'already applied'
B = chr(92)

# 1) 捕获时把 +0x1A8 指向的文件名内容拷进模板尾部 (+0x9A0, 0x60 字节)
old = '''                HANDLE f = CreateFileA(IMG_TEMPLATE_PATH, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);'''
assert old in src
src = src.replace(old, '''                {   // v70: 文件名字符串内容内嵌到模板尾部 (跨会话自包含)
                    u64 fnptr = *(u64*)(obj + 0x1A8);
                    if (fnptr) memcpy(g_imgTemplate + 0x9A0, (const void*)fnptr, 0x60);
                }
                HANDLE f = CreateFileA(IMG_TEMPLATE_PATH, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);''', 1)

# 2) ImageFlush + INIT 加载 image_template.bin (g_imgTemplate 已由 v69 声明, 勿重复)
anchor = '// ==== v66: 空闲自主冲刷'
assert anchor in src
block = '''// ==== v70: 图片自主发送 ====
static void ImageFlush(Cmd* a) {''' + '''
    if (!g_imgTemplate || !g_mgr2) return;
    unsigned char* clone = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, IMG_CAP_SIZE);
    if (!clone) return;
    memcpy(clone, g_imgTemplate, IMG_CAP_SIZE);
    *(u64*)(clone + 0x08) = (u64)(ULONG_PTR)clone;        // self
    *(u64*)(clone + 0x10) = (u64)(ULONG_PTR)(clone - 0x10); // refcount block
    if (a->targetLen > 0) WrFresh(clone, 0xB0, a->target, a->targetLen);
    {   // 文件名字符串 (+0x1A8): ptr -> 模板尾部内嵌缓冲 (克隆体内)
        memcpy(clone + 0x9A0, g_imgTemplate + 0x9A0, 0x60);
        *(u64*)(clone + 0x1A8) = (u64)(ULONG_PTR)(clone + 0x9A0);
        // size(+0x1B8)=0x28, cap(+0x1C0)=0x2F 随模板原值
    }
    {   // 新 clientMsgId (+0x6F8)
        char au[37]; GenUuid(au);
        WrFresh(clone, 0x6F8, au, 36);
    }
    LogL("[IMG] calling UP1 flag=1");
    void* csp[2] = {clone, NULL};
    UP1_fn up1f = (UP1_fn)(g_base + UP1_RVA);
    u64 fout[2] = {0, 0};
    up1f(g_mgr2, fout, (void*)csp, 1);
    LogL("[IMG] UP1 returned");
    g_rw++;
}

''' + anchor
src = src.replace(anchor, block, 1)

# 2.5) INIT 加载 image_template.bin
old = '''        HANDLE f = CreateFileA(TEMPLATE_PATH, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);'''
assert old in src
src = src.replace(old, '''        {
            HANDLE f2 = CreateFileA(IMG_TEMPLATE_PATH, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (f2 != INVALID_HANDLE_VALUE) {
                g_imgTemplate = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, IMG_CAP_SIZE);
                DWORD r2 = 0;
                ReadFile(f2, g_imgTemplate, IMG_CAP_SIZE, &r2, NULL);
                CloseHandle(f2);
                LogL("[IMG] template loaded from disk");
            }
        }
''' + old, 1)

# 3) FlushBodyForCo: flags==4 → ImageFlush
old = '''static void __fastcall FlushBodyForCo(void* arg) {
    Cmd* a = (Cmd*)arg;
    if (!a) return;
    LogL("[CORO] clone flush begin");
    FactoryFlush(a);
    LogL("[CORO] clone flush done");
}'''
assert old in src
src = src.replace(old, '''static void __fastcall FlushBodyForCo(void* arg) {
    Cmd* a = (Cmd*)arg;
    if (!a) return;
    if (a->flags == 4) { LogL("[CORO] image flush begin"); ImageFlush(a); LogL("[CORO] image flush done"); return; }
    LogL("[CORO] clone flush begin");
    FactoryFlush(a);
    LogL("[CORO] clone flush done");
}''', 1)

# 4) AIMG 管道命令 (flags=4)
old = '''    } else if (pos == 6 && req[0]=='S') {'''
assert old in src
src = src.replace(old, '''    } else if (pos >= 6 && req[0]=='A' && req[1]=='I' && req[2]=='M' && req[3]=='G' && req[4]=='|') {
        char* p2 = req + 5;
        char* sep = p2; while (*sep && *sep != '|') sep++;
        Cmd cmd; cmd.targetLen = 0; cmd.flags = 4;
        if (*sep == '|') {
            *sep = 0;
            for (char* s = p2; *s && cmd.targetLen < (int)sizeof(cmd.target)-1; s++) cmd.target[cmd.targetLen++] = *s;
        }
        cmd.target[cmd.targetLen] = 0;
        cmd.contentLen = 0; cmd.content[0] = 0;
        if (QPushA(&cmd)) lstrcpyA(resp, "OK aimg\n"); else lstrcpyA(resp, "ERR full\n");
''' + old, 1)

io.open(P, 'w', encoding='utf-8').write(src)
print('v70 applied OK')
