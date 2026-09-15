# -*- coding: utf-8 -*-
# v69: 图片模板捕获 — UP1 非文本 vtable → image_template.bin + 记录 vtable RVA + resp 扩容
import io, re
P = r'E:\weixin-hook-4.1.8\hook-wx\m3\src\wx_send_v65.c'
src = io.open(P, encoding='utf-8').read()
assert 'IMG_TEMPLATE' not in src, 'already applied'
B = chr(92)

imgpath = '#define IMG_TEMPLATE_PATH   "E:' + B+B + 'weixin-hook-4.1.8' + B+B + 'hook-wx' + B+B + 'm3' + B+B + 'image_template.bin"\n#define IMG_CAP_SIZE    0xA00'

# 1) 常量 (插在 TEMPLATE_PATH 行后)
m = re.search(r'#define TEMPLATE_PATH[^\n]*\n', src)
assert m, 'TEMPLATE_PATH anchor'
src = src.replace(m.group(0), m.group(0) + imgpath + '\n', 1)

# 2) 全局
old = 'unsigned char* g_templateObj = 0;'
assert old in src
src = src.replace(old, '''unsigned char* g_templateObj = 0;
// v69: 图片(非文本vtable)模板捕获
unsigned char* g_imgTemplate = 0;
volatile u64 g_imgVtRva = 0;''', 1)

# 3) C_helper vtable 失配分支 → 捕获图片模板
old = '    if (*(void**)obj != (void*)((u64)g_base + VT_RVA)) return;'
assert old in src
new = '''    if (*(void**)obj != (void*)((u64)g_base + VT_RVA)) {
        // v69: 非文本 vtable (图片等) -> 捕获模板一次
        if (!g_imgTemplate) {
            u64 vt = *(u64*)obj;
            g_imgVtRva = vt - (u64)(ULONG_PTR)g_base;
            g_imgTemplate = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, IMG_CAP_SIZE);
            if (g_imgTemplate) {
                memcpy(g_imgTemplate, obj, IMG_CAP_SIZE);
                LogL("[IMG] template captured");
                LogHex("[IMG] vtable RVA=", g_imgVtRva);
                LogHex("[IMG] obj=", (u64)(ULONG_PTR)obj);
                HANDLE f = CreateFileA(IMG_TEMPLATE_PATH, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
                if (f != INVALID_HANDLE_VALUE) { DWORD w = 0; WriteFile(f, g_imgTemplate, IMG_CAP_SIZE, &w, NULL); CloseHandle(f); LogL("[IMG] saved to disk"); }
            }
        }
        return;
    }'''
src = src.replace(old, new, 1)

# 4) STATUS 增报 img
m = re.search(r'wsprintfA\(resp, "OK hits=[^;]+;', src)
assert m, 'status line'
line = m.group(0)
new_line = line.replace('mgr=%I64u', 'mgr=%I64u img=%I64u').replace('g_pumpHits, g_sessExec, g_mgr2);', 'g_pumpHits, g_sessExec, g_mgr2, g_imgVtRva);')
src = src.replace(line, new_line, 1)

# 5) resp 扩容
oldbuf = 'char resp[64] = "ERR' + B+'n' + '";'
assert oldbuf in src, 'resp buffer'
src = src.replace(oldbuf, 'char resp[160] = "ERR' + B+'n' + '";', 1)

io.open(P, 'w', encoding='utf-8').write(src)
print('v69 applied OK')
