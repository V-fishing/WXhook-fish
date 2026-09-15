# -*- coding: utf-8 -*-
"""给 monitor_web.py 打 3 个最小补丁: OWN_WXID / self_msg 字段 / /wx 路由"""
import os

PATH = r'E:\Desktop_fish\ProgramStudy\wechat-decrypt-main\wechat-decrypt-main\monitor_web.py'
src = open(PATH, encoding='utf-8').read()
ok = True

# ── 补丁1: 解析自己的 wxid (数据目录名) ──
A1 = 'WECHAT_BASE_DIR = _cfg.get("wechat_base_dir", "")'
P1 = A1 + '''
# [wx-ui] 自己的 wxid (从数据目录名解析, 用于气泡左右判断)
OWN_WXID = ""
_bn = os.path.basename(WECHAT_BASE_DIR.replace("\\\\", "/").rstrip("/")) if WECHAT_BASE_DIR else ""
if _bn.startswith("wxid_"):
    OWN_WXID = _bn'''
if 'OWN_WXID' not in src:
    if A1 not in src: print('FAIL anchor1'); ok = False
    else: src = src.replace(A1, P1, 1); print('patch1 OK (OWN_WXID)')
else:
    print('patch1 already applied')

# ── 补丁2: 消息对象加 self_msg / raw_sender ──
A2 = "                    'unread': curr['unread'],"
P2 = ("                    'unread': curr['unread'],\n"
      "                    'self_msg': (OWN_WXID and curr['sender'] == OWN_WXID),\n"
      "                    'raw_sender': curr['sender'],")
cnt = src.count(A2)
if cnt == 1:
    src = src.replace(A2, P2, 1); print('patch2 OK (self_msg, %d occurrence)' % cnt)
elif 'self_msg' in src:
    print('patch2 already applied')
else:
    print('FAIL anchor2 count=', cnt); ok = False

# ── 补丁3: /wx 路由 (高仿微信界面) ──
A3 = '        elif self.path == "/api/tool":'
P3 = '''        elif self.path == '/wx' or self.path.startswith('/wx?'):
            # [wx-ui] 高仿微信界面 (wx_page.html 外部文件, __MY_WXID__ 注入)
            wx_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wx_page.html')
            try:
                with open(wx_file, 'rb') as f:
                    html = f.read().decode('utf-8')
                html = html.replace('__MY_WXID__', OWN_WXID or '')
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(html.encode('utf-8'))
            except Exception as wx_err:
                self.send_error(404, str(wx_err))

''' + A3
if '/wx' not in src:
    if A3 not in src: print('FAIL anchor3'); ok = False
    else: src = src.replace(A3, P3, 1); print('patch3 OK (/wx route)')
else:
    print('patch3 already applied')

if ok:
    open(PATH, 'w', encoding='utf-8').write(src)
    print('SAVED')
    compile(open(PATH, 'rb').read(), PATH, 'exec')
    print('COMPILE OK')
else:
    print('NOT SAVED - fix anchors first')
