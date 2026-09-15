# -*- coding: utf-8 -*-
"""分析 contact.db 的联系人构成 —— 回答"21497个联系人哪来的"""
import os
import sys
import json
import sqlite3
import tempfile

sys.path.insert(0, r'E:\Desktop_fish\ProgramStudy\wechat-decrypt-main\wechat-decrypt-main')
from decrypt_db import decrypt_database  # noqa: E402
import config as cfg  # noqa: E402

keys = json.load(open(cfg.keys_file, encoding='utf-8'))

# 找 contact.db 的密钥
contact_key = None
for k, v in keys.items():
    if 'contact.db' in k and 'fts' not in k:
        contact_key = v
        break
if not contact_key:
    print('contact.db key not found')
    sys.exit(1)

src = os.path.join(cfg.db_dir, 'contact', 'contact.db')
tmp = os.path.join(tempfile.gettempdir(), 'contact_analysis.db')
decrypt_database(src, tmp, bytes.fromhex(contact_key['enc_key']))

conn = sqlite3.connect(tmp)
total = conn.execute('SELECT COUNT(*) FROM contact').fetchone()[0]
print('contact 表总行数:', total)
print()

# 按 username 前缀分类
rows = conn.execute('SELECT username, nick_name, remark, type FROM contact').fetchall()
cats = {
    '群聊(@chatroom)': 0,
    '公众号/服务号(gh_)': 0,
    '企业微信(wecom工作)': 0,
    '微信团队/系统官方': 0,
    '普通联系人(wxid等)': 0,
    '其他': 0,
}
samples = {k: [] for k in cats}
for username, nick, remark, typ in rows:
    u = username or ''
    if u.endswith('@chatroom'):
        k = '群聊(@chatroom)'
    elif u.startswith('gh_'):
        k = '公众号/服务号(gh_)'
    elif u.startswith('wxid_') or u.startswith('weixin'):
        k = '普通联系人(wxid等)'
    elif 'corpx' in u.lower() or u.startswith('CORP') or u.startswith('WXWork') or u.startswith('ww'):
        k = '企业微信(wecom工作)'
    elif u in ('weixin', 'filehelper', 'fmessage', 'medianote', 'newsapp', 'floatbottle'):
        k = '微信团队/系统官方'
    else:
        k = '其他'
    cats[k] += 1
    if len(samples[k]) < 3:
        samples[k].append((u[:28], (nick or '')[:16]))

for k, v in sorted(cats.items(), key=lambda x: -x[1]):
    print('%-22s %6d' % (k, v))
    for s in samples[k]:
        print('     e.g. %s (%s)' % s)

conn.close()
os.remove(tmp)
