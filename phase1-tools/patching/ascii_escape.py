# -*- coding: utf-8 -*-
"""把 WX_EMOJI 常量区域的非 ASCII 字符转成 JS \\u{} 转义 → 源码变纯 ASCII"""
import os

PATH = r'E:\Desktop_fish\ProgramStudy\wechat-decrypt-main\wechat-decrypt-main\monitor_web.py'

data = open(PATH, 'rb').read()
lines = data.split(b'\n')

def to_js_escapes(text):
    out = []
    for c in text:
        if ord(c) < 0x80:
            out.append(c)
        else:
            out.append('\\u{%x}' % ord(c))
    return ''.join(out)

changed = 0
for idx, line in enumerate(lines):
    if len(line) <= 200:
        continue
    text = line.decode('utf-8')
    non_ascii = sum(1 for c in text if ord(c) > 0x7f)
    # 密集非 ASCII 的行(emoji 表/中文UI串)才转义; 只转 >100 字节的行规避 tokenizer bug
    if non_ascii > 10:
        new_text = to_js_escapes(text)
        lines[idx] = new_text.encode('ascii')
        changed += 1
        print('line %d: %dB %d nonascii -> ascii %dB' % (idx + 1, len(line), non_ascii, len(lines[idx])))

if changed:
    open(PATH, 'wb').write(b'\n'.join(lines))
    print('saved,', changed, 'lines converted')
else:
    print('no dense non-ascii lines found')
