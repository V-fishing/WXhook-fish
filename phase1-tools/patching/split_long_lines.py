# -*- coding: utf-8 -*-
"""拆分 monitor_web.py 中的超长行(绕开 CPython 3.9 tokenizer 超长行多字节截断 bug)"""
import os

PATH = r'E:\Desktop_fish\ProgramStudy\wechat-decrypt-main\wechat-decrypt-main\monitor_web.py'
MAX_LINE = 1000

data = open(PATH, 'rb').read()
lines = data.split(b'\n')
print('before:', len(lines), 'lines')

changed = 0
for idx, line in enumerate(lines):
    if len(line) <= MAX_LINE:
        continue
    text = line.decode('utf-8')
    # 只处理 JS 对象字面量形态: const XXX={...};
    stripped = text.strip()
    if stripped.startswith('const ') and '={' in stripped and stripped.endswith(';'):
        m_start = stripped.index('={') + 2
        m_end = stripped.rindex('};')
        head = stripped[:m_start]          # const WX_EMOJI={
        body = stripped[m_start:m_end]     # 'k':'v','k':'v',...
        tail = '};'
        # 按 '',' 边界切分条目 (键为中文/数字, 值为 emoji, 均不含 ASCII 逗号)
        entries = body.split(',')
        out_lines = []
        cur = head
        for e in entries:
            piece = e + ','
            if len(cur) + len(piece) > 900:
                out_lines.append(cur)
                cur = '    ' + piece
            else:
                cur += piece
        cur += tail
        out_lines.append(cur)
        new_text = '\n'.join(out_lines)
        lines[idx] = new_text.encode('utf-8')
        changed += 1
        print(f'split line {idx+1}: {len(line)}B -> {len(out_lines)} lines')
    else:
        print(f'line {idx+1} is {len(line)}B but not a JS const object; skipped')

if changed:
    open(PATH, 'wb').write(b'\n'.join(lines))
    print('saved. changed', changed, 'line(s)')
else:
    print('nothing changed')
