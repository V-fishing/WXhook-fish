# -*- coding: utf-8 -*-
# 字符串/注释感知的大括号深度分析: POnUp1 区域的真实嵌套结构
import io

lines = io.open('wx_payload.c', encoding='utf-8', errors='replace').read().split('\n')
start = next(i for i, l in enumerate(lines) if 'static void POnUp1' in l)
end_limit = min(len(lines), start + 220)

depth = 0
in_str = False
in_chr = False
in_comment = False
events = []
for i in range(start, end_limit):
    l = lines[i]
    j = 0
    line_events = []
    while j < len(l):
        ch = l[j]
        if in_comment:
            if l[j:j+2] == '*/':
                in_comment = False
                j += 2
                continue
            j += 1
            continue
        if in_str:
            if ch == '\\':
                j += 2
                continue
            if ch == '"':
                in_str = False
            j += 1
            continue
        if in_chr:
            if ch == '\\':
                j += 2
                continue
            if ch == "'":
                in_chr = False
            j += 1
            continue
        if l[j:j+2] == '//':
            break
        if l[j:j+2] == '/*':
            in_comment = True
            j += 2
            continue
        if ch == '"':
            in_str = True
            j += 1
            continue
        if ch == "'":
            in_chr = True
            j += 1
            continue
        if ch == '{':
            depth += 1
            line_events.append('open->' + str(depth))
        elif ch == '}':
            depth -= 1
            line_events.append('close->' + str(depth))
            if depth == 0:
                events.append((i + 1, 'FUNCTION END', l.strip()[:60]))
                break
        j += 1
    if events and events[-1][1] == 'FUNCTION END':
        break
    # 关键行标注
    for m in ('文本捕获', 'SES 捕获', '文本模板活体', 'SpawnAutoFlush();', 'IMG 分支', 'return;', 'M3 rewrite', 'FLUSH] dispatched'):
        if m in l:
            events.append((i + 1, f'depth={depth}', m + ' | ' + l.strip()[:40]))

for ln, tag, txt in events:
    print(f'{ln}: {tag}  {txt}')
print('最终 depth:', depth)
