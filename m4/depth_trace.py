# -*- coding: utf-8 -*-
# 逐行深度追踪 POnUp1
import io

lines = io.open('wx_payload.c', encoding='utf-8', errors='replace').read().split('\n')
start = next(i for i, l in enumerate(lines) if 'static void POnUp1' in l)
depth = 0
in_str = in_chr = in_com = False
BS = chr(92)

for i in range(start, min(start + 135, len(lines))):
    l = lines[i]
    j = 0
    opened = closed = 0
    while j < len(l):
        ch = l[j]
        if in_com:
            if l[j:j+2] == '*/':
                in_com = False
            j += 1
            continue
        if in_str:
            if ch == BS:
                j += 2
                continue
            if ch == '"':
                in_str = False
            j += 1
            continue
        if in_chr:
            if ch == BS:
                j += 2
                continue
            if ch == "'":
                in_chr = False
            j += 1
            continue
        if l[j:j+2] == '//':
            break
        if l[j:j+2] == '/*':
            in_com = True
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
            opened += 1
        elif ch == '}':
            depth -= 1
            closed += 1
        j += 1
    print(f'{i+1}: d={depth} (+{opened}/-{closed})  {l[:64]}')
    if depth < 0:
        break
