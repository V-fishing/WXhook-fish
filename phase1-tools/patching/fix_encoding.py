# -*- coding: utf-8 -*-
"""修复 monitor_web.py 的混合编码问题: 把 GBK 段落转成 UTF-8"""
import os

PATH = r'E:\Desktop_fish\ProgramStudy\wechat-decrypt-main\wechat-decrypt-main\monitor_web.py'

data = open(PATH, 'rb').read()
print('file size:', len(data))

# 迭代修复: 反复尝试 utf-8 解码, 在失败点尝试 GBK 解码局部
for round_i in range(50):
    try:
        text = data.decode('utf-8')
        print(f'round {round_i}: fully valid UTF-8 now')
        break
    except UnicodeDecodeError as e:
        bad_start = e.start
        # 向后找到一个能切的边界 (最多 200 字节窗口)
        fixed = False
        for win in range(2, 200):
            seg = data[bad_start:bad_start + win]
            try:
                seg_text = seg.decode('gbk')
            except Exception:
                continue
            # 确认这段确实是 GBK 中文 (解码后含 CJK)
            if any('\u4e00' <= c <= '\u9fff' for c in seg_text):
                new_bytes = seg_text.encode('utf-8')
                data = data[:bad_start] + new_bytes + data[bad_start + win:]
                line_no = data[:bad_start].count(b'\n') + 1
                print(f'round {round_i}: fixed GBK segment @byte {bad_start} (line ~{line_no}): "{seg_text[:20]}"')
                fixed = True
                break
        if not fixed:
            # 跳过一个字节继续
            print(f'round {round_i}: unfixable byte @ {bad_start} (0x{data[bad_start]:02X}), dropping')
            data = data[:bad_start] + data[bad_start+1:]
else:
    print('WARNING: did not converge')

open(PATH, 'wb').write(data)
print('saved as UTF-8')

# 最终验证
text = open(PATH, encoding='utf-8').read()
print('verify: file now decodes as UTF-8 OK,', len(text), 'chars')
