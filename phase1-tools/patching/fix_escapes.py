# -*- coding: utf-8 -*-
"""把 monitor_web.py 中所有单反斜杠的 \\u{ 变成双反斜杠 \\u{ (Python 字符串字面量里保留给 JS)"""
p = r'E:\Desktop_fish\ProgramStudy\wechat-decrypt-main\wechat-decrypt-main\monitor_web.py'

data = open(p, 'rb').read()
SINGLE = bytes([0x5C, 0x75, 0x7B])   # \u{
DOUBLE = bytes([0x5C, 0x5C, 0x75, 0x7B])  # \\u{
n = data.count(SINGLE)
print('found', n, 'occurrences of single-backslash \\u{')
if n:
    data = data.replace(SINGLE, DOUBLE)
    open(p, 'wb').write(data)
    print('replaced all ->', DOUBLE.hex())
# verify: compile
compile(open(p, 'rb').read(), p, 'exec')
print('compile OK')
