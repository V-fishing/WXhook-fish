import re

data = open(r'E:\weixin-hook-4.1.8\-ce-\微信过低版本工具.exe', 'rb').read()

print('=== ascii strings with path/underscore (name-like) ===')
seen = set()
for m in re.finditer(rb'[\x20-\x7e]{5,100}', data):
    t = m.group().decode('latin1')
    if t in seen:
        continue
    seen.add(t)
    if ('\\' in t or '_' in t):
        lo = t.lower()
        if any(x in lo for x in ['map', 'sec', 'shm', 'mem', 'share', 'pipe', 'event', 'mutex', 'wx', 'wechat', 'tencent', 'qq', 'local', 'global']):
            print(repr(t))

print()
print('=== utf16 strings ===')
seen = set()
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){4,80}', data):
    t = m.group().decode('utf-16le', errors='ignore')
    if t in seen or len(t) < 5:
        continue
    seen.add(t)
    lo = t.lower()
    if any(x in lo for x in ['map', 'sec', 'shm', 'mem', 'share', 'pipe', 'event', 'mutex', 'wechat', 'tencent', '3.9', '4.1']) or '\\' in t:
        print(repr(t))

print()
print('=== ALL short strings 4-20 chars (sample 100) ===')
short = [s.decode('latin1') for s in set(re.findall(rb'[\x20-\x7e]{4,20}', data))]
print('\n'.join(sorted(short)[:100]))
