import zlib
import re
import sys

path = r'C:\Users\fish\AppData\Roaming\Tencent\WeChat\log\MM_20260912.xlog'
data = open(path, 'rb').read()
print('file size:', len(data))

# try zlib streams at each plausible header
outputs = []
magics = [b'\x78\x9c', b'\x78\x01', b'\x78\xda', b'\x78\x5e']
pos = 0
attempts = 0
while pos < len(data) - 2:
    m = -1
    for mg in magics:
        i = data.find(mg, pos)
        if i >= 0 and (m < 0 or i < m):
            m = i
    if m < 0:
        break
    # try decompress from m
    try:
        d = zlib.decompressobj()
        out = d.decompress(data[m:m + 2 * 1024 * 1024])
        if len(out) > 8:
            outputs.append(out)
    except Exception:
        pass
    attempts += 1
    pos = m + 1
    if attempts > 8000:
        break

print('streams decompressed:', len(outputs))
blob = b'\n'.join(outputs)
print('total decompressed bytes:', len(blob))

text = blob.decode('utf-8', errors='replace')
lines = text.split('\n')
print('lines:', len(lines))

keywords = ['errcode', 'error', 'login', 'Login', '版本', 'version', '过低', 'kick', '限制', 'forcelogin', 'forceupdate', 'update', '升级']
interesting = []
for ln in lines:
    if any(k in ln for k in keywords):
        interesting.append(ln)

print('=== interesting lines:', len(interesting), '===')
for ln in interesting[-120:]:
    print(ln.strip()[:300])
