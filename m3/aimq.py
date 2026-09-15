# -*- coding: utf-8 -*-
import sys
PIPE = chr(92)*2 + '.' + chr(92) + 'pipe' + chr(92) + 'wxsend'
req = 'AIMG|filehelper|x' + chr(10)
f = open(PIPE, 'r+b', buffering=0)
f.write(req.encode())
resp = f.read(200)
print('resp:', resp)
f.close()
