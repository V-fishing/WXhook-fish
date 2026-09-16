# -*- coding: utf-8 -*-
import sys
PIPE = '\\\\.\\pipe\\wxsend'
f = open(PIPE, 'r+b', buffering=0)
f.write(b'STATUS\n')
print(f.read(400).decode(errors='replace').strip())
f.close()
