# -*- coding: utf-8 -*-
import base64, sys
msg = sys.argv[1] if len(sys.argv) > 1 else 'SSO-TEST'
b64 = base64.b64encode(msg.encode('utf-8')).decode()
PIPE = '\\\\.\\pipe\\wxsend'
f = open(PIPE, 'r+b', buffering=0)
f.write(('AUTO|filehelper|' + b64 + '\n').encode())
print('reply:', f.read(200).decode(errors='replace').strip())
f.close()
