# -*- coding: utf-8 -*-
# 触发热重载: RELOAD 命令 -> bootstrap 加载 wx_payload_incoming.dll 为新一代
f = open('\\\\.\\pipe\\wxsend', 'r+b', buffering=0)
f.write(b'RELOAD\n')
print(f.read(200).decode(errors='replace').strip())
f.close()
