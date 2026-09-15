# -*- coding: utf-8 -*-
# M3/M4 原生 DLL 客户端: 通过命名管道下发命令
# 用法:
#   python m3_native_client.py STATUS
#   python m3_native_client.py AUTO <target> <content>   # M4 自主发送(无需载体)
#   python m3_native_client.py SEND <target> <content>   # M3 搭车改写
#   python m3_native_client.py DUMPNEW                   # 工厂新对象初态转储(看日志)
import sys, base64

PIPE = r'\\.\pipe\wxsend'

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    mode = sys.argv[1].upper()
    if mode == 'STATUS':
        req = b'STATUS\n'
    elif mode == 'FACT':
        req = b'FACT\n'
    elif mode == 'DUMPNEW':
        req = b'DUMPNEW\n'
    elif mode in ('AUTO', 'SEND', 'SEND2'):
        if len(sys.argv) < 4:
            print('need <target> <content>')
            sys.exit(1)
        target = sys.argv[2]
        content = sys.argv[3].encode('utf-8')
        b64 = base64.b64encode(content).decode()
        req = ('%s|%s|%s\n' % (mode, target, b64)).encode()
    else:
        # 兼容旧用法: target content = SEND
        target = sys.argv[1]
        content = sys.argv[2].encode('utf-8') if isinstance(sys.argv[2], str) else sys.argv[2]
        b64 = base64.b64encode(content).decode()
        req = ('SEND|%s|%s\n' % (target, b64)).encode()

    f = open(PIPE, 'r+b', buffering=0)
    try:
        f.write(req)
        resp = b''
        while b'\n' not in resp:
            ch = f.read(1)
            if not ch:
                break
            resp += ch
        print('response:', resp.decode(errors='replace').strip())
    finally:
        f.close()

if __name__ == '__main__':
    main()
