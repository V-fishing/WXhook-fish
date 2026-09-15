# -*- coding: utf-8 -*-
# 监控 ws2_32 发送函数 (安全: 系统 DLL)
import frida, time, sys, io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

PID = int(sys.argv[1]) if len(sys.argv) > 1 else 15288

JS = r"""
const ws2 = Process.getModuleByName('ws2_32.dll');
const sendPtr = ws2.getExportByName('send');
const wsaSendPtr = ws2.getExportByName('WSASend');
send('[*] ws2_32 send=' + sendPtr + ' WSASend=' + wsaSendPtr);

Interceptor.attach(sendPtr, {
    onEnter: function(args) {
        this.len = args[2].toInt32();
    },
    onLeave: function(ret) {
        const t = Date.now() % 100000;
        send('[NET] send() len=' + this.len + ' ret=' + ret.toInt32() + ' t=' + t);
    }
});

Interceptor.attach(wsaSendPtr, {
    onEnter: function(args) {
        this.len = 0;
        try {
            const d = args[1].readPointer();
            const cnt = args[2].toInt32();
            for (let i = 0; i < cnt; i++) {
                this.len += d.add(i * 24).readU32();
            }
        } catch (e) {}
    },
    onLeave: function(ret) {
        send('[NET] WSASend() len=' + this.len + ' ret=' + ret.toInt32());
    }
});
send('[*] net hooks ready');
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(time.strftime('%H:%M:%S'), message['payload'], flush=True)
    elif message['type'] == 'error':
        print('ERR:', str(message.get('description', ''))[:200], flush=True)

session = frida.attach(PID)
script = session.create_script(JS)
script.on('message', on_message)
script.load()
print('tracing ws2_32 on pid', PID, flush=True)
try:
    while True:
        time.sleep(2)
except KeyboardInterrupt:
    pass
