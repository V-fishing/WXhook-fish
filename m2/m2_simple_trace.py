# -*- coding: utf-8 -*-
"""M2 Frida 简化版: hook send + 打印调用链"""
import frida
import sys
import time
import psutil

best_pid, best_mem = 0, 0
for p in psutil.process_iter(['name', 'pid', 'memory_info']):
    try:
        if p.info['name'] == 'Weixin.exe':
            mem = p.info['memory_info'].rss
            if mem > best_mem:
                best_pid, best_mem = p.info['pid'], mem
    except Exception:
        pass
if not best_pid:
    print('[-] Weixin.exe not found'); sys.exit(1)
print('[+] target pid:', best_pid)

JS = r"""
'use strict';
const wxMod = Process.getModuleByName('Weixin.dll');
const wxBase = wxMod.base;
const wxEnd = wxBase.add(wxMod.size);
console.log('[*] Weixin.dll base=' + wxBase + ' size=' + wxMod.size);

const sendAddr = Module.getExportByName('ws2_32.dll', 'send');
console.log('[*] ws2_32!send @ ' + sendAddr);

let msgCount = 0;

Interceptor.attach(sendAddr, {
    onEnter: function(args) {
        const len = args[2].toInt32();
        // 只关注消息级别大小
        if (len > 50 && len < 100000) {
            msgCount++;
            console.log('=== SEND #' + msgCount + ' len=' + len + ' sock=' + args[0] + ' ===');

            // 打印调用栈
            const bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
            for (let i = 0; i < bt.length; i++) {
                const addr = bt[i];
                if (addr.compare(wxBase) >= 0 && addr.compare(wxEnd) < 0) {
                    const rva = addr.sub(wxBase);
                    console.log('  [' + i + '] Weixin.dll+0x' + rva.toString(16));
                }
            }

            // 打印前 32 字节数据
            const data = args[1].readByteArray(Math.min(len, 32));
            console.log('  data: ' + Array.from(new Uint8Array(data)).map(b => b.toString(16).pad(2,'0')).join(' '));
        }
    }
});

console.log('[*] hooks installed. send a message from WeChat!');
"""

def on_message(message, data):
    if message['type'] == 'send':
        print('[JS]', message['payload'])
    elif message['type'] == 'error':
        print('[JS ERR]', message.get('description', '')[:200])

session = frida.attach(best_pid)
print('[+] frida attached')
script = session.create_script(JS)
script.on('message', on_message)
script.load()

print('[+] waiting 90s for message send...')
print('[!] NOW: 在微信里手动发送一条消息!')
start = time.time()
while time.time() - start < 90:
    time.sleep(2)
session.detach()
print('[+] done')
