# -*- coding: utf-8 -*-
"""M2 Frida: 网络层回溯 → 定位发送函数
原理: hook ws2_32!send + WSASend, 用户发消息时捕获完整调用栈
      从调用栈中提取所有 Weixin.dll 内的返回地址 → 逐层反汇编 → 找到 SendTextMsg
"""
import frida
import sys
import time
import json
import psutil

# 找主进程
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

print('[+] target: Weixin.exe pid=%d mem=%dMB' % (best_pid, best_mem // 1024 // 1024))

JS = r"""
'use strict';

// Weixin.dll 基址和大小 (用于过滤调用栈中的地址)
let wxBase = 0, wxEnd = 0, wxName = 'Weixin.dll';

function initBase() {
    const mods = Process.enumerateModules();
    for (const m of mods) {
        if (m.name === 'Weixin.dll') {
            wxBase = m.base;
            wxEnd = m.base.add(m.size);
            send({type:'info', text:'Weixin.dll base=' + m.base + ' size=' + m.size});
            return true;
        }
    }
    send({type:'info', text:'Weixin.dll not found in modules'});
    return false;
}

// 记录所有发送相关调用
let callLog = [];
let capturing = false;
let captureCount = 0;

function doBacktrace(context) {
    const bt = Thread.backtrace(context, Backtracer.ACCURATE);
    const chain = [];
    for (const addr of bt) {
        if (addr.compare(wxBase) >= 0 && addr.compare(wxEnd) < 0) {
            const rva = addr.sub(wxBase);
            chain.push('0x' + rva.toString(16));
        }
    }
    return chain;
}

// hook ws2_32!send
const sendAddr = Module.getExportByName('ws2_32.dll', 'send');
if (sendAddr) {
    Interceptor.attach(sendAddr, {
        onEnter: function(args) {
            const sock = args[0].toInt32();
            const buf = args[1];
            const len = args[2].toInt32();
            // 只捕获合理大小的发送 (消息级别, 不是心跳)
            if (len > 50 && len < 100000 && capturing) {
                captureCount++;
                const chain = doBacktrace(this.context);
                const data = buf.readByteArray(Math.min(len, 64));
                callLog.push({
                    n: captureCount,
                    api: 'send',
                    sock: sock,
                    len: len,
                    chain: chain,
                    hex: Array.from(new Uint8Array(data)).map(b => b.toString(16).pad(2,'0')).join(''),
                    ts: Date.now(),
                });
                send({type:'hit', n: captureCount, api:'send', len: len, chain: chain});
            }
        }
    });
    send({type:'info', text:'hooked ws2_32!send @ ' + sendAddr});
}

// hook WSASend
const wsaSendAddr = Module.getExportByName('ws2_32.dll', 'WSASend');
if (wsaSendAddr) {
    Interceptor.attach(wsaSendAddr, {
        onEnter: function(args) {
            if (!capturing) return;
            const sock = args[0].toInt32();
            const lpBuffers = args[1];
            if (lpBuffers.isNull()) return;
            try {
                const bufCount = args[2].toInt32();
                let totalLen = 0;
                const firstBuf = lpBuffers.add(8).readPointer();
                // WSABUF: {ULONG len; CHAR FAR *buf}
                totalLen = lpBuffers.readULong();
                if (totalLen > 50 && totalLen < 100000) {
                    captureCount++;
                    const chain = doBacktrace(this.context);
                    callLog.push({
                        n: captureCount,
                        api: 'WSASend',
                        sock: sock,
                        len: totalLen,
                        chain: chain,
                        ts: Date.now(),
                    });
                    send({type:'hit', n: captureCount, api:'WSASend', len: totalLen, chain: chain});
                }
            } catch(e) {}
        }
    });
    send({type:'info', text:'hooked ws2_32!WSASend @ ' + wsaSendAddr});
}

// 开始捕获
initBase();
capturing = true;
send({type:'ready'});

rpc.exports = {
    getlog: function() { return callLog; },
    getbase: function() { return {base: wxBase.toString(), end: wxEnd.toString()}; },
};
"""

def on_message(message, data):
    if message['type'] == 'send':
        p = message['payload']
        t = p.get('type', '')
        if t == 'info':
            print('[*]', p['text'])
        elif t == 'ready':
            print('[+] hooks ready! NOW SEND A MESSAGE FROM WECHAT')
        elif t == 'hit':
            print('[HIT #%d] api=%s len=%s' % (p['n'], p['api'], p.get('len','')))
            for i, addr in enumerate(p.get('chain', [])[:15]):
                print('    [%02d] Weixin+%s' % (i, addr))
    elif message['type'] == 'error':
        print('[JS ERR]', message.get('description', '')[:200])

session = frida.attach(best_pid)
print('[+] frida attached to', best_pid)
script = session.create_script(JS)
script.on('message', on_message)
script.load()

print('[+] waiting for message send... (60s window)')
print('[!] 请在微信里手动发送一条消息!')
start = time.time()
while time.time() - start < 60:
    time.sleep(1)
    # 检查是否有命中
    logs = script.exports_sync.getlog()
    if logs:
        print('[+] captured %d calls, dumping...' % len(logs))
        with open(r'E:\weixin-hook-4.1.8\hook-wx\m2\send_callchain.json', 'w') as f:
            json.dump(logs, f, indent=2)
        for entry in logs:
            print('CALL #%d api=%s len=%s' % (entry['n'], entry['api'], entry['len']))
            for i, addr in enumerate(entry.get('chain', [])):
                print('  [%02d] Weixin+%s' % (i, addr))
        break

session.detach()
print('[+] done')
