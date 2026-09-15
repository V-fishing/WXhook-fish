# -*- coding: utf-8 -*-
"""M2 Frida 探针: 定位输入框缓冲 → 监控访问 → 抓发送路径
用法: python m2_frida.py <Weixin主进程PID>
然后: 在微信输入框输入/确认文本 ZXBENCH2026 → 告诉脚本 → 按回车发送
"""
import frida
import sys
import time

PID = int(sys.argv[1]) if len(sys.argv) > 1 else 12048

JS = r"""
'use strict';
const PATTERN = '5A 00 58 00 42 00 45 00 4E 00 43 00 48 00 32 00 30 00 32 00 30 00 36 00';
let monitorArmed = false;
let foundAddresses = [];

function scanForInput() {
    const ranges = Process.enumerateRanges('rw-');
    let total = 0;
    send({type: 'log', text: 'scanning ' + ranges.length + ' RW ranges...'});
    for (const range of ranges) {
        if (range.size > 0x20000000) continue;  // 跳过 >512MB
        try {
            const found = Memory.scanSync(range.base, range.size, PATTERN);
            for (const m of found) {
                foundAddresses.push(m.address);
                send({type: 'found', address: m.address.toString(), size: range.size});
                total++;
            }
        } catch (e) { /* 不可读区域跳过 */ }
    }
    send({type: 'log', text: 'scan done: ' + total + ' occurrences'});
    return foundAddresses;
}

function armMonitor(addrs) {
    // 页对齐 + 合并
    const pages = [];
    for (const a of addrs) {
        const p = a.and(ptr('0xFFFFFFFFFFFFF000'));
        if (!pages.some(x => x.base.equals(p))) {
            pages.push({base: p, size: 4096});
        }
    }
    send({type: 'log', text: 'arming MemoryAccessMonitor on ' + pages.length + ' pages'});
    MemoryAccessMonitor.enable(pages, {
        onAccess(details) {
            const mod = Process.findModuleByAddress(details.from);
            const modName = mod ? mod.name + '+0x' + details.from.sub(mod.base).toString(16) : 'unknown';
            send({
                type: 'access',
                operation: details.operation,
                from: details.from.toString(),
                fromModule: modName,
                address: details.address.toString(),
                tid: Process.getCurrentThreadId(),
            });
            // 重新武装 (Frida 的 monitor 一次性)
            if (!monitorArmed) {
                setImmediate(() => { try { MemoryAccessMonitor.enable(pages, this.onAccess); } catch(e){} });
            }
        }
    });
    monitorArmed = true;
}

rpc.exports = {
    scan: function() {
        const addrs = scanForInput();
        if (addrs.length > 0) {
            armMonitor(addrs);
            return {found: addrs.length, addresses: addrs.map(a => a.toString())};
        }
        return {found: 0};
    },
    ping: function() { return 'pong'; }
};
"""

def on_message(message, data):
    if message['type'] == 'send':
        p = message['payload']
        t = p.get('type', '')
        if t == 'log':
            print('[*]', p['text'])
        elif t == 'found':
            print('[+] FOUND input buffer @', p['address'])
        elif t == 'access':
            print('[ACCESS]', p['operation'], 'from', p['fromModule'], '->', p['address'], 'tid', p['tid'])
    elif message['type'] == 'error':
        print('[JS ERROR]', message['description'])

session = frida.attach(PID)
print('[+] attached to pid', PID)
script = session.create_script(JS)
script.on('message', on_message)
script.load()
print('[+] script loaded. commands: scan / quit')

while True:
    cmd = input('> ').strip()
    if cmd == 'scan':
        r = script.exports_sync.scan()
        print('[result]', r)
    elif cmd == 'quit':
        break
session.detach()
