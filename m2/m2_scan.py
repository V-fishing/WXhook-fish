# -*- coding: utf-8 -*-
"""M2 Frida Phase A: 扫描输入框缓冲 (微信进程内执行, 毫秒级)"""
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
PID = best_pid
print('[+] target pid:', PID, 'mem:', best_mem // 1024 // 1024, 'MB')
if not PID:
    print('[-] Weixin.exe not found'); sys.exit(1)

JS = r"""
'use strict';
const PATTERN = '5A 00 58 00 42 00 45 00 4E 00 43 00 48 00 32 00 30 00 32 00 30 00 36 00';
const results = [];
const ranges = Process.enumerateRanges('rw-');
send({type:'log', text:'scanning ' + ranges.length + ' RW ranges in-process...'});
let scanned = 0;
for (const range of ranges) {
    if (range.size > 0x40000000) continue;
    try {
        const found = Memory.scanSync(range.base, range.size, PATTERN);
        scanned += range.size;
        for (const m of found) {
            results.push(m.address);
            send({type:'found', address: m.address.toString(),
                  region: range.base.toString(), regionSize: range.size});
        }
    } catch (e) { }
}
send({type:'done', count: results.length, scannedMB: Math.round(scanned/1048576)});
"""

hits = []

def on_message(message, data):
    if message['type'] == 'send':
        p = message['payload']
        t = p.get('type', '')
        if t == 'log':
            print('[*]', p['text'])
        elif t == 'found':
            hits.append(p['address'])
            print('[FOUND]', p['address'], 'region:', p['region'], 'size:', hex(p['regionSize']))
        elif t == 'done':
            print('[*] scan complete:', p['count'], 'hits,', p['scannedMB'], 'MB scanned')
    elif message['type'] == 'error':
        print('[JS ERR]', message.get('description', '')[:200])

session = frida.attach(PID)
print('[+] frida attached to', PID)
script = session.create_script(JS)
script.on('message', on_message)
script.load()
time.sleep(10)
session.detach()
print('[+] total hits:', len(hits))
if hits:
    print('[ADDRESSES]', ','.join(hits))
