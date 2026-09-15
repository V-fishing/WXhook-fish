# -*- coding: utf-8 -*-
"""M2 Frida Phase B: 监控输入框缓冲访问 → 抓发送路径
用法: python m2_monitor.py <逗号分隔的地址列表>
然后: 在微信里按回车发送那条消息 → 本脚本记录所有访问
"""
import frida
import sys
import time

PID = 0
import subprocess
r = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq Weixin.exe', '/FO', 'CSV'],
                   capture_output=True, text=True)
best_pid, best_mem = 0, 0
for line in r.stdout.strip().split('\n')[1:]:
    parts = line.split('","')
    if len(parts) >= 5:
        pid = int(parts[1])
        mem = int(parts[4].replace('"', '').replace(' K', '').replace(',', ''))
        if mem > best_mem:
            best_pid, best_mem = pid, mem
PID = best_pid

ADDRESSES = sys.argv[1].split(',') if len(sys.argv) > 1 else []
print('[+] target pid:', PID)
print('[+] monitoring addresses:', ADDRESSES)

ADDR_ARRAY = ','.join('"%s"' % a for a in ADDRESSES)

JS = r"""
'use strict';
const TARGETS = [__ADDR_ARRAY__].map(a => ptr(a));
let accessLog = [];

function armMonitor() {
    const pages = [];
    for (const a of TARGETS) {
        const p = a.and(ptr('0xFFFFFFFFFFFFF000'));
        if (!pages.some(x => x.base.equals(p))) {
            pages.push({base: p, size: 4096});
        }
    }
    send({type:'log', text:'arming monitor on ' + pages.length + ' pages'});
    MemoryAccessMonitor.enable(pages, {
        onAccess(details) {
            let mod = 'unknown';
            try {
                const m = Process.findModuleByAddress(details.from);
                if (m) mod = m.name + '+0x' + details.from.sub(m.base).toString(16);
            } catch(e) {}
            const rec = {
                op: details.operation,
                from: details.from.toString(),
                mod: mod,
                addr: details.address.toString(),
                tid: Process.getCurrentThreadId(),
                ts: Date.now(),
            };
            accessLog.push(rec);
            send({type:'access', data: rec});
            // 重新武装 (监控是一次性的)
            setImmediate(() => { try { armMonitor(); } catch(e) {} });
        }
    });
}

rpc.exports = {
    arm: function() { armMonitor(); return 'armed'; },
    getlog: function() { return accessLog; }
};

send({type:'log', text:'script ready'});
"""

def on_message(message, data):
    if message['type'] == 'send':
        p = message['payload']
        t = p.get('type', '')
        if t == 'log':
            print('[*]', p['text'])
        elif t == 'access':
            d = p['data']
            print('[ACCESS]', d['op'], 'from', d['mod'], 'addr', d['addr'], 'tid', d['tid'])
    elif message['type'] == 'error':
        print('[JS ERR]', message.get('description', '')[:200])

session = frida.attach(PID)
print('[+] frida attached to', PID)
script = session.create_script(JS)
script.on('message', on_message)
script.load()

import json
with open(r'C:\Users\fish\ZCodeProject\wx_bp5_log.txt', 'a', encoding='utf-8') as f:
    f.write('\n=== frida monitor started %s ===\n' % time.strftime('%H:%M:%S'))
    print('[+] monitoring... press Enter in this console to stop')
    print('[!] NOW: 在微信里按回车发送那条消息!')
    try:
        while True:
            time.sleep(1)
            # 持续导出日志
            log = script.exports_sync.getlog()
            for rec in log:
                f.write('%s %s from %s addr %s tid %s\n' % (rec['ts'], rec['op'], rec['mod'], rec['addr'], rec['tid']))
            f.flush()
            if len(accessLog := script.exports_sync.getlog()) > 200:
                print('[!] access count:', len(accessLog), '(hit flood detected)')
                break
    except KeyboardInterrupt:
        pass
session.detach()
print('[+] detached')
