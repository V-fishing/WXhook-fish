# -*- coding: utf-8 -*-
# Hook CORE(0x1795500) + Mid_575B(0x39BD150): 转储任务内层对象并跟随指针字段
# 安全模式: 单次拷贝, 副本解码, 禁 readUtf8String
import frida, time, sys, io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

LOG = r'E:\weixin-hook-4.1.8\hook-wx\m2\m2_hook_taskdump.log'
logf = open(LOG, 'a', encoding='utf-8')

def out(s):
    line = time.strftime('%H:%M:%S ') + s
    print(line, flush=True)
    logf.write(line + '\n')
    logf.flush()

import psutil
pid = None
for _ in range(60):
    best = 0
    pid = None
    for p in psutil.process_iter(['pid', 'name']):
        try:
            if p.info['name'] and p.info['name'].lower() == 'weixin.exe':
                mem = p.memory_info().rss
                if mem > best:
                    best = mem
                    pid = p.pid
        except Exception:
            pass
    if pid:
        break
    time.sleep(10)
if pid is None:
    print('NO Weixin.exe')
    sys.exit(1)
out('=' * 50)
out('pid=%d' % pid)

JS = r"""
const wx = Process.findModuleByName('Weixin.dll');
const base = wx.base;
send('[*] base=' + base);

function copy(p, len) {
    try { return new Uint8Array(p.readByteArray(len)); } catch (e) { return null; }
}
function u64at(u8, off) {
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(u8[off + i]);
    return v;
}
function hex(u8) {
    const lines = [];
    for (let off = 0; off < u8.length; off += 16) {
        let hx = '', ax = '';
        for (let j = 0; j < 16 && off + j < u8.length; j++) {
            hx += ('0' + u8[off+j].toString(16)).slice(-2) + ' ';
            ax += (u8[off+j] >= 0x20 && u8[off+j] < 0x7F) ? String.fromCharCode(u8[off+j]) : '.';
        }
        lines.push('    ' + ('000' + off.toString(16)).slice(-4) + '  ' + hx + ' ' + ax);
    }
    return lines.join('\n');
}
// SSO std::string 规则: 数据@X(或指针@X), size@X+0x10, cap@X+0x18
function trySSO(buf, off, tag) {
    if (off + 0x20 > buf.length) return;
    const size = u64at(buf, off + 0x10);
    const cap = u64at(buf, off + 0x18);
    if (size > 0n && size < 300n && cap >= size && cap < 0x40000n) {
        let u8s = null, u16s = null, src = null;
        if (cap > 15n) {
            const pv = u64at(buf, off);
            if (pv > 0x10000n && pv < 0x7ffffffffffen) {
                const heapbuf = copy(ptr(pv.toString()), Math.min(Number(size) + 2, 300));
                src = heapbuf;
            }
        } else {
            src = buf.slice(off, off + 0x10);
        }
        if (src) {
            let s8 = '';
            let ok8 = true;
            for (let i = 0; i < src.length; i++) {
                const c = src[i];
                if (c === 0) break;
                if (c < 0x20 || c > 0x7E) { ok8 = false; break; }
                s8 += String.fromCharCode(c);
            }
            if (ok8 && s8.length > 0) u8s = s8;
            let s16 = '';
            for (let i = 0; i + 1 < src.length; i += 2) {
                const c = src[i] | (src[i+1] << 8);
                if (c === 0) break;
                if (c < 0x20 || (c >= 0xD800 && c < 0xE000)) { s16 = null; break; }
                s16 += String.fromCharCode(c);
            }
            send('    str@' + tag + '+0x' + off.toString(16) + ' size=' + size +
                 ' u8="' + (u8s || '?') + '" u16="' + (s16 || '?') + '"');
        }
    }
}

let cnt = 0;
function dumpTask(inner, label) {
    cnt++;
    if (cnt > 6) return;
    send('>>> ' + label + ' #' + cnt + ' inner=' + inner + ' <<<');
    const m = copy(inner, 0x100);
    if (!m) { send('  unreadable'); return; }
    send('  inner_hex:\n' + hex(m));
    for (let off = 0; off + 0x20 <= m.length; off += 8) {
        trySSO(m, off, 'inner');
    }
    // 跟随 +0x60..0xB8 的所有指针
    for (let off = 0x60; off + 8 <= 0xB8 && off + 8 <= m.length; off += 8) {
        const v = u64at(m, off);
        if (v < 0x10000n || v > 0x7ffffffffffen) continue;
        const tgt = copy(ptr(v.toString()), 0x80);
        if (!tgt) continue;
        send('  ptr@+0x' + off.toString(16) + ' -> 0x' + v.toString(16) + ':\n' + hex(tgt));
        for (let o2 = 0; o2 + 0x20 <= tgt.length; o2 += 8) {
            trySSO(tgt, o2, 'p' + off.toString(16));
        }
    }
}

Interceptor.attach(base.add(0x1795500), {
    onEnter: function(args) {
        // CORE(mgr, task+0x48) -> inner = rdx - 0x38
        const inner = args[1].sub(0x38);
        dumpTask(inner, 'CORE');
    }
});
Interceptor.attach(base.add(0x39BD150), {
    onEnter: function(args) {
        dumpTask(args[0], 'MID');
    }
});
send('[*] ready');
"""

def on_message(message, data):
    if message['type'] == 'send':
        p = message['payload']
        if isinstance(p, str):
            out(p)
    elif message['type'] == 'error':
        out('[JS-ERR] ' + str(message.get('description', ''))[:300])

session = frida.attach(pid)
out('[+] attached')
script = session.create_script(JS)
script.on('message', on_message)
script.load()
out('[+] watching')

try:
    while True:
        time.sleep(5)
except KeyboardInterrupt:
    pass
finally:
    session.detach()
    out('[+] detached')
    logf.close()
