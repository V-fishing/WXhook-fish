# -*- coding: utf-8 -*-
# Hook newsendmsg CGI 函数 (0x3A25E80 / 0x3A2A770)
# 捕获参数 + 两级对象图遍历, 定位消息正文与 wxid
import frida, time, sys, io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

PID = int(sys.argv[1]) if len(sys.argv) > 1 else 21556
LOG = r'E:\weixin-hook-4.1.8\hook-wx\m2\m2_hook_newsendmsg.log'

logf = open(LOG, 'a', encoding='utf-8')

def out(s):
    line = time.strftime('%H:%M:%S ') + s
    print(line, flush=True)
    logf.write(line + '\n')
    logf.flush()

out('=' * 50)
out('attach pid=%d' % PID)

JS = r"""
const wx = Process.findModuleByName('Weixin.dll');
const base = wx.base;
send('[*] base=' + base);

function readable(p, len) {
    try { p.readByteArray(len); return true; } catch (e) { return false; }
}

function utfRuns(p, maxBytes) {
    const runs = [];
    try {
        const buf = p.readByteArray(maxBytes);
        const u8 = new Uint8Array(buf);
        let cur = '';
        for (let i = 0; i + 1 < u8.length; i += 2) {
            const c = u8[i] | (u8[i+1] << 8);
            if (c >= 0x20 && c < 0xFFFD && !(c >= 0xD800 && c < 0xE000)) cur += String.fromCharCode(c);
            else { if (cur.length >= 4) runs.push('u16:' + cur); cur = ''; }
        }
        if (cur.length >= 4) runs.push('u16:' + cur);
    } catch (e) {}
    try {
        const s = p.readUtf8String(maxBytes > 200 ? 200 : maxBytes);
        if (s && s.length >= 4 && /^[\x20-\x7e]+$/.test(s.substring(0, 40))) runs.push('u8:' + s.substring(0, 80));
    } catch (e) {}
    return runs;
}

// 两级对象图遍历
function walk(objPtr, depth, path, results) {
    if (depth > 2 || results.length > 24) return;
    try {
        const buf = objPtr.readByteArray(0x100);
        const dv = new DataView(buf);
        for (let off = 0; off + 8 <= 0x100; off += 8) {
            const v = dv.getBigUint64(off, true);
            if (v < 0x10000n || v > 0x7ffffffffffen) continue;
            const p = ptr(v.toString());
            if (!readable(p, 0x40)) continue;
            const runs = utfRuns(p, 0x40);
            for (const r of runs) {
                results.push(path + '+0x' + off.toString(16) + ' -> ' + r);
                if (results.length > 24) return;
            }
            if (depth < 2) walk(p, depth + 1, path + '+0x' + off.toString(16), results);
        }
    } catch (e) {}
}

const targets = {
    'NEWSENDMSG_A_0x3A25E80': 0x3A25E80,
    'NEWSENDMSG_B_0x3A2A770': 0x3A2A770,
};

let counts = {};
for (const [name, rva] of Object.entries(targets)) {
    (function(name, rva) {
        try {
            Interceptor.attach(base.add(rva), {
                onEnter: function(args) {
                    counts[name] = (counts[name] || 0) + 1;
                    const n = counts[name];
                    send('>>> ' + name + ' #' + n + ' <<<');
                    send('  rcx=' + args[0] + ' rdx=' + args[1] + ' r8=' + args[2] + ' r9=' + args[3]);
                    for (let k = 0; k < 3; k++) {
                        if (readable(args[k], 0x80)) {
                            const b = args[k].readByteArray(0x80);
                            send('  arg' + k + '_hex:', b);
                        }
                        if (readable(args[k], 0x100)) {
                            const results = [];
                            walk(args[k], 0, 'arg' + k, results);
                            if (results.length) {
                                for (const r of results) send('  ' + r);
                            }
                        }
                    }
                }
            });
            send('[+] hooked ' + name);
        } catch (e) {
            send('[!] hook ' + name + ' failed: ' + e);
        }
    })(name, rva);
}
send('[*] ready');
"""

def hexdump(b):
    u8 = bytes(b)
    lines = []
    for off in range(0, len(u8), 16):
        chunk = u8[off:off+16]
        h = ' '.join('%02x' % c for c in chunk)
        a = ''.join(chr(c) if 0x20 <= c < 0x7F else '.' for c in chunk)
        lines.append('    %04x  %-47s  %s' % (off, h, a))
    return '\n'.join(lines)

def on_message(message, data):
    if message['type'] == 'send':
        p = message['payload']
        if isinstance(p, str):
            if data:
                out(p + '\n' + hexdump(data))
            else:
                out(p)
    elif message['type'] == 'error':
        out('[JS-ERR] ' + str(message.get('description', ''))[:300])

session = frida.attach(PID)
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
