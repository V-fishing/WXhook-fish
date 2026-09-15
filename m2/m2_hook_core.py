# -*- coding: utf-8 -*-
# Hook 发送核心区 3 个函数 + 对象图一级遍历 (找消息明文)
#   0x1795500 (6KB) - StartSendMessageSyncStage 直接调用者
#   0x1790970       - 上层
#   0x17A3620       - 上层
import frida, time, sys, io, json

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

PID = int(sys.argv[1]) if len(sys.argv) > 1 else 21556
LOG = r'E:\weixin-hook-4.1.8\hook-wx\m2\m2_hook_core.log'

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

function isReadable(p, len) {
    try { p.readByteArray(len); return true; } catch (e) { return false; }
}

// 提取缓冲区中可打印 UTF-16 串
function utf16Runs(p, maxBytes) {
    const runs = [];
    try {
        const buf = p.readByteArray(maxBytes);
        const u8 = new Uint8Array(buf);
        let cur = '';
        for (let i = 0; i + 1 < u8.length; i += 2) {
            const c = u8[i] | (u8[i+1] << 8);
            if (c >= 0x20 && c < 0xFFFD && !(c >= 0xD800 && c < 0xE000)) {
                cur += String.fromCharCode(c);
            } else {
                if (cur.length >= 3) runs.push(cur);
                if (runs.length >= 12) return runs;
                cur = '';
            }
        }
        if (cur.length >= 3) runs.push(cur);
    } catch (e) {}
    return runs;
}

// 对象图一级遍历: 对象前 0x180 字节按指针字段展开
function walkObject(objPtr, tag) {
    const found = [];
    try {
        const buf = objPtr.readByteArray(0x180);
        const dv = new DataView(buf);
        for (let off = 0; off + 8 <= 0x180; off += 8) {
            const v = dv.getBigUint64(off, true);
            if (v < 0x10000n || v > 0x7ffffffffffen) continue;
            const p = ptr(v.toString());
            if (!isReadable(p, 0x60)) continue;
            const runs = utf16Runs(p, 0x60);
            for (const r of runs) {
                found.push('+0x' + off.toString(16) + ' -> "' + r + '"');
                if (found.length >= 16) return found;
            }
        }
    } catch (e) {}
    return found;
}

const targets = {
    'CORE_0x1795500': 0x1795500,
    'UP1_0x1790970': 0x1790970,
    'UP2_0x17A3620': 0x17A3620,
};

let counts = {};
for (const [name, rva] of Object.entries(targets)) {
    (function(name, rva) {
        try {
            Interceptor.attach(base.add(rva), {
                onEnter: function(args) {
                    this.a = [args[0], args[1], args[2], args[3]];
                    counts[name] = (counts[name] || 0) + 1;
                    this.n = counts[name];
                },
                onLeave: function(retval) {
                    send('>>> ' + name + ' #' + this.n + ' <<< ret=' + retval);
                    send('  rcx=' + this.a[0] + ' rdx=' + this.a[1] +
                         ' r8=' + this.a[2] + ' r9=' + this.a[3]);
                    // 参数内存 hexdump
                    for (let k = 0; k < 4; k++) {
                        if (isReadable(this.a[k], 0x20)) {
                            const b = this.a[k].readByteArray(0x20);
                            send('  arg' + k + '_mem:', b);
                        }
                    }
                    // rcx 对象图遍历
                    if (isReadable(this.a[0], 0x180)) {
                        const f = walkObject(this.a[0], name);
                        if (f.length) send('  rcx_graph: ' + JSON.stringify(f));
                    }
                    // rdx 对象图遍历
                    if (isReadable(this.a[1], 0x180)) {
                        const f = walkObject(this.a[1], name);
                        if (f.length) send('  rdx_graph: ' + JSON.stringify(f));
                    }
                }
            });
            send('[+] hooked ' + name + ' (0x' + rva.toString(16) + ')');
        } catch (e) {
            send('[!] hook ' + name + ' failed: ' + e);
        }
    })(name, rva);
}
send('[*] ready');
"""

def on_message(message, data):
    if message['type'] == 'send':
        p = message['payload']
        if isinstance(p, str):
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
