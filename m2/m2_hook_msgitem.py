# -*- coding: utf-8 -*-
# Hook Mid_575B (0x39BD150) - 消息条目转字符串函数, 发送时逐条触发
# 全量 hexdump 消息对象 + 子对象, 用于定位消息正文的位置
import frida, time, sys, io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

PID = int(sys.argv[1]) if len(sys.argv) > 1 else 21556
LOG = r'E:\weixin-hook-4.1.8\hook-wx\m2\m2_hook_msgitem.log'

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

// 读 MSVC SSO std::string (data@p, size@p+0x10, cap@p+0x18)
function readSSO(p) {
    try {
        const cap = p.add(0x18).readU64();
        const size = p.add(0x10).readU64();
        let dataptr = p;
        if (cap > 15) dataptr = p.readPointer();
        const n = Math.min(size.toNumber(), 200);
        if (n <= 0) return '(empty)';
        const bytes = dataptr.readByteArray(n);
        const u8 = new Uint8Array(bytes);
        // 尝试 UTF-16LE
        let u16 = '';
        let ok16 = true;
        for (let i = 0; i + 1 < n; i += 2) {
            const c = u8[i] | (u8[i+1] << 8);
            if (c < 0x20 || (c >= 0xD800 && c < 0xE000)) { ok16 = false; break; }
            u16 += String.fromCharCode(c);
        }
        // 尝试 UTF-8/ASCII
        let u8s = '';
        let ok8 = true;
        for (let i = 0; i < n; i++) {
            if (u8[i] < 0x20 || u8[i] > 0x7E) {
                if (u8[i] < 0x80) { ok8 = false; break; }
            }
        }
        if (ok8) u8s = dataptr.readUtf8String(n);
        return 'size=' + size + ' u8="' + (ok8 ? u8s : '?') + '" u16="' + (ok16 ? u16 : '?') + '"';
    } catch (e) { return 'err:' + e; }
}

let cnt = 0;
Interceptor.attach(base.add(0x39BD150), {
    onEnter: function(args) {
        cnt++;
        this.skip = cnt > 30;   // 最多详细记录 30 条
        if (this.skip) return;
        const msg = args[0];
        const outp = args[1];
        send('>>> MSGITEM #' + cnt + ' <<< msg=' + msg + ' out=' + outp);
        // 完整 hexdump 消息对象
        if (readable(msg, 0x180)) {
            send('  msg_hex:', msg.readByteArray(0x180));
        }
        // +0x38 的 SSO 字符串
        send('  str@+0x38: ' + readSSO(msg.add(0x38)));
        // 子对象 +0x18 和 +0x08
        try {
            const p18 = msg.add(0x18).readPointer();
            if (readable(p18, 0x180)) {
                send('  sub@+0x18 (' + p18 + '):', p18.readByteArray(0x180));
            }
        } catch (e) {}
        try {
            const p08 = msg.add(0x08).readPointer();
            if (readable(p08, 0x60)) {
                send('  sub@+0x08 (' + p08 + '):', p08.readByteArray(0x60));
            }
        } catch (e) {}
    },
    onLeave: function(retval) {
        if (this.skip) return;
        // 输出字符串内容 ("sending_..." 标签)
    }
});
send('[*] ready - hooking Mid_575B');
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
