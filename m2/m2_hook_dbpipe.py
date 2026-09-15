# -*- coding: utf-8 -*-
# Hook 发送管线 4 个日志锚点函数 (Ghidra 静态分析所得)
#   0x179E6C0  <- 'SaveSendMessagesAtOnce'
#   0x17CA0E0  <- 'SendMsgFailed'
#   0x17F4FC0  <- 'Begin StartSendMessageSyncStage' + 'GetAddSendMessageToDb'
#   0x17F9270  <- 'Begin StartSendMessageSyncStage'
# 捕获: 参数 + 栈上模块内返回地址链 + rcx/rdx 指向内存的 UTF-16 明文扫描
import frida, time, sys, io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

PID = int(sys.argv[1]) if len(sys.argv) > 1 else 21556
LOG = r'E:\weixin-hook-4.1.8\hook-wx\m2\m2_hook_dbpipe.log'

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
const lo = base, hi = base.add(wx.size);
send('[*] base=' + base);

const targets = {
    'SaveSendMsgs_0x179E6C0': 0x179E6C0,
    'SendMsgFailed_0x17CA0E0': 0x17CA0E0,
    'StartSendSync_A_0x17F4FC0': 0x17F4FC0,
    'StartSendSync_B_0x17F9270': 0x17F9270,
};

function dumpUtf16(ptr, tag) {
    // 在前 0x2000 字节里找可打印 UTF-16 串 (>=4 chars)
    try {
        const buf = ptr.readByteArray(0x2000);
        const u8 = new Uint8Array(buf);
        let runs = [], cur = '';
        for (let i = 0; i + 1 < u8.length; i += 2) {
            const c = u8[i] | (u8[i+1] << 8);
            if (c >= 0x20 && c < 0xFFFD && !(c >= 0xD800 && c < 0xE000)) {
                cur += String.fromCharCode(c);
            } else {
                if (cur.length >= 4) runs.push(cur);
                if (runs.length >= 8) break;
                cur = '';
            }
        }
        if (cur.length >= 4) runs.push(cur);
        if (runs.length) send('  ' + tag + '_utf16: ' + JSON.stringify(runs));
    } catch (e) {}
}

function walkStack(ctx, tag) {
    // 纯栈扫描: RSP 起 0x1000 字节内的模块内地址 (返回地址链)
    try {
        const rsp = ctx.rsp;
        const buf = rsp.readByteArray(0x1000);
        const u8 = new Uint8Array(buf);
        const dv = new DataView(buf);
        const frames = [];
        for (let off = 0; off + 8 <= u8.length; off += 8) {
            const v = dv.getBigUint64(off, true);
            if (v > 0x10000n) {
                const p = ptr(v.toString());
                if (p.compare(lo) >= 0 && p.compare(hi) < 0) {
                    frames.push('wx+0x' + p.sub(base).toString(16));
                    if (frames.length >= 20) break;
                }
            }
        }
        send('  ' + tag + '_stack: ' + frames.join(' <- '));
    } catch (e) {
        send('  ' + tag + '_stack_err: ' + e);
    }
}

let counts = {};
for (const [name, rva] of Object.entries(targets)) {
    (function(name, rva) {
        try {
            Interceptor.attach(base.add(rva), {
                onEnter: function(args) {
                    counts[name] = (counts[name] || 0) + 1;
                    const n = counts[name];
                    send('>>> ' + name + ' #' + n + ' <<<');
                    send('  rcx=' + args[0] + ' rdx=' + args[1] +
                         ' r8=' + args[2] + ' r9=' + args[3]);
                    walkStack(this.context, name);
                    dumpUtf16(args[0], 'rcx');
                    dumpUtf16(args[1], 'rdx');
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

def on_message(message, data):
    if message['type'] == 'send':
        out(str(message['payload']))
    elif message['type'] == 'error':
        out('[JS-ERR] ' + str(message.get('description', ''))[:300])

session = frida.attach(PID)
out('[+] attached')
script = session.create_script(JS)
script.on('message', on_message)
script.load()
out('[+] watching (Ctrl+C to stop)')

try:
    while True:
        time.sleep(5)
except KeyboardInterrupt:
    pass
finally:
    session.detach()
    out('[+] detached')
    logf.close()
