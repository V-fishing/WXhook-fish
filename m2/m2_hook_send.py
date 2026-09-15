# -*- coding: utf-8 -*-
# 常驻 hook: 监视 Weixin.dll+0x6482E00 (发送管线第二层)
# 用法: python m2_hook_send.py <pid>
# 日志实时写入 m2_hook_send.log
import frida, time, sys, io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

PID = int(sys.argv[1]) if len(sys.argv) > 1 else 21556
LOG = r'E:\weixin-hook-4.1.8\hook-wx\m2\m2_hook_send.log'

logf = open(LOG, 'a', encoding='utf-8')

def out(s):
    line = time.strftime('%H:%M:%S ') + s
    print(line, flush=True)
    logf.write(line + '\n')
    logf.flush()

out('=' * 50)
out('attach pid=%d' % PID)

JS = """
const wx = Process.findModuleByName('Weixin.dll');
const base = wx.base;
send('[*] Weixin.dll base = ' + base);
send('[*] .text size = 0x' + wx.size.toString(16));

// 目标: 发送管线第二层 (来自网络回栈 13 帧中的关键帧)
const targets = {
    'L2_0x6482E00': 0x6482E00,   // 主目标
    'L1_0x68E610':  0x68E610,    // 上层调用者 (验证关系)
};

let hits = {};

for (const [name, rva] of Object.entries(targets)) {
    (function(name, rva) {
        try {
            Interceptor.attach(base.add(rva), {
                onEnter: function(args) {
                    hits[name] = (hits[name] || 0) + 1;
                    const n = hits[name];
                    send('>>> ' + name + ' CALL #' + n + ' <<<');
                    send('  rcx=' + args[0] + ' rdx=' + args[1] +
                         ' r8=' + args[2] + ' r9=' + args[3]);
                    try {
                        const b = args[2].readByteArray(48);
                        send('  r8_mem:', b);
                    } catch(e) {}
                    try {
                        const s = args[2].readUtf8String(64);
                        if (s) send('  r8_str="' + s + '"');
                    } catch(e) {}
                    try {
                        const b2 = args[1].readByteArray(64);
                        send('  rdx_mem:', b2);
                    } catch(e) {}
                    // 模块内回栈 (精确模式, Weixin.dll 内部帧)
                    const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress);
                    let frames = [];
                    for (const f of bt) {
                        const d = f.toString();
                        if (d.indexOf('Weixin') >= 0) {
                            // 只保留模块内偏移
                            const addr = f.sub(base);
                            frames.push('wx+0x' + addr.toString(16));
                        }
                        if (frames.length >= 12) break;
                    }
                    send('  bt: ' + frames.join(' <- '));
                }
            });
            send('[+] hooked ' + name + ' (rva 0x' + rva.toString(16) + ')');
        } catch(e) {
            send('[!] hook ' + name + ' failed: ' + e);
        }
    })(name, rva);
}
send('[*] all hooks ready - waiting for sends...');
"""

def on_message(message, data):
    if message['type'] == 'send':
        out(str(message['payload']))
    elif message['type'] == 'error':
        out('[JS-ERR] ' + str(message.get('description', ''))[:400])

session = frida.attach(PID)
out('[+] frida attached')
script = session.create_script(JS)
script.on('message', on_message)
script.load()
out('[+] hooks installed - watching indefinitely (Ctrl+C to stop)')

try:
    while True:
        time.sleep(5)
except KeyboardInterrupt:
    pass
finally:
    session.detach()
    out('[+] detached')
    logf.close()
