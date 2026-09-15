# -*- coding: utf-8 -*-
# Hook UP1 (0x1790970) - 发送任务组装函数, 自证调用者
# 安全模式: 每指针单次 readByteArray 拷贝, 副本上分析, 禁 readUtf8String
# 自动发现 Weixin 主进程 PID
import frida, time, sys, io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

LOG = r'E:\weixin-hook-4.1.8\hook-wx\m2\m2_hook_up1.log'
logf = open(LOG, 'a', encoding='utf-8')

def out(s):
    line = time.strftime('%H:%M:%S ') + s
    print(line, flush=True)
    logf.write(line + '\n')
    logf.flush()

# 自动找主进程 (内存最大的 Weixin.exe), 未找到则等待
import psutil
pid = None
for _ in range(120):  # 最多等 20 分钟
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
    print('NO Weixin.exe process found after 20 min wait')
    sys.exit(1)
out('=' * 50)
out('auto-selected pid=%d (rss=%.0fMB)' % (pid, best / 1048576))

JS = r"""
const wx = Process.findModuleByName('Weixin.dll');
const base = wx.base;
const lo = base, hi = base.add(wx.size);
send('[*] base=' + base);

function copy(p, len) {
    try { return new Uint8Array(p.readByteArray(len)); } catch (e) { return null; }
}

function u64at(u8, off) {
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(u8[off + i]);
    return v;
}

// 副本上解 ASCII/UTF16 串
function decU8(u8, start, maxc) {
    let s = '';
    for (let i = start; i < u8.length && s.length < maxc; i++) {
        const c = u8[i];
        if (c === 0) break;
        if (c < 0x20 || c > 0x7E) return null;
        s += String.fromCharCode(c);
    }
    return s.length >= 2 ? s : null;
}
function decU16(u8, start, maxc) {
    let s = '';
    for (let i = start; i + 1 < u8.length && s.length < maxc; i += 2) {
        const c = u8[i] | (u8[i+1] << 8);
        if (c === 0) break;
        if (c < 0x20 || (c >= 0xD800 && c < 0xE000)) return null;
        s += String.fromCharCode(c);
    }
    return s.length >= 2 ? s : null;
}

let cnt = 0;
Interceptor.attach(base.add(0x1790970), {
    onEnter: function(args) {
        cnt++;
        if (cnt > 40) return;
        const a = [args[0], args[1], args[2], args[3]];
        send('>>> UP1 #' + cnt + ' <<<');
        send('  rcx=' + a[0] + ' rdx=' + a[1] + ' r8=' + a[2] + ' r9=' + a[3]);

        // 栈扫描: RSP 起 0x900, 从副本过滤模块内地址 (调用者链!)
        const sp = copy(this.context.rsp, 0x900);
        if (sp) {
            const frames = [];
            for (let off = 0; off + 8 <= sp.length && frames.length < 16; off += 8) {
                const v = u64at(sp, off);
                if (v > 0x10000n && v < 0x7ffffffffffen) {
                    const p = ptr(v.toString());
                    if (p.compare(lo) >= 0 && p.compare(hi) < 0) {
                        frames.push('wx+0x' + p.sub(base).toString(16));
                    }
                }
            }
            send('  stack: ' + frames.join(' <- '));
        }

        // param_3 = shared_ptr {obj, ctrl}: 单次拷贝后解析
        const p3 = copy(a[2], 0x10);
        if (p3) {
            const objv = u64at(p3, 0);
            send('  param3.obj=0x' + objv.toString(16));
            if (objv > 0x10000n && objv < 0x7ffffffffffen) {
                const obj = ptr(objv.toString());
                // 全量 0x800 字节 (消息对象 >= 0x798, 正文候选在 +0x758/+0x778)
                const m = copy(obj, 0x800);
                if (m) {
                    send('  obj_dump@' + obj);
                    for (let off = 0; off < m.length; off += 16) {
                        let hx = '', ax = '';
                        for (let j = 0; j < 16 && off + j < m.length; j++) {
                            hx += ('0' + m[off+j].toString(16)).slice(-2) + ' ';
                            ax += (m[off+j] >= 0x20 && m[off+j] < 0x7F) ? String.fromCharCode(m[off+j]) : '.';
                        }
                        send('    ' + ('000' + off.toString(16)).slice(-4) + '  ' + hx + ' ' + ax);
                    }
                    // 全对象 SSO 串扫描
                    for (let off = 0; off + 0x20 <= m.length; off += 8) {
                        const size = u64at(m, off + 0x10);
                        const cap = u64at(m, off + 0x18);
                        if (size > 0n && size < 300n && cap >= size && cap < 0x100000n) {
                            let s8 = decU8(m, off, Number(size));
                            let s16 = decU16(m, off, Number(size));
                            if (s8 || s16) {
                                send('    str@+0x' + off.toString(16) + ' size=' + size +
                                     ' u8="' + (s8 || '?') + '" u16="' + (s16 || '?') + '"');
                            }
                        }
                    }
                }
            }
        }
    }
});
send('[*] ready (safe)');
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
