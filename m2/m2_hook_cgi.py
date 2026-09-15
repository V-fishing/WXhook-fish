# -*- coding: utf-8 -*-
# Hook newsendmsg CGI (0x3A25E80 / 0x3A2A770) - 安全版
# 教训: 上一版 readUtf8String 直读指针 + 多线程并发释放 → frida-agent 0xc0000005 崩溃
# 规则: 每个指针只做一次 readByteArray(异常保护), 全部解码在副本上进行
import frida, time, sys, io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# 自动找主进程 (内存最大的 Weixin.exe), 未找到则等待
import psutil
PID = None
for _ in range(120):
    best = 0
    PID = None
    for p in psutil.process_iter(['pid', 'name']):
        try:
            if p.info['name'] and p.info['name'].lower() == 'weixin.exe':
                mem = p.memory_info().rss
                if mem > best:
                    best = mem
                    PID = p.pid
        except Exception:
            pass
    if PID:
        break
    time.sleep(10)
if PID is None:
    print('NO Weixin.exe after wait')
    sys.exit(1)
LOG = r'E:\weixin-hook-4.1.8\hook-wx\m2\m2_hook_cgi.log'

logf = open(LOG, 'a', encoding='utf-8')

def out(s):
    line = time.strftime('%H:%M:%S ') + s
    print(line, flush=True)
    logf.write(line + '\n')
    logf.flush()

out('=' * 50)
out('attach pid=%d (SAFE build)' % PID)

JS = r"""
const wx = Process.findModuleByName('Weixin.dll');
const base = wx.base;
send('[*] base=' + base);

// 唯一的原生读取入口: 异常保护 + 一次性拷贝
function copy(p, len) {
    try { return new Uint8Array(p.readByteArray(len)); } catch (e) { return null; }
}

// u64 LE 从副本
function u64at(u8, off) {
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(u8[off + i]);
    return v;
}

// 在副本上解码 UTF-16LE 串
function decU16(u8, start, maxChars) {
    let s = '';
    for (let i = start; i + 1 < u8.length && s.length < maxChars; i += 2) {
        const c = u8[i] | (u8[i+1] << 8);
        if (c === 0) break;
        if (c < 0x20 || (c >= 0xD800 && c < 0xE000)) return null;
        s += String.fromCharCode(c);
    }
    return s.length >= 3 ? s : null;
}

// 在副本上解码 ASCII/UTF-8 串
function decU8(u8, start, maxChars) {
    let s = '';
    for (let i = start; i < u8.length && s.length < maxChars; i++) {
        const c = u8[i];
        if (c === 0) break;
        if (c < 0x20 || c > 0x7E) return null;
        s += String.fromCharCode(c);
    }
    return s.length >= 3 ? s : null;
}

// 副本上扫描可打印串 (u16 + u8); 严格排除代理区, 截断长度 —— 防 send() 序列化崩溃
function sanitize(s) {
    let out = '';
    for (let i = 0; i < s.length && out.length < 64; i++) {
        const c = s.charCodeAt(i);
        if (c >= 0xD800 && c <= 0xDFFF) break;   // 未配对代理: 终止
        out += s[i];
    }
    return out;
}

function runsFromCopy(u8) {
    const out = [];
    let cur16 = '', cur8 = '';
    for (let i = 0; i + 1 < u8.length; i += 2) {
        const c = u8[i] | (u8[i+1] << 8);
        if (c >= 0x20 && c < 0xFFFD && !(c >= 0xD800 && c < 0xE000)) {
            if (cur16.length < 64) cur16 += String.fromCharCode(c);
        } else {
            if (cur16.length >= 4) out.push('u16:' + cur16);
            if (out.length >= 6) return out;
            cur16 = '';
        }
    }
    if (cur16.length >= 4) out.push('u16:' + cur16);
    for (let i = 0; i < u8.length; i++) {
        const c = u8[i];
        if (c >= 0x20 && c <= 0x7E) {
            if (cur8.length < 64) cur8 += String.fromCharCode(c);
        } else {
            if (cur8.length >= 4) out.push('u8:' + cur8);
            if (out.length >= 6) return out;
            cur8 = '';
        }
    }
    if (cur8.length >= 4) out.push('u8:' + cur8);
    return out;
}

// 两级遍历, 每指针只读一次, 深度浅窗口小
function walkSafe(root, label, results) {
    // level 0: 根对象 0x100
    let l0 = copy(root, 0x100);
    if (!l0) return;
    for (let off = 0; off + 8 <= l0.length && results.length < 20; off += 8) {
        const v = u64at(l0, off);
        if (v < 0x10000n || v > 0x7ffffffffffen) continue;
        const p = ptr(v.toString());
        let l1 = copy(p, 0x80);            // level 1
        if (!l1) continue;
        for (const r of runsFromCopy(l1)) {
            results.push(label + '+0x' + off.toString(16) + ' -> ' + r);
            if (results.length >= 20) return;
        }
        // level 2: 只展开前 6 个指针字段, 各读 0x60
        let expanded = 0;
        for (let o2 = 0; o2 + 8 <= l1.length && expanded < 6 && results.length < 20; o2 += 8) {
            const v2 = u64at(l1, o2);
            if (v2 < 0x10000n || v2 > 0x7ffffffffffen) continue;
            let l2 = copy(ptr(v2.toString()), 0x60);
            if (!l2) continue;
            expanded++;
            for (const r of runsFromCopy(l2)) {
                results.push(label + '+0x' + off.toString(16) + '>[+0x' + o2.toString(16) + '] -> ' + r);
                if (results.length >= 20) return;
            }
        }
    }
}

const targets = {
    'CGI_A_0x3A25E80': 0x3A25E80,
    'CGI_B_0x3A2A770': 0x3A2A770,
};

let counts = {};
for (const [name, rva] of Object.entries(targets)) {
    (function(name, rva) {
        try {
            Interceptor.attach(base.add(rva), {
                onEnter: function(args) {
                    counts[name] = (counts[name] || 0) + 1;
                    const n = counts[name];
                    if (n > 12) return;      // 只详录前 12 次
                    send('>>> ' + name + ' #' + n + ' <<<');
                    send('  rcx=' + args[0] + ' rdx=' + args[1] + ' r8=' + args[2] + ' r9=' + args[3]);
                    for (let k = 0; k < 3; k++) {
                        const h = copy(args[k], 0x80);
                        if (h) {
                            send('  arg' + k + '_hex@' + args[k]);
                            for (let off = 0; off < h.length; off += 16) {
                                let hx = '', ax = '';
                                for (let j = 0; j < 16 && off + j < h.length; j++) {
                                    hx += ('0' + h[off+j].toString(16)).slice(-2) + ' ';
                                    ax += (h[off+j] >= 0x20 && h[off+j] < 0x7F) ? String.fromCharCode(h[off+j]) : '.';
                                }
                                send('    ' + ('000' + off.toString(16)).slice(-4) + '  ' + hx + ' ' + ax);
                            }
                            const results = [];
                            walkSafe(args[k], 'arg' + k, results);
                            for (const r of results) send('  ' + r);
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
send('[*] ready (safe mode)');
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
