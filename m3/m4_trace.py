# -*- coding: utf-8 -*-
# M5: 发送管线阶段探针 — 对比真实发送 vs 自主发送的轨迹差异
# 全部使用 M2/M3 已证安全的 hook 点, 只计数+单行日志 (安全模式)
import frida, time, sys, io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

LOG = r'E:\weixin-hook-4.1.8\hook-wx\m3\m4_trace.log'
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
out('trace pid=%d' % pid)

JS = r"""
const wx = Process.findModuleByName('Weixin.dll');
const base = wx.base;
send('[*] base=' + base);

function copy(p, len) {
    try { return new Uint8Array(p.readByteArray(len)); } catch (e) { return null; }
}

// 读 MSVC SSO 字符串 (单次拷贝), 只取可打印 ASCII 摘要
function readStr(p) {
    const h = copy(p, 0x20);
    if (!h) return null;
    let size = 0n, cap = 0n;
    for (let i = 7; i >= 0; i--) { size = (size << 8n) | BigInt(h[0x10 + i]); cap = (cap << 8n) | BigInt(h[0x18 + i]); }
    if (size > 64n || cap < size || cap > 0x10000n) return null;
    let src = h;
    if (cap > 15n) {
        let v = 0n;
        for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(h[i]);
        if (v < 0x10000n) return null;
        src = copy(ptr(v.toString()), Number(size) + 1);
        if (!src) return null;
    }
    let s = '';
    for (let i = 0; i < src.length && s.length < Number(size); i++) {
        const c = src[i];
        if (c === 0) break;
        s += (c >= 0x20 && c < 0x7F) ? String.fromCharCode(c) : '?';
    }
    return s;
}

const STAGES = {
    'BODY_ENTRY':  0x1790981,   // UP1+17: trampoline 跳回主体处
    'CTOR_SITE':   0x1790A5A,   // UP1 体内 call TASK_CTOR 的指令地址
    'REG_SITE':    0x1790AA4,   // UP1 体内 call QUEUE_REG 的指令地址
    'CORE_SITE':   0x1790AB1,   // UP1 体内 call CORE 的指令地址
    'TASK_CTOR':   0x39B94B0,   // 任务构造器函数入口
    'QUEUE_REG':   0x17948C0,   // 任务入队函数入口
    'CORE':        0x1795500,   // 会话发送处理函数入口
    'MID':         0x39BD150,   // 每任务条目转字符串 (CORE 循环内)
    'SYNC_A':      0x17F4FC0,   // StartSendMessageSyncStage
    'SYNC_B':      0x17F9270,
};

for (const [name, rva] of Object.entries(STAGES)) {
    (function(name, rva) {
        Interceptor.attach(base.add(rva), {
            onEnter: function(args) {
                const tid = Process.getCurrentThreadId();
                let extra = '';
                if (name === 'MID' || name === 'CORE') {
                    // MID: args[0]=inner任务 (wxid@+0x38); CORE: args[1]=task+0x48 (wxid)
                    let wxp = (name === 'MID') ? args[0].add(0x38) : args[1];
                    const s = readStr(wxp);
                    if (s) extra = ' wxid="' + s + '"';
                }
                send('STAGE ' + name + ' tid=' + tid + extra);
            }
        });
        send('[+] probe ' + name);
    })(name, rva);
}
send('[*] all probes ready');
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
out('[+] tracing')

try:
    while True:
        time.sleep(5)
except KeyboardInterrupt:
    pass
finally:
    session.detach()
    out('[+] detached')
    logf.close()
