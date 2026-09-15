# -*- coding: utf-8 -*-
# M3-α 原型: UP1(0x1790970) hook + 消息对象字段改写 = 发送原语
#
# 用法: python m3_send_proto.py
#   - 自动等待/发现微信主进程并挂载
#   - 轮询 m3_cmd.json: {"target": "filehelper", "content": "..."}
#     文件存在即入队, 消费后删除
#   - 下一条经过 UP1 的消息对象被改写后放行 (搭车模式)
#
# 安全规则 (M2 教训):
#   - 只用 readByteArray/writeByteArray 单次拷贝模式, 无 readUtf8String
#   - 输出串过滤代理区 (sanitize)
#   - 改写内容长度 <= 原字符串 cap (零分配, 不触碰微信堆管理器)
#   - vtable 校验 (0x8BDF0F8) 防误改无关对象
import frida, time, sys, io, os, json

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

BASE_DIR = r'E:\weixin-hook-4.1.8\hook-wx\m2'
LOG = os.path.join(BASE_DIR, 'm3_send_proto.log')
CMD = os.path.join(BASE_DIR, 'm3_cmd.json')

logf = open(LOG, 'a', encoding='utf-8')

def out(s):
    line = time.strftime('%H:%M:%S ') + s
    print(line, flush=True)
    logf.write(line + '\n')
    logf.flush()

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
    print('NO Weixin.exe')
    sys.exit(1)
out('=' * 60)
out('M3-alpha proto, pid=%d' % PID)

JS = r"""
const wx = Process.findModuleByName('Weixin.dll');
const base = wx.base;
send('[*] base=' + base);

const MSGOBJ_VTABLE_RVA = 0x8BDF0F8;
const UP1_RVA = 0x1790970;
// BigInt 形式的期望 vtable (避免 BigInt!==NativePointer 类型坑)
const EXPECT_VT = BigInt(base.add(MSGOBJ_VTABLE_RVA).toString());

let g_queue = [];      // {target, content}
let g_hits = 0;
let g_rewrites = 0;
let g_mismatchLogged = false;

function sanitize(s) {
    let o = '';
    for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        if (c >= 0xD800 && c <= 0xDFFF) break;
        o += s[i];
    }
    return o;
}

// JS string -> UTF-8 bytes
function utf8enc(s) {
    const out = [];
    for (let i = 0; i < s.length; i++) {
        let c = s.codePointAt(i);
        if (c > 0xFFFF) i++;               // surrogate pair consumed
        if (c < 0x80) out.push(c);
        else if (c < 0x800) out.push(0xC0 | (c >> 6), 0x80 | (c & 63));
        else if (c < 0x10000) out.push(0xE0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
        else out.push(0xF0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
    return out;
}

function copy(p, len) {
    try { return new Uint8Array(p.readByteArray(len)); } catch (e) { return null; }
}
function u64at(u8, off) {
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(u8[off + i]);
    return v;
}
function decU8(u8, start, maxc) {
    let s = '';
    for (let i = start; i < u8.length && s.length < maxc; i++) {
        const c = u8[i];
        if (c === 0) break;
        if (c < 0x20 || c > 0x7E) return null;
        s += String.fromCharCode(c);
    }
    return s.length >= 1 ? s : null;
}

// 原地改写 std::string (零分配: 新内容必须 <= cap)
function rewriteString(objBase, strOff, newBytes, tag) {
    const head = copy(objBase.add(strOff), 0x20);
    if (!head) return { ok: false, why: tag + ': unreadable' };
    const size = u64at(head, 0x10);
    const cap = u64at(head, 0x18);
    if (newBytes.length > Number(cap)) {
        return { ok: false, why: tag + ': new(' + newBytes.length + ') > cap(' + cap + ')' };
    }
    // 数据位置: cap<=15 SSO 内联, 否则 +0 处是指针
    let bufp;
    if (cap > 15n) {
        const pv = u64at(head, 0);
        if (pv < 0x10000n) return { ok: false, why: tag + ': bad heap ptr' };
        bufp = ptr(pv.toString());
    } else {
        bufp = objBase.add(strOff);
    }
    const nb = newBytes.slice();
    nb.push(0);                                    // NUL
    try {
        bufp.writeByteArray(nb);
    } catch (e) {
        return { ok: false, why: tag + ': write fail ' + e };
    }
    objBase.add(strOff + 0x10).writeU64(newBytes.length);   // size
    return { ok: true, oldSize: Number(size), cap: Number(cap) };
}

Interceptor.attach(base.add(UP1_RVA), {
    onEnter: function(args) {
        g_hits++;
        if (g_queue.length === 0) return;
        // r8 -> shared_ptr {obj, ctrl} (先看对象是否文本消息, 匹配才消费命令)
        const p3 = copy(args[2], 0x10);
        if (!p3) return;
        const objv = u64at(p3, 0);
        if (objv < 0x10000n) return;
        const obj = ptr(objv.toString());
        // vtable 校验 (BigInt vs BigInt)
        const vt = copy(obj, 8);
        if (!vt) return;
        let vtv = 0n;
        for (let i = 7; i >= 0; i--) vtv = (vtv << 8n) | BigInt(vt[i]);
        if (vtv !== EXPECT_VT) {
            if (!g_mismatchLogged) {
                send('[i] 非文本消息对象 (vt=0x' + vtv.toString(16) + '), 跳过不改, 命令保留');
                g_mismatchLogged = true;
            }
            return;
        }
        // 匹配 -> 消费命令
        const cmd = g_queue.shift();
        // 读原值
        const wxidHead = copy(obj.add(0xB0), 0x20);
        const cntHead = copy(obj.add(0x758), 0x20);
        if (!wxidHead || !cntHead) { send('[!] cmd skip: fields unreadable'); return; }
        let oldWxid = '?';
        {
            const cap = u64at(wxidHead, 0x18);
            let src = null;
            if (cap > 15n) {
                const pv = u64at(wxidHead, 0);
                if (pv > 0x10000n) src = copy(ptr(pv.toString()), 32);
            } else {
                src = wxidHead.slice(0, 16);
            }
            if (src) oldWxid = sanitize(decU8(src, 0, 16) || '?');
        }
        let oldContent = '?';
        {
            const cap = u64at(cntHead, 0x18);
            let src = null;
            if (cap > 15n) {
                const pv = u64at(cntHead, 0);
                if (pv > 0x10000n) src = copy(ptr(pv.toString()), 64);
            } else {
                src = cntHead.slice(0, 16);
            }
            if (src) {
                let s = '';
                for (let i = 0; i < src.length; i++) {
                    const c = src[i];
                    if (c === 0) break;
                    s += (c >= 0x20 && c < 0x7F) ? String.fromCharCode(c) : '?';
                }
                oldContent = sanitize(s);
            }
        }
        send('[*] REWRITE #' + (++g_rewrites) + ' obj=' + obj);
        send('    old wxid="' + oldWxid + '" old content="' + oldContent + '"');
        // 改写 content
        const cBytes = utf8enc(cmd.content);
        const rc = rewriteString(obj, 0x758, cBytes, 'content');
        send('    content -> "' + sanitize(cmd.content) + '" (' + cBytes.length + 'B): ' +
             (rc.ok ? 'OK oldSize=' + rc.oldSize + ' cap=' + rc.cap : 'FAIL ' + rc.why));
        // 改写 wxid (可选)
        if (cmd.target && rc.ok) {
            const wBytes = utf8enc(cmd.target);
            const rw = rewriteString(obj, 0xB0, wBytes, 'wxid');
            send('    wxid -> "' + sanitize(cmd.target) + '": ' +
                 (rw.ok ? 'OK cap=' + rw.cap : 'FAIL ' + rw.why));
            if (!rw.ok) {
                // wxid 改写失败 -> 回滚 content, 避免把改写内容发给原目标
                // (无法恢复原 content 字节, 因为已被覆盖 -> 只能放弃本次, 警告)
                send('[!!] wxid 改写失败且 content 已改 -> 本次将发给原目标(' + oldWxid + '), 内容已变!');
            }
        }
    }
});

rpc.exports = {
    queueSend: function(target, content) {
        g_queue.push({ target: target, content: content });
        return g_queue.length;
    },
    status: function() {
        return { queued: g_queue.length, hits: g_hits, rewrites: g_rewrites };
    }
};
send('[*] M3-alpha ready');
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
api = script.exports_sync
out('[+] ready - polling %s' % CMD)

try:
    while True:
        if os.path.exists(CMD):
            try:
                with open(CMD, encoding='utf-8') as f:
                    cmd = json.load(f)
                os.remove(CMD)
                target = cmd.get('target', 'filehelper')
                content = cmd.get('content', '')
                out('[cmd] queue target="%s" content="%s"' % (target, content))
                api.queue_send(target, content)
            except Exception as e:
                out('[cmd-ERR] %s' % e)
        time.sleep(1)
except KeyboardInterrupt:
    pass
finally:
    session.detach()
    out('[+] detached')
    logf.close()
