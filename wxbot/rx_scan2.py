# -*- coding: utf-8 -*-
# v99 接收捕获: 扫描微信堆中的 AddMsg protobuf (filehelper), 追加写入 received_text.txt
# 协议: 每行 "ts|target|content"; 触发 = 出现沿 (本轮堆里出现、上一轮没有)
# 去重键 = (content, msg_timestamp): 同文重发 ts 不同会触发; 同一消息的多内存副本 ts 相同只触发一次
import ctypes, ctypes.wintypes as wt, subprocess, time, os, re, sys

OUT = r'E:\weixin-hook-4.1.8\wxbot\received_text.txt'
VT_RVA = 0x8BDF0F8

kernel32 = ctypes.windll.kernel32
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.OpenProcess.restype = wt.HANDLE
kernel32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.ReadProcessMemory.restype = wt.BOOL
kernel32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.CloseHandle.argtypes = [wt.HANDLE]

class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_uint64), ('AllocationBase', ctypes.c_uint64),
                ('AllocationProtect', wt.DWORD), ('RegionSize', ctypes.c_uint64),
                ('State', wt.DWORD), ('Protect', wt.DWORD), ('Type', wt.DWORD)]

def get_main_pid():
    out = subprocess.run(['powershell', '-NoProfile', '-Command',
                          '(Get-Process Weixin | Sort-Object WS -Descending | Select-Object -First 1).Id'],
                         capture_output=True, text=True).stdout.strip()
    try: return int(out)
    except: return 0

def read_regions(h):
    chunks = []
    addr = 0
    mbi = MBI()
    while addr < 0x7FFFFFFFFFFF:
        if kernel32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        sz = mbi.RegionSize
        prot = mbi.Protect & 0xFF
        if mbi.State == 0x1000 and (prot in (0x04, 0x40)) and 0 < sz < 300*1024*1024:
            b = ctypes.create_string_buffer(sz)
            got = ctypes.c_size_t(0)
            if kernel32.ReadProcessMemory(h, ctypes.c_uint64(mbi.BaseAddress), b, ctypes.c_size_t(sz), ctypes.byref(got)) and got.value > 0:
                chunks.append(b.raw[:got.value])
        nxt = mbi.BaseAddress + sz
        if nxt <= addr: break
        addr = nxt
    return chunks

def _varint(d, p):
    v = 0; shift = 0
    for k in range(10):
        if p + k >= len(d): return None, p
        b = d[p+k]
        v |= (b & 0x7F) << shift
        if not (b & 0x80):
            return v, p + k + 1
        shift += 7
    return None, p

def parse_content_ts(d, i):
    """'filehelper' 起点解析 field5(content) + field9(timestamp)。返回 (content, ts)"""
    p = i + 10
    end = min(len(d), p + 96)
    content = None; ts = 0
    while p < end:
        tag = d[p]
        if tag == 0x2a:
            ln = d[p+1] if p+1 < len(d) else 0
            if p + 2 + ln > len(d): break
            seg = d[p+2:p+2+ln]
            if len(seg) >= 2 and seg[0] == 0x0a:
                cl = seg[1]
                if 2 + cl <= len(seg):
                    try: content = seg[2:2+cl].decode('utf-8', errors='replace')
                    except Exception: content = None
            p = p + 2 + ln
        elif tag in (0x20, 0x30, 0x38, 0x48, 0x50):
            v, p2 = _varint(d, p+1)
            if v is None: break
            if tag == 0x48: ts = v
            p = p2
        elif tag == 0x42:
            ln = d[p+1] if p+1 < len(d) else 0
            p = p + 2 + ln
        else:
            break
        if content is not None and ts:
            break
    return (content, ts)

def parse_content(d, i):
    """'filehelper' 命中点向后: 跳过 20 xx, 解 2a <len> 0a <clen> <content>"""
    p = i + 10
    end = min(len(d), p + 64)
    while p < end:
        if d[p] == 0x2a:
            ln = d[p+1]
            if p + 2 + ln > len(d): return None
            seg = d[p+2:p+2+ln]
            if len(seg) >= 2 and seg[0] == 0x0a:
                cl = seg[1]
                if 2 + cl <= len(seg):
                    try: return seg[2:2+cl].decode('utf-8', errors='replace')
                    except Exception: return None
            return None
        elif d[p] == 0x20:
            p += 2
        else:
            return None
    return None

def scan_current(h):
    """返回本轮堆内 filehelper 消息集合: {(content, ts)}"""
    cur = set()
    cur = set()
    for chunk in read_regions(h):
        for m in re.finditer(rb'\x1a\x0c\x0a\x0afilehelper', chunk):
            c, t = parse_content_ts(chunk, m.start() + 4)
            if c and c.strip():
                cur.add((c, t))
    return cur

def main():
    import sys
    lock = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rx_scan2.pid')
    try:
        old = open(lock).read().strip()
        if old and int(old) != os.getpid():
            import subprocess
            r = subprocess.run(['powershell', '-NoProfile', '-Command',
                                f'(Get-Process -Id {old} -ErrorAction SilentlyContinue).ProcessName'],
                               capture_output=True, text=True)
            if r.stdout.strip() == 'python':
                print('already running (pid ' + old + '), exit'); sys.exit(1)
    except Exception: pass
    open(lock, 'w').write(str(os.getpid()))
    pid = get_main_pid()
    if not pid: print('no weixin'); return
    h = kernel32.OpenProcess(0x0010 | 0x0400, False, pid)
    if not h: print('open fail'); return
    print('watching pid', pid, flush=True)

    prev = scan_current(h)   # 基线: 存量不触发
    print(f'baseline: {len(prev)} existing', flush=True)

    while True:
        time.sleep(0.7)
        # 微信退出检测: 进程句柄已终止 -> 自动重挂新进程 (重基线, 不触发)
        if kernel32.WaitForSingleObject(h, 0) == 0:
            print('[WATCH] wechat exited, waiting for new process...', flush=True)
            kernel32.CloseHandle(h)
            prev = set()
            while True:
                time.sleep(1.5)
                npid = get_main_pid()
                if npid:
                    h = kernel32.OpenProcess(0x0010 | 0x0400, False, npid)
                    if h:
                        prev = scan_current(h)
                        print(f'[WATCH] re-attached pid {npid}, baseline {len(prev)}', flush=True)
                        break
            continue
        try:
            cur = scan_current(h)
        except Exception as e:
            print('err', e, flush=True)
            try: kernel32.CloseHandle(h)
            except: pass
            pid = get_main_pid()
            if pid:
                h = kernel32.OpenProcess(0x0010 | 0x0400, False, pid)
                prev = scan_current(h)
                print('recovered, baseline', len(prev), flush=True)
            continue
            # 进程重启后基线重建, 不触发
        new = cur - prev
        if new:
            now = int(time.time())
            with open(OUT, 'a', encoding='utf-8') as f:
                for c, t in sorted(new):
                    f.write(f'{now}|filehelper|{c}\n')
            for c, t in sorted(new):
                print(f'[RX] ({t})', c[:80], flush=True)
        prev = cur

if __name__ == '__main__':
    main()
