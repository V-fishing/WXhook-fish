# -*- coding: utf-8 -*-
# 自动化测试驱动: 部署检查 → 武装等待 → 发送 → PC 侧验证 → PASS/FAIL 报告
# 用法: python driver.py [--inject] [--full]
import subprocess, time, os, sys, base64, re

WXBOT = os.path.dirname(os.path.abspath(__file__))
PIPE = '\\\\.\\pipe\\wxsend'
LOG = r'E:\weixin-hook-4.1.8\hook-wx\m2\wx_send.log'
LAST_TEXT = os.path.join(WXBOT, 'last_text.txt')
WX_EXE = r'E:\weixin-hook-4.1.8\weixin-4.1.8\Weixin\Weixin.exe'
DLL = os.path.join(WXBOT, 'bin', 'wx_boot.dll')

def status():
    """查 DLL 状态, 返回 dict 或 None (管道不存在)"""
    try:
        f = open(PIPE, 'r+b', buffering=0)
        f.write(b'STATUS\n')
        r = f.read(400).decode(errors='replace').strip()
        f.close()
        d = {}
        for kv in r.replace('OK ', '').split():
            if '=' in kv:
                k, v = kv.split('=')
                try: d[k] = int(v)
                except: d[k] = v
        return d
    except Exception:
        return None

def wechat_running():
    out = subprocess.run(['powershell', '-NoProfile', '-Command',
                          '(Get-Process Weixin -ErrorAction SilentlyContinue | Measure-Object).Count'],
                         capture_output=True, text=True).stdout.strip()
    try: return int(out) > 0
    except: return False

def inject():
    exe = os.path.join(WXBOT, 'bin', 'wx_inject.exe')
    r = subprocess.run([exe, 'auto', DLL], capture_output=True, text=True, cwd=os.path.join(WXBOT, 'bin'))
    print('  inject:', (r.stdout or r.stderr).strip().splitlines()[-1] if (r.stdout or r.stderr) else '?')

def start_wechat():
    subprocess.Popen(['powershell', '-NoProfile', '-Command',
                      f'Start-Process -FilePath "{WX_EXE}"'])
    print('  wechat started, waiting window...')
    for _ in range(60):
        time.sleep(2)
        if wechat_running(): return True
    return False

def pipe_send(msg, target='filehelper'):
    b64 = base64.b64encode(msg.encode('utf-8')).decode()
    f = open(PIPE, 'r+b', buffering=0)
    f.write(f'AUTO|{target}|{b64}\n'.encode())
    r = f.read(200).decode(errors='replace').strip()
    f.close()
    return r

def tail_log(pattern, since_bytes=None):
    try:
        with open(LOG, 'rb') as f:
            f.seek(0, 2); end = f.tell()
            start = max(0, end - 65536)
            f.seek(start)
            return f.read().decode(errors='replace')
    except Exception:
        return ''

def main():
    inject_first = '--inject' in sys.argv
    full = '--full' in sys.argv
    results = []

    # 1. 微信进程
    if not wechat_running():
        print('[1] WeChat not running -> start')
        if not start_wechat():
            results.append(('wechat-start', False, 'timeout'))
    else:
        results.append(('wechat-running', True, ''))

    # 2. 注入 + 武装
    st = status()
    if st is None:
        if inject_first or full:
            print('[2] injecting...')
            inject()
            time.sleep(3)
            st = status()
        else:
            print('[2] DLL not injected (use --inject to deploy)')
            results.append(('injected', False, 'no pipe'))
            st = None
    if st is not None:
        if st.get('exec', 0):
            results.append(('armed', True, f"exec={st.get('exec'):#x}"))
        else:
            print('[2] waiting for arm (login)...')
            ok = False
            for _ in range(150):
                time.sleep(2)
                st = status()
                if st and st.get('exec', 0):
                    ok = True; break
            results.append(('armed', ok, f"exec={st.get('exec', 0):#x}" if ok else 'timeout (5min)'))

    if full:
        # 3. 发送 + PC 侧验证
        token = f'DRV-{int(time.time())}'
        # 记录日志当前大小 + 清空 last_text (DLL 会重建)
        log_size = 0
        try:
            log_size = os.path.getsize(LOG)
        except Exception: pass
        try: os.remove(LAST_TEXT)
        except Exception: pass

        print(f'[3] send {token}')
        r = pipe_send(token)
        results.append(('pipe-accept', r.startswith('OK'), r))

        # 验证1: 日志新增字节里出现 [PRECHECK] ok + [CLONE] UP1 returned
        # 验证2: last_text.txt 内容 == token
        ok_clone = ok_text = False
        t0 = time.time()
        while time.time() - t0 < 90:
            try:
                with open(LOG, 'rb') as f:
                    f.seek(log_size)
                    new_log = f.read().decode(errors='replace')
                if '[PRECHECK] ok' in new_log and '[CLONE] UP1 returned' in new_log:
                    ok_clone = True
            except Exception: pass
            try:
                with open(LAST_TEXT, encoding='utf-8', errors='replace') as f:
                    if token in f.read(): ok_text = True
            except Exception: pass
            if ok_clone and ok_text: break
            time.sleep(2)
        results.append(('clone-flush', ok_clone, 'PRECHECK ok + UP1 returned' if ok_clone else 'no new CLONE log'))
        results.append(('pc-text-capture', ok_text, 'last_text match' if ok_text else 'no match'))

    print('\n===== RESULT =====')
    npass = 0
    for name, ok, info in results:
        print(f'  {"PASS" if ok else "FAIL"}  {name}  {info}')
        npass += ok
    print(f'{npass}/{len(results)} passed')
    sys.exit(0 if npass == len(results) else 1)

if __name__ == '__main__':
    main()
