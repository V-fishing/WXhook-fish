# -*- coding: utf-8 -*-
# 看门狗: 检测微信主进程 -> 自动注入 wx_boot.dll (幂等, 已注入则跳过)
# 配合 rx_scan2 的重挂机制: 微信重启后全链路自动恢复
import ctypes, ctypes.wintypes as wt, subprocess, time, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
INJECTOR = os.path.join(HERE, 'bin', 'wx_inject.exe')
DLL = os.path.join(HERE, 'bin', 'wx_boot.dll')
PIPE = '\\\\.\\pipe\\wxsend'
PSAPI = ctypes.windll.psapi
kernel32 = ctypes.windll.kernel32
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.OpenProcess.restype = wt.HANDLE
kernel32.CloseHandle.argtypes = [wt.HANDLE]

def get_main_pid():
    out = subprocess.run(['powershell', '-NoProfile', '-Command',
                          '(Get-Process Weixin | Sort-Object WS -Descending | Select-Object -First 1).Id'],
                         capture_output=True, text=True).stdout.strip()
    try: return int(out)
    except: return 0

def pipe_alive():
    try:
        f = open(PIPE, 'r+b', buffering=0)
        f.write(b'STATUS\n')
        f.read(64)
        f.close()
        return True
    except Exception:
        return False

def main():
    print('watchdog started', flush=True)
    last_injected_pid = 0
    while True:
        try:
            pid = get_main_pid()
            if pid and pid != last_injected_pid and not pipe_alive():
                print(f'[{time.strftime("%H:%M:%S")}] new wechat main pid={pid}, injecting...', flush=True)
                r = subprocess.run([INJECTOR, 'auto', DLL], capture_output=True, text=True)
                line = (r.stdout or r.stderr).strip().splitlines()
                print('  ', line[-1] if line else '?', flush=True)
                last_injected_pid = pid
            elif pid and pid == last_injected_pid and pipe_alive():
                pass  # 已注入且管道正常
            elif not pid:
                last_injected_pid = 0  # 微信全退, 重置
            time.sleep(2)
        except Exception as e:
            print('err', e, flush=True)
            time.sleep(3)

if __name__ == '__main__':
    main()
