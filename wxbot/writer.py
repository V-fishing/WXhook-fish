# -*- coding: utf-8 -*-
r"""
wxbot 写侧封装 — 对 hook-wx 注入 DLL (wx_send_v65.dll) 管道的统一操作入口。

用法:
  python writer.py inject                 # 找到微信主进程并注入 bin/wx_send_v65.dll (须在登录前)
  python writer.py status                 # 武装/队列/计数状态
  python writer.py auto <target> <msg>    # 自主发送 (零触发, 队列空闲即发)
  python writer.py send <target> <msg>    # 触发式改写 (下一条真实消息被改写)
"""
import base64
import glob
import os
import subprocess
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BS = chr(92)
PIPE = BS*2 + '.' + BS + 'pipe' + BS + 'wxsend'
DLL = os.path.join(SCRIPT_DIR, 'bin', 'wx_send_v65.dll')
INJECTOR = os.path.join(SCRIPT_DIR, 'bin', 'wx_inject.exe')
INJECTOR_PS = 'Start-Process -FilePath ' + chr(39) + os.path.abspath(DLL) + chr(39)


def _find_main_pid():
    """找到加载了 Weixin.dll 的主进程 (UI 进程)"""
    import ctypes, ctypes.wintypes as wt
    k32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi
    psapi.EnumProcessModulesEx.argtypes = [wt.HANDLE, ctypes.POINTER(wt.HMODULE), wt.DWORD, ctypes.POINTER(wt.DWORD), wt.DWORD]
    psapi.GetModuleFileNameExW.argtypes = [wt.HANDLE, wt.HMODULE, wt.LPWSTR, wt.DWORD]
    out = subprocess.run(["powershell", "-NoProfile", "-Command",
                          "Get-Process Weixin -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id"],
                         capture_output=True, text=True).stdout.split()
    for pid in map(int, out):
        h = k32.OpenProcess(0x410, False, pid)
        if not h:
            continue
        hmods = (wt.HMODULE * 1024)()
        cb = wt.DWORD()
        if psapi.EnumProcessModulesEx(h, hmods, ctypes.sizeof(hmods), ctypes.byref(cb), 0x03):
            found = False
            for i in range(cb.value // ctypes.sizeof(wt.HMODULE)):
                nm = ctypes.create_unicode_buffer(300)
                psapi.GetModuleFileNameExW(h, hmods[i], nm, 300)
                if nm.value.lower().endswith("weixin.dll"):
                    found = True
                    break
            k32.CloseHandle(h)
            if found:
                return pid
        else:
            k32.CloseHandle(h)
    return None


def _pipe_req(req: str, retries: int = 3) -> str:
    """管道请求 (服务端单实例, 偶发重建间隙自动重试)"""
    last_err = None
    for _ in range(retries):
        try:
            f = open(PIPE, 'r+b', buffering=0)
            try:
                f.write(req.encode())
                return f.read(200).decode(errors='replace')
            finally:
                f.close()
        except FileNotFoundError as e:
            last_err = e
            time.sleep(1.0)
    raise last_err


def inject() -> str:
    pid = _find_main_pid()
    if not pid:
        return "ERR: Weixin 主进程未找到 (微信未启动?)"
    r = subprocess.run([INJECTOR, str(pid), DLL], capture_output=True, text=True)
    tail = (r.stdout or '').strip().splitlines()[-1:] or ['']
    return f"pid={pid} | " + tail[0]


def status() -> str:
    return _pipe_req('STATUS\n').strip()


def auto(target: str, msg: str) -> str:
    b64 = base64.b64encode(msg.encode('utf-8')).decode()
    return _pipe_req(f'AUTO|{target}|{b64}\n').strip()


def send(target: str, msg: str) -> str:
    b64 = base64.b64encode(msg.encode('utf-8')).decode()
    return _pipe_req(f'SEND|{target}|{b64}\n').strip()


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == 'inject':
        print(inject())
    elif len(sys.argv) >= 2 and sys.argv[1] == 'status':
        print(status())
    elif len(sys.argv) >= 4 and sys.argv[1] == 'auto':
        print(auto(sys.argv[2], sys.argv[3]))
    elif len(sys.argv) >= 4 and sys.argv[1] == 'send':
        print(send(sys.argv[2], sys.argv[3]))
    else:
        print(__doc__)


if __name__ == '__main__':
    main()
