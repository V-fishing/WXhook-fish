# -*- coding: utf-8 -*-
# 一键启动: 杀旧实例 -> 分离式启动 watchdog/rx_scan2/bot -> 验证
import subprocess, os, time, sys

HERE = os.path.dirname(os.path.abspath(__file__))
PY = r'E:\Desktop_fish\ProgramStudy\wechat-decrypt-main\wechat-decrypt-main\.venv\Scripts\python.exe'
DETACHED = 0x00000008 | 0x00000200   # DETACHED_PROCESS | NEW_PROCESS_GROUP

def kill_old():
    r = subprocess.run(['powershell', '-NoProfile', '-Command',
                        "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | "
                        "Where-Object { $_.CommandLine -match 'bot.py|rx_scan2|watchdog' } | "
                        "ForEach-Object { Stop-Process -Id $_.ProcessId -Force; $_.ProcessId }"],
                       capture_output=True, text=True)
    killed = [x for x in r.stdout.split() if x.strip()]
    if killed:
        print('killed:', killed)
    time.sleep(1)

def start(script):
    logf = open(os.path.join(HERE, script.replace('.py', '.out.log')), 'ab')
    subprocess.Popen([PY, '-u', os.path.join(HERE, script)],
                     cwd=HERE, creationflags=DETACHED,
                     stdout=logf, stderr=logf)
    print('started', script)

def count_py():
    r = subprocess.run(['powershell', '-NoProfile', '-Command',
                        "(Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | "
                        "Where-Object { $_.CommandLine -match 'wxbot' } | Measure-Object).Count"],
                       capture_output=True, text=True)
    try: return int(r.stdout.strip())
    except: return 0

if __name__ == '__main__':
    kill_old()
    start('watchdog.py')
    time.sleep(1)
    start('rx_scan2.py')
    time.sleep(1)
    start('bot.py')
    time.sleep(4)
    print('running python (wxbot):', count_py())
    print('done — 旧实例已清理, 三件套已分离启动')
