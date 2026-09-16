# -*- coding: utf-8 -*-
# wxbot bot: phone sends /command -> PC executes -> replies
import ctypes, ctypes.wintypes as wt, os, sys, time, json, subprocess, base64
from datetime import datetime

WXBOT = os.path.dirname(os.path.abspath(__file__))
VENV_PY = r'E:\Desktop_fish\ProgramStudy\wechat-decrypt-main\wechat-decrypt-main\.venv\Scripts\python.exe'
READ_MSG = os.path.join(WXBOT, 'read_msg.py')
TARGET = 'filehelper'
POLL = 3
BS = chr(92)
PIPE = BS*2 + '.' + BS + 'pipe' + BS + 'wxsend'

def send_text(target, msg):
    b64 = base64.b64encode(msg.encode('utf-8')).decode()
    try:
        f = open(PIPE, 'r+b', buffering=0)
        f.write(('AUTO|' + target + '|' + b64 + '\n').encode())
        r = f.read(200).decode(errors='replace').strip()
        f.close()
        return r
    except Exception as e:
        return 'ERR:' + str(e)

def find_wechat_hwnd():
    user32 = ctypes.windll.user32
    return user32.FindWindowW(None, '微信')

def screenshot_and_send():
    import pyautogui
    from PIL import Image
    import io as _io
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    hwnd = find_wechat_hwnd()
    if not hwnd:
        print('[IMG] WeChat window not found')
        return False
    # 截图
    img = pyautogui.screenshot()
    # 复制到剪贴板 (CF_DIB)
    CF_DIB = 8; GMEM_MOVEABLE = 2
    buf = _io.BytesIO()
    img.save(buf, 'BMP')
    dib = buf.getvalue()[14:]
    if not user32.OpenClipboard(0): return False
    user32.EmptyClipboard()
    hMem = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(dib))
    p = kernel32.GlobalLock(hMem)
    ctypes.memmove(p, dib, len(dib))
    kernel32.GlobalUnlock(hMem)
    user32.SetClipboardData(CF_DIB, hMem)
    user32.CloseClipboard()
    # 聚焦微信
    user32.SetForegroundWindow(hwnd)
    time.sleep(0.5)
    # 粘贴
    pyautogui.hotkey('ctrl', 'v')
    time.sleep(1)
    # 发送
    pyautogui.press('enter')
    time.sleep(0.5)
    return True

def handle(text):
    if not text.startswith('/'): return None
    t = text.strip()
    if t == '/ping': return 'pong'
    if t == '/help': return 'cmds: /screenshot | /cmd <cmd> | /ping | /help'
    if t in ('/screenshot', '/截图'): return '__SCREENSHOT__'
    if t.startswith('/cmd '):
        c = t[5:].strip()
        try:
            r = os.popen(c).read()
            return r[:1500] if r else '(no output)'
        except Exception as e: return 'err:' + str(e)
    return 'unknown: ' + t + ' (/help for cmds)'

RX_FILE = os.path.join(WXBOT, 'received_text.txt')
_rx_off = 0          # 已消费偏移 (追加协议: 每行 ts|target|content)

def read_new_msgs():
    """读自上次消费以来的新消息 (文件被截断则自动复位)"""
    global _rx_off
    out = []
    try:
        size = os.path.getsize(RX_FILE)
        if size < _rx_off:
            _rx_off = 0
        if size == _rx_off:
            return out
        with open(RX_FILE, encoding='utf-8') as f:
            f.seek(_rx_off)
            data = f.read()
            _rx_off = f.tell()
        for line in data.splitlines():
            parts = line.split('|', 2)
            if len(parts) == 3 and parts[1] == TARGET:
                out.append(parts[2])
    except FileNotFoundError:
        pass
    except Exception as e:
        print('rx read err:', e)
    return out

def main():
    print('wxbot started ' + datetime.now().strftime('%H:%M:%S'))
    print('target:' + TARGET + ' poll:' + str(POLL) + 's')
    last_sent = ''
    while True:
        try:
            for summary in read_new_msgs():
                if summary == last_sent:
                    continue  # 回声抑制: bot 自己的回复
                if not summary.startswith('/'):
                    continue
                print('\n[CMD] ' + summary[:60])
                result = handle(summary)
                if result == '__SCREENSHOT__':
                    print('[BOT] screenshot + send...')
                    ok = screenshot_and_send()
                    reply = '截图已发送' if ok else '截图失败'
                    last_sent = reply
                    send_text(TARGET, reply)
                    print('[BOT] ' + reply)
                elif result is not None:
                    last_sent = result
                    send_text(TARGET, result)
                    print('[BOT] reply: ' + result[:60])
        except Exception as e:
            print('poll err: ' + str(e))
        time.sleep(POLL)

if __name__ == '__main__':
    main()
