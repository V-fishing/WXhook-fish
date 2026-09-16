# -*- coding: utf-8 -*-
# wxbot bot: phone sends /command -> PC executes -> replies
import ctypes, ctypes.wintypes as wt, os, sys, time, json, subprocess, base64
from datetime import datetime

WXBOT = os.path.dirname(os.path.abspath(__file__))
VENV_PY = r'E:\Desktop_fish\ProgramStudy\wechat-decrypt-main\wechat-decrypt-main\.venv\Scripts\python.exe'
READ_MSG = os.path.join(WXBOT, 'read_msg.py')
TARGET = 'filehelper'
POLL = 1
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
    user32.FindWindowW.argtypes = [wt.LPCWSTR, wt.LPCWSTR]
    user32.FindWindowW.restype = wt.HWND
    return user32.FindWindowW(None, '微信')

def screenshot_and_send():
    import pyautogui
    import io as _io
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    # 64 位原型 (缺失会导致句柄截断 -> AV)
    user32.SetForegroundWindow.argtypes = [wt.HWND]
    user32.OpenClipboard.argtypes = [wt.HWND]
    user32.SetClipboardData.argtypes = [wt.UINT, wt.HANDLE]
    user32.SetClipboardData.restype = wt.HANDLE
    kernel32.GlobalAlloc.argtypes = [wt.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wt.HGLOBAL
    kernel32.GlobalLock.argtypes = [wt.HGLOBAL]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [wt.HGLOBAL]
    hwnd = find_wechat_hwnd()
    if not hwnd:
        print('[IMG] WeChat window not found')
        return False
    img = pyautogui.screenshot()
    CF_DIB = 8; GMEM_MOVEABLE = 0x0002
    buf = _io.BytesIO()
    img.save(buf, 'BMP')
    dib = buf.getvalue()[14:]
    if not user32.OpenClipboard(None):
        print('[IMG] clipboard open fail')
        return False
    ok = False
    try:
        user32.EmptyClipboard()
        hMem = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(dib))
        if hMem:
            p = kernel32.GlobalLock(hMem)
            if p:
                try:
                    ctypes.memmove(p, dib, len(dib))
                finally:
                    kernel32.GlobalUnlock(hMem)
                if user32.SetClipboardData(CF_DIB, hMem):
                    ok = True
    finally:
        user32.CloseClipboard()
    if not ok:
        print('[IMG] clipboard write fail')
        return False
    # 强制前置 + 验证 (最多 3 次); 遮挡没关系, 最小化才不行
    prev_fg = user32.GetForegroundWindow()
    if user32.IsIconic(hwnd):                       # 最小化: 先还原 (否则前置必败)
        user32.ShowWindow(hwnd, 9)                  # SW_RESTORE
        time.sleep(0.4)
    fg_ok = False
    for _ in range(3):
        user32.SetForegroundWindow(hwnd)
        time.sleep(0.35)
        if user32.GetForegroundWindow() == hwnd:
            fg_ok = True
            break
    if not fg_ok:
        print('[IMG] cannot focus WeChat')
        return False
    pyautogui.hotkey('ctrl', 'v')
    time.sleep(1.2)
    pyautogui.press('enter')
    time.sleep(0.5)
    # 清空剪贴板 (防截图残留误贴到其他窗口) + 还原焦点
    if user32.OpenClipboard(None):
        user32.EmptyClipboard()
        user32.CloseClipboard()
    if prev_fg and prev_fg != hwnd:
        user32.SetForegroundWindow(prev_fg)
    return True

def handle(text):
    if not text.startswith('/'): return None
    t = text.strip()
    if t == '/ping': return 'pong'
    if t == '/help': return 'cmds: /screenshot | /cmd <cmd> | /ping | /help | 其他文字 -> AI'
    if t in ('/screenshot', '/截图'): return '__SCREENSHOT__'
    if t.startswith('/cmd '):
        c = t[5:].strip()
        try:
            r = os.popen(c).read()
            return r[:1500] if r else '(no output)'
        except Exception as e: return 'err:' + str(e)
    return 'unknown: ' + t + ' (/help for cmds)'

# ---- AI 会话 (非 / 消息) ----
_ai_history = []   # [{'role','content'}]
AI_ON = True

def ai_reply(text):
    """非指令消息交给 AI; 返回回复文本"""
    import ai_brain
    global _ai_history
    try:
        r = ai_brain.chat(text, _ai_history, screenshot_and_send)
        _ai_history.append({'role': 'user', 'content': text})
        _ai_history.append({'role': 'assistant', 'content': r})
        if len(_ai_history) > 40:
            _ai_history = _ai_history[-20:]
        return r
    except Exception as e:
        return 'AI 异常: ' + str(e)[:200]

RX_FILE = os.path.join(WXBOT, 'received_text.txt')
_rx_off = -1         # 已消费偏移; -1 = 启动时跳到文件尾 (不重放积压)

def _rx_init():
    global _rx_off
    try:
        _rx_off = os.path.getsize(RX_FILE)
    except OSError:
        _rx_off = 0

def read_new_msgs():
    """读自上次消费以来的新消息 (文件被截断则自动复位)"""
    global _rx_off
    out = []
    try:
        size = os.path.getsize(RX_FILE)
        if _rx_off < 0:
            _rx_init()
            return out
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
                    if AI_ON:
                        print('[AI] <- ' + summary[:60])
                        reply = ai_reply(summary)
                        last_sent = reply
                        send_text(TARGET, reply)
                        print('[AI] -> ' + reply[:60])
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
