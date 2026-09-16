# -*- coding: utf-8 -*-
# wxbot bot: phone sends /command -> PC executes -> replies
import ctypes, ctypes.wintypes as wt, os, sys, time, json, subprocess, base64
import tools
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

def _win_protos():
    """64 位原型 (缺失会导致句柄截断 -> AV)"""
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    user32.SetForegroundWindow.argtypes = [wt.HWND]
    user32.OpenClipboard.argtypes = [wt.HWND]
    user32.SetClipboardData.argtypes = [wt.UINT, wt.HANDLE]
    user32.SetClipboardData.restype = wt.HANDLE
    user32.GetClipboardData.argtypes = [wt.UINT]
    user32.GetClipboardData.restype = wt.HANDLE
    kernel32.GlobalAlloc.argtypes = [wt.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wt.HGLOBAL
    kernel32.GlobalLock.argtypes = [wt.HGLOBAL]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [wt.HGLOBAL]
    user32.IsIconic.argtypes = [wt.HWND]
    user32.ShowWindow.argtypes = [wt.HWND, wt.INT]
    user32.keybd_event.argtypes = [wt.BYTE, wt.BYTE, wt.DWORD, ctypes.c_void_p]
    user32.GetForegroundWindow.restype = wt.HWND
    user32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
    user32.AttachThreadInput.argtypes = [wt.DWORD, wt.DWORD, wt.BOOL]
    kernel32.GetCurrentThreadId.restype = wt.DWORD

def _focus_wechat(hwnd):
    """强制前置 + 验证 (ALT 脉冲 + AttachThreadInput 降级, 3 次重试)"""
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    for attempt in range(3):
        if user32.IsIconic(hwnd):
            user32.ShowWindow(hwnd, 9)              # SW_RESTORE
            time.sleep(0.4)
        user32.keybd_event(0x12, 0, 0, 0)           # ALT down: 解除前台锁
        user32.keybd_event(0x12, 0, 2, 0)           # ALT up
        user32.SetForegroundWindow(hwnd)
        time.sleep(0.35)
        if user32.GetForegroundWindow() == hwnd:
            return True
        fg = user32.GetForegroundWindow()
        if fg:
            fg_tid = user32.GetWindowThreadProcessId(fg, None)
            my_tid = kernel32.GetCurrentThreadId()
            user32.AttachThreadInput(my_tid, fg_tid, True)
            user32.SetForegroundWindow(hwnd)
            user32.AttachThreadInput(my_tid, fg_tid, False)
            time.sleep(0.3)
            if user32.GetForegroundWindow() == hwnd:
                return True
        time.sleep(0.5)
    return False

def _clipboard_clear():
    user32 = ctypes.windll.user32
    if user32.OpenClipboard(None):
        user32.EmptyClipboard()
        user32.CloseClipboard()

def send_file_to_wechat(path):
    """CF_HDROP 剪贴板 + 粘贴: 把电脑上的文件以文件消息发到微信当前会话 (原始字节)"""
    _win_protos()
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    p = os.path.abspath(os.path.expandvars(os.path.expanduser(path.strip())))
    if not os.path.isfile(p):
        print('[FILE] not found:', p)
        return '文件不存在: ' + p
    sz = os.path.getsize(p)
    if sz > 400 * 1024 * 1024:
        return '文件过大 (>400MB)'
    hwnd = find_wechat_hwnd()
    if not hwnd:
        print('[FILE] WeChat window not found')
        return '找不到微信窗口'
    # CF_HDROP: DROPFILES 头 (20B) + 宽字符路径 + 双零结尾
    class DROPFILES(ctypes.Structure):
        _fields_ = [('pFiles', wt.DWORD), ('pt', wt.POINT), ('fNC', wt.BOOL), ('fWide', wt.BOOL)]
    df = DROPFILES(); df.pFiles = 20; df.fWide = True
    wide = p.encode('utf-16-le') + b'\x00\x00'
    payload = bytes(df) + wide + b'\x00\x00'
    CF_HDROP = 15; GMEM_MOVEABLE = 0x0002
    if not user32.OpenClipboard(None):
        print('[FILE] clipboard open fail')
        return '剪贴板被占用'
    ok = False
    try:
        user32.EmptyClipboard()
        hMem = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(payload))
        if hMem:
            ptr = kernel32.GlobalLock(hMem)
            if ptr:
                try:
                    ctypes.memmove(ptr, payload, len(payload))
                finally:
                    kernel32.GlobalUnlock(hMem)
                if user32.SetClipboardData(CF_HDROP, hMem):
                    ok = True
    finally:
        user32.CloseClipboard()
    if not ok:
        print('[FILE] clipboard write fail')
        return '剪贴板写入失败'
    if not _focus_wechat(hwnd):
        print('[FILE] cannot focus WeChat')
        return '无法聚焦微信窗口 (是否最小化?)'
    import pyautogui
    pyautogui.hotkey('ctrl', 'v')
    time.sleep(2.0)      # 文件粘贴后微信显示文件卡片, 稍长等待
    pyautogui.press('enter')
    time.sleep(0.5)
    _clipboard_clear()
    prev_fg = user32.GetForegroundWindow()
    if prev_fg and prev_fg != hwnd:
        pass
    print('[FILE] sent:', p)
    return 'OK: ' + os.path.basename(p) + f' ({sz//1024}KB)'

def screenshot_and_send():
    import pyautogui
    import io as _io
    _win_protos()
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
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
    # 强制前置 + 验证; 遮挡没关系, 最小化才不行
    if not _focus_wechat(hwnd):
        print('[IMG] cannot focus WeChat')
        return False
    pyautogui.hotkey('ctrl', 'v')
    time.sleep(1.2)
    pyautogui.press('enter')
    time.sleep(0.5)
    # 清空剪贴板 (防截图残留误贴到其他窗口) + 还原焦点
    _clipboard_clear()
    prev_fg = user32.GetForegroundWindow()
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
tools.register('take_screenshot', screenshot_and_send)
tools.register('send_file', send_file_to_wechat)
_ai_history = []   # [{'role','content'}]
AI_ON = True

# ---- 定时提醒 + 白名单发送 ----
WL_FILE = os.path.join(WXBOT, 'send_whitelist.json')
REM_FILE = os.path.join(WXBOT, 'reminders.json')
_reminders = []   # [{'due': epoch, 'text': str}]

def _load_whitelist():
    try:
        with open(WL_FILE, encoding='utf-8') as f:
            wl = json.load(f)
        if isinstance(wl, dict):
            wl.setdefault('文件传输助手', 'filehelper')
            return wl
    except Exception:
        pass
    return {'文件传输助手': 'filehelper'}

def _load_reminders():
    try:
        with open(REM_FILE, encoding='utf-8') as f:
            return [r for r in json.load(f) if isinstance(r, dict) and 'due' in r]
    except Exception:
        return []

def send_to_contact(contact, message):
    wl = _load_whitelist()
    wxid = None
    alias = None
    for k, v in wl.items():
        if contact.lower() == k.lower() or contact == v:
            wxid = v; alias = k; break
    if not wxid:
        return '联系人不在白名单: ' + contact + ' (可用: ' + ', '.join(wl.keys()) + ')'
    b64 = base64.b64encode(message.encode('utf-8')).decode()
    try:
        f = open(PIPE, 'r+b', buffering=0)
        f.write(('AUTO|' + wxid + '|' + b64 + '\n').encode())
        resp = f.read(200).decode(errors='replace').strip()
        f.close()
    except Exception as e:
        return '发送失败 (管道不可用): ' + str(e)[:80]
    if resp.startswith('OK'):
        return '已发送给 ' + alias
    return '发送失败: ' + resp

def _save_reminders():
    try:
        with open(REM_FILE, 'w', encoding='utf-8') as f:
            json.dump(_reminders, f, ensure_ascii=False)
    except Exception:
        pass

def set_reminder_impl(delay_minutes, text):
    try:
        m = float(delay_minutes)
    except Exception:
        return '参数错误: delay_minutes 需为数字'
    m = max(0.05, min(m, 1440))
    due = time.time() + m * 60
    items = _load_reminders()
    items.append({'due': due, 'text': text})
    with open(REM_FILE, 'w', encoding='utf-8') as f:
        json.dump(items, f, ensure_ascii=False)
    return f'已设置提醒: {time.strftime("%H:%M:%S", time.localtime(due))} -> {text}'

def _reminder_loop():
    """每轮读 reminders.json (跨进程队列): 到期的触发并移除"""
    while True:
        try:
            items = _load_reminders()
            now = time.time()
            due_list = [r for r in items if r['due'] <= now]
            if due_list:
                keep = [r for r in items if r['due'] > now]
                with open(REM_FILE, 'w', encoding='utf-8') as f:
                    json.dump(keep, f, ensure_ascii=False)
                for r in due_list:
                    reply = '⏰ 提醒: ' + r['text']
                    send_text(TARGET, reply)
                    print('[REMIND]', reply[:60], flush=True)
        except Exception as e:
            print('[REMIND] err', e, flush=True)
        time.sleep(2)

tools.register('set_reminder', set_reminder_impl)
tools.register('send_to', send_to_contact)

def ai_reply(text):
    """非指令消息交给 AI; 返回回复文本"""
    import ai_brain
    global _ai_history
    try:
        r = ai_brain.chat(text, _ai_history, tools.execute)
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
    import sys
    import threading
    threading.Thread(target=_reminder_loop, daemon=True).start()

    lock = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bot.pid')
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
