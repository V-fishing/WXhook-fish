# -*- coding: utf-8 -*-
# 窗口视觉层 (v99.2 简化版, 按用户设计):
#   list_windows  枚举窗口
#   window_ocr    找窗口 -> 置顶 (SetWindowPos, 不受前台锁限制) -> 全屏截图裁剪 -> OCR -> 还原 Z 序
# 置顶不是抢前台: SetWindowPos HWND_TOP 后台进程可直接调用, 无权限问题
import os, re, time, json, subprocess, ctypes
import ctypes.wintypes as wt

HERE = os.path.dirname(os.path.abspath(__file__))
PS_DIR = os.path.join(HERE, 'ps')

_user32 = ctypes.windll.user32
_gdi32 = ctypes.windll.gdi32

def _proto():
    u = _user32
    u.EnumWindows.argtypes = [ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM), wt.LPARAM]
    u.IsWindowVisible.argtypes = [wt.HWND]
    u.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
    u.GetWindowTextLengthW.argtypes = [wt.HWND]
    u.GetForegroundWindow.restype = wt.HWND
    u.IsIconic.argtypes = [wt.HWND]
    u.ShowWindow.argtypes = [wt.HWND, wt.INT]
    u.SetWindowPos.argtypes = [wt.HWND, wt.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wt.UINT]
    u.GetWindowRect.argtypes = [wt.HWND, ctypes.c_void_p]
    u.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
    u.GetWindowLongW.argtypes = [wt.HWND, ctypes.c_int]
    g = _gdi32
    return u, g

HWND_TOP = 0
HWND_NOTOPMOST = -2
HWND_TOPMOST = -1
GWL_EXSTYLE = -20
WS_EX_TOPMOST = 0x8
SWP_NOMOVE = 0x2
SWP_NOSIZE = 0x1
SW_RESTORE = 9

def list_windows(_=None):
    """枚举所有可见顶层窗口 (含被遮挡), 附 pid 与最小化状态"""
    u, g = _proto()
    result = []
    @ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    def cb(hwnd, lp):
        if not u.IsWindowVisible(hwnd):
            return True
        n = u.GetWindowTextLengthW(hwnd)
        if n <= 0:
            return True
        buf = ctypes.create_unicode_buffer(n + 1)
        u.GetWindowTextW(hwnd, buf, n + 1)
        title = buf.value.strip()
        if not title:
            return True
        pid = wt.DWORD(0)
        u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        mini = ' [最小化]' if u.IsIconic(hwnd) else ''
        result.append(f'#{hwnd} pid={pid.value} {title}{mini}')
        return True
    u.EnumWindows(cb, 0)
    if not result:
        return '(没有可见窗口)'
    return '\n'.join(result[:40])

def _find_hwnd(target):
    """按标题子串 / #hwnd / pid=N / 纯数字pid 找窗口 (跳过最小化)"""
    u, g = _proto()
    target = str(target).strip()
    if target.startswith('#'):
        try:
            hwnd = int(target[1:])
        except ValueError:
            return None, None
        n = u.GetWindowTextLengthW(hwnd)
        buf = ctypes.create_unicode_buffer(n + 1)
        u.GetWindowTextW(hwnd, buf, n + 1)
        return hwnd, buf.value
    pid_match = re.fullmatch(r'(?:pid=)?(\d+)', target)
    tl = target.lower()
    best = [None, '']
    @ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    def cb(hwnd, lp):
        if not u.IsWindowVisible(hwnd) or u.IsIconic(hwnd):
            return True
        n = u.GetWindowTextLengthW(hwnd)
        if n <= 0:
            return True
        buf = ctypes.create_unicode_buffer(n + 1)
        u.GetWindowTextW(hwnd, buf, n + 1)
        t = buf.value
        if pid_match:
            pid = wt.DWORD(0)
            u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value == int(pid_match.group(1)) and len(t) > len(best[1]):
                best[0] = hwnd; best[1] = t
            return True
        if tl in t.lower() and len(t) > len(best[1]):
            best[0] = hwnd; best[1] = t
        return True
    u.EnumWindows(cb, 0)
    return best[0], best[1]

def _clear_topmost_overlaps(target_hwnd, rect):
    """临时清除与目标相交的其他置顶窗口的 topmost (否则它们会盖住置顶后的目标), 返回恢复函数"""
    L, T, R, B = rect
    cleared = []
    @ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    def cb(hwnd, lp):
        try:
            if hwnd == target_hwnd or not _user32.IsWindowVisible(hwnd):
                return True
            ex = _user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
            if not (ex & WS_EX_TOPMOST):
                return True
            r = wt.RECT()
            if not _user32.GetWindowRect(hwnd, ctypes.byref(r)):
                return True
            if r.left < R and r.right > L and r.top < B and r.bottom > T:
                _user32.SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE)
                cleared.append(hwnd)
        except Exception:
            pass
        return True
    _user32.EnumWindows(cb, 0)
    def restore():
        for h in cleared:
            _user32.SetWindowPos(h, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE)
    return restore

def window_ocr(window=""):
    """找窗口 -> 置顶(可遮挡场景) -> 全屏截图裁剪 -> OCR -> 恢复原窗口 Z 序"""
    u, g = _proto()
    hwnd, title = _find_hwnd(window)
    if not hwnd:
        return "找不到窗口: " + str(window) + " (用 list_windows 查看所有窗口)"
    if u.IsIconic(hwnd):
        return f'窗口 "{title}" 处于最小化状态, 无法截取 (请先在电脑上还原它)'
    class RECT2(ctypes.Structure):
        _fields_ = [('L', ctypes.c_long), ('T', ctypes.c_long), ('R', ctypes.c_long), ('B', ctypes.c_long)]
    prev_fg = u.GetForegroundWindow()
    # 关键: 用 TOPMOST 带 (高于前台带) —— HWND_TOP 只到普通带顶部, 压不过前台窗口
    u.SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE)
    time.sleep(0.2)
    rc = RECT2()
    u.GetWindowRect(hwnd, ctypes.byref(rc))
    restore_topmost = _clear_topmost_overlaps(hwnd, (rc.L, rc.T, rc.R, rc.B))
    time.sleep(0.25)                                                      # 等 DWM 重绘
    import pyautogui
    img = pyautogui.screenshot()
    restore_topmost()
    u.SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE)   # 退出 topmost 带
    u.GetWindowRect(hwnd, ctypes.byref(rc))
    # 还原 Z 序: 把之前的前台窗口提回顶部
    if prev_fg and prev_fg != hwnd:
        u.SetWindowPos(prev_fg, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE)
    L = max(0, rc.L); T = max(0, rc.T)
    crop = img.crop((L, T, min(rc.R, img.width), min(rc.B, img.height)))
    if crop.width <= 0 or crop.height <= 0:
        return '窗口区域异常'
    png = os.path.join(os.environ.get('TEMP', '.'), f'wxocr_{int(time.time())}.png')
    crop.save(png)
    ps1 = os.path.join(PS_DIR, 'ocr.ps1')
    try:
        r = subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                            '-File', ps1, '-img', png], capture_output=True, timeout=40)
        out = r.stdout.decode('utf-8', errors='replace').strip()
    except subprocess.TimeoutExpired:
        out = 'OCR 超时'
    finally:
        try: os.remove(png)
        except Exception: pass
    if 'NO_OCR_ENGINE' in out:
        return '系统没有可用的 OCR 引擎 (需在 Windows 设置里安装中文语言包)'
    if not out.strip():
        return f'窗口 "{title}" OCR 没有识别到文字'
    out = re.sub(r'(?<=[\u4e00-\u9fff]) (?=[\u4e00-\u9fff])', '', out)   # CJK 字间空格清理
    return (f'窗口 "{title}" 的识别文字:\n' + out[:1500])

SCHEMAS = [
    {'type': 'function', 'function': {
        'name': 'list_windows',
        'description': '列出用户电脑当前所有可见窗口的标题、pid 和最小化状态 (含被遮挡的)。用户提到"某个窗口/程序/应用"时先调用这个; 程序 pid 也可用于 window_ocr。',
        'parameters': {'type': 'object', 'properties': {}, 'required': []}}},
    {'type': 'function', 'function': {
        'name': 'window_ocr',
        'description': '把某窗口置顶后截屏并 OCR 识别文字 (被遮挡也能用, 会短暂置顶窗口)。window 参数 = 窗口标题关键词、list_windows 里的 #编号 或 pid=进程号。',
        'parameters': {'type': 'object', 'properties': {
            'window': {'type': 'string', 'description': '窗口标题关键词 / #编号 / pid=进程号'}},
            'required': ['window']}}},
]
