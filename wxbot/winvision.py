# -*- coding: utf-8 -*-
# 窗口视觉层: 窗口枚举 / UIA 文本提取 / PrintWindow 截窗 + WinRT OCR
# 被遮挡的窗口: UIA 和 PrintWindow 都可读 (DWM 保留渲染表面); 最小化不行
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
    u.PrintWindow.argtypes = [wt.HWND, wt.HDC, wt.UINT]
    u.GetWindowDC.argtypes = [wt.HWND]
    u.GetWindowDC.restype = wt.HDC
    u.ReleaseDC.argtypes = [wt.HWND, wt.HDC]
    u.GetWindowRect.argtypes = [wt.HWND, ctypes.c_void_p]
    g = _gdi32
    g.CreateCompatibleDC.argtypes = [wt.HDC]
    g.CreateCompatibleDC.restype = wt.HDC
    g.CreateCompatibleBitmap.argtypes = [wt.HDC, ctypes.c_int, ctypes.c_int]
    g.CreateCompatibleBitmap.restype = wt.HBITMAP
    g.SelectObject.argtypes = [wt.HDC, wt.HGDIOBJ]
    g.GetDIBits.argtypes = [wt.HDC, wt.HBITMAP, wt.UINT, wt.UINT, ctypes.c_void_p, ctypes.c_void_p, wt.UINT]
    g.DeleteDC.argtypes = [wt.HDC]
    g.DeleteObject.argtypes = [wt.HGDIOBJ]

def list_windows(_=None):
    """枚举所有可见顶层窗口 (含被遮挡), 标注最小化"""
    _proto()
    result = []
    @ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    def cb(hwnd, lp):
        if not _user32.IsWindowVisible(hwnd):
            return True
        n = _user32.GetWindowTextLengthW(hwnd)
        if n <= 0:
            return True
        buf = ctypes.create_unicode_buffer(n + 1)
        _user32.GetWindowTextW(hwnd, buf, n + 1)
        title = buf.value.strip()
        if not title:
            return True
        mini = ' [最小化]' if _user32.IsIconic(hwnd) else ''
        result.append(f'#{hwnd} {title}{mini}')
        return True
    _user32.EnumWindows(cb, 0)
    if not result:
        return '(没有可见窗口)'
    return '\n'.join(result[:40])

def _find_hwnd(target):
    """按标题子串或 #hwnd 找窗口; 返回 (hwnd, title) 或 (None, None)"""
    _proto()
    target = str(target).strip()
    if target.startswith('#'):
        try:
            hwnd = int(target[1:])
        except ValueError:
            return None, None
        n = _user32.GetWindowTextLengthW(hwnd)
        buf = ctypes.create_unicode_buffer(n + 1)
        _user32.GetWindowTextW(hwnd, buf, n + 1)
        return hwnd, buf.value
    tl = target.lower()
    best = [None, '']
    @ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    def cb(hwnd, lp):
        if not _user32.IsWindowVisible(hwnd) or _user32.IsIconic(hwnd):
            return True
        n = _user32.GetWindowTextLengthW(hwnd)
        if n <= 0:
            return True
        buf = ctypes.create_unicode_buffer(n + 1)
        _user32.GetWindowTextW(hwnd, buf, n + 1)
        t = buf.value
        if tl in t.lower() and len(t) > len(best[1]):
            best[0] = hwnd; best[1] = t
        return True
    _user32.EnumWindows(cb, 0)
    return best[0], best[1]

def read_window_text(window=""):
    """UIA 提取窗口内文本 (被遮挡也能读)"""
    hwnd, title = _find_hwnd(window)
    if not hwnd:
        return '找不到窗口: ' + str(window) + ' (用 list_windows 查看所有窗口)'
    ps1 = os.path.join(PS_DIR, 'uia_dump.ps1')
    try:
        r = subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                            '-File', ps1, '-hwnd', str(hwnd)],
                           capture_output=True, timeout=25)
        out = r.stdout.decode('utf-8', errors='replace').strip()
    except subprocess.TimeoutExpired:
        return 'UIA 提取超时 (窗口元素过多)'
    if not out:
        return f'窗口 "{title}" 没有可提取的文本 (UIA 无暴露, 建议改用 window_ocr)'
    lines = [l for l in out.splitlines() if l.strip()]
    return (f'窗口 "{title}" 的文本内容:\n' + '\n'.join(lines[:80]))[:2000]

def window_ocr(window=""):
    """PrintWindow 截窗口 (可被遮挡) + Windows OCR"""
    _proto()
    hwnd, title = _find_hwnd(window)
    if not hwnd:
        return '找不到窗口: ' + str(window) + ' (用 list_windows 查看所有窗口)'
    if _user32.IsIconic(hwnd):
        return f'窗口 "{title}" 处于最小化状态, 无法截取 (请先在电脑上还原它)'
    class RECT2(ctypes.Structure):
        _fields_ = [('L', ctypes.c_long), ('T', ctypes.c_long), ('R', ctypes.c_long), ('B', ctypes.c_long)]
    rc = RECT2()
    _user32.GetWindowRect(hwnd, ctypes.byref(rc))
    w, h = rc.R - rc.L, rc.B - rc.T
    if w <= 0 or h <= 0 or w > 8000 or h > 8000:
        return '窗口尺寸异常'
    hdc = _user32.GetWindowDC(hwnd)
    mem = _gdi32.CreateCompatibleDC(hdc)
    bmp = _gdi32.CreateCompatibleBitmap(hdc, w, h)
    _gdi32.SelectObject(mem, bmp)
    ok = _user32.PrintWindow(hwnd, mem, 2)   # PW_RENDERFULLCONTENT
    class BMIH(ctypes.Structure):
        _fields_ = [('biSize', wt.DWORD), ('biWidth', ctypes.c_long), ('biHeight', ctypes.c_long),
                    ('biPlanes', wt.WORD), ('biBitCount', wt.WORD), ('biCompression', wt.DWORD),
                    ('biSizeImage', wt.DWORD), ('biXPelsPerMeter', ctypes.c_long),
                    ('biYPelsPerMeter', ctypes.c_long), ('biClrUsed', wt.DWORD), ('biClrImportant', wt.DWORD)]
    bi = BMIH(); bi.biSize = ctypes.sizeof(BMIH); bi.biWidth = w; bi.biHeight = -h
    bi.biPlanes = 1; bi.biBitCount = 32; bi.biCompression = 0
    buf = ctypes.create_string_buffer(w * h * 4)
    _gdi32.GetDIBits(mem, bmp, 0, h, buf, ctypes.byref(bi), 0)
    _gdi32.DeleteDC(mem); _gdi32.DeleteObject(bmp)
    _user32.ReleaseDC(hwnd, hdc)
    if not ok:
        return 'PrintWindow 失败'
    sample = buf.raw[:min(len(buf.raw), 200000):64]
    if sum(sample) < 3:
        return f'窗口 "{title}" 截取得到了黑屏 (硬件加速渲染), 建议 read_window_text 或让用户处理'
    from PIL import Image
    img = Image.frombuffer('RGB', (w, h), buf.raw, 'raw', 'BGRX', 0, 1)
    png = os.path.join(os.environ.get('TEMP', '.'), f'wxocr_{int(time.time())}.png')
    img.save(png)
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
    out = re.sub(r'(?<=[一-鿿]) (?=[一-鿿])', '', out)
    return (f'窗口 "{title}" 的识别文字:\n' + out[:1800])

SCHEMAS = [
    {'type': 'function', 'function': {
        'name': 'list_windows',
        'description': '列出用户电脑当前所有可见窗口的标题 (含被遮挡的), 标注是否最小化。用户提到"某个窗口/程序/应用"时先调用这个。',
        'parameters': {'type': 'object', 'properties': {}, 'required': []}}},
    {'type': 'function', 'function': {
        'name': 'read_window_text',
        'description': '提取某窗口内的文本内容 (UIA 接口, 被遮挡也能读)。window 参数 = 窗口标题关键词或 list_windows 里的 #编号。记事本/浏览器/Office 等效果好。',
        'parameters': {'type': 'object', 'properties': {
            'window': {'type': 'string', 'description': '窗口标题关键词或 #编号'}},
            'required': ['window']}}},
    {'type': 'function', 'function': {
        'name': 'window_ocr',
        'description': '截取某窗口画面并 OCR 识别其中的文字 (被遮挡也能截, 最小化不行)。适合 UIA 提取不到文本的窗口。',
        'parameters': {'type': 'object', 'properties': {
            'window': {'type': 'string', 'description': '窗口标题关键词或 #编号'}},
            'required': ['window']}}},
]
