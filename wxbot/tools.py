# -*- coding: utf-8 -*-
# AI 工具集: schema 定义 + 实现 + 注册表
# 安全等级: 绿灯(只读/启动) —— AI 可自主调用; 黄灯(写操作)后续加确认机制
import os, subprocess, ctypes, ctypes.wintypes as wt, shutil, json, time
import winvision

HERE = os.path.dirname(os.path.abspath(__file__))

# ---- 实现 ----

READONLY_CMDS = ('tasklist', 'dir', 'ipconfig', 'netstat', 'systeminfo',
                 'whoami', 'hostname', 'ver', 'where', 'getmac', 'ping', 'nslookup')

def run_command(command):
    """白名单只读命令"""
    c = command.strip()
    first = c.split()[0].lower() if c.split() else ''
    if first not in READONLY_CMDS:
        return '拒绝: 命令不在只读白名单 (' + ', '.join(READONLY_CMDS) + ')'
    try:
        r = subprocess.run(c, shell=True, capture_output=True, timeout=20)
        out = r.stdout.decode('gbk', errors='replace') or r.stderr.decode('gbk', errors='replace')
        return out[:1500] if out else '(无输出)'
    except subprocess.TimeoutExpired:
        return '(超时 20s)'

def _shell_folder(name):
    """真实外壳文件夹路径 (支持用户重定向, 如桌面在 E 盘)"""
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                           r'Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders')
        v, _ = winreg.QueryValueEx(k, name)
        winreg.CloseKey(k)
        return os.path.expandvars(v)
    except Exception:
        return os.path.join(os.path.expanduser('~'), name)

DESKTOP = _shell_folder('Desktop')
DIR_ALIASES = {'桌面': DESKTOP, 'desktop': DESKTOP, '下载': _shell_folder('{374DE290-123F-4565-9164-39C4925E467B}'),
               '文档': _shell_folder('Personal'), '图片': _shell_folder('My Pictures'), '音乐': _shell_folder('My Music')}

def _resolve_dir(p):
    p = p.strip()
    base = p.replace(chr(92), '/').split('/')[-1].lower() if p else ''
    if p.lower() in DIR_ALIASES: return os.path.expanduser(DIR_ALIASES[p.lower()])
    if base in DIR_ALIASES: return os.path.expanduser(DIR_ALIASES[base])
    return p

def list_files(path=''):
    p = _resolve_dir(path) or DESKTOP
    p = os.path.expandvars(os.path.expanduser(p))
    if not os.path.isdir(p):
        return '目录不存在: ' + p
    items = []
    try:
        for name in sorted(os.listdir(p))[:60]:
            fp = os.path.join(p, name)
            tag = '[D] ' if os.path.isdir(fp) else '[F] '
            size = ''
            if os.path.isfile(fp):
                sz = os.path.getsize(fp)
                size = f' {sz//1024}KB' if sz >= 1024 else f' {sz}B'
            items.append(tag + name + size)
        if not items:
            return p + ' : 目录存在但为空'
        return (p + '\n' + '\n'.join(items))[:1500]
    except Exception as e:
        return '读取失败: ' + str(e)

def search_files(name, path=''):
    base = _resolve_dir(path) or DESKTOP
    base = os.path.expandvars(os.path.expanduser(base))
    name_l = name.lower()
    found = []
    t0 = time.time()
    for root, dirs, files in os.walk(base):
        if time.time() - t0 > 10:
            break
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for f in files:
            if name_l in f.lower():
                found.append(os.path.join(root, f))
                if len(found) >= 20:
                    break
        if len(found) >= 20:
            break
    return '\n'.join(found) if found else '未找到 (搜了 10 秒, 最多 20 条)'

def read_file(path, max_chars=2000):
    p = os.path.expandvars(os.path.expanduser(path.strip()))
    if not os.path.isfile(p):
        return '文件不存在: ' + p
    try:
        with open(p, 'rb') as f:
            raw = f.read(max_chars * 2)
        for enc in ('utf-8', 'gbk'):
            try:
                return raw.decode(enc)[:max_chars]
            except Exception:
                continue
        return raw.decode('utf-8', errors='replace')[:max_chars]
    except Exception as e:
        return '读取失败: ' + str(e)

def get_clipboard():
    user32 = ctypes.windll.user32
    user32.OpenClipboard.argtypes = [wt.HWND]
    user32.GetClipboardData.argtypes = [wt.UINT]
    user32.GetClipboardData.restype = wt.HANDLE
    if not user32.OpenClipboard(None):
        return '(剪贴板被占用)'
    try:
        h = user32.GetClipboardData(13)   # CF_UNICODETEXT
        if not h:
            return '(剪贴板无文本)'
        k32 = ctypes.windll.kernel32
        k32.GlobalAlloc.argtypes = [wt.UINT, ctypes.c_size_t]
        k32.GlobalAlloc.restype = wt.HGLOBAL
        k32.GlobalLock.argtypes = [wt.HGLOBAL]
        k32.GlobalLock.restype = ctypes.c_void_p
        k32.GlobalUnlock.argtypes = [wt.HGLOBAL]
        user32.CloseClipboard.argtypes = []
        p = k32.GlobalLock(h)
        if not p:
            return '(锁定失败)'
        try:
            s = ctypes.wstring_at(p, 4096).split('\x00')[0]
            return s[:1500] if s else '(空)'
        finally:
            k32.GlobalUnlock(h)
    finally:
        user32.CloseClipboard()

def system_info(_=None):
    total, used, free = shutil.disk_usage('C:/')
    mem = ctypes.create_string_buffer(64)
    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [('dwLength', wt.DWORD), ('dwMemoryLoad', wt.DWORD),
                    ('ullTotalPhys', ctypes.c_uint64), ('ullAvailPhys', ctypes.c_uint64),
                    ('ullTotalPageFile', ctypes.c_uint64), ('ullAvailPageFile', ctypes.c_uint64),
                    ('ullTotalVirtual', ctypes.c_uint64), ('ullAvailVirtual', ctypes.c_uint64),
                    ('ullAvailExtendedVirtual', ctypes.c_uint64)]
    ms = MEMORYSTATUSEX(); ms.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
    up_h = ctypes.windll.kernel32.GetTickCount64() // 3600000
    return (f'磁盘C: 剩余 {free//(1<<30)}GB / {total//(1<<30)}GB\n'
            f'内存: 已用 {ms.dwMemoryLoad}% (剩 {ms.ullAvailPhys//(1<<30)}GB)\n'
            f'开机时长: 约 {up_h} 小时')

APPS = {'记事本': 'notepad', '计算器': 'calc', '画图': 'mspaint', 'notepad': 'notepad',
        'calc': 'calc', 'explorer': 'explorer', 'chrome': 'chrome', 'edge': 'msedge'}

def open_app(name):
    n = name.strip().lower()
    exe = APPS.get(n, n)
    try:
        subprocess.Popen(['cmd', '/c', 'start', '', exe], shell=True,
                         creationflags=subprocess.CREATE_NO_WINDOW)
        return '已启动: ' + exe
    except Exception as e:
        return '启动失败: ' + str(e)

def take_screenshot_stub(_=None):
    return '截图由 bot 层注册'

# ---- 注册表 ----
_REGISTRY = {
    'run_command': run_command,
    'list_files': list_files,
    'search_files': search_files,
    'read_file': read_file,
    'get_clipboard': get_clipboard,
    'system_info': system_info,
    'open_app': open_app,
    'take_screenshot': take_screenshot_stub,   # bot 启动时覆盖注册
    'list_windows': winvision.list_windows,
    'window_ocr': winvision.window_ocr,
}

def register(name, fn):
    _REGISTRY[name] = fn

SCHEMAS = [
    {'type': 'function', 'function': {
        'name': 'run_command',
        'description': '在用户电脑上执行只读命令 (白名单: tasklist/dir/ipconfig/netstat/systeminfo/whoami/hostname/ver/where/getmac/ping/nslookup)。查询进程、网络、系统信息时使用。',
        'parameters': {'type': 'object', 'properties': {
            'command': {'type': 'string', 'description': '要执行的命令, 如 tasklist'}},
            'required': ['command']}}},
    {'type': 'function', 'function': {
        'name': 'list_files',
        'description': '列出用户电脑某目录下的文件和文件夹。path 为空时默认桌面。',
        'parameters': {'type': 'object', 'properties': {
            'path': {'type': 'string', 'description': '目录路径, 如 C:/Users 或桌面'}},
            'required': []}}},
    {'type': 'function', 'function': {
        'name': 'search_files',
        'description': '按文件名在用户电脑上搜索文件 (默认从桌面开始, 最多 20 条)。',
        'parameters': {'type': 'object', 'properties': {
            'name': {'type': 'string', 'description': '文件名关键词'},
            'path': {'type': 'string', 'description': '搜索起始目录, 可空'}},
            'required': ['name']}}},
    {'type': 'function', 'function': {
        'name': 'read_file',
        'description': '读取用户电脑上的文本文件内容 (前 2000 字符)。',
        'parameters': {'type': 'object', 'properties': {
            'path': {'type': 'string', 'description': '文件完整路径'}},
            'required': ['path']}}},
    {'type': 'function', 'function': {
        'name': 'get_clipboard',
        'description': '读取用户电脑当前的剪贴板文本内容。',
        'parameters': {'type': 'object', 'properties': {}, 'required': []}}},
    {'type': 'function', 'function': {
        'name': 'system_info',
        'description': '获取用户电脑的系统状态: 磁盘剩余空间、内存占用、开机时长。',
        'parameters': {'type': 'object', 'properties': {}, 'required': []}}},
    {'type': 'function', 'function': {
        'name': 'open_app',
        'description': '在用户电脑上启动一个应用程序, 如 notepad/calc/chrome 或中文应用名。',
        'parameters': {'type': 'object', 'properties': {
            'name': {'type': 'string', 'description': '应用名'}},
            'required': ['name']}}},
    {'type': 'function', 'function': {
        'name': 'take_screenshot',
        'description': '截取电脑当前屏幕画面并自动发送到用户的微信。当用户想看屏幕、桌面、验证操作结果时调用。',
        'parameters': {'type': 'object', 'properties': {}, 'required': []}}},
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

def execute(name, args_json):
    """AI 工具调用分发: 参数为 JSON 字符串"""
    fn = _REGISTRY.get(name)
    if not fn:
        return '未知工具: ' + name
    try:
        args = json.loads(args_json) if args_json else {}
    except Exception:
        args = {}
    if not isinstance(args, dict):
        args = {}
    try:
        return str(fn(**args))
    except TypeError as e:
        return '参数错误: ' + str(e)
    except Exception as e:
        return '执行异常: ' + str(e)[:150]
