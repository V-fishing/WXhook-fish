# -*- coding: utf-8 -*-
# AI 大脑: 火山方舟 Ark (OpenAI 兼容, urllib 传输 — httpx 的 TLS 在本机被掐) + 工具循环
# key 在 ai_key.txt (不入库); "model" 字段支持模型名或 ep- 推理接入点 ID
import json, os, time
import urllib.request, urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(HERE, 'ai_key.txt')
MODEL_FILE = os.path.join(HERE, 'ai_model.txt')
BASE = 'https://ark.cn-beijing.volces.com/api/coding/v3'

import tools as _tools
TOOLS = _tools.SCHEMAS

SYSTEM = (
    '你是一个运行在用户 Windows 电脑上的 PC 助手, 通过微信与用户对话。'
    '用户在手机上发消息给你, 你在电脑端执行并回复。'
    '你可以调用 take_screenshot 截取屏幕并自动发给用户。'
    '回答用简体中文, 简洁口语化, 不要使用 markdown 标记。'
    '用户桌面路径: ' + _tools.DESKTOP + ' , 列目录/搜文件优先用绝对路径。'
    '【视觉/窗口任务决策协议, 按顺序】'
    '1) 先用工具自己查 (list_windows / read_window_text / window_ocr), 不要直接问用户;'
    '2) 能枚举出候选项 -> 用文字编号选项问用户 (回复数字即可);'
    '3) 候选无法用文字描述 (视觉歧义) -> 调 take_screenshot 发画面 + 文字编号选项一起问;'
    '4) 实在不行 -> 告诉用户需要 TA 到电脑前操作。'
    '永远不要只发截图不说话; 永远不要让用户回答你看不到的东西。'
)

def _key():
    try:
        with open(KEY_FILE, encoding='utf-8') as f:
            return f.read().strip()
    except Exception:
        return ''

def _model():
    try:
        with open(MODEL_FILE, encoding='utf-8') as f:
            m = f.read().strip()
            if m: return m
    except Exception:
        pass
    return ''

def _save_model(m):
    with open(MODEL_FILE, 'w', encoding='utf-8') as f:
        f.write(m)

def _post(body, timeout=90):
    req = urllib.request.Request(BASE + '/chat/completions',
        data=json.dumps(body).encode('utf-8'),
        headers={'Authorization': 'Bearer ' + _key(), 'Content-Type': 'application/json'})
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return 200, r.read().decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', errors='replace')
    except Exception as e:
        return 0, type(e).__name__ + ' ' + str(e)[:150]

def _call(messages, use_tools=True):
    """返回 (content, tool_calls, err)"""
    key = _key()
    if not key:
        return ('AI 未配置: 缺少 ai_key.txt', None, 'no key')
    model = _model()
    if not model:
        return ('AI 未配置模型: 请在 ai_model.txt 填入模型名或 ep- 接入点 ID', None, 'no model')
    body = {'model': model, 'messages': messages}
    if use_tools:
        body['tools'] = TOOLS
    code, text = _post(body)
    if code == 0:                       # 传输失败/超时: 重试一次
        code, text = _post(body)
    if code != 200:
        return ('AI 调用失败 HTTP %s: %s' % (code, text[:180]), None, text)
    d = json.loads(text)
    msg = d['choices'][0]['message']
    return (msg.get('content') or '', msg.get('tool_calls'), None)

def chat(user_text, history, dispatcher):
    """入口: 用户消息 + 历史 -> AI 回复文本。工具循环最多 3 轮。"""
    msgs = [{'role': 'system', 'content': SYSTEM}] + history[-12:] + [
        {'role': 'user', 'content': user_text}]
    for _ in range(5):
        content, calls, err = _call(msgs)
        if err:
            return content or ('AI 异常: ' + err)
        if not calls:
            return content or '(空回复)'
        msgs.append({'role': 'assistant', 'content': content or '', 'tool_calls': calls})
        for c in calls:
            fn = c.get('function', {})
            name = fn.get('name', '')
            args_json = fn.get('arguments', '{}')
            print('[AI] tool:', name, str(args_json)[:80], flush=True)
            try:
                result = dispatcher(name, args_json)
            except Exception as e:
                result = '工具执行异常: ' + str(e)[:120]
            msgs.append({'role': 'tool', 'tool_call_id': c.get('id', ''), 'content': str(result)})
    return '(工具循环超限)'
