# -*- coding: utf-8 -*-
"""WeChatHook 框架最小测试 —— 由 ZCode 生成"""
import sys
import os

# 用你下载的本地框架
FW = r'E:\weixin-hook-4.1.8\WeChatHook-lyx102-patch-1 (2)\WeChatHook-lyx102-patch-1'
sys.path.insert(0, FW)

from wxhook import Bot
from wxhook import events

print('=' * 60)
print('  WeChatHook 测试启动')
print('  - 自动启动微信 3.9.5.81 并注入 wxhook.dll')
print('  - 版本伪装目标: 3.9.12.17')
print('=' * 60)


def on_start(bot: Bot):
    print('>>> 微信客户端已启动,请二维码扫码登录...')


def on_login(bot: Bot, event):
    print('')
    print('#' * 60)
    print('#  登录成功!!! 版本伪装生效了!')
    print('#' * 60)
    print('')


bot = Bot(
    faked_version="3.9.12.17",   # 版本伪装:解除低版本限制
    on_start=on_start,
    on_login=on_login,
)


@bot.handle(events.TEXT_MESSAGE)
def on_message(bot: Bot, event):
    print('>>> 收到消息:', event)
    try:
        bot.send_text("filehelper", "hello from wxhook - 链路测试成功!")
        print('>>> 已向文件传输助手发送测试消息')
    except Exception as e:
        print('>>> 发送失败:', e)


print('>>> 启动中...(如果弹出 UAC 请允许)')
bot.run()
