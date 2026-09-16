# wxbot — 微信 4.1.13.65 手机↔PC 自动化机器人

微信 Windows 4.1.13.65 的读写一体 bot：手机发指令 → PC 捕获 → 执行 → 回传结果。
无需数据库密钥，不依赖微信 UI 可见，锁屏可用。

## 架构 (v98)

```
                    ┌──────────────── 常驻层 ────────────────┐
手机/脚本 → 管道 AUTO|target|b64 → wx_boot.dll                       │
                    │   解码 → AUTO 队列 (状态: exec/mgr/模板)       │
                    │   ↓ 池空闲触发                                │
                    │   POnIdle → CoCreate 派生 → FactoryFlush      │
                    │   克隆+预检 → UP1 → PC+手机 双达              │
                    └────────── RELOAD ──┬───────────────────────┘
                                         ▼
                    ┌──────────────── 业务层 (可热换) ─────────┐
                    │ wx_payload_g<N>.dll                      │
                    │   克隆/预检/冲刷/配置  经 WxApi 读写状态  │
                    └──────────────────────────────────────────┘

收侧 (外部, 零侵入):
手机消息 → 微信堆 AddMsg protobuf → rx_scan2.py (RPM 轮询, 出现沿触发)
        → received_text.txt (追加: ts|target|content) → bot.py (偏移量消费) → 管道

验证: driver.py --full  = 微信检查→注入→武装等待→发token→三重校验→PASS/FAIL
迭代: 编译 payload → cp → reload.py → driver  (全程零重启)
```

### 关键设计
- **boot/payload 分层**: 状态永驻 boot; payload 换代不丢武装, 旧代码不卸载 (在途调用安全), 旧线程 stopEvent 优雅退出
- **预检器**: 克隆体进 UP1 前校验 vtable/目标/内容/UUID, 不合格拒绝调用 (崩溃→报错)
- **VEH 取证**: 自身代码段 AV 精确记录 RIP/出错地址/读写类型
- **SafeRead**: 批量内存扫描用 RPM 自读, 内核处理缺页竞态
- **SSO 兼容**: 短文本 (≤15B) 内联存储的正确读写
- **出现沿触发**: 收侧按 "本轮有/上轮无" 判定新消息, 缓冲区驻留不重复触发

## 已验证状态 (2026-09-16)

- ✅ 全链路: 手机 `/ping` → 自动回复 `pong`
- ✅ 热重载: gen0→1→2 连续换代零重启, 武装不丢
- ✅ 自动登录下的延迟注入 (exec 三路捕获: MGRCTOR/PUMP/任意发送)
- ⏳ 图片: UP2+暂存覆盖已通, continuation 重放待解 (M4 §40)

## 文件结构

```
bot.py            bot 主循环: 偏移量消费 received_text.txt → 指令 → 回复
rx_scan2.py       接收捕获: AddMsg protobuf → received_text.txt (追加队列)
reload.py         触发热重载 (RELOAD 管道命令)
driver.py         自动化测试驱动 (--inject --full)
writer.py         写侧包装 (注入/状态/AUTO/SEND 管道命令)
status.py / auto_test.py  管道查询 / 发送测试
bin/
  wx_inject.exe   反射注入器
  wx_boot.dll     常驻层 (源码: ../hook-wx/m4/wx_boot.c)
  wx_payload.dll  业务层当前版 (源码: ../hook-wx/m4/wx_payload.c)
  wx_payload_incoming.dll   热重载投放位
  wx_payload.conf 配置 (staged_dir 等)
last_text.txt     DLL 写: 最近一次流经 UP1 的文本 (PC 发出)
received_text.txt rx_scan2 写: 收到的消息 (追加, ts|target|content)
decrypt/          DB 解密工具链 (当前版本微信无法提取密钥, 备查)
tools_archive/    逆向诊断脚本存档
```

## 使用

```bash
# 0. 部署 (源码改动后先重编 ../hook-wx/m4): 启动微信后立即注入
bin/wx_inject.exe auto "bin\wx_boot.dll"

# 1. 启动接收捕获 (微信登录后运行)
python rx_scan2.py

# 2. 启动 bot
python bot.py

# 3. 手机端给文件传输助手发:
/ping          → pong
/help          → 指令列表
/screenshot    → 截取 PC 桌面发回
/cmd <命令>    → 执行命令回传输出

# 日常迭代 (改 payload 后):
#   重编 payload → cp bin\wx_payload.dll → wx_payload_incoming.dll → python reload.py → python driver.py
```

## 对标 wxhelper 的进度

| 能力 | wxhelper | 本项目 |
|---|---|---|
| 发文本/emoji (自主) | ✔ API | ✔ 管道, 双端可达 |
| 收消息 hook | ✔ | ✔ 外部 protobuf 轮询 (无侵入) |
| 发图片 | ✔ | UP2+暂存覆盖已通, continuation 重放待解 |
| 指令 bot | ✘ | ✔ |
ai_key.txt
