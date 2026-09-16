# WXhook-fish — 微信 4.1.13.65 消息机器人研究工程

> Windows x64 · Weixin.dll 4.1.13.65 · 从只读监控到**纯自主发送**（零触发、零手工武装）。
>
> ⚠️ 仅供个人自动化与协议研究学习使用，请遵守当地法律法规与微信使用条款，勿用于骚扰、批量营销或任何违法用途。

## 里程碑

- [x] M1 注入验证：LoadLibrary / 反射注入主进程，微信无感知
- [x] M2 偏移发现：发送管线测绘（UI → UP2 → UP1 → CORE → CGI）
- [x] M3 原生发送原语：三段式调用 + flag 参数（0=本地入队，1=CGI 入网）
- [x] M4 **纯自主发送**：登录瞬间全自动武装 + 队列空闲自主派发，PC/移动端双达
- [x] M4.5 **接收捕获 + bot**：AddMsg protobuf 外部轮询（无密钥/无侵入）+ 指令 bot（/ping /cmd /screenshot），手机 /ping → 自动回复 pong 实测
- [x] M4.8 **热重载架构 (m4/)**：boot/payload 分离，RELOAD 换代零重启；预检器 + VEH 取证 + SafeRead（崩溃→报错）
- [ ] M5 图片发送：UP2+暂存覆盖已通，continuation 重放待解（见 docs M4 §40）
- [ ] M6 AI 接入：自然语言指令 → 工具执行 → 回传

## 一期架构（v71b 单体, 已归档至 m3/LEGACY）

```
[启动] Weixin.exe → 0.3s 内极速注入 wx_send_v65.dll（抢在自动登录 ~8s 前）

[登录瞬间: 全自动武装, 零用户动作]
  mgr 类构造函数钩（0x1788920 / 0x178B5B0，经 vtable 写入点扫描定位）
    → rcx = 会话发送管理器
  登录协程 TLS 链（TEB→slot12→+0x1F0→coro→+0x368）
    → 会话执行器 exec
  磁盘模板加载：template.bin（文本 0x798）/ image_template.bin（图片 0xA00）

[任意时刻: 队列自主发送]
  AUTO|目标|内容(b64) 排队
  → UP1 线程池空闲（10s 静默闸）→ WAITHOOK（0x7329A7C，调用点白名单）
  → CoCreate 派生协程（exec options+0x20）→ 异步执行
  → FactoryFlush：克隆模板 + 改写 会话/内容/新 clientMsgId → UP1(flag=1)
  → CGI 入网 → PC + 移动端双达，进程稳定
```

钩子清单：UP1（发送捕获/文本改写）、MGRCTOR×2（被动武装）、WAITHOOK（空闲触发）、PUMPHOOK（队列泵观测）、LOGOFF2。
注意：**CoCreate 页保持零接触**——保护者会对补丁页去执行化（详见 M4 文档 §34）。

## 当前架构（v98, m4/ + wxbot/）

```
wx_boot.dll   常驻层: 钩子/状态/队列/管道服务 (含 RELOAD 热重载)
wx_payload.dll 业务层: 消息克隆/预检/冲刷 (可热换代, 状态经 WxApi 读写)
rx_scan2.py   外部接收: AddMsg protobuf 轮询 (无密钥, 无侵入)
bot.py        指令 bot: 偏移量消费收件 → /ping /cmd /screenshot → 回复
driver.py     自动化验证: 注入→武装→发送→三重校验 (5/5 PASS)
```

迭代循环: 改 payload → 编译 → cp → wx_payload_incoming.dll → reload.py → driver.py （约 30 秒, 零重启）

## 一期仓库文件（自主发送成功链路的最小集）

```
hook-wx/
├── m3/src/wx_send_v65.c        # ★ 核心：全部钩子与自主发送逻辑（单文件，v65→v71b）
├── m3/m3_native_client.py      # 操作客户端：STATUS 状态总览 / AUTO 自主发送 / SEND 改写
├── m1/src/injector_main.c      # 注入器 CLI
├── m1/src/ReflectiveInject.c/.h # 反射注入核心（注入器侧）
├── m1/src/ReflectiveLoader.c/.h # 反射加载器（DLL 侧，编译时与主源一同编译）
└── docs/M4状态-自主发送攻坚.md  # ★ 全程战报：flag 参数→协程派生→被动武装→纯自主闭环
```

> 模板快照（template.bin / image_template.bin）与构建产物不入库：前者含会话数据且运行时自动重新捕获（首次注入后发一条消息即生成），后者由下方命令构建。

## 构建

```
toolchain/mingw64/bin/gcc -O2 -fms-extensions -shared \
    -o m3/bin/wx_send_v65.dll \
    m3/src/wx_send_v65.c m1/src/ReflectiveLoader.c
```

注入器（同目录源码）：

```bash
GCC="toolchain/mingw64/bin/gcc.exe"
cd m1/src
"$GCC" -O2 -o ../bin/wx_inject.exe injector_main.c ReflectiveInject.c
```

## 使用

```
m1/bin/wx_inject.exe <主进程pid> m3/bin/wx_send_v65.dll   # 微信启动后尽快注入（抢在登录前）
m3/m3_native_client.py STATUS                             # hits/rw/队列/武装状态总览
m3/m3_native_client.py AUTO filehelper "你好"              # 队列一条自主消息
m3/m3_native_client.py SEND filehelper "改写下一条"        # 触发式改写通道
```

## 关键经验（详见 docs/M4状态-自主发送攻坚.md）

| 主题 | 结论 |
|---|---|
| flag 参数 | UP1 第 4 参：0=本地入队（静默丢弃），1=完整 CGI 入网 |
| 协程派生 | CoCreate(exec options+0x20) + sched() 异步投递，冲刷代码必须跑在协程里 |
| 被动武装 | mgr/exec 无静态根、无 TLS 根，只能登录期构造钩捕获；模板磁盘缓存跨会话复用 |
| 模板克隆 | 文本模板跨会话可用（UP1 文本路径不 deref 陈旧指针）；图片路径会（§34 卡点与两条路线） |
| 字节校验 | 校验失败先 dump 双方；反汇编器输出是规范化形式，钩子期望字节必须取自磁盘原文 |
| 保护者 | CoCreate 页勿碰（诱饵写 + 去执行化）；全部内联钩子稳定，唯该页例外 |
