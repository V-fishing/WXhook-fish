# WXhook-fish — 微信 4.1.13.65 消息机器人研究工程

> Windows x64 · Weixin.dll 4.1.13.65 · 从只读监控到**纯自主发送**（零触发、零手工武装）的完整逆向工程记录与实现。
>
> ⚠️ 仅供个人自动化与协议研究学习使用，请遵守当地法律法规与微信使用条款，勿用于骚扰、批量营销或任何违法用途。

## 里程碑（全部完成）

- [x] M0 情报：RevokeHook 反射注入框架精读（`docs/M0笔记-RevokeHook源码精读.md`）
- [x] M1 注入验证：LoadLibrary / 反射注入 4.1.13.65 主进程，微信无感知（2026-09-13）
- [x] M2 偏移发现：发送管线测绘（UI → UP2 → UP1 → CORE → CGI，`docs/M2成果-发送管线测绘.md`）
- [x] M3 原生发送原语：三段式调用 + flag 参数（本地入队 vs CGI 入网），触发式发送/改写（`docs/M3成果-原生发送原语.md`）
- [x] M4 **纯自主发送**：登录瞬间全自动武装 + 队列空闲自主派发，PC/移动端双达（`docs/M4状态-自主发送攻坚.md` §1-34）

## 最终架构（v71b）

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
注意：**CoCreate 页保持零接触**——保护者会对补丁页去执行化（M4 §34 实测）。

## 目录结构

```
hook-wx/
├── docs/                        # 全程逆向笔记与战报（核心阅读）
├── m1/                          # 注入验证（wx_inject.exe 注入器 + ReflectiveLoader）
├── m2/                          # 监控/改写期脚本与管线测绘工具
├── m3/                          # ★ 自主发送主工程
│   ├── src/wx_send_v65.c        #   全部钩子与逻辑（单文件，v65→v71b 演进）
│   ├── patch_v6x/v7x*.py        #   逐版本源码补丁脚本（演进历史）
│   ├── parse_dmp.py 等          #   崩溃取证 / 内存侦察 / 调用图分析
│   ├── m3_native_client.py      #   管道客户端（STATUS / SEND / AUTO）
│   └── template.bin 等          #   运行时模板快照（已 gitignore，运行时自动重新捕获）
├── phase1-tools/                # PE/补丁/扫描通用小工具箱
├── tests/                       # wxhook 框架对接测试
├── thirdparty/RevokeHook/       # 反射注入框架来源
└── toolchain/ ghidra_project/   # （gitignore）MinGW 工具链 / Ghidra 工程
```

## 构建

```
toolchain/mingw64/bin/gcc -O2 -fms-extensions -shared \
    -o m3/bin/wx_send_v65.dll \
    m3/src/wx_send_v65.c m1/src/ReflectiveLoader.c
```

M1 注入器编译（已验证命令）：

```bash
GCC="toolchain/mingw64/bin/gcc.exe"
cd m1/src
"$GCC" -O2 -static -shared -DREFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR \
    -o ../bin/wx_probe.dll wx_probe.c ReflectiveLoader.c
"$GCC" -O2 -o ../bin/wx_inject.exe injector_main.c ReflectiveInject.c
"$GCC" -O2 -o ../bin/wx_inject_lib.exe inject_lib.c     # LoadLibrary 路线(推荐)
```

## 使用

```
m1/bin/wx_inject.exe <主进程pid> m3/bin/wx_send_v65.dll   # 启动后尽快注入（抢在登录前）
m3/m3_native_client.py STATUS                             # hits/rw/队列/武装状态总览
m3/m3_native_client.py AUTO filehelper "你好"              # 队列一条自主消息
m3/m3_native_client.py SEND filehelper "改写下一条"        # 触发式改写通道
```

## 关键经验（详见 M4 文档）

| 主题 | 结论 |
|---|---|
| flag 参数 | UP1 第 4 参：0=本地入队（静默丢弃），1=完整 CGI 入网 |
| 协程派生 | CoCreate(exec options+0x20) + sched() 异步投递，冲刷代码必须跑在协程里 |
| 模板克隆 | 文本模板跨会话可用（UP1 文本路径不 deref 陈旧指针）；图片路径会（§34 卡点） |
| 字节校验 | 校验失败先 dump 双方；反汇编器输出是规范化形式，钩子期望字节必须取自磁盘原文 |
| 保护者 | CoCreate 页勿碰（诱饵写 + 去执行化）；mgr/exec 无静态根，只能登录期构造钩捕获 |
