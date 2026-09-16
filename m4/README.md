# m4 — v98 热重载架构 (bootstrap / payload 分离)

- `wx_api.h`     bootstrap <-> payload 共享 ABI (状态指针 + 队列操作 + 处理器表)
- `wx_boot.c`    常驻层: 钩子安装与桩、全部持久状态、队列、管道服务 (AUTO/SEND/AIMG/STATUS/RELOAD)
- `wx_payload.c` 业务层: 消息克隆/预检/冲刷/配置, 经 WxApi 读写状态; 可 RELOAD 热替换

构建 (MinGW-w64 x64):
```
gcc -O2 -fms-extensions -shared -o wx_boot.dll   wx_boot.c   ../m1/src/ReflectiveLoader.c
gcc -O2 -fms-extensions -shared -o wx_payload.dll wx_payload.c
```

部署: wx_inject 注入 wx_boot.dll → 自动加载 wx_payload.dll (gen0)。
迭代: 改 payload → 编译 → 复制为 wx_payload_incoming.dll → 管道发 RELOAD → gen+1 生效, 零重启。

注: template.bin / image_template.bin 为运行时从本机会话捕获的模板 (含账号相关数据), 不入库;
    首次真实发送时自动活体捕获并落盘 (路径见源码 TPL_PATH/IMG_TPL_PATH)。
