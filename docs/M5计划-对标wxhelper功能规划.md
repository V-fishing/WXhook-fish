# M5 计划 — 对标 wxhelper 功能规划

> 参照项目: [ttttupup/wxhelper](https://github.com/ttttupup/wxhelper) (main 分支, 目标 3.8.0.41~3.9.5.81, VS2022)。
> 本规划: 将我们的 4.1.13.65 工程从"纯自主文本发送"扩展到对标其功能面。

## 一、代差约束 (为什么不能照抄实现)

| 维度 | wxhelper (3.9.x) | 我们 (4.1.13.65) | 约束 |
|---|---|---|---|
| 发送管理器 | `kGetSendMessageMgr` 每次调用获取 | 无静态入口 | 只能登录期构造钩被动捕获 (已解决) |
| 发送调用 | 8 参数高层 Call, 栈缓冲即可 | UP1 需完整 0x798 消息对象 | 高层 Call 思路可借鉴, 需按 4.1 重新定位 |
| 调用上下文 | 任意线程裸调 | 必须协程内 | 所有发送/写操作统一走 CoCreate 派生 (已解决) |
| 收流钩子 | Detours 挂 DoAddMsg (入库前) | 未做 | 4.1 需重找入库函数 |
| 偏移组织 | 每版本一个分支 + offset 表 | 固定版本 + 动态扫描 (vtable 写入点) | 我们的抗漂移方案更适配 4.x |

**wxhelper 3.9 的图片发送先例** (印证 M4 §34 路线 B):
```
NewChatMsg(栈缓冲) → GetSendMessageMgr → SendImageMsg(msg, to, image_path, temp, 1,1,0,0) → FreeChatMsg
```
高层 Call 直收**文件路径**, 暂存/上传全在内部 —— 4.1 大概率存在同类函数, 这就是路线 B 要找的目标。

**收流钩子先例**: Detours 挂 DoAddMsg (消息**落库前**统一拦截, 非网络层), 字段从 param2 偏移读
(fromUser=+0x18, toUser=+0x28, content=+0x30, type=+0x24, msgId=+0x60), JSON 后 HTTP 回调。
我们 M5 在 4.1 找"消息落库"对应函数即可复用该模式。

## 二、功能对照总表

| wxhelper 功能 | 4.1 对应方案 | 状态 | 难度 | 期 |
|---|---|---|---|---|
| CheckLogin | 被动武装成功即已登录 (mgr≠0) | ✅ 顺带 | 易 | P0 |
| SendTextMsg | 克隆模板 + UP1(flag=1) | ✅ 已达成 | — | P0 收编 |
| SendAtText | 文本 + @XML 组装 (需群成员列表) | 待做 | 中 | P2 |
| SendImageMsg | 路线 B: 定位高层 SendImage (先例已证) | 侦察完毕 | 中高 | P1 |
| SendFileMsg | 同族 (type 6), 与图片同路线 | 待做 | 中高 | P1 |
| SendCustomEmotion | 贴纸库 CDN (md5 索引) | 待做 | 高 | P4 |
| ForwardMsg / ForwardPublicMsg | 消息转发 (依赖收流 msgId) | 待做 | 中 | P3 |
| 收消息 hook | 4.1 消息落库函数定位 + Detour/Inline 钩 | 待做 | 中 | P1 ★ |
| CheckLogin/GetSelfInfo | 自身 wxid: 内存/DB 提取 (phase1 有解密基础) | 待做 | 中 | P3 |
| GetContacts / GetContactByWxid | DB 直读 (解密库已有) | 待做 | 中 | P3 |
| 群管理 (成员/增删/昵称) | 群服务层 Call 定位 | 待做 | 高 | P4 |
| SetTopMsg / RemoveTopMsg / AddFavFromMsg | 消息操作服务层 | 待做 | 中 | P4 |
| DoDownloadTask (图片/文件下载) | 下载任务服务层 | 待做 | 中 | P4 |
| GetSNSFirstPage / NextPage | 朋友圈接口 | 远期 | 高 | P5 |
| DecodeImage (dat 解码) | phase1 已有同源能力 | 库内 | 易 | P3 |
| GetVoiceByDB / DoOCRTask | 语音导出 / OCR | 远期 | 高 | P5 |
| DB 解密/查询 | phase1 解密管线已有 | 库内 | 易 | P3 |
| HTTP 服务 (19088) | 见下"架构决策" | 决策项 | — | P0 |

## 三、架构决策

1. **协议 v2 (P0)**: 管道协议从"首字符分派"升级为 **长度前缀 + JSON**:
   - 请求: `{"cmd":"send_text","target":"filehelper","msg":"你好"}`
   - 响应: `{"code":0,"data":{...}}`
   - **主动推送**: 收消息事件由管道主动下行 (对接收回调), 客户端长驻读事件流。
   - 旧首字符协议保留为兼容层 (SEND/AUTO/STATUS 不变)。
2. **Manager 函数表 (P0)**: wx_send_v65.c 拆出 `struct WxApi { const char* name; int (*fn)(json req, json resp); }` 注册表;
   每个写操作统一经 `SpawnOnExec(fn, ctx)` 协程派生 (现有机制), 读操作 (DB/内存) 可直读。
3. **HTTP 层决策**: 不在微信进程内起 HTTP 服务 (暴露端口 + 保护者风险)。
   替代: 进程外 python 转发器 `http_bridge.py` (127.0.0.1:19088 → 管道), 兼容 wxhelper 的调用习惯。
4. **版本指纹 (P0)**: INIT 时校验 Weixin.dll 大小 + 两个特征字节 (UP1 前导/构造函数 lea),
   不匹配则拒绝武装并打日志 —— 防微信更新后错位。

## 四、分期路线

- **P0 基础设施** (1 轮): 协议 v2 + Manager 注册表 + 版本指纹 + CheckLogin/STATUS 升级。
- **P1 收发闭环 ★** (1-2 轮): 收消息钩 (定位 4.1 落库函数 → 钩 → JSON 推送) + 图片/文件发送 (路线 B 定位高层 Call)。
  完成即达成 wxhelper 最核心的两件事: 收到消息、发出媒体。
- **P2 扩展发送**: @消息 (依赖群成员)、贴纸。含 SendAtText 的 XML 组装。
- **P3 数据层**: 联系人/群列表 (DB 直读)、自身信息、转发、下载、dat 解码、HTTP 桥。
- **P4/P5 远期**: 群管理写操作、消息置顶/收藏、SNS、OCR、语音导出。

## 五、风险与对策 (承 M4)

- CoCreate 页零接触原则不变; 新钩子一律先做诱雷窗 (+10..16) 排查。
- 图片克隆 stale 指针 → 路线 B 的高层 Call 若找到则绕开克隆; 找不到再做自包含模板 v2 (§34 路线 A)。
- 微信升级: 版本指纹拒绝武装 (fail-safe), 偏移重新扫描 (vtable lea 扫描可自动化)。
