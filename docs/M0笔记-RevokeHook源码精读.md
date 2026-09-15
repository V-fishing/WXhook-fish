# M0 情报笔记:RevokeHook 源码精读
## —— 4.x hook 的完整方法论提取(二期 B 轨 M0 交付物)

> 源码:EEEEhex/RevokeHook(cloned 2026-09-13,含 Linux 分支)
> 用途:为"4.1.13.65 发送消息"项目提取可复用的方法、算法与代码模板

---

## 一、项目全景(87 文件,三大件)

```
RevokeHook/
├── RevokeHookUI/          ← C#/WPF 偏移搜索工具(自动搜偏移的引擎!)
│   └── Services/
│       ├── SignatureSearchService.cs   ⭐ 特征码搜索引擎(Sunday 算法)
│       ├── CallChainSearchService.cs   ⭐ 调用链搜索
│       ├── CloudConfigService.cs       ⭐ 云端特征码配置(版本自适应!)
│       └── Config3Service.cs
├── RevokeInject/          ← C++ 注入器
│   └── ReflectiveInject.c             ⭐ 反射注入(抹特征)
├── RevokeHook/RevokeHook/ ← 注入后的 Hook DLL(779行 dllmain + VEH 框架)
│   ├── dllmain.cpp       ⭐⭐⭐ 运行时自学习(本笔记核心)
│   ├── vehbp.cpp/.h      ⭐⭐ VEH+INT3 断点框架(64断点/TLS单步跟踪/回调系统)
│   └── ReflectiveLoader.c ⭐ 反射加载器
├── IdaScript/             ← IDA 脚本: destring.py(字符串解密) + emulate.py(模拟执行)
├── Config.json            ← ⭐⭐ 37个版本的偏移搜索配方(4.0.3 → 4.1.7.57)
└── Linux/                 ← Linux 版(含 injector_so/sigbp.c)
```

**关键文章**:[微信4.0防撤回+提醒 (符号恢复+字符串解密)](https://bbs.kanxue.com/thread-286611.htm)(看雪,作者亲述)

---

## 二、核心方法论:它是怎么"追版本"的(最值钱的部分)

### 2.1 三层解耦:特征码 → 运行时自学习 → 结构体偏移

作者的聪明之处:**Config.json 里存的不是函数偏移,而是"搜索配方"**:

```json
"4.1.7.57": {
    "sig1": "48 83 EC ?? 4C ?? ?? 48 ?? ?? C6 44 24 ?? 00 4D ?? ?? 49 ?? ?? E8 ...",
    "sig2": "48 8D 55 ?? 45 31 C0 E8 ...",
    "sig1_delta": 0, "sig2_delta": 24,
    "sig1_rsize": 12, "sig2_rsize": 5,
    "arg_pos": 3,
    "srvid_offset": 192, "revokemsg_offset": 280
}
```

- **sig1/sig2**:带 `??` 通配的机器码特征(Sunday 算法在 Weixin.dll 文件上搜)
- **delta**:特征命中位置 → 目标函数入口的字节差
- **arg_pos / srvid_offset / revokemsg_offset**:消息对象的结构体布局
- 最新版"云端配置"**只存加密字符串的特征码**,偏移完全运行时推导(见 2.2)

**对我们的意义**:4.1.13.65 比它的最新配置(4.1.7.57)更新——sig1 自 4.1.4 起未变,
sig2 每 2-3 版变一次。**用它的搜索引擎跑 4.1.13,大概率 sig1 直接命中,sig2 需按
同方法重新推导**——推导方法作者已完全开源。

### 2.2 运行时自学习(dllmain.cpp 的精髓)

断点命中后(VEH 回调 `OnTargetHit`),**不靠硬编码,现场探测结构**:

```cpp
// ① 断点命中 → 拿寄存器上下文
uint64_t rip = ctx->Rip;
// ② 候选参数(Rdx/R8/R9 = 第2/3/4参数)
uint64_t candidates[] = { ctx->Rdx, ctx->R8, ctx->R9 };
// ③ 在"参数指向的内存"里找已知字符串(撤回消息必含"撤回"/"recalled")
revoke_xml = FindStdStringWithSig(candidates[c], 0x2000, revoke_sig, ...);
// ④ 命中 → 自动记录: 第几个参数是消息XML + 结构内偏移
g_config_info.delmsg_info.arg_msg_index = candidate_indices[c];
g_config_info.delmsg_info.offset_revoke_xml = (int)(revoke_xml - candidates[c]);
```

`FindStdStringWithSig` = **通用"std::string 内容定位"原语**(SSO 感知):
扫内存找 `{size∈(16,0x10000], capability≥size, data_ptr 可读}` 的字符串对象,
再在堆数据里 memcmp 特征。**这个原语可以直接搬到我们的发送函数发现里**
(把"撤回"特征换成"接收者 wxid"/"消息内容"特征)!

### 2.3 偏移搜索引擎(SignatureSearchService.cs)

- **Sunday 算法**(字符串快速搜索)在 **Weixin.dll 磁盘文件**上跑带 `??` 通配的字节模式
- 输出 `SignatureMatch{BaseOffset, AdjustedOffset, PreviewHex}` → 填 Config
- **纯文件级搜索,不需要进程在运行** → 我们可以先离线搜 4.1.13 的 Weixin.dll!

---

## 三、VEH 断点框架(vehbp.cpp,264 行,可直接复用)

| 特性 | 实现 |
|---|---|
| 容量 | 64 个断点,每个含 `address/originalByte/callback/active/enabled` |
| 机制 | INT3(0xCC)+ VEH 派发 + **TLS 跟踪单步状态**(每线程独立) |
| 流程 | WriteByte(强制可写→写0xCC→还原保护+FlushInstructionCache)→ 命中 → VEH 回调 → TLS 标记单步 → 恢复原字节 → TF → 单步异常里重装 0xCC |
| 回调签名 | `void callback(PCONTEXT ctx, PEXCEPTION_RECORD)` → 直接读寄存器/改参数! |
| 评价 | **生产级质量**(线程安全/失败回滚/性能考虑),比我们一期的调试器脚本优雅得多 |

**对发送项目的意义**:这是"运行时参数探测"的现成基础设施——
在候选发送函数装 BP → 回调里检查参数是否含目标 wxid/内容 → 自动确认函数语义。

---

## 四、注入方式:反射注入(ReflectiveInject.c)

- `ReflectiveLoader.c`:经典反射加载(手动映射 PE 到目标进程,不走 LoadLibrary)
- README:"自动反射注入 Hook 逻辑到微信进程中,**并抹去部分特征**"
- 注入器还能**自动启动微信**、支持 `-w` 指定微信目录
- Linux 版用 `injector_so` + `sigbp.c`(ptrace 路线)

**对照我们原计划**:蓝图写的"ilink2.dll 代理劫持"与 RevokeHook 的"反射注入+抹特征"
是两条都经过实战的路线。**决策:先试 RevokeHook 的反射注入**(代码现成、已验证),
ilink2 代理作为备选(它的代理生成在 UI 工具里,可后期提取)。

---

## 五、字符串解密(4.x 的隐藏前提)

微信 4.x 把关键字符串**加密存储**(静态搜不到明文"撤回"等)→ RevokeHook 的解法:
- `IdaScript/destring.py`:IDA 里批量解密字符串
- `IdaScript/emulate.py`:模拟执行解密函数
- DLL 运行时:直接在**已解密的内存**里搜(运行时字符串必然是明文!)

**对我们的影响**:静态找"发送函数"前,要么先跑 destring 拿到明文地址做锚点,
要么用 2.2 的"运行时搜索"(更简单,推荐)。

---

## 六、移植到我们项目的适配清单(发送函数发现的具体做法)

| 步骤 | 复用 RevokeHook 的 | 我们的动作 |
|---|---|---|
| 1. 锚点函数 | sig1/sig2 找 DelMsg 的方法 | 同方法找 4.1.13 的 DelMsg(验证管线工作) |
| 2. 相邻分析 | 调用图(CallChainSearchService) | 从 DelMsg 所在模块向上/向下找 SendText 同族函数 |
| 3. 运行时确认 | vehbp + FindStdStringWithSig | BP 装在候选函数 → 手动发消息 → 参数里找"filehelper"+"内容" |
| 4. 结构学习 | OnTargetHit 的 arg 探测模式 | 自动学习: 哪个参数=wxid / 哪个=content / ChatMsg 大小 |
| 5. 调用复刻 | — | wxhelper 三段式(本地源码) + 4.x 实测参数 |
| 6. 版本追踪 | Config.json 配方模式 | 每版本存"配方"而非偏移,云端/本地均可 |

**关键差异提醒**:RevokeHook 的目标是 DelMsg(撤回,单参数流),我们的是
SendText(8 参数,含 ChatMsg 定长栈对象 0x460)——运行时探测要复杂一档,
但 wxhelper 源码给了我们**精确的参数模式先验**,搜索空间大幅缩小。

---

## 七、M0 结论与 M1 建议

### 结论
1. **方法全部开源可得**:特征码搜索(Sunday)/运行时自学习/VEH 框架/反射注入——
   四大件 RevokeHook 全有生产级实现,我们的工作量 = **组装 + 面向"发送"的适配**;
2. **37 个版本的配方史**证明了"特征码追版本"模式可持续(4.1.4→4.1.7 sig1 未变!);
3. **注入路线修正**:优先采用 RevokeHook 的反射注入(而非 ilink2 劫持),
   ilink2 代理降为备选——少写一个转发层;
4. 4.1.13 比项目最新配置(4.1.7.57)新——**首个任务 = 用其搜索引擎为 4.1.13 生成配方**,
   这本身就是对"偏移发现管线"的第一次实战演练。

### M1 调整(注入验证)
- ~~自研 ilink2 代理~~ → **直接编译 RevokeHook 的 RevokeInject + 我们的空 DLL**,
  反射注入到 4.1.13 → 验证:微信正常/无提示/通信通 → M1 达成
- 空 DLL 先只做三件事:日志文件、列 Weixin.dll 基址、HTTP 心跳

---

*笔记:ZCode · 2026-09-13 · 源码位置 `C:\Users\fish\Downloads\RevokeHook\`*
