// ==== wx_api.h: bootstrap <-> payload 共享 ABI (v98 热重载架构) ====
// bootstrap: 常驻 (钩子/状态/队列/管道); payload: 业务逻辑, 可 RELOAD 热替换
// 约定: 状态全部在 bootstrap, payload 通过 api 指针读写; 旧 payload 永不卸载 (代码常驻)
#pragma once
#include <windows.h>

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;
typedef struct { void* obj; void* ctrl; } SP;

#define QCAP 16
typedef struct { int targetLen, contentLen, flags; char target[128], content[2048]; } Cmd;

// vtable RVA (payload 预检/克隆用)
#define VT_RVA          0x8BDF0F8ULL
#define IMGVT_RVA       0x8E6BCE8ULL
#define IMG_CAP_SIZE    0x1400

typedef struct WxApi {
    // 代际
    DWORD   gen;
    HANDLE  stopEvent;              // signaled: payload 线程应退出

    // ---- bootstrap 服务 ----
    void  (*Log)(const char* s);
    void  (*LogHex)(const char* s, u64 v);
    void  (*LogBytes)(const char* s, const unsigned char* b, int n);

    // ---- bootstrap 状态 (指针传递, payload 直读直写) ----
    unsigned char** ppBase;         // Weixin.dll 基址
    volatile u64*   pSessExec;      // 会话 exec
    void* volatile* ppMgr2;         // mgr
    volatile u64*   pSavedSPPtr;    // 会话 SP
    unsigned char** ppTemplateObj;  // 文本消息模板 (0x798)
    unsigned char** ppImgTemplate;  // 图片消息模板 (+0x9A0 文件名影子)
    volatile u64*   pImgVtRva;
    volatile u64*   pUp1Tick;       // 最近 UP1 时刻 (静默闸)
    volatile DWORD* pTid2;          // UP1 线程 id
    volatile u64*   pHits;
    volatile u64*   pRw;
    volatile LONG*  pBusy2;         // 空闲冲刷互斥
    volatile u64*   pStubRsp;       // UP1 入口 rsp
    unsigned char*  pTplBuf;        // 磁盘文本模板缓冲 (bootstrap 持有, payload 只读比对)
    unsigned char*  pImgTplBuf;     // 磁盘图片模板缓冲

    // ---- 队列操作 (bootstrap 持锁) ----
    BOOL (*QPushA)(const Cmd* c);
    BOOL (*QPopA)(Cmd* o);
    BOOL (*QPopS)(Cmd* o);
    BOOL (*QPushS)(const Cmd* c);
    BOOL (*QEmptyA)(void);

    // ---- payload 提供的处理器 (stub 经 thunk 调用, RELOAD 时整体换表) ----
    void (*onUp1)(struct WxApi* api, void* p3, u64 flag);   // UP1 钩子: 消息对象业务
    void (*onIdle)(struct WxApi* api, u64 retaddr);         // 池空闲: AUTO 冲刷
    // 注: 收侧捕获在外部 rx_scan2.py (protobuf 轮询); DLL 内 RXCTOR 因保护页无法安装, 已移除
} WxApi;
