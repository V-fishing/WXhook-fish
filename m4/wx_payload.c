// ==== wx_payload.c: payload —— 业务逻辑层 (v98) ====
// 经 WxApi 读写 bootstrap 状态; RELOAD 时整体替换; 旧线程收到 stopEvent 后退出
#include "wx_api.h"
#include <string.h>

static WxApi* g_api;

// ---- 状态访问宏 (与 m3 单体同名, 函数体近乎逐字迁移) ----
#define g_base          (*(unsigned char**)g_api->ppBase)
#define g_mgr2          (*g_api->ppMgr2)
#define g_sessExec      (*g_api->pSessExec)
#define g_savedSPPtr    (*g_api->pSavedSPPtr)
#define g_templateObj   (*g_api->ppTemplateObj)
#define g_imgTemplate   (*g_api->ppImgTemplate)
#define g_imgVtRva      (*g_api->pImgVtRva)
#define g_hits          (*g_api->pHits)
#define g_rw            (*g_api->pRw)
#define g_tid2          (*g_api->pTid2)
#define g_up1Tick       (*g_api->pUp1Tick)
#define g_busy2         (*g_api->pBusy2)
#define g_stubRsp       (*g_api->pStubRsp)

// ---- 日志 (转 api) ----
static void LogL(const char* s) { g_api->Log(s); }
static void LogHex(const char* s, u64 v) { g_api->LogHex(s, v); }
static void LogBytes(const char* s, const unsigned char* b, int n) { g_api->LogBytes(s, b, n); }

// ---- 工具 (自包含) ----
static int WrFresh(unsigned char* obj, u64 off, const char* data, int len) {
    unsigned char* p = obj + off;
    if (len > 4000) return 0;
    u64 newCap = (u64)len | 0xF;
    if (newCap < 0x16) newCap = 0x16;
    unsigned char* nb = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)(newCap + 1));
    if (!nb) return 0;
    for (int i = 0; i < len; i++) nb[i] = (unsigned char)data[i];
    nb[len] = 0;
    *(unsigned char**)p = nb;
    *(u64*)(p + 0x10) = (u64)len;
    *(u64*)(p + 0x18) = newCap;
    return 2;
}
static int WrWide(unsigned char* obj, u64 off, const wchar_t* data, int wlen) {
    unsigned char* p = obj + off;
    u64 newCap = (u64)wlen | 0xF;
    if (newCap < 0x16) newCap = 0x16;
    unsigned char* nb = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)(newCap * 2 + 2));
    if (!nb) return 0;
    for (int i = 0; i < wlen; i++) {
        nb[i*2] = (unsigned char)(data[i] & 0xFF);
        nb[i*2+1] = (unsigned char)(data[i] >> 8);
    }
    nb[wlen*2] = 0; nb[wlen*2+1] = 0;
    *(unsigned char**)p = nb;
    *(u64*)(p + 0x10) = (u64)wlen;
    *(u64*)(p + 0x18) = newCap;
    return 2;
}
static unsigned int g_rnd = 0;
static void GenUuid(char out[37]) {
    if (!g_rnd) g_rnd = (unsigned int)GetTickCount64() ^ 0x9E3779B9u;
    unsigned char b[16];
    for (int i = 0; i < 16; i++) { g_rnd ^= g_rnd << 13; g_rnd ^= g_rnd >> 17; g_rnd ^= g_rnd << 5; b[i] = (unsigned char)g_rnd; }
    b[6] = (unsigned char)((b[6] & 0x0F) | 0x40); b[8] = (unsigned char)((b[8] & 0x3F) | 0x80);
    static const char hx[] = "0123456789abcdef";
    static const int dash[16] = {0,0,0,0,1,0,0,0,2,0,0,0,3,0,0,0};
    int p = 0;
    for (int i = 0; i < 16; i++) { if (dash[i]) out[p++] = '-'; out[p++] = hx[b[i] >> 4]; out[p++] = hx[b[i] & 0xF]; }
    out[p] = 0;
}

// ---- 常量 ----
#define UP1_RVA         0x1790970ULL
#define COCREATE_RVA    0x45FCC0ULL
#define SCHED_RVA       0x45FF50ULL
#define ARG1_CTOR_RVA   0x185E570ULL
#define COMPOSER_RVA    0x19D14C0ULL
#define POOL_WAIT_RET   0x73225D1ULL
#define POOL_WAIT_RET2  0x732D872ULL
#define TLS_CURCORO_OFF 0x1F0
#define TLS_INDEX_RVA   0xB5D6A70
typedef void (*UP1_fn)(void*, void*, void*, int);
typedef void (*CoCreateFn)(SP* out, void* P2, void* P3, void* P4, void* P5);
typedef void (*SchedFn)(SP* sp, u64 val);

// payload 本地状态 (reload 丢失可重捕)
static unsigned char g_compBuf[0x1800];
static volatile LONG g_compArmed = 0;
// 配置 (wx_payload.conf: key=value; 缺省=当前账号实测值)
static char g_stagedDir[600] = "D:/xwechat_files/wxid_yahr9o9txwt722_1cda/temp/RWTemp/2026-09/9e20f478899dc29eb19741386f9343c8";
static char g_stagedMonth[300] = "2026-09";

static void LoadConf(void) {
    HANDLE f = CreateFileA("E:\\weixin-hook-4.1.8\\wxbot\\bin\\wx_payload.conf", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) { LogL("[CONF] no conf file, using defaults"); return; }
    static char buf[2048];
    DWORD r = 0;
    ReadFile(f, buf, sizeof(buf) - 1, &r, NULL);
    CloseHandle(f);
    buf[r] = 0;
    char* ctxLine = 0;
    for (char* line = strtok_s(buf, "\r\n", &ctxLine); line; line = strtok_s(0, "\r\n", &ctxLine)) {
        char* eq = 0;
        for (char* s = line; *s; s++) if (*s == '=') { eq = s; break; }
        if (!eq) continue;
        *eq = 0;
        char* val = eq + 1;
        if (0 == lstrcmpA(line, "staged_dir")) { lstrcpynA(g_stagedDir, val, (int)sizeof(g_stagedDir) - 1); LogL("[CONF] staged_dir set"); }
        else if (0 == lstrcmpA(line, "staged_month")) { lstrcpynA(g_stagedMonth, val, (int)sizeof(g_stagedMonth) - 1); }
    }
}

// ==== 预检器 (v97) ====
static BOOL StrFieldOk(unsigned char* obj, u64 off) {
    if (IsBadReadPtr((const void*)(ULONG_PTR)obj, off + 0x20)) return FALSE;
    u64 sptr = *(u64*)(obj + off);
    u64 ssize = *(u64*)(obj + off + 0x10);
    u64 scap = *(u64*)(obj + off + 0x18);
    if (ssize == 0 || ssize > 0x4000) return FALSE;
    const void* p;
    if (scap < ssize || scap <= 15) p = (const void*)(ULONG_PTR)obj;
    else { if (sptr < 0x10000) return FALSE; p = (const void*)(ULONG_PTR)sptr; }
    return !IsBadReadPtr(p, (SIZE_T)ssize);
}
static BOOL CloneSanity(unsigned char* clone, u64 vtExpect, const char* tag) {
    u64 vt = *(u64*)(ULONG_PTR)clone;
    BOOL vtOk = (vt == vtExpect);
    BOOL b0   = StrFieldOk(clone, 0xB0);
    BOOL c758 = StrFieldOk(clone, 0x758);
    BOOL u6f8 = StrFieldOk(clone, 0x6F8);
    BOOL ok = vtOk && b0 && c758 && u6f8;
    if (ok) { LogL(tag); LogL("[PRECHECK] ok"); return TRUE; }
    LogL(tag); LogL("[PRECHECK] FAIL - refuse UP1");
    LogHex("  vtable=", vt); LogHex("  expect=", vtExpect);
    LogL(b0 ? "  +0xB0 ok" : "  +0xB0 BAD");
    LogL(c758 ? "  +0x758 ok" : "  +0x758 BAD");
    LogL(u6f8 ? "  +0x6F8 ok" : "  +0x6F8 BAD");
    return FALSE;
}

// ==== 图片自主发送 ====
static void ImageFlush(Cmd* a) {
    if (!g_mgr2) { LogL("[IMG] not armed"); return; }
    char name[48];
    for (int i = 0; i < 44; i++) name[i] = (char)g_imgTemplate[0x9A0 + i];
    name[44] = 0;
    {
        // 从 staged_dir 逐级建目录链 (config: D:/.../<account>/temp/RWTemp/<month>/<hash>)
        char tmp[600]; lstrcpynA(tmp, g_stagedDir, (int)sizeof(tmp) - 1);
        for (char* s = tmp + 3; *s; s++) {          // 跳过盘符 "D:/"
            if (*s == '/') {
                char keep = *s; *s = 0;
                CreateDirectoryA(tmp, NULL);
                *s = keep;
            }
        }
    }
    char staged[600];
    wsprintfA(staged, "%s/%s", g_stagedDir, name);
    if (!CopyFileA(a->content, staged, FALSE)) { LogL("[IMG] stage copy fail"); return; }
    LogL("[IMG] staged overwritten");
    unsigned char* abase = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1400 + 0x20);
    if (!abase) return;
    unsigned char* clone = abase + 0x10;
    memcpy(clone, g_imgTemplate, 0x1400);
    *(u64*)(clone + 0x00) = (u64)(ULONG_PTR)g_base + IMGVT_RVA;
    *(u32*)(abase + 0x08) = 0x10000;
    *(u32*)(abase + 0x0C) = 0x10000;
    *(u64*)(clone + 0x08) = (u64)(ULONG_PTR)clone;
    *(u64*)(clone + 0x10) = (u64)(ULONG_PTR)abase;
    {
        int wlen = MultiByteToWideChar(CP_UTF8, 0, a->content, a->contentLen, NULL, 0);
        if (wlen > 0 && wlen < 1024) {
            wchar_t* wp = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)(wlen * 2 + 2));
            if (wp) {
                MultiByteToWideChar(CP_UTF8, 0, a->content, a->contentLen, wp, wlen);
                WrWide(clone, 0x120, wp, wlen);
                HeapFree(GetProcessHeap(), 0, wp);
            }
        }
    }
    {
        char au[37]; GenUuid(au);
        WrFresh(clone, 0x6F8, au, 36);
    }
    *(u64*)(clone + 0x1A8) = (u64)(ULONG_PTR)(g_imgTemplate + 0x9A0);
    if (!CloneSanity(clone, (u64)(ULONG_PTR)g_base + IMGVT_RVA, "[IMGFLUSH] sanity")) { HeapFree(GetProcessHeap(), 0, abase); return; }
    unsigned char* arg1 = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x100);
    if (!arg1) return;
    typedef void (*Arg1CtorFn)(void*);
    Arg1CtorFn ctorfn = (Arg1CtorFn)(g_base + ARG1_CTOR_RVA);
    LogL("[IMG] calling arg1 ctor");
    ctorfn(arg1);
    LogL("[IMG] arg1 ctor ok");
    void* elem[2] = {clone, abase};
    *(u64*)(arg1 + 0x08) = (u64)(ULONG_PTR)elem;
    *(u64*)(arg1 + 0x10) = (u64)(ULONG_PTR)(elem + 2);
    *(u64*)(arg1 + 0x18) = (u64)(ULONG_PTR)(elem + 2);
    LogL("[IMG] arg1 vector set");
    typedef void (*CompFn)(void*);
    CompFn comp = (CompFn)(g_base + COMPOSER_RVA);
    LogL("[IMG] calling composer");
    comp(arg1);
    LogL("[IMG] composer returned");
    g_rw++;
}

// ==== 自主发送 ====
static void FactoryFlush(Cmd* a) {
    unsigned char* clone = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x798);
    if (!clone) { LogL("[CLONE] alloc fail"); return; }
    if (!g_templateObj) { HeapFree(GetProcessHeap(), 0, clone); return; }
    memcpy(clone, g_templateObj, 0x798);
    *(u64*)(ULONG_PTR)clone = (u64)(ULONG_PTR)g_base + VT_RVA;
    WrFresh(clone, 0x758, a->content, a->contentLen);
    if (a->targetLen > 0) WrFresh(clone, 0xB0, a->target, a->targetLen);
    char au[37]; GenUuid(au);
    WrFresh(clone, 0x6F8, au, 36);
    if (!CloneSanity(clone, (u64)(ULONG_PTR)g_base + VT_RVA, "[CLONE] sanity")) { HeapFree(GetProcessHeap(), 0, clone); return; }
    void* csp[2] = {clone, NULL};
    UP1_fn up1f = (UP1_fn)(g_base + UP1_RVA);
    u64 fout[2] = {0, 0};
    up1f(g_mgr2, fout, (void*)csp, 1);
    LogL("[CLONE] UP1 returned");
    g_rw++;
}

static void __fastcall FlushBodyForCo(void* arg) {
    Cmd* a = (Cmd*)arg;
    if (!a) return;
    if (a->flags == 4) { LogL("[CORO] image flush begin"); ImageFlush(a); LogL("[CORO] image flush done"); return; }
    LogL("[CORO] clone flush begin");
    FactoryFlush(a);
    LogL("[CORO] clone flush done");
}

static void SpawnAutoFlush(void) {
    CoCreateFn cocreate = (CoCreateFn)(g_base + COCREATE_RVA);
    SchedFn sched = (SchedFn)(g_base + SCHED_RVA);
    Cmd a;
    while (g_api->QPopA(&a)) {
        if (!g_sessExec) { LogL("[SPAWN] no exec"); break; }
        Cmd* hc = (Cmd*)HeapAlloc(GetProcessHeap(), 0, sizeof(Cmd));
        if (!hc) break;
        *hc = a;
        static void* bh = 0; if (!bh) bh = (void*)&FlushBodyForCo;
        void* ah = (void*)hc;
        static void* ch = 0;
        SP sp2;
        unsigned char opts[0x40];
        memset(opts, 0, sizeof(opts));
        *(u64*)(opts + 0x20) = g_sessExec;
        *(int*)(opts + 0x38) = -1;
        cocreate(&sp2, (void*)bh, (void*)ah, (void*)ch, opts);
        if (!sp2.obj) { LogL("[SPAWN] fail"); HeapFree(GetProcessHeap(),0,hc); continue; }
        sched(&sp2, 0);
        LogL("[SPAWN] scheduled");
        g_rw++;
    }
}

// ==== UP1 业务 (原 C_helper, 逐字迁移) ====
static void POnUp1(WxApi* api, void* p3, u64 flag) {
    (void)api; (void)flag;
    g_hits++;
    g_tid2 = GetCurrentThreadId();
    g_up1Tick = GetTickCount64();
    void** sp = (void**)p3;
    if (!sp) return;
    unsigned char* obj = (unsigned char*)sp[0];
    if (!obj) return;
    {
        static LONG vtn = 0;
        if (InterlockedIncrement((volatile LONG*)&vtn) <= 10) {
            LogHex("[VT] obj=", (u64)(ULONG_PTR)obj);
            LogHex("[VT] vt=", *(u64*)obj);
        }
    }
    if (*(void**)obj != (void*)((u64)g_base + VT_RVA)) {
        if (!g_compArmed) {
                {
                    u64 w = g_stubRsp;
                    if (w) {
                        MEMORY_BASIC_INFORMATION mbi90;
                        u64 limit = w + 0x6000;
                        if (VirtualQuery((LPCVOID)w, &mbi90, sizeof(mbi90))) {
                            u64 stop = (u64)(ULONG_PTR)mbi90.BaseAddress + mbi90.RegionSize;
                            if (w + 0x6000 > stop - 0x40) limit = stop - 0x40;
                        }
                        u64 vtTarget = (u64)(ULONG_PTR)g_base + 0x8EF3198ULL;
                        u64 arg1 = 0;
                        for (u64 off = 0; w + off < limit && !arg1; off += 8) {
                            u64 v = *(u64*)(w + off);
                            if (v > 0x10000 && v < 0x7fffffffffff && (v & 7) == 0 &&
                                !IsBadReadPtr((const void*)(ULONG_PTR)v, 0x40)) {
                                if (*(u64*)(ULONG_PTR)v == vtTarget) arg1 = v;
                            }
                        }
                        if (arg1) {
                            unsigned char* B = g_compBuf;
                            for (int i = 0; i < 0x40; i++) B[i] = ((unsigned char*)(ULONG_PTR)arg1)[i];
                            u64 begin = *(u64*)(B + 8);
                            u64 end = *(u64*)(B + 0x10);
                            u64 span = (end > begin && end - begin <= 0x100) ? (end - begin) : 0x10;
                            if (!IsBadReadPtr((const void*)(ULONG_PTR)begin, (SIZE_T)span)) {
                                for (u64 i = 0; i < span; i++) B[0x40 + i] = ((unsigned char*)(ULONG_PTR)begin)[i];
                            }
                            u64 obj2 = *(u64*)(B + 0x40);
                            u64 ctrl2 = *(u64*)(B + 0x48);
                            if (obj2 && !IsBadReadPtr((const void*)(ULONG_PTR)obj2, 0x1400)) {
                                for (int i = 0; i < 0x1400; i++) B[0x140 + i] = ((unsigned char*)(ULONG_PTR)obj2)[i];
                            }
                            if (ctrl2 && !IsBadReadPtr((const void*)(ULONG_PTR)ctrl2, 0x20)) {
                                for (int i = 0; i < 0x20; i++) B[0x1540 + i] = ((unsigned char*)(ULONG_PTR)ctrl2)[i];
                            }
                            u64 nptr = *(u64*)(B + 0x140 + 0x1A8);
                            if (nptr && !IsBadReadPtr((const void*)(ULONG_PTR)nptr, 0x30)) {
                                for (int i = 0; i < 0x30; i++) B[0x1760 + i] = ((unsigned char*)(ULONG_PTR)nptr)[i];
                            }
                            InterlockedExchange((volatile LONG*)&g_compArmed, 1);
                            LogL("[CAP] arg1 graph armed");
                        } else {
                            LogL("[CAP] arg1 not found on stack");
                            if (!IsBadReadPtr((const void*)(ULONG_PTR)w, 0x400)) {
                                for (int off = 0; off < 0x400; off += 0x40) {
                                    LogBytes("[STACK] ", (const unsigned char*)(ULONG_PTR)(w + off), 0x40);
                                }
                            }
                        }
                    }
                }
        }
        {
            static BOOL g_imgArmed = FALSE;
            if (!g_imgArmed) {
            u64 vt = *(u64*)obj;
            g_imgVtRva = vt - (u64)(ULONG_PTR)g_base;
            if (!g_imgTemplate) g_imgTemplate = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, IMG_CAP_SIZE);
            if (g_imgTemplate) {
                g_imgArmed = TRUE;
                memcpy(g_imgTemplate, obj, IMG_CAP_SIZE);
                LogL("[IMG] template captured");
                LogHex("[IMG] vtable RVA=", g_imgVtRva);
                LogHex("[IMG] obj=", (u64)(ULONG_PTR)obj);
                {
                    u64 fnptr = *(u64*)(obj + 0x1A8);
                    if (fnptr) memcpy(g_imgTemplate + 0x9A0, (const void*)fnptr, 0x60);
                }
                HANDLE f = CreateFileA("E:\\weixin-hook-4.1.8\\hook-wx\\m4\\image_template.bin", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
                if (f != INVALID_HANDLE_VALUE) { DWORD w = 0; WriteFile(f, g_imgTemplate, IMG_CAP_SIZE, &w, NULL); CloseHandle(f); LogL("[IMG] saved to disk"); }
            }
            }
        }
        return;
    }

    // 文本捕获 (SSO 兼容)
    {
        static LONG diagN = 0;
        u64 cptr = *(u64*)(obj + 0x758);
        u64 csize = *(u64*)(obj + 0x758 + 0x10);
        u64 ccap = *(u64*)(obj + 0x758 + 0x18);
        if (InterlockedIncrement((volatile LONG*)&diagN) <= 3)
            LogHex("[TXT] ptr=", cptr), LogHex("[TXT] size=", csize), LogHex("[TXT] cap=", ccap);
        if (csize > 0 && csize < 0x2000) {
            const char* data = (const char*)(ULONG_PTR)cptr;
            char ssoBuf[16];
            if (ccap < csize || ccap <= 15) {
                for (int i = 0; i < 16; i++) ssoBuf[i] = *(unsigned char*)(obj + 0x758 + i);
                data = ssoBuf;
            }
            if (!IsBadReadPtr((const void*)(ULONG_PTR)data, (SIZE_T)csize)) {
                HANDLE f = CreateFileA("E:\\weixin-hook-4.1.8\\wxbot\\last_text.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
                if (f != INVALID_HANDLE_VALUE) { DWORD w = 0; WriteFile(f, data, csize, &w, NULL); CloseHandle(f); }
            }
        }
    }

    // SES 捕获 (TLS 链)
    {
        u64 tlsarr = 0, blk = 0;
        __asm__ volatile("movq %%gs:0x58, %0" : "=r"(tlsarr));
        u32 ti = *(u32*)((unsigned char*)g_base + TLS_INDEX_RVA);
        blk = *(u64*)(tlsarr + (u64)ti * 8);
        if (blk) {
            u64 spptr = *(u64*)(blk + TLS_CURCORO_OFF);
            if (spptr && !g_savedSPPtr) {
                g_savedSPPtr = spptr;
                LogL("[SES] session SP captured");
                u64 scoro = *(u64*)spptr;
                if (scoro) {
                    u64 sexec = *(u64*)(scoro + 0x368);
                    if (sexec && !g_sessExec) { g_sessExec = sexec; LogL("[SES] exec captured"); }
                }
            }
        }
    }

    // 文本模板活体优先
    {
        static BOOL g_tplLive = FALSE;
        if (!g_tplLive) {
            if (!g_templateObj) g_templateObj = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, 0x798);
            if (g_templateObj) {
                memcpy(g_templateObj, obj, 0x798); g_tplLive = TRUE; LogL("[TPL] template obj captured (live)");
                HANDLE f = CreateFileA("E:\\weixin-hook-4.1.8\\hook-wx\\m4\\template.bin", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
                if (f != INVALID_HANDLE_VALUE) { DWORD w = 0; WriteFile(f, g_templateObj, 0x798, &w, NULL); CloseHandle(f); LogL("[TPL] saved to disk"); }
            }
        }
    }

    // AUTO 队列冲刷
    SpawnAutoFlush();

    // M3 rewrite (SEND 队列)
    Cmd tmp;
    if (!g_api->QPopS(&tmp)) return;
    WrFresh(obj, 0x758, tmp.content, tmp.contentLen);
    if (tmp.targetLen > 0) WrFresh(obj, 0xB0, tmp.target, tmp.targetLen);
    if (tmp.flags) { char u[37]; GenUuid(u); WrFresh(obj, 0x6F8, u, 36); }
    g_rw++;
    LogL("[FLUSH] dispatched");
}

// ==== 池空闲 (原 C_idle) ====
static void POnIdle(WxApi* api, u64 retaddr) {
    (void)api;
    if (g_api->QEmptyA()) return;                     // 热路径: AUTO 队列空
    if (!g_base || !g_mgr2 || !g_sessExec) return;
    if (g_tid2 && GetCurrentThreadId() != g_tid2) return;
    u64 roff = retaddr - (u64)g_base;
    if (roff != POOL_WAIT_RET && roff != POOL_WAIT_RET2) {
        static volatile LONG n = 0;
        if (InterlockedExchangeAdd((volatile LONG*)&n, 1) < 5) LogHex("[IDLE] site retaddr=", retaddr);
        return;
    }
    if (GetTickCount64() - g_up1Tick < 10000) return;
    if (InterlockedExchange(g_api->pBusy2, 1)) return;
    LogL("[IDLE] autonomous flush begin");
    SpawnAutoFlush();
    InterlockedExchange(g_api->pBusy2, 0);
}

// ==== 密钥捕获线程 (诊断) ====
// 安全读: 对自身进程用 RPM, 内核处理缺页竞态, 不会 AV (直接读+IsBadReadPtr 有检查/读取间竞态)
static BOOL SafeRead(const void* addr, SIZE_T sz, void* out) {
    SIZE_T got = 0;
    return ReadProcessMemory(GetCurrentProcess(), addr, out, sz, &got) && got == sz;
}
static DWORD WINAPI KeyCatchThread(LPVOID p) {
    (void)p;
    for (int i = 0; i < 1200 && !g_sessExec; i++) {
        if (WaitForSingleObject(g_api->stopEvent, 100) == WAIT_OBJECT_0) return 0;
    }
    if (!g_sessExec) return 1;
    LogL("[KEYCATCH] armed, scanning...");
    char outpath[128];
    wsprintfA(outpath, "E:\\weixin-hook-4.1.8\\wxbot\\keycands_g%u.txt", g_api->gen);
    u64 t0 = GetTickCount64();
    LONG total = 0;
    HANDLE out = CreateFileA(outpath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    if (out == INVALID_HANDLE_VALUE) { LogL("[KEYCATCH] out file fail"); return 1; }
    DWORD written = 0;
    static unsigned char chunk[0x100000];   // 1MB 分块
    while (GetTickCount64() - t0 < 45000) {
        if (WaitForSingleObject(g_api->stopEvent, 0) == WAIT_OBJECT_0) break;
        SYSTEM_INFO si; GetSystemInfo(&si);
        u64 addr = (u64)(ULONG_PTR)si.lpMinimumApplicationAddress;
        u64 maxa = (u64)(ULONG_PTR)si.lpMaximumApplicationAddress;
        MEMORY_BASIC_INFORMATION mbi;
        while (addr < maxa) {
            if (VirtualQuery((LPCVOID)(ULONG_PTR)addr, &mbi, sizeof(mbi)) == 0) break;
            u64 rsz = mbi.RegionSize;
            DWORD prot = mbi.Protect & 0xFF;
            BOOL readable = (prot == PAGE_READONLY || prot == PAGE_READWRITE ||
                             prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READ ||
                             prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY);
            if (mbi.State == MEM_COMMIT && readable && rsz > 0 && rsz < 0x40000000) {
                u64 base = (u64)(ULONG_PTR)mbi.BaseAddress;
                u64 off = 0;
                while (off + 70 < rsz) {
                    u64 take = rsz - off;
                    if (take > sizeof(chunk)) take = sizeof(chunk);
                    if (!SafeRead((const void*)(base + off), (SIZE_T)take, chunk)) break;
                    for (u64 i = 0; i + 70 < take; i++) {
                        if (chunk[i] != 'x' || chunk[i+1] != '\'') continue;
                        u64 j = i + 2;
                        while (j < take && (((chunk[j]>='0'&&chunk[j]<='9')||(chunk[j]>='a'&&chunk[j]<='f')||(chunk[j]>='A'&&chunk[j]<='F')))) j++;
                        u64 len = j - (i + 2);
                        if (len >= 64 && len <= 192 && j < take && chunk[j] == '\'') {
                            char buf[200];
                            for (u64 k = 0; k < len; k++) {
                                char c = (char)chunk[i+2+k];
                                buf[k] = (c >= 'A' && c <= 'F') ? (char)(c + 32) : c;
                            }
                            buf[len] = '\n';
                            WriteFile(out, buf, (DWORD)(len + 1), &written, NULL);
                            total++;
                        }
                        i = j;
                    }
                    off += take - 64;   // 保留 64B 重叠防跨界漏检
                }
            }
            addr += rsz;
            if (rsz == 0) addr += 0x1000;
        }
        Sleep(120);
    }
    CloseHandle(out);
    LogL("[KEYCATCH] done");
    LogHex("[KEYCATCH] candidates=", total);
    return 0;
}

// ==== 入口 ====
#define PAYLOAD_VER "r3"
__declspec(dllexport) BOOL WxPayloadMain(WxApi* api) {
    if (!api) return FALSE;
    g_api = api;
    LoadConf();
    api->onUp1 = POnUp1;
    api->onIdle = POnIdle;
    HANDLE t2 = CreateThread(NULL, 0, KeyCatchThread, NULL, 0, NULL);
    if (t2) CloseHandle(t2);
    char buf[64];
    wsprintfA(buf, "[PAYLOAD] gen %u ready %s", api->gen, PAYLOAD_VER);
    LogL(buf);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)h; (void)r;
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(h);
    return TRUE;
}
