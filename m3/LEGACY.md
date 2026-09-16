# m3 = legacy (v65 单体 DLL, 2026-09-16 归档)

自 v98 起架构拆分为 m4/:
- wx_boot.c   常驻层 (钩子/状态/队列/管道 + RELOAD)
- wx_payload.c 业务层 (热重载)
- wx_api.h    共享 ABI

本目录 wx_send_v65.c 为拆分前的单体实现, 保留作历史参考 (patch_v*.py 的最终产物)。
模板文件已迁至 m4/。请勿注入本目录产物 (会与 m4 双钩子打架)。
