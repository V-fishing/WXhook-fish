# -*- coding: utf-8 -*-
# Ghidra Jython Script: 搜索微信消息管理器中的发送相关函数
# 在 Ghidra headless 的 -process 模式下运行
# @category WeChat.M2

from ghidra.program.model.symbol import RefType

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

# ── 1. 搜索所有包含 Send/Co 的已定义字符串 ──
print("=" * 60)
print("PHASE 1: Searching for Send-related strings")
print("=" * 60)

send_strings = []
di = listing.getDefinedData(True)
for data in di:
    try:
        if data.hasStringValue():
            val = str(data.getValue())
            if any(k in val for k in ['Send', 'send', 'SendMsg', 'SendText', 'CoSend', 'SendMsgFailed', 'SaveSendMessage']):
                addr = data.getAddress()
                rva = addr.getOffset() - 0x180000000
                send_strings.append((addr, val, rva))
                print("  STR @ rva=0x%X: %s" % (rva, val[:80]))
    except:
        pass

print("\nFound %d send-related strings" % len(send_strings))

# ── 2. 对每个字符串, 找引用它的代码 ──
print("\n" + "=" * 60)
print("PHASE 2: Finding functions that reference these strings")
print("=" * 60)

func_results = []
for addr, val, rva in send_strings:
    refs = getReferencesTo(addr)
    for ref in refs:
        from_addr = ref.getFromAddress()
        func = getFunctionContaining(from_addr)
        if func:
            func_name = func.getName()
            func_entry = func.getEntryPoint()
            func_rva = func_entry.getOffset() - 0x180000000
            info = "STR rva=0x%X '%s' -> func rva=0x%X '%s'" % (rva, val[:40], func_rva, func_name)
            print("  " + info)
            func_results.append(info)

# ── 3. 搜索函数名包含 Send 的 ──
print("\n" + "=" * 60)
print("PHASE 3: Functions with 'Send' in name")
print("=" * 60)

for func in fm.getFunctions(True):
    name = func.getName()
    if 'send' in name.lower() or 'Send' in name:
        entry = func.getEntryPoint()
        rva = entry.getOffset() - 0x180000000
        print("  FUNC rva=0x%X name=%s" % (rva, name))

# ── 4. 搜索所有日志串 (Co 前缀 = 消息管理器函数族) ──
print("\n" + "=" * 60)
print("PHASE 4: All 'Co' prefixed strings (message manager)")
print("=" * 60)

co_strings = []
di2 = listing.getDefinedData(True)
for data in di2:
    try:
        if data.hasStringValue():
            val = str(data.getValue())
            if val.startswith('Co') and len(val) > 5:
                addr = data.getAddress()
                rva = addr.getOffset() - 0x180000000
                co_strings.append((rva, val))
                print("  Co @ rva=0x%X: %s" % (rva, val[:80]))
    except:
        pass

print("\nTotal Co-prefixed strings: %d" % len(co_strings))
print("\n=== SCRIPT COMPLETE ===")
