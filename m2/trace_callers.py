# -*- coding: utf-8 -*-
# Ghidra Jython script: 从发送管线入口向上追溯调用链
# @category WeChat.M2

from ghidra.program.model.address import Address
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()
af = currentProgram.getAddressFactory().getDefaultAddressSpace()
monitor = ConsoleTaskMonitor()

# 发送管线入口函数 (rva 0x6482E00)
TARGET_RVA = 0x6482E00
target_addr = af.getAddress(base.getOffset() + TARGET_RVA)

di = DecompInterface()
di.openProgram(currentProgram)

print("=" * 70)
print("PHASE 1: Function at rva 0x%X" % TARGET_RVA)
print("=" * 70)

func = fm.getFunctionContaining(target_addr)
if func is None:
    func = fm.getFunctionAt(target_addr)

if func:
    print("Function: %s" % func.getName())
    print("Entry: %s" % func.getEntryPoint())
    print("Body: %s - %s" % (func.getBody().getMinAddress(), func.getBody().getMaxAddress()))
else:
    print("No function found!")

# ── 找所有引用这个函数地址的代码 ──
print("\n" + "=" * 70)
print("PHASE 2: All references TO this function")
print("=" * 70)

ref_mgr = currentProgram.getReferenceManager()
refs = ref_mgr.getReferencesTo(target_addr)

callers = []
for ref in refs:
    from_addr = ref.getFromAddress()
    ref_type = ref.getReferenceType()
    from_rva = from_addr.getOffset() - base.getOffset()
    calling_func = fm.getFunctionContaining(from_addr)
    if calling_func:
        caller_name = calling_func.getName()
        caller_entry = calling_func.getEntryPoint()
        caller_rva = caller_entry.getOffset() - base.getOffset()
        callers.append((from_rva, ref_type, caller_rva, caller_name))
        print("  CALLER: rva=0x%X  type=%s  func=%s (rva=0x%X)" % (
            from_rva, ref_type, caller_name, caller_rva))
    else:
        print("  REF: rva=0x%X  type=%s  (no function)" % (from_rva, ref_type))

print("\nTotal references: %d" % len(callers))

# ── 反编译每个调用者 ──
print("\n" + "=" * 70)
print("PHASE 3: Decompiling callers")
print("=" * 70)

seen_funcs = set()
for from_rva, ref_type, caller_rva, caller_name in callers[:5]:
    if caller_rva in seen_funcs:
        continue
    seen_funcs.add(caller_rva)

    caller_addr = af.getAddress(base.getOffset() + caller_rva)
    caller_func = fm.getFunctionAt(caller_addr)
    if caller_func is None:
        continue

    print("\n" + "=" * 70)
    print("CALLER: %s (rva 0x%X)" % (caller_name, caller_rva))
    print("=" * 70)

    result = di.decompileFunction(caller_func, 120, monitor)
    if result.decompileCompleted():
        code = result.getDecompiledFunction().getC()
        # 只打印前 100 行 (避免输出过长)
        lines = code.split('\n')
        for line in lines[:100]:
            print(line)
        if len(lines) > 100:
            print("  ... (%d more lines)" % (len(lines) - 100))
    else:
        print("  Decompilation failed")

print("\n" + "=" * 70)
print("DONE")
print("=" * 70)
