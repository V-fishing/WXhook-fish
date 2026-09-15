# -*- coding: utf-8 -*-
# Ghidra Jython: 反编译发送核心区 3 个函数
#   0x1795500 (6KB) - StartSendMessageSyncStage 直接调用者
#   0x1790970 (0x205) - 上层
#   0x17A3620 (0xADE) - 上层
# @category WeChat.M2

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

TARGET_FUNCS = [
    (0x1795500, "SendCore_6KB"),
    (0x1790970, "Upper1_517B"),
    (0x17A3620, "Upper2_AD9B"),
    (0x39BD150, "Mid_575B"),
]

base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()
af = currentProgram.getAddressFactory().getDefaultAddressSpace()

di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

print("=" * 70)
print("DECOMPILING SEND CORE FUNCTIONS")
print("=" * 70)

for rva, label in TARGET_FUNCS:
    addr = base.add(rva)
    func = fm.getFunctionContaining(addr)
    if func is None:
        func = fm.getFunctionAt(addr)
    if func is None:
        print("!! no function at 0x%X (%s)" % (rva, label))
        continue
    print("\n===== %s (rva 0x%X, %s, body %s .. %s) =====" % (
        label, rva, func.getName(), func.getEntryPoint(), func.getBody().getMaxAddress()))
    res = di.decompileFunction(func, 180, monitor)
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("!! decompile failed: %s" % res.getErrorMessage())

print("=" * 70)
print("DONE")
