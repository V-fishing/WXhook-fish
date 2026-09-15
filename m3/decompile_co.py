# -*- coding: utf-8 -*-
# @category WeChat.M5
from ghidra.app.decompiler import DecompInterface
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.util.task import ConsoleTaskMonitor

TARGET_FUNCS = [
    (0x462EE0, "Sched_1"),       # FUN_180462ee0(&DAT_18b5d8320, id, name, 0, ...)
    (0x462A80, "Sched_2"),       # FUN_180462a80(&DAT_18b5d8320)
    (0x462B70, "GetCtx_DEB"),    # 崩溃函数: 读 ctx 链
]

base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()
di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

print("=" * 70)
for rva, label in TARGET_FUNCS:
    addr = base.add(rva)
    func = fm.getFunctionContaining(addr)
    if func is None:
        cmd = CreateFunctionCmd(addr)
        cmd.applyTo(currentProgram, monitor)
        func = fm.getFunctionContaining(addr)
    if func is None:
        print("!! no function at 0x%X" % rva)
        continue
    print("\n===== %s (rva 0x%X, body %s .. %s) =====" % (
        label, rva, func.getEntryPoint(), func.getBody().getMaxAddress()))
    res = di.decompileFunction(func, 180, monitor)
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("!! failed")
print("DONE")
