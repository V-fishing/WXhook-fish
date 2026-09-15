# -*- coding: utf-8 -*-
# @category WeChat.M5
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()
di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

func = fm.getFunctionContaining(base.add(0x465440))
print("===== SetCtx candidate 0x465440 =====")
res = di.decompileFunction(func, 120, monitor)
if res.decompileCompleted():
    print(res.getDecompiledFunction().getC())
print("DONE")
