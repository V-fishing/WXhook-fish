# -*- coding: utf-8 -*-
# @category WeChat.M5
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()
di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

f = fm.getFunctionAt(base.add(0x72F2584))
if f:
    print("===== FUN_1872f2584 (called with 3 when state==0) =====")
    res = di.decompileFunction(f, 180, monitor)
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
print("DONE")
