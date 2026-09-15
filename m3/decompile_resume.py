# -*- coding: utf-8 -*-
# @category WeChat.M5
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()
di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

# resume_if inner (0x45FFA0) FULL body
func = fm.getFunctionContaining(base.add(0x45FFA0))
res = di.decompileFunction(func, 300, monitor)
if res.decompileCompleted():
    c = res.getDecompiledFunction().getC()
    open("resume_full.c","w").write(c)
    print("lines:", c.count("\n"))
print("DONE")
