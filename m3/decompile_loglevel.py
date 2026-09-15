# -*- coding: utf-8 -*-
# @category WeChat.M5
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()
di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

for rva, label in [(0xD9E810, "LogEnabled_D9E810"), (0xD9E5F0, "LogSink_D9E5F0")]:
    f = fm.getFunctionAt(base.add(rva))
    if f:
        print("===== %s =====" % label)
        res = di.decompileFunction(f, 120, monitor)
        if res.decompileCompleted():
            print(res.getDecompiledFunction().getC())
print("DONE")
