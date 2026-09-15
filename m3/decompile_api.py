# -*- coding: utf-8 -*-
# @category WeChat.M5
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

TARGET_FUNCS = [(0x45FD60, "CoCreate_API_FEB")]

base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()
di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

for rva, label in TARGET_FUNCS:
    func = fm.getFunctionContaining(base.add(rva))
    print("===== %s =====" % label)
    res = di.decompileFunction(func, 120, monitor)
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
print("DONE")
