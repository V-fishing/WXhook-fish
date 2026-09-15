# -*- coding: utf-8 -*-
# @category WeChat.M5
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.cmd.function import CreateFunctionCmd

base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()
di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

for rva, label in [(0x45FF50, "SchedEntry_45FF50")]:
    a = base.add(rva)
    func = fm.getFunctionAt(a)
    if func is None:
        CreateFunctionCmd(a).applyTo(currentProgram, monitor)
        func = fm.getFunctionAt(a)
    print("===== %s =====" % label)
    if func:
        res = di.decompileFunction(func, 180, monitor)
        if res.decompileCompleted():
            print(res.getDecompiledFunction().getC())
print("DONE")
