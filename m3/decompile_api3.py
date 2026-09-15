# -*- coding: utf-8 -*-
# @category WeChat.M5
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()
di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

from ghidra.app.cmd.function import CreateFunctionCmd
func = fm.getFunctionContaining(base.add(0xDB9150))
if func is None:
    CreateFunctionCmd(base.add(0xDB9150)).applyTo(currentProgram, monitor)
    func = fm.getFunctionContaining(base.add(0xDB9150))
res = di.decompileFunction(func, 120, monitor)
if res.decompileCompleted():
    print(res.getDecompiledFunction().getC())
print("DONE")
