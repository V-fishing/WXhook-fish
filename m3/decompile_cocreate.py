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
baseoff = base.getOffset()

for rva, label in [(0x45FCC0, "CoCreate_45FCC0"), (0x45FD60, "CoCreate2_45FD60")]:
    a = base.add(rva)
    func = fm.getFunctionAt(a)
    if func is None:
        CreateFunctionCmd(a).applyTo(currentProgram, monitor)
        func = fm.getFunctionAt(a)
    print("===== %s (rva 0x%X) =====" % (label, rva))
    if func is None:
        print("  <no function>")
        continue
    res = di.decompileFunction(func, 180, monitor)
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("  <fail>")
print("DONE")
