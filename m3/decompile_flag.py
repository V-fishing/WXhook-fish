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

for rva, label in [(0xDDE030, "FlagHandler_DDE030"), (0x39B94B0, "TaskCtor_39B94B0")]:
    a = base.add(rva)
    func = fm.getFunctionAt(a)
    if func is None:
        ok = CreateFunctionCmd(a).applyTo(currentProgram, monitor)
        func = fm.getFunctionAt(a)
        print("(created=%s)" % ok)
    print("===== %s (rva 0x%X) =====" % (label, rva))
    if func is None:
        print("  <still no function>"); continue
    res = di.decompileFunction(func, 180, monitor)
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("  <fail: %s>" % res.getErrorMessage())
print("DONE")
