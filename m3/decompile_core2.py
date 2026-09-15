# -*- coding: utf-8 -*-
# @category WeChat.M5
# Dump SendCore (0x1795500) raw C to file for searching; plus disasm of xrefs to task+0xB8
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()
di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

func = fm.getFunctionContaining(base.add(0x1795500))
res = di.decompileFunction(func, 300, monitor)
if res.decompileCompleted():
    c = res.getDecompiledFunction().getC()
    open("core_full.c","w").write(c)
    print("wrote core_full.c lines:", c.count("\n"))
print("DONE")
