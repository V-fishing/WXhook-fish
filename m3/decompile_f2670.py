# -*- coding: utf-8 -*-
# @category WeChat.M5
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()
di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

f = fm.getFunctionAt(base.add(0x72F2670))
if f:
    print("===== FUN_1872f2670 =====")
    res = di.decompileFunction(f, 180, monitor)
    if res.decompileCompleted():
        c = res.getDecompiledFunction().getC()
        open("f2670_full.c","w").write(c)
        print("lines:", c.count(chr(10)))
print("DONE")
