# -*- coding: utf-8 -*-
# @category WeChat.M5
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()
di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

f = fm.getFunctionAt(base.add(0xD9E850))
if f:
    print("===== FUN_180d9e850 (log context create) =====")
    res = di.decompileFunction(f, 300, monitor)
    if res.decompileCompleted():
        c = res.getDecompiledFunction().getC()
        open("logctx_full.c","w").write(c)
        print("lines:", c.count(chr(10)))
print("DONE")
