# -*- coding: utf-8 -*-
# @category WeChat.M5
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

base = currentProgram.getImageBase()
baseoff = base.getOffset()
fm = currentProgram.getFunctionManager()
di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

f = fm.getFunctionContaining(base.add(0x46440F))
if f:
    print("===== entry rva: %#x =====" % (f.getEntryPoint().getOffset()-baseoff))
    res = di.decompileFunction(f, 300, monitor)
    if res.decompileCompleted():
        c = res.getDecompiledFunction().getC()
        open("starthelper_full.c","w").write(c)
        print("lines:", c.count(chr(10)))
else:
    print("no function containing 0x46440F")
print("DONE")
