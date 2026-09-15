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

for rva, label in [(0x730C412, "FmtCaller_730C412")]:
    f = fm.getFunctionContaining(base.add(rva))
    if f:
        print("===== %s (entry %#x) =====" % (label, f.getEntryPoint().getOffset()-baseoff))
        res = di.decompileFunction(f, 300, monitor)
        if res.decompileCompleted():
            c = res.getDecompiledFunction().getC()
            open("fmt_full.c","w").write(c)
            print("lines:", c.count(chr(10)))
    else:
        print("no function containing %#x" % rva)
print("DONE")
