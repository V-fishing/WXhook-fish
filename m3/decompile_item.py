# -*- coding: utf-8 -*-
# @category WeChat.M5
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()
di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

# the resume-item handler (code label inside .text)
a = base.add(0xB97038)
f = fm.getFunctionContaining(a)
print("handler func:", f.getName() if f else "<none>", "entry:", hex(f.getEntryPoint().getOffset()-base.getOffset()) if f else "-")
if f:
    res = di.decompileFunction(f, 300, monitor)
    if res.decompileCompleted():
        c = res.getDecompiledFunction().getC()
        open("item_handler.c","w").write(c)
        print("lines:", c.count("\n"))
print("DONE")
