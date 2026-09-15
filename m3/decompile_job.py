# -*- coding: utf-8 -*-
# @category WeChat.M5
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()
di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

# dump job vtable at 0xB8D5E8
import struct
a = base.add(0xB8D5E8)
print("===== job vtable entries =====")
for i in range(6):
    fn = getQuad(a.add(i*8))
    if fn:
        print("  vtable[%d] = %#x" % (i, fn.getOffset() - base.getOffset()))
print("DONE")
