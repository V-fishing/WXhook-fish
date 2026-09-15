# -*- coding: utf-8 -*-
# @category WeChat.M5
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.cmd.disassemble import DisassembleCommand

base = currentProgram.getImageBase()
baseoff = base.getOffset()
fm = currentProgram.getFunctionManager()
di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

a = base.add(0xB97038)
if fm.getFunctionAt(a) is None:
    # disassemble from here then create function
    cmd = DisassembleCommand(a, None, True)
    cmd.applyTo(currentProgram, monitor)
    ok = CreateFunctionCmd(a).applyTo(currentProgram, monitor)
    print("created:", ok)
f = fm.getFunctionContaining(a)
if f is None:
    f = fm.getFunctionAt(a)
print("===== ResumeItemHandler_0B97038 =====")
if f:
    print("entry rva: %#x" % (f.getEntryPoint().getOffset() - baseoff))
    res = di.decompileFunction(f, 180, monitor)
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
print("DONE")
