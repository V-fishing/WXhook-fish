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

a = base.add(0xFD9220)
func = fm.getFunctionAt(a)
if func is None:
    DisassembleCommand(a, None, True).applyTo(currentProgram, monitor)
    CreateFunctionCmd(a).applyTo(currentProgram, monitor)
    func = fm.getFunctionAt(a)
print("entry:", hex(func.getEntryPoint().getOffset()-baseoff) if func else "<none>")
if func:
    res = di.decompileFunction(func, 300, monitor)
    if res.decompileCompleted():
        c = res.getDecompiledFunction().getC()
        open("submit_full.c","w").write(c)
        print("lines:", c.count(chr(10)))
print("DONE")
