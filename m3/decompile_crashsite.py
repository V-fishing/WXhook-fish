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

for rva, label in [(0xFEA90, "CrashSite_FEA90"), (0x72E594B, "Caller_72E594B")]:
    a = base.add(rva)
    f = fm.getFunctionContaining(a)
    if f is None and label.startswith("CrashSite"):
        DisassembleCommand(a, None, True).applyTo(currentProgram, monitor)
        CreateFunctionCmd(a).applyTo(currentProgram, monitor)
        f = fm.getFunctionAt(a)
        if f is None:
            f = fm.getFunctionContaining(a)
    print("===== %s =====" % label)
    if f:
        print("func entry rva: %#x" % (f.getEntryPoint().getOffset()-baseoff))
        res = di.decompileFunction(f, 300, monitor)
        if res.decompileCompleted():
            c = res.getDecompiledFunction().getC()
            open(("crashsite_%s.c" % label.split('_')[0]),"w").write(c)
            print("lines:", c.count(chr(10)))
    else:
        print("  <no function>")
print("DONE")
