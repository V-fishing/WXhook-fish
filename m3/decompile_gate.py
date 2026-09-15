# -*- coding: utf-8 -*-
# @category WeChat.M5
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import ghidra.program.model.address as addr
from ghidra.app.cmd.function import CreateFunctionCmd

base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()
di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

for rva, label in [(0x1E2F4A0, "GatePredicate_1E2F4A0"), (0x178F980, "ShortCircuit_178F980")]:
    a = base.add(rva)
    func = fm.getFunctionAt(a)
    if func is None:
        cmd = CreateFunctionCmd(a)
        ok = cmd.applyTo(currentProgram, monitor)
        func = fm.getFunctionAt(a)
        print("(created=%s)" % ok)
    print("===== %s (rva 0x%X) =====" % (label, rva))
    if func is None:
        print("  <still no function>")
        continue
    res = di.decompileFunction(func, 180, monitor)
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("  <decompile failed: %s>" % res.getErrorMessage())
print("DONE")
