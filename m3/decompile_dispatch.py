# -*- coding: utf-8 -*-
# @category WeChat.M5
from ghidra.app.decompiler import DecompInterface
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.util.task import ConsoleTaskMonitor

TARGET_FUNCS = [
    (0x72F241C, "LoopBase_70B"),
    (0x27F4930, "Loop2_175B"),
    (0x1105F60, "Trampoline_FB"),
    (0x464950, "UIHandler_486B"),
    (0xDBA100, "Callback_13BB"),
    (0x19D14C0, "Handler_1DBB"),
    (0x465AF0, "Thunk_2AB"),
]

base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()
di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

print("=" * 70)
print("DECOMPILING DISPATCH CHAIN (force-create where missing)")
print("=" * 70)
for rva, label in TARGET_FUNCS:
    addr = base.add(rva)
    func = fm.getFunctionContaining(addr)
    if func is None:
        cmd = CreateFunctionCmd(addr)
        ok = cmd.applyTo(currentProgram, monitor)
        print("created function at 0x%X: %s" % (rva, ok))
        func = fm.getFunctionContaining(addr)
    if func is None:
        print("!! still no function at 0x%X (%s)" % (rva, label))
        continue
    print("\n===== %s (rva 0x%X, %s, body %s .. %s) =====" % (
        label, rva, func.getName(), func.getEntryPoint(), func.getBody().getMaxAddress()))
    res = di.decompileFunction(func, 180, monitor)
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("!! decompile failed: %s" % res.getErrorMessage())
print("=" * 70)
print("DONE")
