# -*- coding: utf-8 -*-
# @category WeChat.M2
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

TARGET_FUNCS = [
    (0x6EC950, "Disp_11DB"),
    (0x19D14C0, "Handler_1DBB"),
    (0x389D30, "Thunk_D7B"),
    (0xDBA100, "Callback_13BB"),
    (0x464950, "UIHandler_486B"),
    (0x27F4930, "UI_175B"),
    (0x72F241C, "UI_70B"),
]

base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()
di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

print("=" * 70)
print("DECOMPILING SEND CHAIN")
print("=" * 70)
for rva, label in TARGET_FUNCS:
    addr = base.add(rva)
    func = fm.getFunctionContaining(addr)
    if func is None:
        print("!! no function at 0x%X (%s)" % (rva, label))
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
