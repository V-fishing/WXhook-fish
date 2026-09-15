# -*- coding: utf-8 -*-
# @category WeChat.M2
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

TARGET_FUNCS = [
    (0x18259A0, "SendTextCand_DE4B"),
    (0x7574F0, "MsgObjCtor1_C3B"),
    (0x758820, "MsgObjCtor2_A7B"),
    (0x7589E0, "MsgObjCtor3_20FB"),
    (0x6EC830, "MsgObjFactory_E8B"),
    (0x2BAE360, "BigRef_2F67B"),
    (0x17A68E0, "NestedReq1"),
    (0x17A70D0, "NestedReq2"),
    (0x6EC360, "Disp_387B"),
]

base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()
di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

print("=" * 70)
print("DECOMPILING FINAL BATCH")
print("=" * 70)
for rva, label in TARGET_FUNCS:
    addr = base.add(rva)
    func = fm.getFunctionContaining(addr)
    if func is None:
        print("!! no function at 0x%X (%s)" % (rva, label))
        continue
    print("\n===== %s (rva 0x%X, %s, body %s .. %s) =====" % (
        label, rva, func.getName(), func.getEntryPoint(), func.getBody().getMaxAddress()))
    res = di.decompileFunction(func, 240, monitor)
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("!! decompile failed: %s" % res.getErrorMessage())
print("=" * 70)
print("DONE")
