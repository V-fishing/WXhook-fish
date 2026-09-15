# -*- coding: utf-8 -*-
# Ghidra Jython script: decompile send pipeline functions
# @category WeChat.M2

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

TARGET_FUNCS = [
    (0x731D6EC, "Routing_94B"),
    (0x71659EC, "Routing2_60B"),
    (0x732E220, "Dispatch_666B"),
    (0x4DED3B0, "Serialize_3KB"),
    (0x4D34740, "Network_443B"),
    (0x6482E00, "UI_Entry_49B"),
    (0x6A1A0,   "StringEncode_1700B"),
]

base = currentProgram.getImageBase()
af = currentProgram.getAddressFactory().getDefaultAddressSpace()
fm = currentProgram.getFunctionManager()

di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

print("=" * 70)
print("DECOMPILING SEND PIPELINE FUNCTIONS")
print("=" * 70)

for rva, label in TARGET_FUNCS:
    addr = af.getAddress(base.getOffset() + rva)
    func = fm.getFunctionContaining(addr)
    if func is None:
        func = fm.getFunctionAt(addr)

    print("\n===== %s (rva 0x%X) =====" % (label, rva))

    if func is None:
        print("  NO FUNCTION FOUND")
        continue

    print("Function: %s @ %s" % (func.getName(), func.getEntryPoint()))
    print("Body: %s to %s" % (func.getBody().getMinAddress(), func.getBody().getMaxAddress()))

    result = di.decompileFunction(func, 120, monitor)
    if result.decompileCompleted():
        code = result.getDecompiledFunction().getC()
        print("--- DECOMPILED C CODE ---")
        print(code)
        print("--- END ---")
    else:
        print("  Decompilation failed: %s" % result.getErrorMessage())

print("\n" + "=" * 70)
print("DECOMPILATION COMPLETE")
print("=" * 70)
