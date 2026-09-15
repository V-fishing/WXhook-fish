# -*- coding: utf-8 -*-
# Ghidra Jython script: decompile DelMsg handler + mgr vtable methods
# @category WeChat.M2

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

TARGET_FUNCS = [
    (0x24C9090, "DelMsg_Handler_8KB"),
    (0x1865560, "mgr_vtable_0"),
    (0x178C290, "mgr_vtable_1"),
    (0x230830,  "mgr_vtable_2"),
    (0x178EC80, "mgr_vtable_3"),
    (0x178F260, "mgr_vtable_4"),
    # also decompile the send pipeline entry
    (0x6482E00, "UI_Entry_49B"),
    (0x68E610,  "UI_Callback_17B"),
]

base = currentProgram.getImageBase()
af = currentProgram.getAddressFactory().getDefaultAddressSpace()
fm = currentProgram.getFunctionManager()

di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

print("=" * 70)
print("DECOMPILING DELMSG HANDLER + MGR VTABLE METHODS")
print("=" * 70)

for rva, label in TARGET_FUNCS:
    addr = af.getAddress(base.getOffset() + rva)
    func = fm.getFunctionContaining(addr)
    if func is None:
        func = fm.getFunctionAt(addr)

    print("\n" + "=" * 70)
    print("===== %s (rva 0x%X) =====" % (label, rva))

    if func is None:
        print("  NO FUNCTION FOUND at 0x%X" % (base.getOffset() + rva))
        # try to create it
        from ghidra.app.cmd.function import CreateFunctionCmd
        from ghidra.app.cmd.function import CreateFunctionCmd
        cmd = CreateFunctionCmd(addr)
        if cmd.applyTo(currentProgram, monitor):
            func = fm.getFunctionAt(addr)
            print("  Created function: %s" % func.getName())
        else:
            continue

    print("Function: %s" % func.getName())
    print("Body: %s to %s (size=%d bytes)" % (
        func.getBody().getMinAddress(), func.getBody().getMaxAddress(),
        func.getBody().getMaxAddress().subtract(func.getBody().getMinAddress())))

    result = di.decompileFunction(func, 300, monitor)
    if result.decompileCompleted():
        code = result.getDecompiledFunction().getC()
        print("--- DECOMPILED C ---")
        print(code)
        print("--- END ---")
    else:
        print("  Decompilation failed: %s" % result.getErrorMessage())

print("\n" + "=" * 70)
print("ALL DECOMPILATION COMPLETE")
print("=" * 70)
