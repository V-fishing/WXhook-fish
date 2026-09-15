# -*- coding: utf-8 -*-
# @category WeChat.M5
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

TARGET_FUNCS = [
    (0x465BB0, "CoroutineSpawn_67EB"),
    (0x464ED0, "Co_A_315B"),
    (0x465280, "Co_B_18BB"),
    (0x465440, "Co_C_30CB"),
]

base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()
di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

print("=" * 70)
for rva, label in TARGET_FUNCS:
    addr = base.add(rva)
    func = fm.getFunctionContaining(addr)
    if func is None:
        print("!! no function at 0x%X" % rva)
        continue
    print("\n===== %s (rva 0x%X, body %s .. %s) =====" % (
        label, rva, func.getEntryPoint(), func.getBody().getMaxAddress()))
    res = di.decompileFunction(func, 180, monitor)
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("!! failed")
print("DONE")
