# -*- coding: utf-8 -*-
# Ghidra Jython: 反编译 UP1 的全部调用者 (发送函数家族)
# @category WeChat.M2
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

TARGET_FUNCS = [
    (0x17908B0, "Wrap_A_87B"),
    (0x1790F90, "Wrap_B_87B"),
    (0x1791050, "Send_988B"),
    (0x1791E40, "Big_21E0B"),
    (0x179D970, "Send_8A2B"),
    (0x17A4AD0, "Send_73EB"),
    (0x17A75A0, "Send_3C7B"),
    (0x18259A0, "Send_DE4B"),
    (0x1791050, "dup1"),
    (0x39BE5C0, "Mod2_2E7B"),
    (0x2657DE0, "Mod3_7C6B"),
]

base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()

di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

print("=" * 70)
print("DECOMPILING UP1 CALLERS (send family)")
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
