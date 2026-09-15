# -*- coding: utf-8 -*-
# @category WeChat.M4
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()
di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

for rva, label in [(0x462B70, "CrashFn_DEB"), (0x464950, "UIHandler_486B")]:
    addr = base.add(rva)
    func = fm.getFunctionContaining(addr)
    if func is None:
        # 强制创建函数
        from ghidra.app.cmd.function import CreateFunctionCmd
        cmd = CreateFunctionCmd(addr)
        ok = cmd.applyTo(currentProgram, monitor)
        print("!! created function at 0x%X: %s" % (rva, ok))
        func = fm.getFunctionContaining(addr)
    if func is None:
        print("!! still no function at 0x%X" % rva)
        continue
    print("\n===== %s (rva 0x%X, body %s .. %s) =====" % (label, rva, func.getEntryPoint(), func.getBody().getMaxAddress()))
    res = di.decompileFunction(func, 180, monitor)
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("!! failed: %s" % res.getErrorMessage())
print("DONE")
