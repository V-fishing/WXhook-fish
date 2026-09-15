# -*- coding: utf-8 -*-
# @category WeChat.M5
base = currentProgram.getImageBase()
baseoff = base.getOffset()
fm = currentProgram.getFunctionManager()
refMgr = currentProgram.getReferenceManager()

f = fm.getFunctionContaining(base.add(0x716BDE0))
if f:
    entry = f.getEntryPoint().getOffset()
    rva = entry - baseoff
    print("abort func entry rva: 0x%x" % rva)
    n = 0
    for r in refMgr.getReferencesTo(f.getEntryPoint()):
        frm = r.getFromAddress().getOffset() - baseoff
        fc = fm.getFunctionContaining(r.getFromAddress())
        fe = (fc.getEntryPoint().getOffset() - baseoff) if fc else 0
        print("  caller from rva 0x%x (func 0x%x)" % (frm, fe))
        n += 1
        if n > 40: break
    print("callers shown:", n)
else:
    print("no function containing 0x716BDE0")
print("DONE")
