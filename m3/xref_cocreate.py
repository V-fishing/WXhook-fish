# -*- coding: utf-8 -*-
# @category WeChat.M5
base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()
af = currentProgram.getAddressFactory()
baseoff = base.getOffset()
refMgr = currentProgram.getReferenceManager()
target = base.add(0x45FCC0)
refs = refMgr.getReferencesTo(target)
n = 0
for r in refs:
    fromAddr = r.getFromAddress()
    f = fm.getFunctionContaining(fromAddr)
    fname = f.getName() if f else "<none>"
    fentry = f.getEntryPoint().getOffset() - baseoff if f else 0
    print("xref from rva %#x  in %s (entry %#x)  type %s" % (fromAddr.getOffset()-baseoff, fname, fentry, r.getReferenceType()))
    n += 1
    if n > 40: break
print("total shown:", n)
print("DONE")
