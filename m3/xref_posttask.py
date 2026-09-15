# -*- coding: utf-8 -*-
# @category WeChat.M5
base = currentProgram.getImageBase()
baseoff = base.getOffset()
fm = currentProgram.getFunctionManager()
refMgr = currentProgram.getReferenceManager()
for rva, label in [(0xdb9150, "PostTask")]:
    print("===== xrefs to %s (%#x) =====" % (label, rva))
    n = 0
    for r in refMgr.getReferencesTo(base.add(rva)):
        fromAddr = r.getFromAddress()
        f = fm.getFunctionContaining(fromAddr)
        fname = f.getName() if f else "<none>"
        fentry = (f.getEntryPoint().getOffset() - baseoff) if f else 0
        print("  from rva %#x in %s (entry %#x) type %s" % (fromAddr.getOffset()-baseoff, fname, fentry, r.getReferenceType()))
        n += 1
        if n > 30: break
    print("  shown:", n)
print("DONE")
