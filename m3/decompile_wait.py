# -*- coding: utf-8 -*-
# @category WeChat.M5
base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()
baseoff = base.getOffset()
for rva in (0x731EE0B, 0x73225D1, 0x7165A0B, 0x731D730):
    a = base.add(rva)
    f = fm.getFunctionContaining(a)
    if f:
        entry = f.getEntryPoint().getOffset()
        print("rva %#x -> func entry rva %#x name %s" % (rva, entry - baseoff, f.getName()))
    else:
        print("rva %#x -> <no function>" % rva)
print("DONE")
