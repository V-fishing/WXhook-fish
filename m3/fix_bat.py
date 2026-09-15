content = open('run_gate.bat', encoding='utf-8').read()
import re
content = re.sub(r'-postScript \S+\.py', '-postScript decompile_abort2.py', content)
content = re.sub(r'> "\S+abort2_decompiled\.txt"', '> "E:\\weixin-hook-4.1.8\\hook-wx\\m3\\abort2_decompiled.txt"', content)
# simpler: rewrite the redirect path
import re as r2
content = r2.sub(r'> "[^"]+"', '> "E:\\weixin-hook-4.1.8\\hook-wx\\m3\\abort2_decompiled.txt"', content)
open('run_gate.bat','w',encoding='utf-8').write(content)
print('bat fixed')
