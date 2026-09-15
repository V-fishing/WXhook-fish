# -*- coding: utf-8 -*-
import re
import shutil

src = r'E:\weixin-hook-4.1.8\-ce-\微信过低版本工具.exe'
dst = r'E:\weixin-hook-4.1.8\WeChat\[3.9.5.80]\微信过低版本工具.exe'

shutil.copy2(src, dst)
d = open(dst, 'rb').read()
d2 = d.replace(b'3.9.11.17', b'3.9.12.17')
open(dst, 'wb').write(d2)
print('copied + patched ->', dst)
print('3.9.12.17 hits:', len(re.findall(re.escape(b'3.9.12.17'), d2)))
