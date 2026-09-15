# repair_broken_asm.py - join broken asm string lines
src = open('src/wx_send.c', encoding='utf-8').read()
lines = src.split('\n')
out = []
i = 0
fixed = 0
while i < len(lines):
    l = lines[i]
    if (i+1) < len(lines) and lines[i+1] == '"' and l.strip().startswith('"  ') and not l.rstrip().endswith('"'):
        merged = l.rstrip() + '\\n"'
        out.append(merged)
        fixed += 1
        i += 2
        continue
    out.append(l)
    i += 1
open('src/wx_send.c', 'w', encoding='utf-8').write('\n'.join(out))
print('repaired lines:', fixed)
