# repair_hijack_asm.py — fix broken multi-line asm strings (real newlines inside quotes)
src = open('src/wx_send.c', encoding='utf-8').read()
lines = src.split('\n')
out = []
i = 0
fixed = 0
while i < len(lines):
    l = lines[i]
    # broken pattern: a line ending with `"` is fine; a line NOT ending with quote-terminated string
    # inside the __asm__ block: a line like `".text` (missing closing `"` content) followed by `"` line
    out.append(l)
    i += 1
# simpler approach: rebuild the hijack asm block wholesale by locating markers
start = src.find('__asm__(\n".text\n"\n".globl hijack_stub')
if start < 0:
    # find by the globl line
    g = src.find('.globl hijack_stub')
    print('globl found at char', g)
print('checking...')
# count how many lines have a bare `"` (broken)
broken = sum(1 for l in lines if l.strip() == '"')
print('bare quote lines:', broken)
