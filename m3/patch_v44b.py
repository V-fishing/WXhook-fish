# patch_v44b.py - make C_coHook global + forward declare before asm
src = open('src/wx_send.c', encoding='utf-8').read()

src = src.replace('static void __fastcall C_coHook(void* dummy, u64 retaddr) {',
                  'void __fastcall C_coHook(void* dummy, u64 retaddr) {', 1)

old = 'extern void cocreate_stub(void);'
assert old in src
src = src.replace(old, 'void __fastcall C_coHook(void* dummy, u64 retaddr);\nextern void cocreate_stub(void);', 1)

open('src/wx_send.c', 'w', encoding='utf-8').write(src)
print('done')
