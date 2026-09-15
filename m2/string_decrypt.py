# -*- coding: utf-8 -*-
"""
WeChat 4.x 字符串解密器
基于 RevokeHook destring.py 的方法:
  1. 在 .text 中搜索解密代码模式 (cmp 0 + jnz + xor + lea enc + lea dec)
  2. 用 Unicorn 引擎模拟执行解密逻辑
  3. 输出解密后的字符串

模式来自 RevokeHook/IdaScript/destring.py:
  cmp [addr], 0          → 检查是否已解密
  jnz already_decrypted   → 已解密则跳过
  xor reg, reg           → 安全清零
  lea reg, [enc_data]     → 加密数据地址
  lea reg, [dec_buffer]   → 解密输出地址
  ... 解密代码 ...
  cmp reg, len           → 检查长度
  jnz error              → 错误处理
  mov [flag], 1           → 标记已解密
"""
import struct
import sys
import capstone
import unicorn

# Weixin.dll .text 节参数
TEXT_RVA = 0x1000
TEXT_RAW = 0x400
TEXT_SIZE = 0x7335B17
IMAGE_BASE = 0x180000000

data = open(r'D:\Weixin\4.1.13.65\Weixin.dll', 'rb').read()
text_data = data[TEXT_RAW:TEXT_RAW + TEXT_SIZE]
text_rva_start = TEXT_RVA

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

def rva2off(rva):
    return rva - TEXT_RVA + TEXT_RAW

def off2rva(off):
    return off - TEXT_RAW + TEXT_RVA

def find_decrypt_patterns():
    """在 .text 中搜索字符串解密模式"""
    # 策略: 搜索 "xor reg, reg" 指令 (解密函数的标志性指令)
    # x64 的 xor reg,reg 编码: 4D 8B xx 或 4C 8B xx 或 31 xx 或 33 xx
    # 但最常见的32位清零是: 45 31 C0 (xor r8d, r8d), 45 31 D2 (xor r10d, r10d) 等
    
    # 更高效的方法: 搜索 lea 指令对 (lea enc + lea dec)
    # 这两个 lea 指令紧挨着, 指向加密数据和解密缓冲区
    
    # 从 destring.py 的分析: 模式是
    # cmp *, 0 → jnz → xor reg,reg → lea enc → lea dec
    
    # x64 编码: xor r8d,r8d = 45 31 C0
    #           xor r9d,r9d = 45 31 C9
    #           xor eax,eax = 31 C0
    #           等等...
    
    # 搜索所有 xor reg, reg (编码: 31 xx 或 33 xx 其中两个操作数相同)
    results = []
    
    # 方法: 找 "cmp qword ptr [X], 0" 后跟 "jnz" 后跟 "xor reg, reg" 的序列
    # cmp qword ptr [rip+XX], 0 的编码: 48 83 3D XX XX XX XX 00
    # 或: 48 8B 05 XX XX XX XX 48 85 C0 (mov+test)
    
    # 简化: 搜索 "48 83 3D" (cmp qword ptr [rip+X], imm8) 
    # 后面跟着 00 (值为0)
    # 然后在后续 20 字节内找 31/33 (xor)
    
    print("[*] scanning for decrypt patterns in %d MB of .text..." % (TEXT_SIZE // 1048576))
    
    # 搜索模式: cmp [rip+X], 0 后面跟着 xor
    # 48 83 3D XX XX XX XX 00 = cmp qword ptr [rip+disp8], 0
    cmp_pattern = b'\x48\x83\x3D'
    
    pos = 0
    count = 0
    matches = []
    
    while pos < len(text_data) - 20:
        idx = text_data.find(cmp_pattern, pos)
        if idx < 0:
            break
        
        # 解析 cmp 指令长度 (7 bytes: 48 83 3D + 4B disp + 1B imm)
        cmp_end = idx + 7
        
        # 在后续 30 字节内找 jnz (0F 85 或 75) 和 xor (31/33)
        window = text_data[cmp_end:cmp_end + 30]
        
        # 找 jnz (75 xx = 短跳)
        jnz_off = -1
        for j in range(len(window) - 1):
            if window[j] == 0x75:  # jnz short
                jnz_off = j
                break
        
        if jnz_off >= 0:
            # 找 xor reg, reg (31 xx 或 33 xx, mod=11)
            for j in range(jnz_off + 2, min(jnz_off + 10, len(window) - 1)):
                if window[j] in (0x31, 0x33):
                    modrm = window[j + 1]
                    if (modrm >> 6) == 3 and (modrm & 7) == ((modrm >> 3) & 7):
                        # 找到了 xor reg, reg!
                        # 再找两个 lea
                        lea_start = cmp_end + jnz_off + j + 2
                        leas = []
                        for k in range(lea_start, min(lea_start + 30, len(text_data) - 4)):
                            if text_data[k] == 0x48 and text_data[k+1] == 0x8D:
                                leas.append(k)
                                if len(leas) >= 2:
                                    break
                        if len(leas) >= 2:
                            matches.append({
                                'cmp_off': idx,
                                'jnz_off': cmp_end + jnz_off,
                                'xor_off': cmp_end + j,
                                'lea1_off': leas[0],
                                'lea2_off': leas[1],
                            })
                            count += 1
                            if count >= 500:
                                break
        pos = idx + 1
        if count >= 500:
            break
    
    print('[*] found %d decrypt pattern candidates' % count)
    return matches


def try_decrypt_with_unicorn(match):
    """用 Unicorn 模拟执行解密逻辑"""
    # 这个函数需要:
    # 1. 反汇编 match 附近的代码
    # 2. 提取 lea 指令指向的加密数据地址
    # 3. 用 Unicorn 模拟执行
    # 4. 从输出缓冲区读取解密后的字符串
    pass


if __name__ == '__main__':
    matches = find_decrypt_patterns()
    
    # 打印前几个匹配的上下文
    for m in matches[:10]:
        rva = off2rva(m['cmp_off'])
        print('\n[match] rva=0x%X' % rva)
        print('  cmp @ 0x%X, jnz @ 0x%X, xor @ 0x%X' % (
            off2rva(m['cmp_off']), off2rva(m['jnz_off']), off2rva(m['xor_off'])))
        print('  lea1 @ 0x%X, lea2 @ 0x%X' % (
            off2rva(m['lea1_off']), off2rva(m['lea2_off'])))
        # 反汇编上下文
        start = m['cmp_off']
        end = m['lea2_off'] + 20
        chunk = text_data[start:end]
        va = IMAGE_BASE + off2rva(start)
        print('  disasm:')
        for insn in md.disasm(chunk, va):
            print('    %X: %s %s' % (insn.address, insn.mnemonic, insn.op_str))
            if insn.mnemonic == 'ret':
                break
