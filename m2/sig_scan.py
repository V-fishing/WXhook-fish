# -*- coding: utf-8 -*-
"""sig_scan.py — 在 PE 文件上执行带 ?? 通配的特征码搜索 (M2)
用法: python sig_scan.py <pe文件> "<sig1>" ["<sig2>" ...]
输出: 命中的文件偏移 + RVA + 运行时 VA(需 -b 指定基址)
"""
import sys
import struct
import json

PAGE_SZ = 4096


def parse_pattern(sig_str):
    """'48 83 EC ?? 4C ??' -> [0x48, 0x83, 0xEC, None, 0x4C, None]"""
    parts = sig_str.strip().split()
    return [None if p == '??' else int(p, 16) for p in parts]


def sunday_search(data, pattern):
    """Sunday 算法, 支持通配符 None。返回所有命中偏移。"""
    n = len(data)
    m = len(pattern)
    if m == 0 or n < m:
        return []

    # 移动表: 每个字节值 -> 该值在模式中最后一次出现位置距末尾的距离(通配符=永远命中)
    shift = {}
    for i, b in enumerate(pattern):
        shift[b] = m - 1 - i  # None 也会存进来(key=None 表示通配)
    # 对具体字节的 shift 取与通配符的最小值(通配符匹配一切, 移动距离取两者较小)
    wild_shift = m - 1 - max((i for i, b in enumerate(pattern) if b is None), default=-1) if any(b is None for b in pattern) else None

    hits = []
    i = 0
    while i <= n - m:
        j = m - 1
        while j >= 0:
            if pattern[j] is not None and data[i + j] != pattern[j]:
                break
            j -= 1
        if j < 0:
            hits.append(i)
            i += m
            continue
        # 失配: 按 data[i+m] 查移动表
        nxt = data[i + m] if i + m < n else None
        s1 = shift.get(nxt, None)
        s2 = wild_shift
        cands = [x for x in (s1, s2) if x is not None]
        move = max(min(cands) if cands else m - 0, 1) if cands else m
        # Sunday 规则: 移动 = m - lastpos, 通配情况下最小位移
        i += max((min(cands) if cands else 0) + 1 if False else 1, 1)
    return hits


def sunday_search_simple(data, pattern):
    """朴素但正确的通配搜索(198MB 也能在可接受时间跑完, 用 bytes.find 加速)"""
    # 提取锚点: 模式中最长的具体字节连续段
    hits = []
    n = len(data)
    m = len(pattern)
    if m == 0:
        return hits
    # 找最长连续非通配段作为锚
    best_start, best_len, cur_start, cur_len = 0, 0, 0, 0
    for i, b in enumerate(pattern):
        if b is not None:
            if cur_len == 0:
                cur_start = i
            cur_len += 1
            if cur_len > best_len:
                best_len, best_start = cur_len, cur_start
        else:
            cur_len = 0
    if best_len < 2:
        # 锚太短, 全暴力(慢)
        rng = range(0, n - m)
        for i in rng:
            ok = True
            for j in range(m):
                if pattern[j] is not None and data[i + j] != pattern[j]:
                    ok = False
                    break
            if ok:
                hits.append(i)
        return hits
    anchor = bytes(b for b in pattern[best_start:best_start + best_len] if b is not None)
    anchor_pat_off = best_start
    pos = 0
    while True:
        idx = data.find(anchor, pos)
        if idx < 0:
            break
        hit = idx - anchor_pat_off
        if hit >= 0 and hit + m <= n:
            ok = True
            for j in range(m):
                if pattern[j] is not None and data[hit + j] != pattern[j]:
                    ok = False
                    break
            if ok:
                hits.append(hit)
        pos = idx + 1
    return hits


def load_pe_sections(path):
    data = open(path, 'rb').read()
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    coff = e_lfanew + 4
    num_sections = struct.unpack_from('<H', data, coff + 2)[0]
    opt_size = struct.unpack_from('<H', data, coff + 16)[0]
    opt_off = coff + 20
    image_base = struct.unpack_from('<Q', data, opt_off + 24)[0]
    secs = []
    sec_off = opt_off + opt_size
    for i in range(num_sections):
        o = sec_off + i * 40
        name = data[o:o+8].rstrip(b'\x00').decode(errors='replace')
        vsize, vaddr, rsize, rptr = struct.unpack_from('<IIII', data, o + 8)
        secs.append((name, vaddr, vsize, rptr, rsize))
    return data, image_base, secs


def off2rva(off, secs):
    for name, vaddr, vsize, rptr, rsize in secs:
        if rptr <= off < rptr + rsize:
            return vaddr + (off - rptr)
    return None


def main():
    pe_path = sys.argv[1]
    base = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0
    sigs = sys.argv[3:]
    data, image_base, secs = load_pe_sections(pe_path)
    print('PE: %s  size=%.1fMB  image_base=0x%X' % (pe_path.split('\\')[-1], len(data)/1048576, image_base))
    for sig in sigs:
        pat = parse_pattern(sig)
        hits = sunday_search_simple(data, pat)
        print('sig [%s...] hits: %d' % (sig[:40], len(hits)))
        for h in hits[:10]:
            rva = off2rva(h, secs)
            va = image_base + rva if rva else 0
            runva = base + rva if (base and rva) else 0
            print('   file=0x%X  rva=0x%X  va=0x%X  runtimeVA=0x%X' % (h, rva or 0, va, runva))


if __name__ == '__main__':
    main()
