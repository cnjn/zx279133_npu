"""exp79: confirm general encodings.
  A. cset compare codes (bit 13, bits 12:10) on r20[15:0] vs imm / r21
  B. clr (0x001) bit 16 and widths
  C. wide immediate (0x000, bit 51 set): widths and destinations
  D. jump to register (0x0508 form) with src r30
  E. fset2 (0x02a) enable=0 with invert=0/1, and .x (bit 15)
"""
import json
import random
import sys
import bench
sys.path.insert(0, str(bench.HERE.parents[1] / 'npu-re'))
from npisa import put  # noqa: E402

random.seed(79)
b = bench.Bench('exp79')
T = {}


def cset_word(code_hi, code_lo, kreg, idx, src, imm, width):
    # 028a/028b: dst r(8 + bits 48:46).idx, src bits 40:30, imm 29:14, code bit13 + 12:10, width-1 4:0
    w = 0x028a << 48
    w &= ~(1 << 48)
    w |= put(kreg >> 2, 48, 48) | put(kreg & 3, 47, 46) | put(idx, 45, 41) | put(src, 40, 30)
    w |= put(imm, 29, 14) | put(code_hi, 13, 13) | put(code_lo, 12, 10) | put(width - 1, 4, 0)
    return w


def csetr_word(code_hi, code_lo, kreg, idx, src, src2, width):
    w = (0x068a << 48) & ~(1 << 48)
    w |= put(kreg >> 2, 48, 48) | put(kreg & 3, 47, 46) | put(idx, 45, 41) | put(src, 40, 30)
    w |= put(src2, 29, 19) | put(code_hi, 13, 13) | put(code_lo, 12, 10) | put(width - 1, 9, 5) | put(width - 1, 4, 0)
    return w


# A: write result into r9 bit 5 (kreg 1) and r12 bit 7 (kreg 4)
for hi in (0, 1):
    for lo in range(8):
        for imm in (0x0, 0x1234, 0xffff):
            w = cset_word(hi, lo, 1, 5, 20 * 32, imm, 16)
            T[f'A_cset_{hi}{lo}_{imm:x}'] = (['movi32 r9, 0x0', 'nop', f'.word {w:016x}', 'nop'], 'lo')
        w = csetr_word(hi, lo, 4, 7, 20 * 32, 21 * 32, 16)
        T[f'A_csetr_{hi}{lo}'] = (['movi32 r12, 0x0', 'nop', f'.word {w:016x}', 'nop'], 'lo')

# B: clr with bit 16 set / not, widths 8/16/32 on r28 (=0x...)
for b16 in (0, 1):
    for width in (8, 16, 32):
        dst = 28 * 32 + 4
        w = (0x001 << 52) | put(dst, 51, 41) | put(b16, 16, 16) | put(width - 1, 4, 0)
        T[f'B_clr_b{b16}_w{width}'] = ([f'.word {w:016x}', 'nop'], 'hi')

# C: wide immediate: bit 51 set, dst bits 50:41, width bits 4:0; imm as movi32 layout
def movw(dst, imm, width):
    return ((1 << 51) | put(dst, 50, 41) | put(imm >> 8, 40, 17) | put(imm >> 7 & 1, 16, 16)
            | put(imm & 0x7f, 14, 8) | put(width - 1, 4, 0))
for dst, width in ((28 * 32, 32), (28 * 32, 23), (28 * 32, 8), (28 * 32 + 4, 8), (28 * 32 + 16, 16), (28 * 32 + 20, 12)):
    w = movw(dst, 0xdeadbeef & ((1 << width) - 1) if width < 32 else 0xdeadbeef, width)
    T[f'C_movw_{dst}_{width}'] = ([f'.word {w:016x}', 'nop'], 'hi')

# D: jump to register r30[15:0] (0x0508 = mov form with dst 1024): target = label @t
T['D_jr_r30'] = (['movi32 r29, 0x0', 'movi r30[15:0], 0x0 ; JRT', 'nop',
                  '.word %016x' % (0x0508000800000520 & ~(0x7ff << 30) | (30 * 32 << 30) | 15),
                  'movi r29[3:0], 0x1', 'br page_hi', '@t:', 'movi r29[3:0], 0x2'], 'hi')

# E: fset2 variants based on word A (move1: src 4:0, inv 5, en 6, dst 11:7)
A = 0x02aa34cd7adb04d8
for en in (0, 1):
    for inv in (0, 1):
        w = A & ~(0b11 << 5) | (inv << 5) | (en << 6)
        T[f'E_fset2_en{en}_inv{inv}'] = (['movi32 r8, 0x5a5a5a5a', 'nop', f'.word {w:016x}', 'nop'], 'lo')
T['E_fset2_x'] = (['movi32 r8, 0x5a5a5a5a', 'nop', f'.word {A | (1 << 15):016x}', 'nop'], 'lo')

if __name__ == '__main__':
    blocks = {}
    for n, (lines, pg) in T.items():
        blocks[n] = b.block(lines, pg)
    # resolve the jr target: label of block D's '@t'
    k = blocks['D_jr_r30']
    b.build()
    tgt = b.labels[f'b{k}_t']
    lines, pg = b.blocks[k]
    b.blocks[k] = ([f'movi r30[15:0], {tgt:#x}' if 'JRT' in l else l for l in lines], pg)
    print(b.install())
    names = list(blocks)
    sr = b.run([(blocks[n], [0] * 12) for n in names], window=1, rounds=1)
    bad = [n for n, r in zip(names, sr) if r is None]
    print('no reply:', bad)
    rng = random.Random(1)
    vec, meta = [], []
    edge = [0, 1, 0x1234, 0x1233, 0x1235, 0xffff, 0x8000, 0x7fff]
    for n in names:
        if n in bad:
            continue
        reps = 60 if n.startswith('A_') or n.startswith('E_') else 3
        for i in range(reps):
            if i < 24:
                a, c = edge[i % 8], edge[i // 8 % 8]
            else:
                a, c = rng.getrandbits(16), rng.getrandbits(16)
            ins = [0x77770000 | a, 0x66660000 | c] + [rng.getrandbits(32) for _ in range(6)] + [0xffffffff, 0, 0, 0]
            vec.append((blocks[n], ins))
            meta.append((n, ins))
    res = b.run(vec, window=32, rounds=2)
    b.restore()
    json.dump({'bad': bad, 'rows': [(n, ins, r) for (n, ins), r in zip(meta, res)]}, open('runs/exp79.json', 'w'))
    print(bench.health())
