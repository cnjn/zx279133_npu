"""exp90: (1) the 16 modes of the logic ops 0x022 (imm) / 0x062 (reg), (2) shift ops
0x024/0x025 (imm amount) and 0x064/0x065 (register amount) with modes 0..15,
(3) coprocessor lookup ops 8..16 with table 0 into slot 0 / slot 2.
Safety pass first (one packet per block), then random vectors."""
import json
import random
import sys
import bench
sys.path.insert(0, str(bench.HERE.parents[1] / 'npu-re'))
from npisa import put  # noqa: E402

random.seed(90)
D, A, B = 28 * 32, 20 * 32, 21 * 32
IMM = 0x5a3c
SH = 5


def alu(op12, bit51, mode, width, swidth, imm=None, src2=None, dst=D, src=A):
    w = (op12 << 52) | (bit51 << 51) | put(dst, 50, 41) | put(src, 40, 30) | put(mode, 13, 10)
    w |= put(swidth - 1, 9, 5) | put(width - 1, 4, 0)
    if imm is not None:
        w |= put(imm, 29, 14)
    if src2 is not None:
        w |= put(src2, 29, 19)
    return w


T = {}
for m in range(16):
    T[('logic_reg', m)] = alu(0x062, 1, m, 32, 32, src2=B)
    T[('logic_imm', m)] = alu(0x022, 1, m, 16, 16, imm=IMM)
    T[('shl_imm', m)] = alu(0x024, 1, m, 32, 32, imm=SH)
    T[('shr_imm', m)] = alu(0x025, 1, m, 32, 32, imm=SH)
    T[('shl_reg', m)] = alu(0x064, 1, m, 32, 5, src2=B)
    T[('shr_reg', m)] = alu(0x065, 1, m, 32, 5, src2=B)
T[('logic_reg_b51_0', 0)] = alu(0x062, 0, 0, 32, 32, src2=B)
T[('logic_imm_b51_0', 0)] = alu(0x022, 0, 0, 16, 16, imm=IMM)

KEYFILL = [f'kmov key[{4 * i}..{4 * i + 3}], r{20 + i}' for i in range(12)] + ['nop']
COP = {}
for op in range(8, 17):
    COP[(op, 0)] = KEYFILL + [f'lkup s0, {op:#x}, #0', 'nop', 'nop']
    COP[(op, 2)] = KEYFILL + [f'lkup s2, {op:#x}, #0', 'nop', 'nop']

if __name__ == '__main__':
    b = bench.Bench('exp90')
    blk = {}
    for k, w in T.items():
        blk[('alu',) + k] = b.block(['movw r28, 0xdeadbeef', 'nop', f'.word {w:016x}', 'nop', 'nop'], 'hi')
    for (op, s), lines in COP.items():
        blk[('cop', op, s)] = b.block(lines, 'hi' if s == 0 else 'top')
    print(len(b.blocks), 'blocks')
    print(b.install())
    keys = list(blk)
    sr = b.run([(blk[k], [random.getrandbits(32) for _ in range(12)]) for k in keys], window=1, rounds=1)
    bad = [k for k, r in zip(keys, sr) if r is None]
    print('no reply in safety pass:', bad)
    print('health after safety', bench.health())
    vec, meta = [], []
    for k in keys:
        if k in bad:
            continue
        if k[0] == 'alu':
            for i in range(48):
                ins = [random.getrandbits(32) for _ in range(12)]
                if i < 8:
                    ins[1] = [0, 1, 31, 32, 33, 0xffffffff, 16, 4][i]
                vec.append((blk[k], ins))
                meta.append((k, ins))
        else:
            fixed = [0x11111111 * (j + 1) & 0xffffffff for j in range(12)]
            for i in range(8):
                vec.append((blk[k], fixed))
                meta.append((k + ('fixed',), fixed))
            for i in range(8):
                ins = [random.getrandbits(32) for _ in range(12)]
                vec.append((blk[k], ins))
                meta.append((k + ('rand',), ins))
    res = b.run(vec, window=1 if len(vec) < 50 else 16, rounds=1)
    b.restore()
    json.dump({'bad': [list(k) for k in bad],
               'rows': [(list(k), ins, r) for (k, ins), r in zip(meta, res)]}, open('runs/exp90.json', 'w'))
    print('health', bench.health())
