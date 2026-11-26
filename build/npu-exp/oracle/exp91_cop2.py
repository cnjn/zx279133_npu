"""exp91: (A) coprocessor ops 8, 9, 11, 12, 15 with different table-id fields,
(B) shift/rotate ops 0x024/0x025 on narrow fields, (C) the SR1010 'movbit' word."""
import json
import random
import sys
import bench
sys.path.insert(0, str(bench.HERE.parents[1] / 'npu-re'))
from npisa import put  # noqa: E402
from exp90_alu import alu

random.seed(91)
KEYFILL = [f'kmov key[{4 * i}..{4 * i + 3}], r{20 + i}' for i in range(12)] + ['nop']
TIDS = (0, 1, 2, 3, 4, 5, 6, 7, 8, 16, 32, 64, 128, 255)
b = bench.Bench('exp91')
blk = {}
for op in (8, 9, 11, 12, 15):
    for t in TIDS:
        blk[('cop', op, t)] = b.block(KEYFILL + [f'lkup s0, {op:#x}, #{t}', 'nop', 'nop'], 'hi')
for op12 in (0x024, 0x025):
    for width, amt, lo in ((8, 3, 0), (16, 5, 0), (12, 4, 4), (32, 3, 0)):
        w = alu(op12, 1, 0, width, width, imm=amt, dst=28 * 32 + lo, src=20 * 32 + lo)
        blk[('sh', op12, width, amt, lo)] = b.block(['movw r28, 0xdeadbeef', 'nop', f'.word {w:016x}', 'nop', 'nop'], 'hi')
# SR1010 PC 2285: 06295c500a000c00 = old 'movbit r5[14], r10[0]'
for r10 in (0, 1):
    blk[('movbit', r10)] = b.block([f'movw r10, {r10:#x}', 'movw r5, 0x0', 'nop', '.word 06295c500a000c00', 'nop', 'nop',
                                    'mov r28, r5', 'nop'], 'hi')
    blk[('movbit1', r10)] = b.block([f'movw r10, {r10:#x}', 'movw r5, 0xffffffff', 'nop', '.word 06295c500a000c00', 'nop',
                                     'nop', 'mov r28, r5', 'nop'], 'hi')

if __name__ == '__main__':
    print(b.install())
    keys = list(blk)
    fixed = [0x11111111 * (j + 1) & 0xffffffff for j in range(12)]
    fixed[0] = 0x00002011  # small length-like prefix for crc-style ops
    sr = b.run([(blk[k], fixed) for k in keys], window=1, rounds=1)
    bad = {k for k, r in zip(keys, sr) if r is None}
    print('health after safety', bench.health())
    vec, meta = [], []
    for k in keys:
        if k in bad:
            continue
        for i in range(12):
            ins = fixed if i < 3 else [random.getrandbits(32) for _ in range(12)]
            vec.append((blk[k], ins))
            meta.append((k, ins))
    res = b.run(vec, window=16, rounds=1)
    b.restore()
    json.dump({'bad': [list(k) for k in bad], 'rows': [(list(k), ins, r) for (k, ins), r in zip(meta, res)]},
              open('runs/exp91.json', 'w'))
    print('replied blocks:', sorted({tuple(k) for k, _, r in [(m[0], m[1], x) for m, x in zip(meta, res)] if r}, key=str)[:80])
    print('health', bench.health())
