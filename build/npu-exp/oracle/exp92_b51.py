"""exp92: bit 51 clear variants: shifts 0x024/0x025 (imm 5) and 0x064/0x065 (reg amount),
logic 0x062/0x022 modes 1..7; widths 32 and 8."""
import json
import random
import bench
from exp90_alu import alu, IMM, B
random.seed(92)
T = {}
for op12 in (0x024, 0x025):
    T[('shimm', op12, 32)] = alu(op12, 0, 0, 32, 32, imm=5)
    T[('shimm', op12, 8)] = alu(op12, 0, 0, 8, 8, imm=3)
for op12 in (0x064, 0x065):
    T[('shreg', op12, 32)] = alu(op12, 0, 0, 32, 5, src2=B)
for m in range(1, 8):
    T[('logreg', m, 32)] = alu(0x062, 0, m, 32, 32, src2=B)
    T[('logimm', m, 16)] = alu(0x022, 0, m, 16, 16, imm=IMM)
b = bench.Bench('exp92')
blk = {k: b.block(['movw r28, 0xdeadbeef', 'nop', f'.word {w:016x}', 'nop', 'nop'], 'hi') for k, w in T.items()}
print(b.install())
keys = list(blk)
sr = b.run([(blk[k], [0x12345678, 3]) for k in keys], window=1, rounds=1)
bad = {k for k, r in zip(keys, sr) if r is None}
print('no reply:', bad, bench.health())
vec, meta = [], []
for k in keys:
    if k in bad:
        continue
    for i in range(40):
        ins = [random.getrandbits(32), random.getrandbits(32) if i >= 6 else [0, 1, 3, 8, 31, 32][i]] + [0] * 10
        vec.append((blk[k], ins)); meta.append((k, ins))
res = b.run(vec, window=16, rounds=1)
b.restore()
json.dump([(list(k), ins, r and r['r28']) for (k, ins), r in zip(meta, res)], open('runs/exp92.json', 'w'))
print(bench.health())
