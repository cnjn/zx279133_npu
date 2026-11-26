"""exp82: low bits of the xmovi immediate. idx preloaded with 40 via xmov; xmovi word with
value bit 3 set (word bit 15) plus one extra bit 0..14 flipped; also byte counts 1/2."""
import json
import sys
import bench
sys.path.insert(0, str(bench.HERE.parents[1] / 'npu-re'))
from npisa import parse  # noqa
from exp80_eram import pattern
base = parse('xmovi idx[0..3], 0x0', 0, {}) | (1 << 15)
tests = {f'b{k}': base ^ (1 << k) for k in range(0, 15) if k != 15}
tests['base8'] = base
# byte count variants: write only idx[3] / idx[2..3]
tests['n1_idx3'] = parse('xmovi idx[3..3], 0x0', 0, {}) | (1 << 15)
tests['n2_idx2'] = parse('xmovi idx[2..3], 0x0', 0, {}) | (1 << 15)
b = bench.Bench('exp82')
blk = {n: b.block(['movw r29, 0x28', 'nop', 'xmov idx[0..3], r29', f'.word {w:016x}', 'nop',
                   'lkup s1, 0x2, #201', 'nop'], 'hi') for n, w in tests.items()}
print(b.install())
names = list(blk)
res = b.run([(blk[n], []) for n in names], window=1, rounds=1)
b.restore()
pat = {pattern(32, i)[0]: i for i in range(64)}
for n, r in zip(names, res):
    print(n, hex(tests[n]), 'drop' if r is None else f'index {pat.get(r["r36"])}')
print(bench.health())
