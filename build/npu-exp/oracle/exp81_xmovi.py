"""exp81: xmovi immediate layout. Look up our 32-bit table #201 (64 entries,
entry i = pattern) with idx[0..3] written by raw xmovi words carrying a value in
different bit positions."""
import json
import sys
import bench
sys.path.insert(0, str(bench.HERE.parents[1] / 'npu-re'))
from npisa import parse, put  # noqa
from exp80_eram import pattern

base = parse('xmovi idx[0..3], 0x0', 0, {})
tests = {}
for bitpos in range(12, 41):
    w = base | (1 << bitpos)
    tests[f'bit{bitpos}'] = w
# hypothesis: imm = bits 40:12 (like kmovi)
for v in (1, 2, 5, 9, 33, 63):
    tests[f'k_{v}'] = (base & ~(((1 << 29) - 1) << 12)) | (v << 12)
b = bench.Bench('exp81')
blk = {n: b.block([f'.word {w:016x}', 'nop', 'lkup s1, 0x2, #201', 'nop'], 'hi') for n, w in tests.items()}
print(b.install())
names = list(blk)
res = b.run([(blk[n], []) for n in names], window=1, rounds=1)
b.restore()
pat = {pattern(32, i)[0]: i for i in range(64)}
out = {}
for n, r in zip(names, res):
    out[n] = None if r is None else r['r36']
    print(n, hex(tests[n]), 'drop' if r is None else f'r36={r["r36"]:#x} -> index {pat.get(r["r36"])}')
json.dump(out, open('runs/exp81.json', 'w'))
print(bench.health())
