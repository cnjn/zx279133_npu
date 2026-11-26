"""exp71: which of r32..r63 can be written, and which words condition selectors 8..11, 15 read."""
import json, random
import bench
random.seed(71)
b = bench.Bench('exp71')
V = {r: random.getrandbits(32) | 0x80000001 for r in range(64)}
blocks = {}
for x in range(32, 64):
    w = [f'movi32 r30, {V[x]:#x}', 'nop', f'mov r{x}, r30', 'nop', 'nop']
    blocks[(x, 'cs')] = b.block(w, 'c:200:300')
    blocks[(x, 'top')] = b.block(w, 'top' if x < 60 else 'self') if x < 60 else b.block(w + [f'st h1+48, r{x}', 'br reflect'], 'self')
    blocks[(x, 'hi')] = b.block(w, 'hi')
# selector 15 vs r41 timing
blocks[('t', 0)] = b.block(['st h1+48, r41', 'st h1+52, r41', 'nop', 'nop', 'st h1+56, r41', 'movi32 r30, 0x0']
                           + [f'[c{0x3c0 + i:03x}] movi r30[{i}], 0x1' for i in range(32)]
                           + ['nop', 'st h1+60, r30', 'st h1+64, r41', 'st h1+68, r0', 'st h1+72, r0', 'br reflect'], 'self')
print(b.install())
vec = [(k, [0] * 12) for k in blocks.values()]
res = b.run(vec, window=1)
print(b.last_err)
json.dump({'V': V, 'res': {f'{a}|{p}': r for (a, p), r in zip(blocks, res)}}, open('runs/exp71.json', 'w'))
print(b.restore())
