"""exp70: map the 10-bit condition space onto registers.
Every writable register gets a distinct random value, then all 1024 raw condition
codes are sampled ([cNNN] movi) and matched against register bits."""
import json
import random
import sys
import bench

random.seed(70)
V = {r: random.getrandbits(32) for r in range(64)}
SKIP = {1, 6}          # r1 = link (dispatch), r6 = header pointers


def setup(hi=False):
    L = []
    for r in range(32):
        if r not in SKIP:
            L.append(f'movi32 r{r}, {V[r]:#x}')
    if hi:
        for r in range(32, 60):
            L += [f'movi32 r30, {V[r]:#x}', 'nop', f'mov r{r}, r30']
        L.append(f'movi32 r30, {V[30]:#x}')
    L.append('nop')
    return L


b = bench.Bench('exp70')
blocks = {}
for name, st in (('base', []), ('lo', setup()), ('hi', setup(True))):
    for page in ('c0', 'c1', 'lo', 'hi', 'top'):
        blocks[(name, page)] = b.block(st, page)
for r in (60, 61, 62, 63):
    blocks[('st', r)] = b.block([f'st h1+48, r{r}', 'br reflect'], 'self')
print(b.install())
vec = [(k, [V[20 + i] for i in range(12)]) for k in blocks.values()]
res = b.run(vec + vec, window=1)
print(b.last_err)
out = {f'{a}|{p}': r for (a, p), r in zip(list(blocks) + list(blocks), res)}
json.dump({'V': V, 'res': {k: v for k, v in out.items()}}, open('runs/exp70.json', 'w'), default=str)
print(b.restore())
