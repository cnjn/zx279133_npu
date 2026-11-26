"""exp86: lookup op codes 0..31 (fam bits 4:0) on table #201 / slot 1, one packet each.
Dumps r32..r59 and condition selectors; the SE request counters are read per op."""
import json
import re
import bench
from exp75_se import se_stats
CLEAN = []
for S in range(4):
    CLEAN += ['xmovi idx[0..3], 0x0', 'nop', f'lkup s{S}, 0x2, #34']
SETUP = CLEAN + ['movw r29, 0x5', 'nop', 'xmov idx[0..3], r29', 'kmov key[0..3], r20', 'kmov key[4..7], r21',
                 'movw r30, 0x1b000160', 'nop', 'xmov idx[128..131], r30', 'xmovi idx[132..135], 0x0',
                 'xmovi idx[136..139], 0x0', 'nop']
SKIP = {0, 1}   # send / dup end or fork the thread
b = bench.Bench('exp86')
blk = {}
for op in range(32):
    if op in SKIP:
        continue
    for pg in ('hi', 'top'):
        blk[(op, pg)] = b.block(SETUP + [f'lkup s1, {op:#x}, #201', 'nop', 'nop'], pg)
print(b.install())
out = {}
prev = se_stats()
for op in range(32):
    if op in SKIP:
        continue
    r = b.run([(blk[(op, 'hi')], [0xa1a2a3a4, 2]), (blk[(op, 'top')], [0xa1a2a3a4, 2])], window=1, rounds=1)
    cur = se_stats()
    d = {k: cur[k] - prev.get(k, 0) for k in cur if 'se' in k and cur[k] != prev.get(k, 0) and 'rsp' not in k}
    prev = cur
    regs = {}
    for x in r:
        if x: regs.update({int(k[1:]): v for k, v in x.items()})
    out[op] = {'regs': regs, 'se': d, 'replies': sum(x is not None for x in r)}
    ch = ' '.join(f'r{k}={v:08x}' for k, v in sorted(regs.items()) if 32 <= k < 48 and v not in (0, 0x03272000))
    print(f'op {op:2} replies {out[op]["replies"]} se {d} | {ch}')
b.restore()
json.dump(out, open('runs/exp86.json', 'w'))
print(bench.health())
