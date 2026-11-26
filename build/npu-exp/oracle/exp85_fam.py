"""exp85: fam bits of an eRAM lookup (#201, 32-bit, entry i = pattern(i)), index 5.
fam = 2 | (1 << b) for b in 3..22, plus 0x400002 / 0x200002 / 0x600002. Slots cleaned
first (all four from #34[0]); dump r32..r59; afterwards read #201 entries 0..7 back."""
import json
import bench
from exp80_eram import pattern
CLEAN = []
for S in range(4):
    CLEAN += ['xmovi idx[0..3], 0x0', 'nop', f'lkup s{S}, 0x2, #34']
fams = {f'b{b}': 2 | (1 << b) for b in range(3, 23)}
fams.update({'f2': 2, 'f200002': 0x200002, 'f400002': 0x400002, 'f600002': 0x600002})
b = bench.Bench('exp85')
blk = {}
for n, fam in fams.items():
    for pg in ('hi', 'top'):
        blk[(n, pg)] = b.block(CLEAN + ['movw r29, 0x5', 'nop', 'xmov idx[0..3], r29', 'nop',
                                        f'lkup s1, {fam:#x}, #201', 'nop'], pg)
print(b.install())
keys = list(blk)
res = b.run([(blk[k], []) for k in keys], window=1, rounds=1)
b.restore()
pat = {pattern(32, i)[0]: i for i in range(64)}
out = {}
for (n, pg), r in zip(keys, res):
    out.setdefault(n, {})[pg] = r
for n in fams:
    d = out[n]
    if d.get('hi') is None and d.get('top') is None:
        print(f'{n:8} {fams[n]:#08x} drop'); continue
    regs = {}
    for pg in ('hi', 'top'):
        if d.get(pg): regs.update({int(k[1:]): v for k, v in d[pg].items()})
    ch = ' '.join(f'r{r}={v:08x}' + (f'(i{pat[v]})' if v in pat else '')
                  for r, v in sorted(regs.items()) if 32 <= r < 48 and v not in (0, 0x03272000))
    print(f'{n:8} {fams[n]:#08x} {ch}')
print(bench.ser('cd /sys/devices/platform/np/se_debug; dmesg -c >/dev/null; for i in 0 1 2 3 4 5 6 7; do echo 201 $i 1 > cpu_get_eram_by_table_width; done; dmesg -c | grep 0x', 60))
json.dump({n: out[n] for n in out}, open('runs/exp85.json', 'w'))
print(bench.health())
