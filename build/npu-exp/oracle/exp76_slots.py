"""exp76: lookup slots. eRAM #34 / hash #50 lookups into slot 0..3, with and without
op01 before/after; dump r20..r59 and condition selectors 8..11 (codes 0x200..0x2ff)."""
import json
import sys
import bench

ERAM = ['xmovi idx[0..3], 0x0', 'nop', 'lkup s{S}, 0x2, #34']
HASH_HIT = ['movi32 r20, 0x0', 'nop', 'kld key[0..5], h1+0', 'kmov key[6..7], r20[15:0]', 'nop', 'lkup s{S}, 0x4, #50']
HASH_MISS = ['kmov key[0..3], r21', 'kmov key[4..7], r22', 'nop', 'lkup s{S}, 0x4, #50']
TESTS = {}
for S in range(4):
    TESTS[f'none_s{S}'] = []
    TESTS[f'eram_s{S}'] = ERAM
    TESTS[f'hashhit_s{S}'] = HASH_HIT
    TESTS[f'hashmiss_s{S}'] = HASH_MISS
    TESTS[f'eram_op01after_s{S}'] = ERAM + ['op01.7 s{S}, 32']
    TESTS[f'op01before_eram_s{S}'] = ['op01.7 s{S}, 32'] + ERAM
    TESTS[f'op01only_s{S}'] = ['op01.7 s{S}, 32']
PAGES = ('hi', 'top', 'c:200:300')

if __name__ == '__main__':
    b = bench.Bench('exp76')
    blocks = {}
    for n, t in TESTS.items():
        S = int(n[-1])
        lines = [x.replace('{S}', str(S)) for x in t] + ['nop']
        for pg in PAGES:
            blocks[(n, pg)] = b.block(lines, pg)
    print(b.install())
    keys = list(blocks)
    # safety: one packet each, sequential
    sr = b.run([(blocks[k], [0, 0x11223344, 0x55667788] + [0] * 9) for k in keys], window=1, rounds=1)
    bad = [k for k, r in zip(keys, sr) if r is None]
    print('no reply:', bad)
    good = [k for k in keys if k not in bad]
    vec = [(blocks[k], [0, 0x11223344, 0x55667788 + i] + [0] * 9) for k in good for i in range(4)]
    res = b.run(vec, window=16, rounds=2)
    out = {}
    for (k, r) in zip([k for k in good for i in range(4)], res):
        out.setdefault(f'{k[0]}|{k[1]}', []).append(r)
    b.restore()
    json.dump({'bad': [list(k) for k in bad], 'res': out}, open('runs/exp76.json', 'w'))
    print(bench.health())
