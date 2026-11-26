"""exp77: lookup slots with a clean start (all 4 slots loaded from #34[0] first)."""
import json
import bench

P = []
for S in range(4):
    P += ['xmovi idx[0..3], 0x0', 'nop', f'lkup s{S}, 0x2, #34']
P += ['nop']
TESTS = {'P': []}
for S in range(4):
    TESTS[f'op01.7_s{S}'] = [f'op01.7 s{S}, 32']
    TESTS[f'op01.0_s{S}_16'] = [f'op01.0 s{S}, 16']
for sub in range(8):
    TESTS[f'op01.{sub}_s1'] = [f'op01.{sub} s1, 32']
TESTS['op01.1.b_s1'] = ['op01.1.b s1, 32']
TESTS['op01.5.a_s1'] = ['op01.5.a s1, 32']
TESTS['hashmiss_s1'] = ['kmov key[0..3], r21', 'kmov key[4..7], r22', 'nop', 'lkup s1, 0x4, #50']
TESTS['eram1_s1'] = ['xmovi idx[0..3], 0x1', 'nop', 'lkup s1, 0x2, #34']
TESTS['eram2_s1'] = ['xmovi idx[0..3], 0x2', 'nop', 'lkup s1, 0x2, #34']
TESTS['stat48_s2'] = ['movi r30[15:0], 0x160', 'movi r30[27:23], 0x16', 'movi r30[28], 0x1',
                      'xmovi idx[132..135], 0x0', 'xmovi idx[136..139], 0x0', 'xmov idx[128..131], r30', 'nop',
                      'lkup s2, 0x3, #48']
PAGES = ('hi', 'top', 'c0', 'c1')
if __name__ == '__main__':
    b = bench.Bench('exp77')
    blocks = {(n, pg): b.block(P + t + ['nop'], pg) for n, t in TESTS.items() for pg in PAGES}
    print(b.install())
    keys = list(blocks)
    sr = b.run([(blocks[k], [0, 0x11223344, 0x55667788] + [0] * 9) for k in keys], window=1, rounds=1)
    bad = [k for k, r in zip(keys, sr) if r is None]
    print('no reply:', bad)
    good = [k for k in keys if k not in bad]
    vec = [(blocks[k], [0, 0x11223344, 0x55667788] + [0] * 9) for k in good for i in range(8)]
    res = b.run(vec, window=16, rounds=2)
    out = {}
    for k, r in zip([k for k in good for i in range(8)], res):
        out.setdefault(f'{k[0]}|{k[1]}', []).append(r)
    b.restore()
    json.dump({'bad': [list(k) for k in bad], 'res': out}, open('runs/exp77.json', 'w'))
    print(bench.health())
