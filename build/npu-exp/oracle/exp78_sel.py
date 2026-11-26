"""exp78: what do condition selectors 8..11 read? Fill key / idx buffers with distinct
input words, with and without lookups."""
import json
import bench
P = []
for S in range(4):
    P += ['xmovi idx[0..3], 0x0', 'nop', f'lkup s{S}, 0x2, #34']
P += ['nop']
KEYS = [f'kmov key[{4*i}..{4*i+3}], r{20+i}' for i in range(12)]
IDX0 = [f'xmov idx[{4*i}..{4*i+3}], r{20+i}' for i in range(12)]
IDX128 = [f'xmov idx[{128+4*i}..{128+4*i+3}], r{20+i}' for i in range(3)]
STAT = ['movi32 r30, 0x1b000160', 'nop', 'xmovi idx[132..135], 0x0', 'xmovi idx[136..139], 0x0',
        'xmov idx[128..131], r30', 'nop', 'lkup s2, 0x3, #48']
TESTS = {'P': P, 'P_key': P + KEYS, 'P_idx0': P + IDX0, 'P_idx128': P + IDX128,
         'P_stat_s2': P + STAT, 'P_key_stat_s2': P + KEYS + STAT,
         'P_hashmiss_s1': P + ['kmov key[0..3], r21', 'kmov key[4..7], r22', 'nop', 'lkup s1, 0x4, #50'],
         'P_crc_s1': P + KEYS + ['nop', 'crc32 s1'],
         'P_crc_s3': P + KEYS + ['nop', 'crc32 s3']}
if __name__ == '__main__':
    b = bench.Bench('exp78')
    blocks = {(n, pg): b.block(t + ['nop', 'nop'], pg) for n, t in TESTS.items() for pg in ('hi', 'top', 'c:200:300')}
    print(b.install())
    keys = list(blocks)
    ins = [0xa0000000 | (i << 24) | 0x00a5a5 | (i << 8) for i in range(12)]
    sr = b.run([(blocks[k], ins) for k in keys], window=1, rounds=1)
    bad = [k for k, r in zip(keys, sr) if r is None]
    print('no reply:', bad)
    good = [k for k in keys if k not in bad]
    res = b.run([(blocks[k], ins) for k in good for _ in range(6)], window=16, rounds=2)
    out = {}
    for k, r in zip([k for k in good for _ in range(6)], res):
        out.setdefault(f'{k[0]}|{k[1]}', []).append(r)
    b.restore()
    json.dump({'ins': ins, 'res': out}, open('runs/exp78.json', 'w'))
    print(bench.health())
