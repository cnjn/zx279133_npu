"""exp89: op 5 (hash write-back) semantics on #210.
  A. overwrite an existing key (CPU-inserted a1a2a3a4/00000001) with new data
  B. write the same new key twice with different data
  C. fam bits 5..21 on op 5, each on its own fresh key, then read every key back
     (a bit that turns the write into a delete / no-op / update-only shows up here)
  D. delete candidates: op 5 with each fam bit on an existing microcode-inserted key."""
import json
import bench
import exp83_hash
SDT = 211
exp83_hash.SDT = SDT

CLEAN = []
for S in range(4):
    CLEAN += ['xmovi idx[0..3], 0x0', 'nop', f'lkup s{S}, 0x2, #34']
KEY = ['kmov key[0..3], r20', 'kmov key[4..7], r21']
DATA = ['kmov key[8..11], r22', 'kmov key[12..15], r23', 'nop']


def wblock(fam):
    return CLEAN + KEY + DATA + [f'lkup s1, {fam:#x}, #{SDT}', 'nop', 'nop']


READ = CLEAN + KEY + ['nop', f'lkup s1, 0x4, #{SDT}', 'nop']

if __name__ == '__main__':
    pass  # tables already exist (re-creating an SDT re-assigns its hash_table_id, see exp89 notes)
    b = bench.Bench('exp89')
    fams = [5] + [5 | (1 << k) for k in range(5, 22)]
    blk = {f: b.block(wblock(f), 'hi') for f in fams}
    rd = b.block(READ, 'hi')
    print(b.install())
    log = {}

    def W(fam, k0, k1, d0, d1):
        r = b.run([(blk[fam], [k0, k1, d0, d1])], window=1, rounds=1)[0]
        return r is not None

    def R(keys):
        rr = b.run([(rd, [k0, k1]) for k0, k1 in keys], window=1, rounds=1)
        return [None if r is None else (r['r36'], r['r37']) for r in rr]

    # A
    log['A'] = (W(5, 0xa1a2a3a4, 1, 0x0badcafe, 0x12345678), R([(0xa1a2a3a4, 1)]))
    # B
    W(5, 0xd1d2d3d4, 1, 0x11111111, 0x11111111)
    log['B'] = (W(5, 0xd1d2d3d4, 1, 0x22222222, 0x22222222), R([(0xd1d2d3d4, 1)]))
    # C: fresh key per fam bit
    ckeys = {f: (0xe0000000 | f, 0x5) for f in fams}
    log['C_write'] = {f: W(f, *ckeys[f], 0x30000000 | f, 0x0f0f0f0f) for f in fams}
    log['C_read'] = dict(zip(fams, R([ckeys[f] for f in fams])))
    # D: first insert key with plain op 5, then re-issue with flag bit and different data
    dkeys = {f: (0xf0000000 | f, 0x6) for f in fams[1:]}
    for f in fams[1:]:
        W(5, *dkeys[f], 0x40000000 | f, 0)
    log['D_write'] = {f: W(f, *dkeys[f], 0x50000000 | f, 0) for f in fams[1:]}
    log['D_read'] = dict(zip(fams[1:], R([dkeys[f] for f in fams[1:]])))
    b.restore()
    fmt = lambda x: 'drop' if x is None else f'{x[0]:08x} {x[1]:08x}'
    print('A overwrite CPU entry:', log['A'][0], [fmt(x) for x in log['A'][1]])
    print('B rewrite own entry  :', log['B'][0], [fmt(x) for x in log['B'][1]])
    for f in fams:
        print(f'C fam {f:#08x} write-reply={log["C_write"][f]} read={fmt(log["C_read"][f])}')
    for f in fams[1:]:
        print(f'D fam {f:#08x} rewrite-reply={log["D_write"][f]} read={fmt(log["D_read"][f])}')
    json.dump({k: (v if not isinstance(v, dict) else {str(a): c for a, c in v.items()}) for k, v in log.items()},
              open('runs/exp89.json', 'w'))
    print(bench.health())
