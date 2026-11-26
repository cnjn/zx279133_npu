"""exp98b: single-bit flip probe of lookup ops 11/12/15 around the exp94 inputs that succeed.
Two block variants per op: 'tied' (idx[128..131] = r20 = k0, as in exp94) and 'idx0'
(idx[128..131] = 0). Every one of the 384 input bits (r20..r31 = key[0..47]) is flipped
once; output = slot 1 result words r36..r39 or a drop. Ping check after each batch."""
import json
import sys
import bench
from exp88_bisect import ping_ok
from exp98_cop5 import CLEAN, KEYFILL, V94, SUCC

IDX = {'tied': ['xmovi idx[0..3], 0x0', 'xmov idx[128..131], r20', 'xmovi idx[132..135], 0x0', 'xmovi idx[136..139], 0x0'],
       'idx0': ['xmovi idx[0..3], 0x0', 'xmovi idx[128..131], 0x0', 'xmovi idx[132..135], 0x0', 'xmovi idx[136..139], 0x0']}
b = bench.Bench('exp98b')
blk = {}
for op, _ in SUCC:
    for mode, lines in IDX.items():
        blk[(op, mode)] = b.block(CLEAN + KEYFILL + lines + ['nop', f'lkup s1, {op:#x}, #0', 'nop', 'nop'], 'hi')


def vectors(op, base):
    out = [(None, list(base))]
    for w in range(12):
        for bit in range(32):
            v = list(base)
            v[w] ^= 1 << bit
            out.append(((w, bit), v))
    return out


if __name__ == '__main__':
    print(b.install())
    print('baseline ping', ping_ok(), flush=True)
    res = {}
    for op, t in SUCC:
        base = V94[(op, t)]
        for mode in IDX:
            vec = vectors(op, base)
            outs = []
            for i in range(0, len(vec), 128):
                chunk = vec[i:i + 128]
                r = b.run([(blk[(op, mode)], v) for _, v in chunk], window=16, rounds=2)
                outs += r
                ok = ping_ok()
                if not ok:
                    print(f'op {op} {mode}: ping lost after batch {i}; stopping')
                    json.dump(res, open('runs/exp98b.json', 'w'))
                    sys.exit(1)
            rows = []
            for (flip, v), r in zip(vec, outs):
                rows.append({'flip': flip, 'out': None if r is None else [r[f'r{k}'] for k in range(36, 40)]})
            res[f'{op} {mode}'] = rows
            base_out = rows[0]['out']
            ndrop = sum(x['out'] is None for x in rows[1:])
            nchg = sum(x['out'] is not None and x['out'] != base_out for x in rows[1:])
            print(f'op {op} {mode:5}: base {base_out} drops {ndrop} changed {nchg}', flush=True)
    json.dump(res, open('runs/exp98b.json', 'w'))
    print('health', bench.health())
    print(b.restore())
