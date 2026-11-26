"""exp93: (A) coprocessor ops 11/12/15 vs the key[0..2] length prefix, (B) DPI op 6
outputs, (C) global lock ops 17/18 step by step (one packet per step)."""
import json
import random
import bench

random.seed(93)
CLEAN = []
for S in range(4):
    CLEAN += ['xmovi idx[0..3], 0x0', 'nop', f'lkup s{S}, 0x2, #34']
KEYFILL = [f'kmov key[{4 * i}..{4 * i + 3}], r{20 + i}' for i in range(12)] + ['nop']
PREFIXES = (0, 1, 2, 4, 6, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 45, 48)


def key_with_prefix(p, rnd=False):
    words = [random.getrandbits(32) if rnd else (0x01020304 * (j + 1)) & 0xffffffff for j in range(12)]
    words[0] = (p << 8) | (words[0] & 0xff)
    return words


b = bench.Bench('exp93')
blk = {}
for op in (11, 12, 15):
    blk[('cop', op)] = b.block(CLEAN + KEYFILL + [f'lkup s1, {op:#x}, #0', 'nop', 'nop'], 'hi')
blk[('dpi', 0)] = b.block(CLEAN + KEYFILL + ['lkup s1, 0x6, #0', 'nop', 'nop'], 'hi')
blk[('dpi', 1)] = b.block(CLEAN + KEYFILL + ['lkup s1, 0x6, #0', 'nop', 'nop'], 'top')
blk[('lock',)] = b.block(CLEAN + KEYFILL + ['lkup s1, 0x11, #0', 'nop', 'nop'], 'hi')
blk[('unlock',)] = b.block(CLEAN + KEYFILL + ['lkup s1, 0x12, #0', 'nop', 'nop'], 'hi')
blk[('lock_unlock',)] = b.block(CLEAN + KEYFILL + ['lkup s1, 0x11, #0', 'nop', 'mov r29, r36', 'nop',
                                                   'lkup s1, 0x12, #0', 'nop', 'nop'], 'hi')
blk[('lock_lock',)] = b.block(CLEAN + KEYFILL + ['lkup s1, 0x11, #0', 'nop', 'mov r29, r36', 'nop',
                                                 'lkup s1, 0x11, #0', 'nop', 'nop'], 'hi')


def show(r, regs=('r29', 'r36', 'r37', 'r38', 'r39')):
    return 'drop' if r is None else ' '.join(f'{k}={r[k]:08x}' for k in regs if k in r)


if __name__ == '__main__':
    print(b.install())
    out = {}
    # A
    vec, meta = [], []
    for op in (11, 12, 15):
        for p in PREFIXES:
            vec.append((blk[('cop', op)], key_with_prefix(p)))
            meta.append(('A', op, p))
    res = b.run(vec, window=1, rounds=1)
    for m, r in zip(meta, res):
        out[str(m)] = r
    for op in (11, 12, 15):
        print(f'op {op}:', ' '.join(f'p{m[2]}:{"ok" if r else "-"}' for m, r in zip(meta, res) if m[1] == op))
    for m, r in zip(meta, res):
        if r:
            print('  ', m, show(r))
    # B
    keys = [key_with_prefix(32), key_with_prefix(32), key_with_prefix(32, True), key_with_prefix(0, True)]
    res = b.run([(blk[('dpi', 0)], k) for k in keys] + [(blk[('dpi', 1)], k) for k in keys[:2]], window=1, rounds=1)
    for i, r in enumerate(res):
        print('dpi', i, show(r, ('r32', 'r33', 'r36', 'r37', 'r38', 'r39', 'r40', 'r41', 'r44', 'r45')))
        out[f'B{i}'] = r
    print('health before locks', bench.health())
    # C
    steps = [('lock', 1), ('unlock', 1), ('unlock', 1), ('lock_unlock', 1), ('lock', 2), ('unlock', 2),
             ('lock', 3), ('lock', 3), ('unlock', 3), ('unlock', 3), ('lock_lock', 4), ('unlock', 4)]
    for name, lid in steps:
        k = [lid] + [0] * 11
        r = b.run([(blk[(name,)], k)], window=1, rounds=1)[0]
        print(f'{name:12} id {lid}: {show(r)}')
        out[f'C {name} {lid}'] = r
    print('health after locks', bench.health())
    b.restore()
    json.dump(out, open('runs/exp93.json', 'w'))
