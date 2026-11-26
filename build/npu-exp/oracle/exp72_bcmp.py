"""exp72: compare-and-branch semantics for all 16 (bit 51, mode) codes, register and
immediate forms, several widths, random and edge-case operands."""
import json
import random
import sys
import bench

random.seed(72)
b = bench.Bench('exp72')
blocks = []


def blk(head):
    return ['movi32 r29, 0x0', 'nop', head, 'movi r29[3:0], 0x1', 'br page_hi', '@t:', 'movi r29[3:0], 0x2']


for o in (0, 1):
    for mode in range(8):
        mn = f'b.m{mode}' + ('.o' if o else '')
        for w, lo in ((8, 0), (16, 0), (32, 0), (12, 4)):
            f = f'[{lo + w - 1}:{lo}]' if w < 32 else ''
            blocks.append(('reg', o, mode, w, lo, None, b.block(blk(f'{mn} r20{f}, r21{f}, @t'))))
        for w, lo in ((8, 0), (16, 0)):
            f = f'[{lo + w - 1}:{lo}]'
            for imm in (0x0, 0x1, 0x7f, 0x80, 0xff, 0x1234, 0x8000, 0xffff):
                if imm >= 1 << w:
                    continue
                blocks.append(('imm', o, mode, w, lo, imm, b.block(blk(f'{mn} r20{f}, {imm:#x}, @t'))))


def operands(kind, w, imm):
    m = (1 << w) - 1
    out = []
    for _ in range(40):
        a = random.getrandbits(32)
        c = random.getrandbits(32) if kind == 'reg' else 0
        out.append((a, c))
    # edge cases on the field
    base = [0, 1, m, m - 1, 1 << (w - 1), (1 << (w - 1)) - 1, (1 << (w - 1)) + 1]
    for x in base:
        for y in base:
            out.append((x, y))
        if kind == 'imm':
            for d in (-1, 0, 1):
                out.append((((imm + d) & m), 0))
    return out


vec, meta = [], []
for kind, o, mode, w, lo, imm, k in blocks:
    for a, c in operands(kind, w, imm):
        if kind == 'imm':
            a = (a << lo) & 0xffffffff if a < (1 << w) else a
        else:
            a = (a << lo) & 0xffffffff if a < (1 << w) else a
            c = (c << lo) & 0xffffffff if c < (1 << w) else c
        vec.append((k, [a, c]))
        meta.append((kind, o, mode, w, lo, imm, a, c))

if __name__ == '__main__':
    print(len(b.blocks), 'blocks', len(vec), 'vectors')
    print(b.install())
    print('health', bench.health())
    res = b.run(vec, window=64)
    print(b.last_err)
    print('health', bench.health())
    json.dump([(m, r and r['r29']) for m, r in zip(meta, res)], open('runs/exp72.json', 'w'))
    print(b.restore())
