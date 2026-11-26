"""exp98c: limits of the cop ops found in exp98b.
Model: op 8  crc16(key[3..3+L]) (L = key[2]);  op 9 crc32(same);
       op 11 divmod(crc16(key[3..3+L]), key[0..1]);  op 12 divmod(crc32(...), key[0..1]);
       op 15 ~ones-complement-sum(key[4..4+L]) in word 0 [31:16], L = key[0].
Sweeps L = 0..48, divisor 0/1/0xffff, and key[0..1] != 0 for ops 8/9; every result is
compared with the model's prediction."""
import json
import random
import sys
import bench
from exp88_bisect import ping_ok
from exp98_cop5 import CLEAN, KEYFILL

random.seed(98)
DATA = [random.getrandbits(32) for _ in range(12)]


def kb(v):
    return b''.join(x.to_bytes(4, 'big') for x in v)


def crc16(data):
    c = 0
    for b in data:
        c ^= b << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x8005) & 0xffff if c & 0x8000 else (c << 1) & 0xffff
    return c


def crc32(data):
    c = 0
    for b in data:
        c ^= b << 24
        for _ in range(8):
            c = ((c << 1) ^ 0x04C11DB7) & 0xffffffff if c & 0x80000000 else (c << 1) & 0xffffffff
    return c


def csum(data):
    s = 0
    for i in range(0, len(data), 2):
        s += data[i] << 8 | (data[i + 1] if i + 1 < len(data) else 0)
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def predict(op, v):
    k = kb(v)
    if op in (8, 9, 11, 12):
        c = (crc16 if op in (8, 11) else crc32)(k[3:3 + k[2]])
        if op in (8, 9):
            return [c, 0]
        d = k[0] << 8 | k[1]
        return None if d == 0 else [c // d, c % d]
    if op == 15:
        return [csum(k[4:4 + k[0]]) << 16, 0]


def vec(w0):
    v = list(DATA)
    v[0] = w0
    return v


b = bench.Bench('exp98c')
blk = {op: b.block(CLEAN + KEYFILL + ['nop', f'lkup s1, {op:#x}, #0', 'nop', 'nop'], 'hi') for op in (8, 9, 11, 12, 15)}

TESTS = []
for L in range(49):
    for op in (11, 12):
        TESTS.append((op, vec(0x1234 << 16 | L << 8 | 0x5a)))
    TESTS.append((15, vec(L << 24 | 0x00a5c3 & 0xffffff)))
for d in (0, 1, 0xffff):
    for op in (11, 12):
        TESTS.append((op, vec(d << 16 | 20 << 8 | 0x5a)))
for hi in (0x0000, 0x1234, 0xffff):
    for L in (0, 1, 16, 31, 32, 33, 45, 46):
        for op in (8, 9):
            TESTS.append((op, vec(hi << 16 | L << 8 | 0x5a)))

if __name__ == '__main__':
    print(b.install())
    print('baseline ping', ping_ok(), flush=True)
    out = []
    for i in range(0, len(TESTS), 64):
        chunk = TESTS[i:i + 64]
        res = b.run([(blk[op], v) for op, v in chunk], window=8, rounds=2)
        for (op, v), r in zip(chunk, res):
            got = None if r is None else [r['r36'], r['r37']]
            out.append({'op': op, 'w0': v[0], 'got': got, 'pred': predict(op, v)})
        ok = ping_ok()
        print(f'batch {i}: ping {ok}', flush=True)
        if not ok:
            break
    json.dump({'data': DATA, 'rows': out}, open('runs/exp98c.json', 'w'))
    print('health', bench.health())
    print(b.restore())
    bad = [x for x in out if x['got'] != x['pred']]
    print(f'{len(out)} tests, {len(bad)} differ from the model')
    for x in bad:
        print(f"  op {x['op']:2} w0={x['w0']:08x} got {x['got'] and [hex(y) for y in x['got']]} pred {x['pred'] and [hex(y) for y in x['pred']]}")
