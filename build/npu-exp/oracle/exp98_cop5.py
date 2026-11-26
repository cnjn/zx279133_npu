"""exp98: lookup ops 11/12/15 (cop channel).
Part A: replay the three exp94 inputs that succeeded, exactly, one packet each with a ping
after each (does one of them break the path to the CPU?); run them again (deterministic?);
then the same inputs against other table numbers (#211 = our own stat table, #0 = none,
#34) to see whether the table field matters at all."""
import json
import random
import sys
import bench
from exp88_bisect import ping_ok

CLEAN = []
for S in range(4):
    CLEAN += ['xmovi idx[0..3], 0x0', 'nop', f'lkup s{S}, 0x2, #34']
KEYFILL = [f'kmov key[{4 * i}..{4 * i + 3}], r{20 + i}' for i in range(12)] + ['nop']
IDXFILL = ['xmovi idx[0..3], 0x0', 'xmov idx[128..131], r20', 'xmovi idx[132..135], 0x0', 'xmovi idx[136..139], 0x0']


def exp94_vectors():
    random.seed(94)
    v = {}
    for op in (11, 12, 15):
        for t in (34, 50, 48, 210):
            v[(op, t)] = [random.getrandbits(32) for _ in range(12)]
    return v


V94 = exp94_vectors()
SUCC = [(11, 48), (12, 48), (15, 34)]
TABLES = (48, 34, 211, 0)

b = bench.Bench('exp98')
blk = {}
for op in (11, 12, 15):
    for t in TABLES:
        blk[(op, t)] = b.block(CLEAN + KEYFILL + IDXFILL + ['nop', f'lkup s1, {op:#x}, #{t}', 'nop', 'nop'], 'hi')


def show(r):
    return 'drop' if r is None else ' '.join(f'{k}={r[k]:08x}' for k in ('r36', 'r37', 'r38', 'r39'))


def one(op, t, vec, log, tag):
    r = b.run([(blk[(op, t)], vec)], window=1, rounds=1)[0]
    ok = ping_ok()
    print(f'{tag:8} op {op} #{t:<3} k0={vec[0]:08x}: {show(r):48} ping {ok}', flush=True)
    log.append({'tag': tag, 'op': op, 't': t, 'in': vec, 'out': r, 'ping': ok})
    return ok


if __name__ == '__main__':
    log = []
    print(b.install())
    print('baseline ping', ping_ok(), 'health', bench.health(), flush=True)
    alive = True
    try:
        for tag in ('replay1', 'replay2'):
            for op, t in SUCC:
                if not one(op, t, V94[(op, t)], log, tag):
                    alive = False
                    raise StopIteration
        for op, t0 in SUCC:
            for t in TABLES:
                if t != t0 and not one(op, t, V94[(op, t0)], log, 'table'):
                    alive = False
                    raise StopIteration
    except StopIteration:
        print('path to CPU broken; stopping (board needs a reboot)')
    json.dump(log, open('runs/exp98.json', 'w'))
    if alive:
        print('health', bench.health())
        print(b.restore())
