"""exp99: microcode counting on our own stat tables.
Tables (created here): 214 stat_mode 1 (32-bit), 212 stat_mode 2 (64-bit), 213 stat_mode 3
(128-bit), 128 entries each, preset from the CPU to recognisable values.
Operand: idx[128..131] = r20 = bit 28 | mode bits 27:23 | index; idx[132..135] = r21 (byte
count in the stock code); idx[136..139] = r22.
Part A: stock-like operands, repeated on one entry (r36..r39 after each packet).
Part B: every mode 0..31 x bit 28, one entry each (index = m + 32 * b28), CPU read-back.
Health check after every batch; stops if threads hang or ping is lost."""
import json
import re
import sys
import bench
from exp88_bisect import ping_ok

SE = '/sys/devices/platform/np/se_debug'
TABLES = {214: 1, 212: 2, 213: 3}
N = 128
CLEAN = []
for S in range(4):
    CLEAN += ['xmovi idx[0..3], 0x0', 'nop', f'lkup s{S}, 0x2, #34']
OPND = ['xmovi idx[0..3], 0x0', 'xmov idx[128..131], r20', 'xmov idx[132..135], r21', 'xmov idx[136..139], r22', 'nop']

b = bench.Bench('exp99')
blk = {t: b.block(CLEAN + OPND + [f'lkup.stat s1, #{t}', 'nop', 'nop'], 'hi') for t in TABLES}


def preset(i):
    return [0xa0000000 | i, 0xb0000000 | i, 0xc0000000 | i, 0xd0000000 | i]


def board_script(name, lines):
    path = f'/tmp/{name}.sh'
    open(path, 'w').write('\n'.join(lines) + '\n')
    bench.mac_put(path, path)
    r = bench.mac(f'cd {bench.SERDIR} && sh push.sh {path} {path} 9179', 60)
    if len(set(x for x in r.split() if len(x) == 64)) != 1:
        raise RuntimeError('push failed: ' + r)
    return bench.ser(f'sh {path}', 400)


def setup():
    lines = [f'cd {SE}', 'dmesg -c >/dev/null']
    lines += [f'echo {t} {m} {N} > creat_stat_sdt' for t, m in TABLES.items()]
    lines += [f'echo {t} > sdt_get' for t in TABLES]
    lines += ['dmesg -c | grep -E "stat_mode|stat_eram|can"']
    for t in TABLES:
        for i in range(N):
            lines.append(f'echo {t} {i} 4 ' + ' '.join(f'{x:x}' for x in preset(i)) + ' > stat_table_set')
    return board_script('exp99_setup', lines)


def read_all():
    lines = [f'cd {SE}', 'dmesg -c >/dev/null']
    for t in TABLES:
        for i in range(N):
            lines += [f'echo {t} {i} > stat_table_get', f'echo "E {t} {i} $(dmesg -c | grep -o "0x[0-9a-f]*" | tr "\\n" " ")"']
    out = board_script('exp99_read', lines)
    res = {}
    for m in re.finditer(r'^E (\d+) (\d+) ((?:0x[0-9a-f]+ ?)*)', out, re.M):
        res[(int(m[1]), int(m[2]))] = [int(x, 16) for x in m[3].split()]
    return res


def opnd(b28, mode, index):
    return b28 << 28 | mode << 23 | index


def show(r):
    return 'drop' if r is None else ' '.join(f'{r[f"r{k}"]:08x}' for k in range(36, 40))


if __name__ == '__main__':
    log = {'A': [], 'B': []}
    print(setup())
    before = read_all()
    print('preset read-back (index 5):', {t: [hex(x) for x in before[(t, 5)]] for t in TABLES})
    print(b.install())
    print('baseline ping', ping_ok(), 'health', bench.health(), flush=True)
    # Part A: stock-like operands, 3 packets each on entry 100
    stock = {214: (0x16, 0), 212: (0x11, 100), 213: (0x1d, 100)}
    for t, (mode, nbytes) in stock.items():
        for k in range(3):
            r = b.run([(blk[t], [opnd(1, mode, 100), nbytes + 10 * k, 0])], window=1, rounds=1)[0]
            print(f'A #{t} mode {mode:#x} bytes {nbytes + 10 * k}: {show(r)}', flush=True)
            log['A'].append({'t': t, 'mode': mode, 'bytes': nbytes + 10 * k, 'out': r})
    print('health after A', bench.health(), flush=True)
    # Part B: all modes, one packet each, entry m + 32*b28
    stop = False
    for t in TABLES:
        tests = [(b28, m) for b28 in (0, 1) for m in range(32)]
        for i in range(0, len(tests), 16):
            chunk = tests[i:i + 16]
            res = b.run([(blk[t], [opnd(b28, m, m + 32 * b28), 100, 0]) for b28, m in chunk], window=1, rounds=1)
            for (b28, m), r in zip(chunk, res):
                log['B'].append({'t': t, 'b28': b28, 'mode': m, 'out': r})
            h = bench.health()
            ok = ping_ok()
            print(f'B #{t} tests {i}..{i + 15}: replies {sum(x is not None for x in res)} health {h} ping {ok}', flush=True)
            if not ok or (h[0] or 0) > 2:
                stop = True
                break
        if stop:
            break
    after = read_all() if not stop else {}
    log['before'] = {f'{t} {i}': v for (t, i), v in before.items()}
    log['after'] = {f'{t} {i}': v for (t, i), v in after.items()}
    json.dump(log, open('runs/exp99.json', 'w'))
    if not stop:
        print(b.restore())
