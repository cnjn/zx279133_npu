"""exp99b: stat operand modes, one packet at a time (exp99 part B hung the stat engine:
12 stat requests never answered after modes 0..15 with bit 28 = 0 on a 32-bit table).

usage: python3 exp99b_stat.py setup            create + preset tables 214/212/213 (after boot)
       python3 exp99b_stat.py known            stock-like ops + carry tests, then read back
       python3 exp99b_stat.py sweep B28 T M0   modes M0..31 with bit 28 = B28 on table T;
                                               stops at the first request the SE never answers
       python3 exp99b_stat.py read             CPU read-back of all three tables
Tables: 214 stat_mode 1 (32-bit), 212 mode 2 (64-bit), 213 mode 3 (128-bit), 128 entries.
Entry i is preset to words a0..|i, b0..|i, c0..|i, d0..|i (narrow tables keep the tail).
Operand: idx[128..131] = r20, idx[132..135] = r21 (bytes), idx[136..139] = r22.
Results are appended to runs/exp99b.jsonl."""
import json
import re
import sys
import bench


def ping_ok():
    # same check as exp88_bisect.ping_ok (that module parses sys.argv on import)
    out = bench.mac('ping -c 4 -i 0.2 -t 3 192.168.1.1 | grep -o "[0-9]* packets received"', 20)
    return out.strip().startswith(('3', '4'))

SE = '/sys/devices/platform/np/se_debug'
TABLES = {214: 1, 212: 2, 213: 3}
N = 128
CLEAN = []
for S in range(4):
    CLEAN += ['xmovi idx[0..3], 0x0', 'nop', f'lkup s{S}, 0x2, #34']
OPND = ['xmovi idx[0..3], 0x0', 'xmov idx[128..131], r20', 'xmov idx[132..135], r21', 'xmov idx[136..139], r22', 'nop']
LOG = 'runs/exp99b.jsonl'

b = bench.Bench('exp99b')
blk = {t: b.block(CLEAN + OPND + [f'lkup.stat s1, #{t}', 'nop', 'nop'], 'hi') for t in TABLES}


def preset(i):
    return [0xa0000000 | i, 0xb0000000 | i, 0xc0000000 | i, 0xd0000000 | i]


def log(rec):
    with open(LOG, 'a') as f:
        f.write(json.dumps(rec) + '\n')


def board_script(name, lines, timeout=400):
    path = f'/tmp/{name}.sh'
    open(path, 'w').write('\n'.join(lines) + '\n')
    bench.mac_put(path, path)
    r = bench.mac(f'cd {bench.SERDIR} && sh push.sh {path} {path} 9179', 60)
    if len(set(x for x in r.split() if len(x) == 64)) != 1:
        raise RuntimeError('push failed: ' + r)
    return bench.ser(f'sh {path}', timeout)


def setup(extra=()):
    lines = [f'cd {SE}', 'dmesg -c >/dev/null']
    lines += [f'echo {t} {m} {N} > creat_stat_sdt' for t, m in TABLES.items()]
    lines += [f'echo {t} > sdt_get' for t in TABLES]
    lines += ['dmesg -c | grep -E "stat_mode|stat_eram|can"']
    for t in TABLES:
        for i in range(N):
            lines.append(f'echo {t} {i} 4 ' + ' '.join(f'{x:x}' for x in preset(i)) + ' > stat_table_set')
    lines += [f'echo {t} {i} 4 ' + ' '.join(f'{x:x}' for x in w) + ' > stat_table_set' for t, i, w in extra]
    return board_script('exp99b_setup', lines)


def setup_extra(extra):
    lines = [f'cd {SE}'] + [f'echo {t} {i} 4 ' + ' '.join(f'{x:x}' for x in w) + ' > stat_table_set' for t, i, w in extra]
    return board_script('exp99b_extra', lines)


def read_all(entries=None):
    entries = entries or [(t, i) for t in TABLES for i in range(N)]
    lines = [f'cd {SE}', 'dmesg -c >/dev/null']
    for t, i in entries:
        lines += [f'echo {t} {i} > stat_table_get', f'echo "E {t} {i} $(dmesg -c | grep -o "0x[0-9a-f]*" | tr "\\n" " ")"']
    out = board_script('exp99b_read', lines)
    res = {}
    for m in re.finditer(r'^E (\d+) (\d+) ((?:0x[0-9a-f]+ ?)*)', out, re.M):
        res[(int(m[1]), int(m[2]))] = [int(x, 16) for x in m[3].split()]
    return res


def stat_pending():
    out = bench.ser('dmesg -c >/dev/null; cat /sys/devices/platform/np/ppu_debug/cluster_stats; dmesg -c', 30)
    req = re.search(r'ppu2se stat key req vld l\(0x2038\):\s*(\d+)', out)
    rsp = re.search(r'se2ppu stat key rsp sop l\(0x2050\):\s*(\d+)', out)
    return int(req[1]) - int(rsp[1]) if req and rsp else None


def opnd(b28, mode, index):
    return b28 << 28 | mode << 23 | index


def one(t, b28, mode, index, nbytes=100, r22=0, tag=''):
    r = b.run([(blk[t], [opnd(b28, mode, index), nbytes, r22])], window=1, rounds=1)[0]
    out = None if r is None else [r[f'r{k}'] for k in range(36, 40)]
    rec = {'tag': tag, 't': t, 'b28': b28, 'mode': mode, 'index': index, 'bytes': nbytes, 'r22': r22, 'out': out}
    if out is None:
        rec['pending'] = stat_pending()
        rec['ping'] = ping_ok()  # a hung stat request blocks every later packet, ping included
    log(rec)
    print(f"{tag:6} #{t} b28={b28} mode={mode:#04x} idx={index:3} bytes={nbytes:#x}: "
          + ('drop pending=%s ping=%s' % (rec['pending'], rec['ping']) if out is None else ' '.join(f'{x:08x}' for x in out)), flush=True)
    return rec


F = 0xffffffff
EDGE_PRESET = [(212, 110, [0, 0, F, 0xffffff80]), (212, 111, [0, 0, F, 0xffffff80]),
               (212, 112, [0, 0, 0, 0x10]), (212, 113, [0, 0, F, F]), (212, 114, [0, 0, F, F]),
               (212, 115, [0, 0, 1, 0x10]), (214, 110, [0, 0, 0, F]), (213, 110, [F, F, F, F]),
               (213, 111, [F, F, F, F])]
EDGE = [(212, 0x11, 110, 0x100), (212, 0x14, 111, 0x100), (212, 0x12, 112, 0x64), (212, 0x13, 113, 0),
        (212, 0x17, 114, 0), (212, 0x12, 115, 0x64), (214, 0x16, 110, 0), (213, 0x1d, 110, 0x100),
        (213, 0x09, 111, 0)]


if __name__ == '__main__':
    cmd = sys.argv[1]
    if cmd == 'setup':
        # carry tests: entry 101 of 212 and 213 with the low word near overflow
        print(setup(extra=[(212, 101, [0, 0, 0x11111111, 0xffffff80]),
                           (213, 101, [0x22222222, 0x33333333, 0x44444444, 0xffffff80])] + EDGE_PRESET))
    elif cmd == 'known':
        print(b.install())
        print('ping', ping_ok(), flush=True)
        for t, mode in ((214, 0x16), (212, 0x11), (213, 0x1d)):
            for k in range(3):
                one(t, 1, mode, 100, 100 + 10 * k, tag='known')
        one(212, 1, 0x11, 101, 0x100, tag='carry')
        one(213, 1, 0x1d, 101, 0x100, tag='carry')
        print(b.restore())
        res = read_all([(t, i) for t in TABLES for i in (99, 100, 101, 102)])
        for k, v in sorted(res.items()):
            print('read', k, ' '.join(f'{x:08x}' for x in v))
        log({'tag': 'read-known', 'read': {f'{t} {i}': v for (t, i), v in res.items()}})
    elif cmd == 'sweep':
        b28, t, m0 = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
        skip = {int(x, 0) for x in sys.argv[5].split(',')} if len(sys.argv) > 5 else set()
        print(b.install())
        print('ping', ping_ok(), 'pending baseline', stat_pending(), flush=True)
        for m in range(m0, 32):
            if m in skip:
                continue
            rec = one(t, b28, m, m + 32 * b28, tag='sweep')
            if rec['out'] is None and not rec['ping']:
                print(f'STUCK at mode {m:#x}: the board needs a reboot')
                break
        else:
            print(b.restore())
            print('ping after', ping_ok())
    elif cmd == 'edge':
        # wrap / saturate / underflow, and the twin modes (0x11 vs 0x14, 0x13 vs 0x17)
        print(b.install())
        print('ping', ping_ok(), flush=True)
        for t, mode, idx, nbytes in EDGE:
            rec = one(t, 1, mode, idx, nbytes, tag='edge')
            if rec['out'] is None and not rec['ping']:
                print('STUCK'); break
        else:
            print(b.restore())
            res = read_all([(t, i) for t, _, i, _ in EDGE])
            log({'tag': 'read-edge', 'read': {f'{t} {i}': v for (t, i), v in res.items()}})
            for (t, i), v in sorted(res.items()):
                print('read', t, i, ' '.join(f'{x:08x}' for x in v))
    elif cmd == 'arith':
        # carry / borrow across the 32-bit boundary (exp99b edge showed off-by-one results)
        T = [(212, 0x12, 120, [0, 0, 1, 0x10], 0x64), (212, 0x12, 121, [0, 0, 5, 0x10], 0x64),
             (212, 0x12, 122, [0, 0, 1, 0x100], 0x64), (212, 0x12, 123, [0, 0, 2, 0], 1),
             (212, 0x12, 124, [0, 0, 1, 0x64], 0x64), (212, 0x12, 125, [0, 0, 3, 0x5], 0x10),
             (212, 0x11, 126, [0, 0, F, 0xffffff80], 0x100), (212, 0x11, 127, [0, 0, 0xfffffffe, 0xffffff80], 0x100),
             (212, 0x11, 119, [0, 0, F, 0xffffff80], 0x80), (213, 0x1d, 120, [0, F, 0, 0], 0x10),
             (213, 0x1d, 121, [5, F, 0, 0], 0x10), (213, 0x1d, 122, [F, F, 0, 0], 0x10)]
        print(setup_extra([(t, i, w) for t, _, i, w, _ in T]))
        print(b.install())
        print('ping', ping_ok(), flush=True)
        for t, mode, i, w, nb in T:
            rec = one(t, 1, mode, i, nb, tag='arith')
            if rec['out'] is None and not rec['ping']:
                print('STUCK'); break
        else:
            print(b.restore())
            res = read_all([(t, i) for t, _, i, _, _ in T])
            log({'tag': 'read-arith', 'read': {f'{t} {i}': v for (t, i), v in res.items()}})
            for t, mode, i, w, nb in T:
                print(f'#{t} {i} mode {mode:#x} {" ".join(f"{x:08x}" for x in w)} op {nb:#x} -> {" ".join(f"{x:08x}" for x in res[(t, i)])}')
    elif cmd == 'read':
        res = read_all()
        log({'tag': 'read-all', 'read': {f'{t} {i}': v for (t, i), v in res.items()}})
        for (t, i), v in sorted(res.items()):
            if v != [0, 0, 0, 0][:4 - len(v)] + preset(i)[4 - len(v):] and v:
                print('changed', t, i, ' '.join(f'{x:08x}' for x in v))
