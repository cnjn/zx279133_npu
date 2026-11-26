"""exp80: eRAM lookups against our own tables.
Create SDT 200..207 with eram_mode 0..7 (64 entries each), fill them from the CPU with
known patterns, then look them up from microcode with the index from a register."""
import json
import re
import sys
import bench

N = 64
SE = '/sys/devices/platform/np/se_debug'


def pattern(mode_width, i):
    if mode_width <= 32:
        return [((i * 0x9E3779B1) ^ 0x5A5A5A5A) & ((1 << mode_width) - 1)]
    nw = mode_width // 32
    return [(0x11000000 * (k + 1)) | (i << 8) | k for k in range(nw)]


def setup_tables():
    cmds = [f'cd {SE}', 'dmesg -c >/dev/null']
    for m in range(8):
        cmds.append(f'echo {200 + m} {m} {N} > creat_eram_sdt')
    for m in range(8):
        cmds.append(f'echo {200 + m} > sdt_get')
    cmds.append('dmesg -c')
    return bench.ser('; '.join(cmds), 60)


def fill(widths):
    lines = [f'cd {SE}']
    for m, w in widths.items():
        for i in range(N):
            v = pattern(w, i)
            vals = ' '.join(f'{x:x}' for x in v) + ' 0' * (4 - len(v))
            lines.append(f'echo {200 + m} {i} {len(v)} {vals} > cpu_set_eram_by_table_width')
    script = '\n'.join(lines) + '\n'
    open('/tmp/exp80_fill.sh', 'w').write(script)
    bench.mac_put('/tmp/exp80_fill.sh', '/tmp/exp80_fill.sh')
    r = bench.mac(f'cd {bench.SERDIR} && sh push.sh /tmp/exp80_fill.sh /tmp/exp80_fill.sh 9178', 60)
    return r + bench.ser('dmesg -c >/dev/null; sh /tmp/exp80_fill.sh; dmesg -c | tail -5; '
                         f'cd {SE}; echo 203 5 4 > cpu_get_eram_by_table_width; echo 207 5 1 > cpu_get_eram_by_table_width; dmesg -c | tail -20', 120)


if __name__ == '__main__':
    out = setup_tables()
    print(out)
    widths = {}
    for m, w in zip(range(8), re.findall(r'eram_mode\s*:\s*\d+\((\d+)\)', out)[-8:]):
        widths[m] = int(w)
    print('widths', widths)
    print(fill(widths))
    b = bench.Bench('exp80')
    blk = {}
    for m in range(8):
        blk[('xmov', m)] = b.block(['xmov idx[0..3], r20', 'nop', f'lkup s1, 0x2, #{200 + m}', 'nop'], 'hi')
    blk[('xmov', 34)] = b.block(['xmov idx[0..3], r20', 'nop', 'lkup s1, 0x2, #34', 'nop'], 'hi')
    for v in (0, 1, 2, 3):
        blk[('xmovi', v)] = b.block([f'xmovi idx[0..3], {v:#x}', 'nop', 'lkup s1, 0x2, #207', 'nop'], 'hi')
    print(b.install())
    vec, meta = [], []
    for (kind, m), k in blk.items():
        idxs = list(range(N)) + [N, N + 1, 100, 1000] if kind == 'xmov' else [0]
        if m == 34:
            idxs = [0, 1, 2, 3, 31, 32]
        for i in idxs:
            vec.append((k, [i]))
            meta.append((kind, m, i))
    res = b.run(vec, window=16, rounds=2)
    b.restore()
    json.dump({'widths': widths, 'rows': [(m, r) for m, r in zip(meta, res)]}, open('runs/exp80.json', 'w'))
    print(bench.health())
