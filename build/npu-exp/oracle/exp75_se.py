"""exp75: which SE request counters does each instruction drive? One batch of N
packets per test block, cluster_stats read before and after each batch."""
import json
import re
import bench

N = 2000
CNT = ['movi r30[15:0], 0x160', 'movi r30[27:23], 0x16', 'movi r30[28], 0x1',
       'xmovi idx[132..135], 0x0', 'xmovi idx[136..139], 0x0', 'xmov idx[128..131], r30']
TESTS = {
    'ctrl': [],
    'op01.7_s2_32': ['op01.7 s2, 32'],
    'op01.0_s0_16': ['op01.0 s0, 16'],
    'op01.5_s0_32': ['op01.5 s0, 32'],
    'op01.6_s1_32': ['op01.6 s1, 32'],
    'op01.1.b_s1_32': ['op01.1.b s1, 32'],
    'stat48': CNT + ['nop', 'lkup s2, 0x3, #48'],
    'stat48_x2': CNT + ['nop', 'lkup s2, 0x3, #48', 'lkup s2, 0x3, #48'],
    'eram34': ['xmovi idx[0..3], 0x0', 'nop', 'lkup s0, 0x2, #34'],
    'hash50': ['movi32 r20, 0x0', 'nop', 'kld key[0..5], h1+0', 'kmov key[6..7], r20[15:0]', 'nop',
               'lkup s0, 0x4, #50'],
    'crc32': ['kmovi key[0..2], 0x20', 'nop', 'crc32 s0'],
}


def se_stats():
    out = bench.ser('dmesg -c >/dev/null; cat /sys/devices/platform/np/ppu_debug/cluster_stats >/dev/null; dmesg -c', 40)
    v = {}
    for line in out.splitlines():
        m = re.match(r'\s*\[?[\d. ]*\]?\s*(.+?)\s*:\s*(\d+)\s*$', line)
        if m:
            v[m[1].strip()] = int(m[2])
    return v


if __name__ == '__main__':
    b = bench.Bench('exp75')
    ks = {n: b.block(t, 'hi') for n, t in TESTS.items()}
    print(b.install())
    res = {}
    prev = se_stats()
    for n, k in ks.items():
        r = b.run([(k, [0] * 12)] * N, window=64, rounds=1)
        got = sum(x is not None for x in r)
        cur = se_stats()
        d = {key: cur[key] - prev.get(key, 0) for key in cur if cur[key] != prev.get(key, 0)}
        res[n] = {'got': got, 'delta': d, 'sample': r[0]}
        print(n, got, {k2: v for k2, v in d.items() if abs(v) >= N // 4})
        prev = cur
    b.restore()
    json.dump(res, open('runs/exp75.json', 'w'), indent=1)
