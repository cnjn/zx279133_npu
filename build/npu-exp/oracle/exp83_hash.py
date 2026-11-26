"""exp83: hash lookups against our own table. SDT 210: 8-byte key, 64-bit response.
Entries added through the driver's single-hash test path; microcode looks up keys
built from r20/r21 and dumps slot 1 (r36..r39)."""
import json
import sys
import bench

SE = '/sys/devices/platform/np/se_debug'
SDT = int(sys.argv[1]) if len(sys.argv) > 1 else 210
KEYS = {(0xa1a2a3a4, 0x00000001 + i): (0x5000_0000 | i, 0x6000_0000 | (i << 4)) for i in range(4)}


def setup():
    c = [f'cd {SE}', 'dmesg -c >/dev/null',
         f'echo {SDT} 1 1 0 0 0 0 8 0 0 > creat_hash_sdt', f'echo {SDT} > sdt_get']
    for (k0, k1), (v0, v1) in KEYS.items():
        c += ['cat multi_hash_reset >/dev/null', 'echo 1 > multi_hash_sub_key_num',
              'echo 0 64 > multi_hash_sub_key_bit_len', f'echo 0 {k0:08x}{k1:08x} > multi_hash_sub_key_str',
              f'echo 8 {v0:08x}{v1:08x} > multi_hash_rsp_str', f'echo {SDT} 0 > single_hash_op']
    c += [f'echo {SDT} > hash_table_show_by_sdt_no 2>/dev/null', 'cat hash_table_get_all >/dev/null', 'dmesg -c | tail -60']
    script = '\n'.join(c) + '\n'
    open('/tmp/exp83.sh', 'w').write(script)
    bench.mac_put('/tmp/exp83.sh', '/tmp/exp83.sh')
    bench.mac(f'cd {bench.SERDIR} && sh push.sh /tmp/exp83.sh /tmp/exp83.sh 9179', 60)
    return bench.ser('sh /tmp/exp83.sh', 90)


if __name__ == '__main__':
    print(setup())
    b = bench.Bench('exp83')
    k = b.block(['kmov key[0..3], r20', 'kmov key[4..7], r21', 'nop', f'lkup s1, 0x4, #{SDT}', 'nop'], 'hi')
    k6 = b.block(['kmov key[0..3], r20', 'kmov key[4..7], r21', 'nop', f'lkup s1, 0x4, #{SDT}', 'nop'], 'top')
    print(b.install())
    vec = []
    keys = list(KEYS) + [(0xa1a2a3a4, 0x99), (0, 0)]
    for k0, k1 in keys:
        vec += [(k, [k0, k1]), (k6, [k0, k1])]
    res = b.run(vec, window=1, rounds=2)
    b.restore()
    rows = []
    for (blk, ins), r in zip(vec, res):
        rows.append((ins[:2], blk == k, r))
        regs = ' '.join(f'{n}={v:08x}' for n, v in (r or {}).items() if n in ('r36', 'r37', 'r38', 'r39', 'r40', 'r41', 'r42', 'r43'))
        print(f'key {ins[0]:08x}{ins[1]:08x}', 'drop' if r is None else regs)
    json.dump(rows, open(f'runs/exp83_{SDT}.json', 'w'))
    print(bench.health())
