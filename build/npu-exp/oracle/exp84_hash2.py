"""exp84: hash lookup on every slot (where do response and the key echo land?),
and an entry whose response has bit 31 set."""
import json
import bench
SE = '/sys/devices/platform/np/se_debug'
c = [f'cd {SE}', 'dmesg -c >/dev/null', 'cat multi_hash_reset >/dev/null', 'echo 1 > multi_hash_sub_key_num',
     'echo 0 64 > multi_hash_sub_key_bit_len', 'echo 0 b1b2b3b400000007 > multi_hash_sub_key_str',
     'echo 8 f1234567abcdef12 > multi_hash_rsp_str', 'echo 210 0 > single_hash_op', 'dmesg -c | tail -3']
open('/tmp/exp84.sh', 'w').write('\n'.join(c) + '\n')
bench.mac_put('/tmp/exp84.sh', '/tmp/exp84.sh')
bench.mac(f'cd {bench.SERDIR} && sh push.sh /tmp/exp84.sh /tmp/exp84.sh 9180', 60)
print(bench.ser('sh /tmp/exp84.sh', 60))
b = bench.Bench('exp84')
CLEAN = []
for S in range(4):
    CLEAN += ['xmovi idx[0..3], 0x0', 'nop', f'lkup s{S}, 0x2, #34']
blk = {}
for S in range(4):
    for pg in ('hi', 'top'):
        blk[(S, pg)] = b.block(CLEAN + ['nop', 'kmov key[0..3], r20', 'kmov key[4..7], r21', 'nop',
                                        f'lkup s{S}, 0x4, #210', 'nop'], pg)
print(b.install())
keys = [(0xa1a2a3a4, 2), (0xb1b2b3b4, 7), (0xa1a2a3a4, 0x55)]
vec, meta = [], []
for (S, pg), k in blk.items():
    for k0, k1 in keys:
        vec.append((k, [k0, k1]))
        meta.append((S, pg, k0, k1))
res = b.run(vec, window=1, rounds=2)
b.restore()
for (S, pg, k0, k1), r in zip(meta, res):
    if r is None:
        print(S, pg, 'drop'); continue
    regs = ' '.join(f'{n}={v:08x}' for n, v in r.items() if 32 <= int(n[1:]) < 52)
    print(f's{S} {pg:3} key {k0:08x}{k1:08x}: {regs}')
print(bench.health())
