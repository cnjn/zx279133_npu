"""exp87: lookup op 5 (SE 'e key wtb' channel) on hash table #210 (8-byte key, 64-bit rsp).
Write packets put a new key in key[0..7] and candidate data in key[8..15] (variant K) or
idx[0..7] (variant X), then issue op 5. Read packets look the keys up with op 4.
One install, two pump runs, one serial read of the table at the end."""
import json
import bench
import exp83_hash

CLEAN = []
for S in range(4):
    CLEAN += ['xmovi idx[0..3], 0x0', 'nop', f'lkup s{S}, 0x2, #34']
KEY = ['kmov key[0..3], r20', 'kmov key[4..7], r21']
W_K = CLEAN + KEY + ['kmov key[8..11], r22', 'kmov key[12..15], r23', 'nop', 'lkup s1, 0x5, #210', 'nop', 'nop']
W_X = CLEAN + KEY + ['xmov idx[0..3], r22', 'xmov idx[4..7], r23', 'nop', 'lkup s1, 0x5, #210', 'nop', 'nop']
W_K2 = CLEAN + KEY + ['kmov key[8..11], r22', 'kmov key[12..15], r23', 'nop', 'lkup s1, 0x400005, #210', 'nop', 'nop']
READ = CLEAN + KEY + ['nop', 'lkup s1, 0x4, #210', 'nop']

print(exp83_hash.setup()[-400:])
b = bench.Bench('exp87')
blk = {'wk': b.block(W_K, 'hi'), 'wx': b.block(W_X, 'hi'), 'wk2': b.block(W_K2, 'hi'), 'rd': b.block(READ, 'hi')}
print(b.install())
writes = [('wk', 0xc1c2c3c4, 0x11, 0x0a0b0c0d, 0x01020304),
          ('wx', 0xc1c2c3c4, 0x22, 0x1a1b1c1d, 0x11121314),
          ('wk2', 0xc1c2c3c4, 0x33, 0x2a2b2c2d, 0x21222324)]
wr = b.run([(blk[n], [k0, k1, d0, d1]) for n, k0, k1, d0, d1 in writes], window=1, rounds=1)
for (n, k0, k1, d0, d1), r in zip(writes, wr):
    print('write', n, f'{k0:08x}{k1:08x}', 'no reply' if r is None else
          ' '.join(f'{k}={v:08x}' for k, v in r.items() if k in ('r36', 'r37', 'r38', 'r39')))
reads = [(k0, k1) for _, k0, k1, _, _ in writes] + [(0xa1a2a3a4, 1), (0xc1c2c3c4, 0x99)]
rr = b.run([(blk['rd'], [k0, k1]) for k0, k1 in reads], window=1, rounds=1)
for (k0, k1), r in zip(reads, rr):
    print('read ', f'{k0:08x}{k1:08x}', 'no reply' if r is None else
          ' '.join(f'{k}={v:08x}' for k, v in r.items() if k in ('r36', 'r37', 'r38', 'r39')))
b.restore()
print(bench.ser('cd /sys/devices/platform/np/se_debug; dmesg -c >/dev/null; cat hash_table_get_all >/dev/null; '
                'dmesg -c | grep -A6 "sdt_no : 210" | grep -v zgroup', 60))
json.dump({'w': [(x, r) for x, r in zip(writes, wr)], 'r': [(x, r) for x, r in zip(reads, rr)]},
          open('runs/exp87.json', 'w'))
print(bench.health())
