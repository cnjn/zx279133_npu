"""exp96: does repeating the dropped coprocessor ops (exp93 part A) eventually break the
path to the CPU? Ping after every batch of 10 packets."""
import bench
import exp93_cop3 as e
from exp88_bisect import ping_ok
b = e.b
print(b.install())
print('baseline', ping_ok(), bench.health())
vec = [(e.blk[('cop', op)], e.key_with_prefix(p)) for op in (11, 12, 15) for p in e.PREFIXES]
for i in range(0, len(vec), 10):
    r = b.run(vec[i:i + 10], window=1, rounds=1)
    ok = ping_ok()
    print(f'packets {i}-{i + len(r) - 1}: replies {sum(x is not None for x in r)} ping {ok}', flush=True)
    if not ok:
        break
# then the DPI and lock steps of exp93
for name, lid in [('dpi', 0)] * 3 + [('lock', 1), ('unlock', 1), ('lock_lock', 4)]:
    k = e.key_with_prefix(32) if name == 'dpi' else [lid] + [0] * 11
    b.run([(e.blk[(name,) if name != 'dpi' else ('dpi', 0)], k)], window=1, rounds=1)
    ok = ping_ok()
    print(name, lid, 'ping', ok, flush=True)
    if not ok:
        break
b.restore()
print('after restore', ping_ok(), bench.health())
