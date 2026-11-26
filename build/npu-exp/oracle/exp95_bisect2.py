"""exp95: which exp94 block breaks the path to the CPU? One packet each, ping after each."""
import random
import bench
import exp94_cop4 as e
from exp88_bisect import ping_ok

order = [('cop', 15, 34), ('cop', 11, 48), ('cop', 12, 48), ('dpi_keyconst',), ('dpi_keyreg',),
         ('lockT', 1), ('unlockT', 1), ('lock2x',), ('cop', 11, 34), ('cop', 12, 34), ('cop', 15, 48),
         ('cop', 11, 50), ('cop', 12, 50), ('cop', 15, 50)]
b = e.b
print(b.install())
print('baseline', ping_ok())
for k in order:
    r = b.run([(b_blk := e.blk[k], [random.getrandbits(32) for _ in range(12)])], window=1, rounds=1)[0]
    ok = ping_ok()
    print(k, 'reply' if r else 'drop', 'ping', ok, flush=True)
    if not ok:
        break
b.restore()
print('after restore', ping_ok(), bench.health())
