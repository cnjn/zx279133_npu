"""exp88: which lookup op code breaks the to-CPU path (exp86 left ping dead)?
One packet per op (same block as exp86), then a ping check from the Mac; stop at the
first op after which ping fails."""
import sys
import bench

CLEAN = []
for S in range(4):
    CLEAN += ['xmovi idx[0..3], 0x0', 'nop', f'lkup s{S}, 0x2, #34']
SETUP = CLEAN + ['movw r29, 0x5', 'nop', 'xmov idx[0..3], r29', 'kmov key[0..3], r20', 'kmov key[4..7], r21',
                 'movw r30, 0x1b000160', 'nop', 'xmov idx[128..131], r30', 'xmovi idx[132..135], 0x0',
                 'xmovi idx[136..139], 0x0', 'nop']
OPS = [int(x) for x in sys.argv[1].split(',')] if len(sys.argv) > 1 else list(range(2, 19))


def ping_ok():
    out = bench.mac('ping -c 4 -i 0.2 -t 3 192.168.1.1 | grep -o "[0-9]* packets received"', 20)
    return out.strip().startswith(('3', '4'))


if __name__ == '__main__':
    print(bench.ser('echo 201 1 64 > /sys/devices/platform/np/se_debug/creat_eram_sdt; echo ok', 20))
    b = bench.Bench('exp88')
    blk = {op: b.block(SETUP + [f'lkup s1, {op:#x}, #201', 'nop', 'nop'], 'hi') for op in OPS}
    print(b.install())
    print('baseline ping', ping_ok())
    for op in OPS:
        r = b.run([(blk[op], [0xa1a2a3a4, 2])], window=1, rounds=1)
        ok = ping_ok()
        print(f'op {op:2}: reply={r[0] is not None} ping_after={ok}', flush=True)
        if not ok:
            break
    b.restore()
    print('after restore ping', ping_ok())
    print(bench.health())
