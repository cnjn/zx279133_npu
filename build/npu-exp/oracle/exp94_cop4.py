"""exp94: (A) ops 11/12/15 against real tables (#34 eRAM, #50 hash, #48 stat) with idx and
key filled, drop reason read afterwards; (B) DPI: fixed key + random payload vs random key
+ fixed payload; (C) global lock with the id in the table field, same-thread double lock."""
import json
import random
import bench

random.seed(94)
CLEAN = []
for S in range(4):
    CLEAN += ['xmovi idx[0..3], 0x0', 'nop', f'lkup s{S}, 0x2, #34']
KEYFILL = [f'kmov key[{4 * i}..{4 * i + 3}], r{20 + i}' for i in range(12)] + ['nop']
IDXFILL = ['xmovi idx[0..3], 0x0', 'xmov idx[128..131], r20', 'xmovi idx[132..135], 0x0', 'xmovi idx[136..139], 0x0']
KEYCONST = ['movw r28, 0x00002011', 'movw r29, 0x22334455', 'movw r30, 0x66778899', 'movw r31, 0xaabbccdd', 'nop',
            'kmov key[0..3], r28', 'kmov key[4..7], r29', 'kmov key[8..11], r30', 'kmov key[12..15], r31', 'nop']
b = bench.Bench('exp94')
blk = {}
for op in (11, 12, 15):
    for t in (34, 50, 48, 210):
        blk[('cop', op, t)] = b.block(CLEAN + KEYFILL + IDXFILL + ['nop', f'lkup s1, {op:#x}, #{t}', 'nop', 'nop'], 'hi')
blk[('dpi_keyconst',)] = b.block(CLEAN + KEYCONST + ['lkup s1, 0x6, #0', 'nop', 'nop'], 'hi')
blk[('dpi_keyreg',)] = b.block(CLEAN + KEYFILL + ['lkup s1, 0x6, #0', 'nop', 'nop'], 'hi')
for t in (1, 2):
    blk[('lockT', t)] = b.block(CLEAN + KEYFILL + [f'lkup s1, 0x11, #{t}', 'nop', 'nop'], 'hi')
    blk[('unlockT', t)] = b.block(CLEAN + KEYFILL + [f'lkup s1, 0x12, #{t}', 'nop', 'nop'], 'hi')
blk[('lock2x',)] = b.block(CLEAN + KEYFILL + ['lkup s1, 0x11, #5', 'nop', 'mov r28, r36', 'nop',
                                              'lkup s1, 0x11, #5', 'nop', 'mov r29, r36', 'nop',
                                              'lkup s1, 0x12, #5', 'nop', 'mov r30, r36', 'nop'], 'hi')


def show(r, regs):
    return 'drop' if r is None else ' '.join(f'{k}={r[k]:08x}' for k in regs if k in r)


def drops():
    o = bench.ser('cd /sys/devices/platform/np/ppu_debug; dmesg -c >/dev/null; cat drop_status; '
                  'echo 1 > me_drop_reason_clr; dmesg -c | grep -E "\\([0-9]\\)|pc" | grep -v ": *0$" | sort | uniq -c', 40)
    return o.replace('[exit 0]', '').strip()


if __name__ == '__main__':
    print(b.install())
    drops()
    res = {}
    for op in (11, 12, 15):
        for t in (34, 50, 48, 210):
            r = b.run([(blk[('cop', op, t)], [random.getrandbits(32) for _ in range(12)])], window=1, rounds=1)[0]
            res[f'cop{op}#{t}'] = r
            print(f'op {op} #{t}: {show(r, ("r36", "r37", "r38", "r39"))}')
    print('drop reasons after A:', drops())
    fixed_payload = [0x01020304 * (j + 1) & 0xffffffff for j in range(12)]
    rows = []
    for i in range(3):
        rows.append(('keyconst/payload random', b.run([(blk[('dpi_keyconst',)], [random.getrandbits(32) for _ in range(12)])], window=1, rounds=1)[0]))
    for i in range(2):
        rows.append(('keyconst/payload fixed', b.run([(blk[('dpi_keyconst',)], fixed_payload)], window=1, rounds=1)[0]))
    for i in range(2):
        rows.append(('keyreg/payload fixed', b.run([(blk[('dpi_keyreg',)], fixed_payload)], window=1, rounds=1)[0]))
    for n, r in rows:
        print(f'dpi {n:26}: {show(r, ("r36", "r37", "r38", "r39"))}')
    res['dpi'] = rows
    print('health before locks', bench.health())
    for name in (('lockT', 1), ('lockT', 1), ('unlockT', 1), ('lockT', 1), ('lockT', 2), ('unlockT', 2), ('unlockT', 1),
                 ('lock2x',), ('lock2x',)):
        r = b.run([(blk[name], [0] * 12)], window=1, rounds=1)[0]
        print(f'{str(name):16}: {show(r, ("r28", "r29", "r30", "r36"))}')
        res[str(name)] = r
    print('health after locks', bench.health())
    b.restore()
    json.dump(res, open('runs/exp94.json', 'w'), default=str)
