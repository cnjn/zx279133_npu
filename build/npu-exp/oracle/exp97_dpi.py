"""exp97: what does lkup op 6 (DPI channel) return? Long packets (1400 bytes) carry the
16-bit value (frame offset // 2) at every even frame offset, so any returned bytes can be
located in the packet. key[0..15] = r20..r23."""
import json
import bench
CLEAN = []
for S in range(4):
    CLEAN += ['xmovi idx[0..3], 0x0', 'nop', f'lkup s{S}, 0x2, #34']
KEY = ['kmov key[0..3], r20', 'kmov key[4..7], r21', 'kmov key[8..11], r22', 'kmov key[12..15], r23', 'nop']
b = bench.Bench('exp97')
k = b.block(CLEAN + KEY + ['lkup s1, 0x6, #0', 'nop', 'nop'], 'hi')
print(b.install())
tests = []
for k0 in (0, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x80000000, 0x00010000, 0x00800000,
           0x00000100, 0x00000001, 0x01020304, 0x00002011, 0x00002004, 0x01000040, 0x01000080, 0x01000100, 0x01000400):
    tests.append((k0, 0, 0, 0))
for k1 in (0x02040608, 0x00000001, 0x00010000, 0x01000000, 0x00000100):
    tests.append((0x01020304, k1, 0, 0))
for k2 in (0x00000001, 0x01000000):
    tests.append((0x01020304, 0, k2, 0))
res = b.run([(k, list(t)) for t in tests], window=1, rounds=1, length=1400)
b.restore()
out = []
for t, r in zip(tests, res):
    if r is None:
        print(' '.join(f'{x:08x}' for x in t), '-> drop'); out.append((t, None)); continue
    w = [r[f'r{36 + i}'] for i in range(4)]
    raw = b''.join(x.to_bytes(4, 'big') for x in w)
    # locate: pattern words give frame offset (value*2) for even offsets
    hints = []
    for i in range(0, 16, 2):
        v = int.from_bytes(raw[i:i + 2], 'big')
        if 48 <= v * 2 < 1500:
            hints.append(v * 2 - i)
    print(' '.join(f'{x:08x}' for x in t), '->', ' '.join(f'{x:08x}' for x in w), 'frame offset hints', sorted(set(hints))[:4])
    out.append((t, w))
json.dump(out, open('runs/exp97.json', 'w'))
print(bench.health())
