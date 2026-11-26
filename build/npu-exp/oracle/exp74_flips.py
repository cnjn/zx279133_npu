"""exp74: single-bit flips (bits 0..47) of fset2 / op052 / cset / cset_r2 / fsetr words."""
import sys
from probe import Probe
BASES = {'fset2A': 0x02aa34cd7adb04d8, 'op052': 0x05223ea5dbe80520, 'csetm80': 0x028a00a01ff0100f,
         'cset_r2': 0x028b3cbc0000000f, 'fsetr': 0x068a02281e0003ff}
which = sys.argv[1].split(',') if len(sys.argv) > 1 else list(BASES)
p = Probe('exp74_' + '_'.join(which), seed=74)
for n in which:
    w = BASES[n]
    p.add(f'{n}_base', [f'.word {w:016x}'], fills=(0, 0xffffffff))
    for i in range(48):
        p.add(f'{n}_b{i}', [f'.word {w ^ (1 << i):016x}'], fills=(0, 0xffffffff))
p.go(nvec=24)
