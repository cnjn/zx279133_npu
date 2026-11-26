"""Summarise a flip experiment: per variant, the changed register bits and their inputs."""
import re
import sys
from collections import Counter
from probe import Probe


def sig(p, name):
    a = p.analyse(name)
    out = []
    for r, desc in a.items():
        if r >= 32:
            continue
        for b, d in enumerate(desc):
            if d != 'keep':
                out.append(f'r{r}.{b}<-{d}')
    return out


if __name__ == '__main__':
    p = Probe.load(sys.argv[1])
    def key(n):
        m = re.match(r'(.*)_b(\d+)$', n)
        return (m[1], int(m[2])) if m else (n[:-5], -1)
    names = sorted({k[0] for k in p.data}, key=key)
    base = {}
    for n in names:
        fam = key(n)[0]
        s = sig(p, n)
        if n.endswith('_base'):
            base[fam] = s
            print(f'{n}: {" ".join(s)}')
        else:
            if s == base.get(fam):
                print(f'  {n}: same')
            else:
                print(f'  {n}: {" ".join(s)}')
