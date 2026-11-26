"""Differential probe: run instruction words on the board with random r20..r31 and
two known fills of the other registers, dump r0..r39, and describe every output
bit that the words change as a function of the inputs.

    from probe import Probe
    p = Probe('exp73')
    p.add('fset2_5009', ['.word 02aa...'])
    p.go(nvec=128)            # install, run, restore
    p.report('fset2_5009')
"""
import json
import random
import bench

FILL_REGS = [0, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]
FILLS = (0x00000000, 0xffffffff, 0x5a5a5a5a)
VOLATILE = {0, 1, 41}          # timer-like / link: ignored in the analysis


class Probe:
    def __init__(self, name, seed=0):
        self.b = bench.Bench(name)
        self.name = name
        self.tests = {}          # name -> {(fill, page): block}
        self.rng = random.Random(seed)

    def add(self, name, words, fills=FILLS, pre=(), post_nops=2):
        blocks = {}
        for f in fills:
            if f'fill_{f:x}:' not in self.b.extra:
                self.b.extra += [f'fill_{f:x}:'] + [f'movi32 r{r}, {f:#x}' for r in FILL_REGS] + ['ret']
            setup = [f'call fill_{f:x}', 'nop']
            body = setup + list(pre) + list(words) + ['nop'] * post_nops
            for page in ('lo', 'hi'):
                blocks[(f, page)] = self.b.block(body, page)
        self.tests[name] = blocks

    def go(self, nvec=96, window=64, rounds=2, inputs=None, safety=True):
        self.inputs = inputs or [[self.rng.getrandbits(32) for _ in range(12)] for _ in range(nvec)]
        print(self.b.install())
        if safety:  # one packet per test first: a test that hangs a thread costs one thread only
            names = list(self.tests)
            sv = [(self.tests[n][(FILLS[0], 'lo')], self.inputs[0]) for n in names]
            sr = self.b.run(sv, window=1, rounds=1)
            self.unsafe = [n for n, r in zip(names, sr) if r is None]
            if self.unsafe:
                print('UNSAFE (no reply):', self.unsafe)
            for n in self.unsafe:
                del self.tests[n]
        vec, meta = [], []
        for name, blocks in self.tests.items():
            for (f, page), k in blocks.items():
                for i, ins in enumerate(self.inputs):
                    vec.append((k, ins))
                    meta.append((name, f, page, i))
        print(len(self.b.blocks), 'blocks', len(vec), 'packets')
        res = self.b.run(vec, window=window, rounds=rounds)
        print(self.b.last_err)
        self.b.restore()
        self.data = {}
        for (name, f, page, i), r in zip(meta, res):
            self.data.setdefault((name, f, i), {})
            if r is not None:
                self.data[(name, f, i)].update({int(k[1:]): v for k, v in r.items()})
        json.dump({'inputs': self.inputs, 'data': [[list(k), v] for k, v in self.data.items()]},
                  open(f'runs/{self.name}.json', 'w'))

    @classmethod
    def load(cls, name):
        p = cls(name)
        d = json.load(open(f'runs/{name}.json'))
        p.inputs = d['inputs']
        p.data = {tuple(k): {int(a): b for a, b in v.items()} for k, v in d['data']}
        return p

    def expected_unchanged(self, f, i, r):
        if 20 <= r < 32:
            return self.inputs[i][r - 20]
        if r in FILL_REGS:
            return f
        return None

    def analyse(self, name):
        """For each register bit: 'keep' (unchanged), a constant, an input bit (rN.b or
        ~rN.b), or 'complex'. Returns {reg: [32 descriptions]} for regs that change."""
        fills = sorted({k[1] for k in self.data if k[0] == name})
        out = {}
        for r in range(40):
            if r in VOLATILE or r == 6:
                continue
            desc = []
            changed = False
            for bit in range(32):
                obs = []
                for (n, f, i), v in self.data.items():
                    if n != name or r not in v:
                        continue
                    exp = self.expected_unchanged(f, i, r)
                    obs.append((f, i, (v[r] >> bit) & 1, None if exp is None else (exp >> bit) & 1))
                if not obs:
                    desc.append('-')
                    continue
                if all(o[3] is not None and o[2] == o[3] for o in obs):
                    desc.append('keep')
                    continue
                changed = True
                vals = {o[2] for o in obs}
                if len(vals) == 1:
                    desc.append(str(vals.pop()))
                    continue
                cands = []
                for rr in range(20, 32):
                    for bb in range(32):
                        s = [(self.inputs[i][rr - 20] >> bb) & 1 for f, i, _, _ in obs]
                        y = [o[2] for o in obs]
                        if s == y:
                            cands.append(f'r{rr}.{bb}')
                        elif all(a != b for a, b in zip(s, y)):
                            cands.append(f'~r{rr}.{bb}')
                if all(o[3] is not None for o in obs):
                    # depends on the fill only?
                    if all(o[2] == o[3] for o in obs if True) is False and len({(o[0], o[2]) for o in obs}) == len({o[0] for o in obs}):
                        cands.append('fill-dependent')
                desc.append('|'.join(cands[:3]) if cands else 'complex')
            if changed:
                out[r] = desc
        return out

    def report(self, name):
        a = self.analyse(name)
        lines = [f'## {name}']
        for r, desc in a.items():
            parts = [f'{b}:{d}' for b, d in enumerate(desc) if d != 'keep']
            lines.append(f'  r{r}: ' + ' '.join(parts))
        return '\n'.join(lines)
