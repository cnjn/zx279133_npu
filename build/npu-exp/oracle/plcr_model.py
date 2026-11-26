"""Model of the SE policer (#252, cd_mode 2) fitted in exp100; replays runs/exp100*.json.

State per flow: C, A, B token counters and the time of the last update (8000 ticks/s).
  cost  = 1000 per packet in packet mode (pkt_sign 1), len + 24 bytes in byte mode, for C;
          A and B are always charged len + 24.
  refill per tick: C += cir_raw (cap cbs); what C cannot take goes to A (cap cbs) and,
          with cf_flag 1, also to B (cap ebs); B += eir_raw on its own (cap ebs).
  colour (input colour 2 with cm_flag = red, input colour 1 with cm_flag skips step 1):
    1. C - cost >= floor_C          -> green, C -= cost  (floor_C 0 in packet mode, 16000 in byte mode)
    2. A - len24 >= 16000 and B - len24 >= 16000 -> green, A -= len24, B -= len24
    3. B - len24 >= 16000           -> yellow, B -= len24
    4. red
The first packet finds the counters full (time_last 0).

usage: python3 plcr_model.py [runs/exp100*.json ...]
"""
import glob
import json
import re
import sys

STOCK = {1: [1, 0, 1, 2, 0, 0, 20000, 4000]}


def raw_profile(fields):
    pkt, cm, cf, cd, ebs, eir, cbs, cir = fields
    div = 8 if pkt else 64
    cir_raw, eir_raw = cir // div, eir // div
    if cbs:
        cbs = max(cbs, 4 * cir_raw)
    if cbs <= 16000:
        cbs = 20000
    if eir_raw:
        if ebs:
            ebs = max(ebs, 4 * eir_raw)
        if ebs <= 16000:
            ebs = 20000
    return dict(pkt=pkt, cm=cm, cf=cf, cbs=cbs, ebs=ebs, cir=cir_raw, eir=eir_raw)


class Policer:
    def __init__(self, p):
        self.p = p
        self.C = self.A = self.B = None
        self.tick = None

    def refill(self, tick):
        p = self.p
        if self.tick is None:
            self.C, self.A, self.B = p['cbs'], p['cbs'], p['ebs']
        else:
            n = tick - self.tick
            if n > 0:
                c = self.C + n * p['cir']
                over = max(0, c - p['cbs'])
                self.C = min(c, p['cbs'])
                self.A = min(self.A + over, p['cbs'])
                self.B = min(self.B + n * p['eir'] + (over if p['cf'] else 0), p['ebs'])
        self.tick = tick

    def packet(self, tick, length, colour=0):
        self.refill(tick)
        p = self.p
        l24 = length + 24
        cost, floor = (1000, 0) if p['pkt'] else (l24, 16000)
        if p['cm'] and colour == 2:
            return 'R'
        if not (p['cm'] and colour == 1) and self.C - cost >= floor:
            self.C -= cost
            return 'G'
        if self.A - l24 >= 16000 and self.B - l24 >= 16000:
            self.A -= l24
            self.B -= l24
            return 'G'
        if self.B - l24 >= 16000:
            self.B -= l24
            return 'Y'
        return 'R'


COL = {0: 'G', 0x8000: 'Y', 0x10000: 'R'}


def replay(path):
    d = json.load(open(path))
    fields = d['fields'] or STOCK.get(d['profile'])
    if fields is None or fields[3] != 2:
        return None
    m = re.search(r'len(\d+)', path)
    length = int(m.group(1)) if m else 100
    m = re.search(r'col(\d)', path)
    colour = int(m.group(1)) if m else 0
    pol = Policer(raw_profile(fields))
    got = want = ''
    for ts, tr, out in d['rows']:
        if not out:
            continue
        want += COL.get(out[0], '?')
        got += pol.packet(int(tr * 8000), length, colour)
    # per 50 ms window (by send time): packets whose colour count differs
    ts = [r[0] for r in d['rows'] if r[2]]
    win = {}
    for t, a, b in zip(ts, got, want):
        w = win.setdefault(int(t * 20), [{}, {}])
        w[0][a] = w[0].get(a, 0) + 1
        w[1][b] = w[1].get(b, 0) + 1
    diff = sum(abs(w[0].get(c, 0) - w[1].get(c, 0)) for w in win.values() for c in 'GYR') // 2
    return len(want) - diff, len(want), got, want


if __name__ == '__main__':
    # these two were overwritten by later runs with another PLCR_LEN (saved again as bytes_len*)
    skip = ('p100_0_0_1_2_0_0_20000_1000.json', 'p100_0_0_1_2_0_0_50000_1000.json')
    files = sys.argv[1:] or [f for f in sorted(glob.glob('runs/exp100*.json')) if not f.endswith(skip)]
    tot = ok = 0
    for f in files:
        r = replay(f)
        if r is None:
            continue
        agree, n, got, want = r
        tot += n
        ok += agree
        cnt = lambda s: ' '.join(f'{c}{s.count(c)}' for c in 'GYR')
        print(f'{agree / n:7.2%} {n:6d}  board {cnt(want):22} model {cnt(got):22} {f}')
    print(f'total {ok}/{tot} = {ok / tot:.3%} (packets whose colour matches within 50 ms windows)')
