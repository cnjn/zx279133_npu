"""exp8: batched board trials at PC 3415 (one serial session for the whole plan).

Observation point as in exp7: an instruction at 3415 that branches to 3421
makes CPU-bound packets count as "port 15 output unicast"; falling through
makes them count as "port 15 output boardcast". The Mac pings the board
continuously while a shell script on the board walks the plan.

Plans
  o:     what bit 51 (.o) and the unseen modes 2/3 do
  bits:  for word W and bit b, compare `[c=(W<<5)|b] br` with `b.eq rW[b], 1`
         -> tests "a condition code is a register bit address"
"""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'npu-re'))
from npisa import Bcmp, Br  # noqa: E402

MAC = '192.168.174.5'
SERDIR = '/tmp/ontser.WZUED8'
PC, TARGET, ORIG = 3415, 3421, 0x02906a760003a001
DWELL = 2

BOARD_SH = r'''
cd /sys/devices/platform/np
cnt(){ dmesg -c >/dev/null; cat table_debug/debug_stat_show; dmesg -c | awk '/port id 15 output unicast/{u=$NF} /port id 15 output boardcast/{b=$NF} END{print u+0, b+0}'; }
while read pc hi lo tag; do
  echo $pc $hi $lo > ppu_debug/inst_set
  set -- $(cnt); u0=$1; b0=$2
  sleep DWELL
  set -- $(cnt); echo "R $tag $(($1-u0)) $(($2-b0))"
done < /tmp/exp8.plan
echo PCX ORIGH ORIGL > ppu_debug/inst_set
dmesg -c >/dev/null; echo PCX > ppu_debug/inst_get; dmesg -c | grep -o 'inst3: 0x[0-9a-f]*'
echo DONE
'''.replace('DWELL', str(DWELL)).replace('PCX', f'{PC:x}').replace(
    'ORIGH', f'{ORIG >> 32:x}').replace('ORIGL', f'{ORIG & 0xffffffff:x}')


def cmp_word(mode, o, v, src=5 * 32 + 24, width=6):
    return Bcmp.encode({'target': TARGET, 'value': v, 'src': src, 'width': width,
                        'mode': mode, 'o': o})


def plan_o():
    rows = []
    for mode in (0, 1, 2, 3, 4, 5, 6, 7):
        for o in (0, 1):
            for v in (14, 15, 16):
                rows.append((f'm{mode}o{o}v{v}', cmp_word(mode, o, v)))
    return rows


def plan_bits(words):
    rows = []
    for w in words:
        for b in range(32):
            c = w << 5 | b
            rows.append((f'c{c:03x}', Br.encode({'pc': PC, 'target': TARGET, 'cond': c})))
            rows.append((f'r{w}.{b}', cmp_word(0, 0, 1, src=w * 32 + b, width=1)))
    return rows


def run(rows, name):
    plan = ''.join(f'{PC:x} {w >> 32:x} {w & 0xffffffff:x} {tag}\n' for tag, w in rows)
    Path(f'/tmp/exp8-{name}.plan').write_text(plan)
    Path('/tmp/exp8.sh').write_text(BOARD_SH)
    secs = len(rows) * (DWELL + 2) + 30
    remote = f'''
set -e
cd {SERDIR}
push(){{ python3 ser.py "nc -l -p $3 > $2 & sleep 1; echo ok" 8 >/dev/null; sleep 1;
  python3 -c "import socket,sys; s=socket.create_connection(('192.168.1.1',int(sys.argv[2]))); s.sendall(open(sys.argv[1],'rb').read()); s.close()" "$1" "$3"; sleep 1; }}
push /tmp/exp8-{name}.plan /tmp/exp8.plan 9131
push /tmp/exp8.sh /tmp/exp8.sh 9132
ping -n -i 0.1 -c {secs * 10} 192.168.1.1 >/dev/null 2>&1 & pp=$!
python3 ser.py "sh /tmp/exp8.sh" {secs}
kill $pp 2>/dev/null || true
'''
    subprocess.run(['scp', '-q', f'/tmp/exp8-{name}.plan', '/tmp/exp8.sh', f'{MAC}:/tmp/'], check=True)
    r = subprocess.run(['ssh', '-o', 'BatchMode=yes', MAC, 'sh -s'], input=remote, text=True,
                       capture_output=True, timeout=secs + 120)
    out = r.stdout
    Path(f'exp8-{name}.log').write_text(out + r.stderr)
    res = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) == 4 and p[0] == 'R':
            res[p[1]] = (int(p[2]), int(p[3]))
    print(json.dumps({'trials': len(res), 'restored': 'inst3: 0x02906a760003a001' in out,
                      'done': 'DONE' in out}))
    return res


def taken(u, b):
    if u + b < 5:
        return None
    return True if u >= 0.9 * (u + b) else False if b >= 0.9 * (u + b) else 'mixed'


def plan_regs(words):
    return [(f'r{w}.{b}', cmp_word(0, 0, 1, src=w * 32 + b, width=1)) for w in words for b in range(32)]


if __name__ == '__main__':
    which = sys.argv[1]
    if which == 'regs':
        words = [int(x) for x in sys.argv[2:]]
        res = run(plan_regs(words), 'regs')
        for w in words:
            bits_ = [taken(*res[f'r{w}.{b}']) if f'r{w}.{b}' in res else None for b in range(32)]
            val = sum(1 << b for b, t in enumerate(bits_) if t is True)
            unk = [b for b, t in enumerate(bits_) if not isinstance(t, bool)]
            print(f'r{w} = {val:#010x}  bytes(lo..hi) {[val >> (8 * i) & 255 for i in range(4)]}  unstable bits {unk}')
        sys.exit()
    if which == 'o':
        res = run(plan_o(), 'o')
        for tag, (u, b) in res.items():
            print(tag, u, b, taken(u, b))
    else:
        words = [int(x) for x in sys.argv[2:]]
        res = run(plan_bits(words), 'bits')
        for w in words:
            agree = n = 0
            line = []
            for b in range(32):
                c = res.get(f'c{(w << 5 | b):03x}')
                r = res.get(f'r{w}.{b}')
                tc = taken(*c) if c else None
                tr = taken(*r) if r else None
                line.append(f'{b}:{"1" if tc is True else "0" if tc is False else "?"}'
                            f'{"1" if tr is True else "0" if tr is False else "?"}')
                if isinstance(tc, bool) and isinstance(tr, bool):
                    n += 1
                    agree += tc == tr
            print(f'word {w}: cond-vs-register agree {agree}/{n}  ', ' '.join(line))
