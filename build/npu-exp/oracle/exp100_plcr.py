"""exp100: the SE policer (#252, stat operand bit 28 = 0, mode 0x1f) on our own flow.

usage: python3 exp100_plcr.py FLOW PROFILE [profile fields...]
  Sets flow FLOW -> PROFILE (plcr_en 1); with 8 more numbers also writes PROFILE first:
  pkt_sign cm_flag cf_flag cd_mode ebs eir cbs cir (sysfs plcr_profile_set order).
  Then sends the PHASES schedule (a burst, then paced phases); every packet asks the
  policer once (idx[136..139] = length PLCR_LEN (default 100), colour 0). Records r36..r39 per packet with send times, plcr_stats
  before/after, and puts the flow back to 0 0 at the end."""
import json
import struct
import sys
import time
import bench

FLOW, PROF = int(sys.argv[1]), int(sys.argv[2])
FIELDS = [int(x) for x in sys.argv[3:11]] if len(sys.argv) >= 11 else None
SE = '/sys/devices/platform/np/se_debug'
CLEAN = []
for S in range(4):
    CLEAN += ['xmovi idx[0..3], 0x0', 'nop', f'lkup s{S}, 0x2, #34']
b = bench.Bench('exp100')
BLK = b.block(CLEAN + ['xmovi idx[0..3], 0x0', 'xmov idx[128..131], r20', 'xmov idx[132..135], r21',
                       'xmov idx[136..139], r22', 'nop', 'lkup.stat s1, #252', 'nop', 'nop'], 'hi')


def payload(ins):
    ins = list(ins) + [0] * (12 - len(ins))
    p = struct.pack('>HI', BLK, 0) + b''.join(struct.pack('>I', x & 0xffffffff) for x in ins)
    return p + bytes(96 - len(p))


PHASES = [('burst', 0.0, None, int(__import__('os').environ.get('PLCR_BURST', '200'))), ('1000pps', 1.0, 1000, 2000), ('1500pps', 4.0, 1500, 3000),
          ('3000pps', 7.0, 3000, 6000), ('6000pps', 10.0, 6000, 12000)]
LENGTH = int(__import__('os').environ.get('PLCR_LEN', '100'))
if __import__('os').environ.get('PLCR_ONLY_BURST'):
    PHASES = PHASES[:1]
if __import__('os').environ.get('PLCR_PHASES'):
    PHASES = eval(__import__('os').environ['PLCR_PHASES'])


def schedule():
    p = payload([0x1f << 23 | FLOW, 0, LENGTH | int(__import__('os').environ.get('PLCR_COLOR', '0')) << 14]).hex()
    plan = []
    for name, t0, rate, n in PHASES:
        plan += [(t0 if rate is None else t0 + i / rate, p) for i in range(n)]
    return plan


def plcr(cmds):
    return bench.ser(f'cd {SE}; dmesg -c >/dev/null; echo 3 > ../test/print_level; ' + '; '.join(cmds)
                     + '; echo 1 > ../test/print_level; dmesg -c | grep -E "plcr_en|profile_id|tei|tci|time_last|pkt_sign|cm_flag|cf_flag|cd_mode|bs |ir\\(|success|fail|error"; cat plcr_stats', 60)


if __name__ == '__main__':
    cmds = []
    if FIELDS:
        cmds.append(f'echo {PROF} ' + ' '.join(map(str, FIELDS)) + ' > plcr_profile_set')
    cmds += [f'echo {FLOW} 1 {PROF} > plcr_flow_set', f'echo {PROF} > plcr_profile_get', f'echo {FLOW} > plcr_flow_get']
    before = plcr(cmds)
    print(before)
    print(b.install())
    plan = schedule()
    open('/tmp/exp100.plan', 'w').write(''.join(f'{t:.6f} {h}\n' for t, h in plan))
    bench.mac_put('/tmp/exp100.plan', '/tmp/exp100.plan')
    bench.mac_put(str(bench.HERE / 'pace.py'), '/tmp/oracle_pace.py')
    print(bench.mac('python3 /tmp/oracle_pace.py /tmp/exp100.plan /tmp/exp100.out', 120))
    import subprocess
    subprocess.run(['scp', '-q', f'{bench.MAC}:/tmp/exp100.out', '/tmp/exp100.out'], check=True)
    rows = []
    for line in open('/tmp/exp100.out'):
        i, ts, tr, h = line.split()
        out = None if h == '-' else [struct.unpack_from('>I', bytes.fromhex(h), 6 + 4 * k)[0] for k in range(16, 20)]
        rows.append([float(ts), float(tr), out])
    after = plcr([f'echo {FLOW} > plcr_flow_get', f'echo {FLOW} 0 0 > plcr_flow_set'])
    print(after)
    print(b.restore())
    name = f'runs/exp100{"b" if len(PHASES) == 1 else ""}_f{FLOW}_p{PROF}' + __import__('os').environ.get('PLCR_TAG', '') + ('_' + '_'.join(map(str, FIELDS)) if FIELDS else '') + '.json'
    json.dump({'flow': FLOW, 'profile': PROF, 'fields': FIELDS, 'before': before, 'after': after, 'rows': rows}, open(name, 'w'))
    # summary per phase: colours, and the pass rate in the steady part (after 0.2 s)
    from collections import Counter
    k = 0
    for name_, t0, rate, n in PHASES:
        ph = rows[k:k + n]
        k += n
        c = Counter(tuple(r[2]) if r[2] else None for r in ph)
        pats = {(' '.join(f'{x:08x}' for x in key) if key else 'drop'): v for key, v in c.most_common(4)}
        if rate is None:
            first_red = next((i for i, r in enumerate(ph) if r[2] and r[2][0]), None)
            print(f'{name_:8} first red at packet {first_red}', pats)
        else:
            st = [r for r in ph if r[0] - t0 >= 0.2]
            g = sum(1 for r in st if r[2] and r[2][0] == 0)
            span = st[-1][0] - st[0][0] if len(st) > 1 else 1
            print(f'{name_:8} sent {len(st) / span:7.0f} pps, passed {g / span:7.0f} pps', pats)
    print('saved', name)
