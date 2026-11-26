"""exp7: pin down the 0290/0298 compare modes on the board.

PC 3415 normally is `b.eq r14[25:24], 0x0, L3421`: taken -> table-48 base 0xc0
("port id N output unicast"), not taken (for unicast r14[25:24]=0 never) ->
falls to the broadcast base 0x140. Pings to the board are counted as port 15.
We replace 3415 by `b.<mode> r5[29:24], V, L3421` (r5[29:24] = 15 is the port
that 3414 copies into the index) and count, per trial, how many of N pings
land in "port 15 output unicast" (taken) vs "... boardcast" (not taken).
The original word is restored at the end and read back.

Run from the analysis VM; the board is reached through the Mac's serial helper.
"""
import json
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'npu-re'))
from npisa import Bcmp  # noqa: E402

MAC = '192.168.174.5'
SER = 'cd /tmp/ontser.WZUED8; python3 ser.py'
PC = 3415
ORIG = 0x02906a760003a001
SRC, WIDTH, TARGET = 5 * 32 + 24, 6, 3421
NPING = 30


def board(cmd, timeout=15):
    r = subprocess.run(['ssh', '-o', 'BatchMode=yes', MAC, f"{SER} {json.dumps(cmd)} {timeout}"],
                       capture_output=True, text=True, timeout=timeout + 20)
    return r.stdout


def mac(cmd, timeout=30):
    return subprocess.run(['ssh', '-o', 'BatchMode=yes', MAC, cmd], capture_output=True,
                          text=True, timeout=timeout).stdout


def write(word):
    out = board(f'cd /sys/devices/platform/np; dmesg -c >/dev/null; '
                f'echo {PC:x} {word >> 32:x} {word & 0xffffffff:x} > ppu_debug/inst_set; '
                f'echo {PC:x} > ppu_debug/inst_get; dmesg -c | tail -3')
    got = re.findall(r'inst3: 0x([0-9a-f]+)', out)   # 3415 is the 4th of its aligned group
    return int(got[-1], 16) if got else None


def counters():
    out = board('cd /sys/devices/platform/np; dmesg -c >/dev/null; '
                'cat table_debug/debug_stat_show; dmesg -c | grep "port id 15 output"')
    c = {}
    for kind in ('unicast', 'multicast', 'boardcast'):
        m = re.search(rf'port id 15 output {kind} cnt:\s+(\d+)', out)
        c[kind] = int(m[1]) if m else None
    return c


def trial(word, label):
    back = write(word)
    if back != word:
        return {'label': label, 'error': f'readback {back!r} != {word:#x}'}
    time.sleep(0.5)
    a = counters()
    p = mac(f'ping -n -c {NPING} -i 0.15 -t 8 192.168.1.1 | tail -2')
    time.sleep(0.5)
    b = counters()
    d = {k: (b[k] - a[k]) if None not in (a[k], b[k]) else None for k in a}
    rx = re.search(r'(\d+) packets received', p)
    return {'label': label, 'word': f'{word:016x}', 'delta': d, 'ping_rx': int(rx[1]) if rx else None}


def main(plan):
    results = []
    try:
        for mode, o, v in plan:
            w = ORIG if mode is None else Bcmp.encode(
                {'target': TARGET, 'value': v, 'src': SRC, 'width': WIDTH, 'mode': mode, 'o': o})
            label = 'orig' if mode is None else f'm{mode}{".o" if o else ""} V={v}'
            r = trial(w, label)
            print(json.dumps(r), flush=True)
            results.append(r)
    finally:
        back = write(ORIG)
        print(json.dumps({'restored': f'{back:#x}' if back else None, 'ok': back == ORIG}), flush=True)
    return results


if __name__ == '__main__':
    which = sys.argv[1] if len(sys.argv) > 1 else 'controls'
    plans = {
        'controls': [(None, 0, 0), (0, 0, 15), (0, 0, 14), (1, 0, 15), (1, 0, 14)],
        'ordered': [(m, 1, v) for m in (4, 5, 6, 7) for v in (14, 15, 16)],
    }
    main(plans[which])
