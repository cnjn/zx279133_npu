#!/usr/bin/env python3
"""Run on the Mac. Fine scan: probe BLK-instruction blocks inside given ranges.
Per block: ICMP ping, TCP SYN to closed port 5555 from a unique source port (refused = reached
CPU), and whether key_last_info's e-key carries that source port. Auto-reboots on a wedge."""
import re, socket, subprocess, sys, time
HERE = '/tmp/ontser.WZUED8'; SER = f'{HERE}/ser.py'; RAW = f'{HERE}/raw.py'; P = '/sys/devices/platform/np/ppu_debug'
RANGES = [(640, 703), (3136, 3199), (3392, 3455), (4160, 4287), (4352, 4479)]
BLK = int(sys.argv[1]) if len(sys.argv) > 1 else 8
def ser(cmd, t=4): return subprocess.run(['python3', SER, cmd, str(t)], capture_output=True, text=True).stdout
def icmp(): return subprocess.run(['ping', '-c', '2', '-t', '3', '192.168.1.1'], capture_output=True).returncode == 0
def tcp(sport):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.settimeout(2)
    try:
        s.bind(('192.168.1.2', sport)); s.connect(('192.168.1.1', 5555)); return 'open'
    except ConnectionRefusedError: return 'ok'
    except OSError: return 'DEAD'
    finally: s.close()
def ekey_has(sport):
    out = ser(f'dmesg -c >/dev/null; cat {P}/key_last_info >/dev/null; dmesg | grep \"e key last 6\"', 5)
    m = re.search(r'e key last 6.*: (0x[0-9a-f]+)', out)
    return m and (int(m.group(1), 16) >> 16) == sport
def healthy(sport): return icmp() and tcp(sport) == 'ok'
def reboot():
    subprocess.run(['python3', RAW, 'reboot\\n', 'network services are disabled', '180'], capture_output=True)
    ser('lan1-up > /var/tmp/lan1.log 2>&1 & sleep 25; echo up', 40)
    stage()
    return icmp()
def stage():
    for i, (f, dst) in enumerate((('m0.bin', '/var/tmp/m0.bin'), ('orig.txt', '/var/tmp/orig.txt'), ('rng.sh', '/var/tmp/rng.sh'))):
        subprocess.run(['sh', f'{HERE}/push.sh', f'{HERE}/{f}', dst, str(9400 + i)], capture_output=True)
    ser('pkill nc; echo s', 3)
log = open(f'{HERE}/scan2.log', 'a'); k = 0
for a, z in RANGES:
    for b in range(a, z + 1, BLK):
        e = min(b + BLK - 1, z); k += 1; sport = 40000 + k
        ser(f'sh /var/tmp/rng.sh probe {b} {e}', 3)
        i_ok = icmp(); t = tcp(sport); key = ekey_has(sport)
        ser(f'sh /var/tmp/rng.sh restore {b} {e}', 3)
        ok = healthy(50000 + k)
        if not ok:
            ser(f'echo /var/tmp/m0.bin > {P}/mcode_download_file', 30); ok = healthy(51000 + k)
        note = '' if ok else ' WEDGED->reboot ' + str(reboot())
        print(f'{b:5d}-{e:5d} icmp={"ok" if i_ok else "DEAD"} tcp={t} ekey_sport={bool(key)}{note}', file=log, flush=True)
print('DONE', file=log, flush=True)
