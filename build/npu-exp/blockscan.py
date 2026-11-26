#!/usr/bin/env python3
"""Run on the Mac. For each 64-instruction block of the main program, replace it with a
probe word, hot-load it on the ONT, test ICMP and TCP from the Mac, then hot-restore m0.
Output: one line per block -> blockscan.log."""
import os, socket, struct, subprocess, sys, time
HERE = '/tmp/ontser.WZUED8'; SER = f'{HERE}/ser.py'; P = '/sys/devices/platform/np/ppu_debug'
PROBE = 0x07ffffffffffffff; BLK = int(sys.argv[1]) if len(sys.argv) > 1 else 64
m0 = open(f'{HERE}/m0.bin', 'rb').read(); n = struct.unpack('>I', m0[12:16])[0]
def ser(cmd, t=20):
    return subprocess.run(['python3', SER, cmd, str(t)], capture_output=True, text=True).stdout
def push(data, dst, port):
    ser(f'nc -l -p {port} > {dst} & sleep 1; echo l', 10)
    s = socket.create_connection(('192.168.1.1', port), timeout=5); s.sendall(data); s.close(); time.sleep(0.5)
def icmp(): return subprocess.run(['ping', '-c', '2', '-t', '3', '192.168.1.1'], capture_output=True).returncode == 0
def tcp():
    try: socket.create_connection(('192.168.1.1', 22), timeout=2).close(); return True
    except OSError: return False
def restore():
    for _ in range(3):
        ser(f'echo /var/tmp/m0.bin > {P}/mcode_download_file', 30)
        if icmp() and tcp(): return True
    return False
START = int(sys.argv[2]) if len(sys.argv) > 2 else 0
log = open(f'{HERE}/blockscan.log', 'a')
for b in range(START, n, BLK):
    e = min(b + BLK, n) - 1
    ser(f'sh /var/tmp/rng.sh probe {b} {e}', 3)
    i_ok, t_ok = icmp(), tcp()
    ser(f'sh /var/tmp/rng.sh restore {b} {e}', 3)
    ok = (icmp() and tcp()) or restore()
    line = f'{b:5d}-{min(b + BLK, n) - 1:5d} icmp={"ok" if i_ok else "DEAD"} tcp={"ok" if t_ok else "DEAD"} restored={ok}'
    print(line, file=log, flush=True)
    if not ok: print('ABORT: restore failed', file=log, flush=True); break
print('DONE', file=log, flush=True)
