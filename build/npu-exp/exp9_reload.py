"""exp9: load whole microcode files built by npasm from edited assembly.

Both files insert a new instruction before L3421, shifting every instruction,
branch target and trailer entry address after PC 3420 by one. `ctrl` changes
nothing else (any relocation error should break the to-CPU path that pings use);
`test` also replaces PC 3415 by `b.eq r5[29:24], 0xe, L3421`, which should move
the per-packet count from "port 15 output unicast" to "... boardcast".
The stock /etc/mcode/mcode_133.bin is reloaded at the end.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'npu-re'))
from npasm import assemble  # noqa: E402
from npdis import disassemble  # noqa: E402

MAC, SERDIR = '192.168.174.5', '/tmp/ontser.WZUED8'
STOCK = HERE.parents[1] / 'extracted/kernel1/rootfs/etc/mcode/mcode_133.bin'
INSERT = '    movi r12[0], 0x0                ; exp9: inserted, unreachable (after br L3422)'


def build():
    src = disassemble(STOCK.read_bytes()).splitlines()
    at = src.index('L3421:')
    pc3415 = next(i for i, l in enumerate(src) if l.split(';')[-1].split()[:1] == ['3415'])
    assert 'b.eq r14[25:24], 0x0, L3421' in src[pc3415], src[pc3415]
    ctrl = src[:at] + [INSERT] + src[at:]
    test = list(ctrl)
    test[pc3415] = '    b.eq r5[29:24], 0xe, L3421      ; exp9: test compare'
    out = {}
    for name, lines in (('ctrl', ctrl), ('test', test)):
        blob = assemble('\n'.join(lines) + '\n', fit_gap=True)
        Path(f'/tmp/exp9-{name}.bin').write_bytes(blob)
        Path(HERE / f'exp9-{name}.s').write_text('\n'.join(lines) + '\n')
        out[name] = blob
    return out


BOARD_SH = r'''
cd /sys/devices/platform/np
cnt(){ dmesg -c >/dev/null; cat table_debug/debug_stat_show; dmesg -c | awk '/port id 15 output unicast/{u=$NF} /port id 15 output boardcast/{b=$NF} END{print u+0, b+0}'; }
show(){ dmesg -c >/dev/null; echo d54 > ppu_debug/inst_get; echo d58 > ppu_debug/inst_get; dmesg -c | grep -o 'inst[0-3]: 0x[0-9a-f]*' | tr '\n' ' '; echo; }
for f in /tmp/exp9-ctrl.bin /tmp/exp9-test.bin /etc/mcode/mcode_133.bin; do
  sha256sum $f | cut -c1-16
  dmesg -c >/dev/null; echo $f > ppu_debug/mcode_download_file; sleep 2; dmesg -c | tail -2
  show
  set -- $(cnt); u0=$1; b0=$2
  sleep 5
  set -- $(cnt); echo "R $f $(($1-u0)) $(($2-b0))"
done
echo DONE
'''


def run():
    Path('/tmp/exp9.sh').write_text(BOARD_SH)
    subprocess.run(['scp', '-q', '/tmp/exp9-ctrl.bin', '/tmp/exp9-test.bin', '/tmp/exp9.sh',
                    f'{MAC}:/tmp/'], check=True)
    remote = f'''
set -e
cd {SERDIR}
push(){{ python3 ser.py "nc -l -p $3 > $2 & sleep 1; echo ok" 8 >/dev/null; sleep 1;
  python3 -c "import socket,sys; s=socket.create_connection(('192.168.1.1',int(sys.argv[2]))); s.sendall(open(sys.argv[1],'rb').read()); s.close()" "$1" "$3"; sleep 2; }}
push /tmp/exp9-ctrl.bin /tmp/exp9-ctrl.bin 9141
push /tmp/exp9-test.bin /tmp/exp9-test.bin 9142
push /tmp/exp9.sh /tmp/exp9.sh 9143
ping -n -i 0.1 -c 600 192.168.1.1 > /tmp/exp9-ping.txt 2>&1 & pp=$!
python3 ser.py "sh /tmp/exp9.sh" 90
kill $pp 2>/dev/null || true
tail -3 /tmp/exp9-ping.txt
'''
    r = subprocess.run(['ssh', '-o', 'BatchMode=yes', MAC, 'sh -s'], input=remote, text=True,
                       capture_output=True, timeout=300)
    (HERE / 'exp9.log').write_text(r.stdout + r.stderr)
    return r.stdout


if __name__ == '__main__':
    blobs = build()
    import hashlib
    for k, b in blobs.items():
        print(k, hashlib.sha256(b).hexdigest()[:16], len(b))
    print(run())
