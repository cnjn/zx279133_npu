"""exp12: one-shot coverage of the to-CPU (ping) path with 64 counter probes."""
import json, re, subprocess, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(HERE.parent / 'npu-re'))
from probe import build, counter_name
from npasm import assemble
from npdis import split, entry_addrs
from npisa import decode, code_targets

MAC, SERDIR = '192.168.174.5', '/tmp/ontser.WZUED8'
STOCK = HERE.parents[1] / 'extracted/kernel1/rootfs/etc/mcode/mcode_133.bin'

def candidates(words):
    D = [decode(y, i) for i, y in enumerate(words)]
    return sorted({a for f, d in D if f for a in code_targets(f, d)} | {0})

BOARD_SH = r'''
cd /sys/devices/platform/np
snap(){ dmesg -c >/dev/null; cat table_debug/debug_stat_show; dmesg -c | grep -E 'port id (3[2-9]|[4-6][0-9]) output (boardcast|multicast)|mac sa lookup fail|protocol action trap|port id 15 output unicast'; }
dmesg -c >/dev/null; echo /tmp/exp12.bin > ppu_debug/mcode_download_file; sleep 2; dmesg -c | tail -1
echo === A; snap
sleep 8
echo === B; snap
dmesg -c >/dev/null; echo /etc/mcode/mcode_133.bin > ppu_debug/mcode_download_file; sleep 2; dmesg -c | tail -1
echo DONE
'''

def main():
    stock = STOCK.read_bytes()
    words = split(stock)[1]
    text, pcs = build(stock, candidates(words))
    (HERE / 'exp12.s').write_text(text)
    blob = assemble(text, fit_gap=True)
    Path('/tmp/exp12.bin').write_bytes(blob)
    Path('/tmp/exp12.sh').write_text(BOARD_SH)
    json.dump(pcs, open(HERE / 'exp12-pcs.json', 'w'))
    print('probes', len(pcs), pcs)
    subprocess.run(['scp', '-q', '/tmp/exp12.bin', '/tmp/exp12.sh', f'{MAC}:/tmp/'], check=True)
    remote = f'''
cd {SERDIR}
push(){{ python3 ser.py "nc -l -p $3 > $2 & sleep 1; echo ok" 8 >/dev/null; sleep 1;
  python3 -c "import socket,sys; s=socket.create_connection(('192.168.1.1',int(sys.argv[2]))); s.sendall(open(sys.argv[1],'rb').read()); s.close()" "$1" "$3"; sleep 2; }}
push /tmp/exp12.bin /tmp/exp12.bin 9161
push /tmp/exp12.sh /tmp/exp12.sh 9162
ping -n -i 0.1 -c 250 192.168.1.1 > /tmp/exp12-ping.txt 2>&1 & pp=$!
python3 ser.py "sh /tmp/exp12.sh" 60
kill $pp 2>/dev/null; tail -2 /tmp/exp12-ping.txt
'''
    r = subprocess.run(['ssh', '-o', 'BatchMode=yes', MAC, 'sh -s'], input=remote, text=True,
                       capture_output=True, timeout=200)
    out = r.stdout
    (HERE / 'exp12.log').write_text(out + r.stderr)
    a, b = out.split('=== A', 1)[1].split('=== B', 1)
    val = lambda txt: {m[0]: int(m[1]) for m in re.findall(r'(port id \d+ output \w+|mac sa lookup fail|protocol action trap) cnt:\s+(\d+)', txt)}
    va, vb = val(a), val(b)
    print('ping:', out.strip().splitlines()[-2:])
    for k, pc in enumerate(pcs):
        n = counter_name(k)
        d = vb.get(n, 0) - va.get(n, 0)
        print(f'probe {k:2} pc {pc:5}: +{d}' + ('   <== executed' if d > 0 else ''))
    for n in ('mac sa lookup fail', 'protocol action trap', 'port id 15 output unicast'):
        print(n, vb.get(n, 0) - va.get(n, 0))

if __name__ == '__main__':
    main()
