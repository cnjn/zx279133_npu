"""exp13: register-free probe (xmovi only): which idx byte order matches xmov idx[128..131], r30?"""
import re, subprocess, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'npu-re'))
from npasm import assemble
from npdis import disassemble
MAC, SERDIR = '192.168.174.5', '/tmp/ontser.WZUED8'
STOCK = HERE.parents[1] / 'extracted/kernel1/rootfs/etc/mcode/mcode_133.bin'
HI = (1 << 12) | (0x16 << 7)          # r30[28] = 1, r30[27:23] = 0x16  -> upper half 0x1b00

def probe(first, second, tag):
    return [f'    xmovi idx[128..129], {first:#x}   ; {tag}', f'    xmovi idx[130..131], {second:#x}',
            '    xmovi idx[132..135], 0x0', '    xmovi idx[136..139], 0x0', '    lkup s2, 0x3, #48']

def main():
    src = disassemble(STOCK.read_bytes()).splitlines()
    at = next(i for i, l in enumerate(src) if l.split(';')[-1].split()[:1] == ['4879'])
    src[at:at] = probe(HI, 0x160, 'order A: hi first') + probe(0x161, HI, 'order B: lo first')
    Path('/tmp/exp13.bin').write_bytes(assemble('\n'.join(src) + '\n', fit_gap=True))
    sh = r'''cd /sys/devices/platform/np
snap(){ dmesg -c >/dev/null; cat table_debug/debug_stat_show; dmesg -c | grep -E 'port id 3[23] output boardcast|mac sa lookup fail'; }
echo /tmp/exp13.bin > ppu_debug/mcode_download_file; sleep 2
echo === A; snap; sleep 6; echo === B; snap
echo /etc/mcode/mcode_133.bin > ppu_debug/mcode_download_file; sleep 2; echo DONE
'''
    Path('/tmp/exp13.sh').write_text(sh)
    subprocess.run(['scp', '-q', '/tmp/exp13.bin', '/tmp/exp13.sh', f'{MAC}:/tmp/'], check=True)
    remote = f'''cd {SERDIR}
push(){{ python3 ser.py "nc -l -p $3 > $2 & sleep 1; echo ok" 8 >/dev/null; sleep 1;
  python3 -c "import socket,sys; s=socket.create_connection(('192.168.1.1',int(sys.argv[2]))); s.sendall(open(sys.argv[1],'rb').read()); s.close()" "$1" "$3"; sleep 2; }}
push /tmp/exp13.bin /tmp/exp13.bin 9171; push /tmp/exp13.sh /tmp/exp13.sh 9172
ping -n -i 0.1 -c 150 192.168.1.1 > /tmp/p13.txt 2>&1 & pp=$!
python3 ser.py "sh /tmp/exp13.sh" 40; kill $pp 2>/dev/null; tail -2 /tmp/p13.txt'''
    r = subprocess.run(['ssh', '-o', 'BatchMode=yes', MAC, 'sh -s'], input=remote, text=True, capture_output=True, timeout=150)
    (HERE / 'exp13.log').write_text(r.stdout + r.stderr)
    a, b = r.stdout.split('=== A', 1)[1].split('=== B', 1)
    val = lambda t: {m[0]: int(m[1]) for m in re.findall(r'(port id \d+ output boardcast|mac sa lookup fail) cnt:\s+(\d+)', t)}
    va, vb = val(a), val(b)
    for k in ('port id 32 output boardcast', 'port id 33 output boardcast', 'mac sa lookup fail'):
        print(k, vb.get(k, 0) - va.get(k, 0))
    print(r.stdout.strip().splitlines()[-2:])

main()
