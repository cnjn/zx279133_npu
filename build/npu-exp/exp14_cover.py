"""exp14: coverage of all probe-able basic blocks for ping traffic, 64 probes per load.

Per batch: build stock+probes (probe.py idiom), load, ping 8 s from the Mac, read
the idle counters, reload stock, check ping. If ping fails after the reload the
NP is wedged: reboot via the established serial procedure and mark the batch.
Results accumulate in exp14-cover.json: {block_start: hits or "wedged"}.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'npu-re'))
from probe import block_probe_sites, build, counter_name  # noqa: E402
from npasm import assemble  # noqa: E402
from npdis import split  # noqa: E402

MAC, SERDIR = '192.168.174.5', '/tmp/ontser.WZUED8'
STOCK = HERE.parents[1] / 'extracted/kernel1/rootfs/etc/mcode/mcode_133.bin'
OUT = HERE / 'exp14-cover.json'

BOARD_SH = r'''
cd /sys/devices/platform/np
snap(){ dmesg -c >/dev/null; cat table_debug/debug_stat_show; dmesg -c | grep -E 'port id (3[2-9]|[4-6][0-9]) output (boardcast|multicast)|mac sa lookup fail'; }
dmesg -c >/dev/null; echo /tmp/exp14.bin > ppu_debug/mcode_download_file; sleep 2
echo === A; snap; sleep 8; echo === B; snap
echo /etc/mcode/mcode_133.bin > ppu_debug/mcode_download_file; sleep 2
echo DONE
'''


def mac(script, timeout):
    r = subprocess.run(['ssh', '-o', 'BatchMode=yes', MAC, 'sh -s'], input=script, text=True,
                       capture_output=True, timeout=timeout)
    return r.stdout + r.stderr


def run_batch(stock, sites, tag):
    text, accepted = build(stock, sites)
    assert accepted == sites, (len(accepted), len(sites))
    Path('/tmp/exp14.bin').write_bytes(assemble(text, fit_gap=True))
    Path('/tmp/exp14.sh').write_text(BOARD_SH)
    subprocess.run(['scp', '-q', '/tmp/exp14.bin', '/tmp/exp14.sh', f'{MAC}:/tmp/'], check=True)
    out = mac(f'''cd {SERDIR}
push(){{ python3 ser.py "nc -l -p $3 > $2 & sleep 1; echo ok" 8 >/dev/null; sleep 1;
  python3 -c "import socket,sys; s=socket.create_connection(('192.168.1.1',int(sys.argv[2]))); s.sendall(open(sys.argv[1],'rb').read()); s.close()" "$1" "$3"; sleep 2; }}
push /tmp/exp14.bin /tmp/exp14.bin 9181; push /tmp/exp14.sh /tmp/exp14.sh 9182
ping -n -i 0.1 -c 150 192.168.1.1 > /tmp/p14.txt 2>&1 & pp=$!
python3 ser.py "sh /tmp/exp14.sh" 45; kill $pp 2>/dev/null
echo PINGDURING; tail -2 /tmp/p14.txt
sleep 1; echo PINGAFTER; ping -n -i 0.2 -c 5 192.168.1.1 | tail -2
''', 200)
    (HERE / f'exp14-{tag}.log').write_text(out)
    healthy = ' 0.0% packet loss' in out.split('PINGAFTER', 1)[-1]
    res = {}
    if '=== A' in out and '=== B' in out:
        a, b = out.split('=== A', 1)[1].split('=== B', 1)
        val = lambda t: {m[0]: int(m[1]) for m in re.findall(r'(port id \d+ output \w+|mac sa lookup fail) cnt:\s+(\d+)', t)}
        va, vb = val(a), val(b)
        for k, pc in enumerate(sites):
            n = counter_name(k)
            res[pc] = vb.get(n, 0) - va.get(n, 0)
        res['_saf'] = vb.get('mac sa lookup fail', 0) - va.get('mac sa lookup fail', 0)
    during = re.search(r'(\d+) packets received', out.split('PINGDURING', 1)[-1])
    res['_ping_during'] = int(during[1]) if during else None
    if not healthy:
        mac(f'''cd {SERDIR}; python3 raw.py "reboot\\n" "network services are disabled" 180 >/dev/null
python3 ser.py "lan1-up > /var/tmp/lan1.log 2>&1 & sleep 25; echo up" 40 >/dev/null; sleep 3''', 300)
        res['_wedged'] = True
    return res


def main():
    stock = STOCK.read_bytes()
    words = split(stock)[1]
    sites = block_probe_sites(words)
    done = json.loads(OUT.read_text()) if OUT.exists() else {}
    todo = [(a, pc) for (a, b), pc in sorted(sites.items()) if str(a) not in done]
    nb = int(sys.argv[1]) if len(sys.argv) > 1 else 99
    for bi in range(nb):
        chunk = todo[bi * 64:(bi + 1) * 64]
        if not chunk:
            break
        res = run_batch(stock, [pc for _, pc in chunk], f'b{bi}')
        for a, pc in chunk:
            done[str(a)] = {'site': pc, 'hits': res.get(pc), 'wedged': res.get('_wedged', False)}
        OUT.write_text(json.dumps(done, indent=0))
        hit = [(a, res.get(pc)) for a, pc in chunk if res.get(pc)]
        print(f'batch {bi}: {len(chunk)} probes, ping during {res.get("_ping_during")}, '
              f'saf {res.get("_saf")}, wedged {res.get("_wedged", False)}, executed {hit}', flush=True)


if __name__ == '__main__':
    main()
