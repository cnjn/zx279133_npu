"""Decode tcpdump -XX (Linux cooked v2) output of probe packets.
usage: regdump_decode.py OUT.txt   (sections '=== name | ...' followed by hex lines)
Packet offset of h1+X in the capture = 20 (SLL2) + X - 14 (Ethernet header stripped)."""
import re
import sys

text = open(sys.argv[1]).read()
for sec in re.split(r'^=== ', text, flags=re.M)[1:]:
    name = sec.split()[0]
    pkts, cur, summary = [], None, ''
    for line in sec.splitlines():
        if re.match(r'\d\d:\d\d:\d\d', line):
            summary = ' '.join(line.split()[1:])[:90]
        m = re.match(r'\s+0x([0-9a-f]{4}):\s+((?:[0-9a-f]{4}\s?)+)', line)
        if not m:
            continue
        off = int(m[1], 16)
        if off == 0:
            cur = bytearray()
            pkts.append((summary, cur))
        if cur is not None:
            cur += bytes.fromhex(m[2].replace(' ', ''))
    print(f'## {name}: {len(pkts)} packet(s)')
    for summary, p in pkts:
        h1 = lambda x: p[20 + x - 14:20 + x - 14 + 4]
        vals = [h1(64 + 4 * i).hex() for i in range(16) if 20 + 64 + 4 * i - 14 + 4 <= len(p)]
        print('  ' + summary)
        print('    h1+64..:', ' '.join(vals))
