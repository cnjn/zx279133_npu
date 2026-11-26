"""Tabulate flag-word dumps (regdump.py flags_at variants) from a run log."""
import re
import sys

text = open(sys.argv[1]).read()
LABELS = [('ICMP echo', 'icmp4'), ('UDP, length 240', None), ('Flags [P.]', None), ('ff02::1.9', 'v6udp_mc'),
          ('.22: tcp', 'v6tcp'), ('IP0', 'vlan_v4'), ('version error', 'vlan_v6'), ('PPPoE', 'pppoe')]


def label(summary):
    if 'ICMP echo' in summary:
        return 'icmp4'
    if 'PPPoE' in summary:
        return 'pppoe'
    if '255.255.255.255' in summary:
        return 'udp4_bc'
    if 'UDP, length 240' in summary and 'IP6' not in summary:
        return 'udp4'
    if 'Flags [P.]' in summary:
        return 'tcp4'
    if 'ff02::1' in summary:
        return 'udp6_mc'
    if '.22: tcp' in summary:
        return 'tcp6'
    if 'IP0' in summary:
        return 'vlan_v4'
    if 'version error' in summary:
        return 'vlan_v6'
    return '?'


res = {}
for sec in re.split(r'^=== ', text, flags=re.M)[1:]:
    name = sec.split()[0]
    m = re.match(r'p(\d+)_f(\d+)_(\d+)', name)
    if not m:
        continue
    hook, w0, w1 = int(m[1]), int(m[2]), int(m[3])
    summary, cur = '', None
    pkts = []
    for line in sec.splitlines():
        if re.match(r'\d\d:\d\d:\d\d', line):
            summary = ' '.join(line.split()[1:])
        mm = re.match(r'\s+0x([0-9a-f]{4}):\s+((?:[0-9a-f]{4}\s?)+)', line)
        if mm:
            if int(mm[1], 16) == 0:
                cur = bytearray()
                pkts.append((summary, cur))
            cur += bytes.fromhex(mm[2].replace(' ', ''))
    for summary, p in pkts:
        at = 20 + 64 - 14
        if len(p) < at + 8:
            continue
        res[(hook, w0, label(summary))] = p[at:at + 4].hex()
        res[(hook, w1, label(summary))] = p[at + 4:at + 8].hex()
cols = ['icmp4', 'udp4', 'udp4_bc', 'tcp4', 'udp6_mc', 'tcp6', 'vlan_v4', 'vlan_v6', 'pppoe']
for hook in sorted({k[0] for k in res}):
    print(f'hook {hook}')
    print('word ' + ' '.join(f'{c:>8}' for c in cols))
    for w in range(16):
        print(f'f{w:<3} ' + ' '.join(f'{res.get((hook, w, c), "-"):>8}' for c in cols))
