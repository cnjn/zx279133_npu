"""Read table_debug/debug_stat_show (cumulative #48 counters) and diff two snapshots."""
import re

import board

CMD = 'dmesg -c >/dev/null; cat /sys/devices/platform/np/table_debug/debug_stat_show; dmesg -c'


def parse(text):
    out = {}
    for line in text.splitlines():
        m = re.match(r'\s*(.*?)[:;]\s+(\d+)\s*$', line)
        if m:
            out[m[1].strip()] = int(m[2])
    return out


def snap():
    return parse(board.bench.ser(CMD, 30))


def diff(a, b):
    return {k: b[k] - a.get(k, 0) for k in b if b[k] != a.get(k, 0)}


def mac_send(n=20, sport=40001, dst='192.168.1.1', dport=7781, payload=None):
    extra = f' {payload}' if payload else ''
    return board.bench.mac(f'python3 /tmp/udpsend.py {n} {sport} {dst} {dport}{extra}', 60)
