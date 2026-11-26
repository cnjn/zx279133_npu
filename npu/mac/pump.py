"""Mac side of the NP oracle bench: send UDP test packets to the board and collect
the reflected replies.

usage: python3 pump.py PLAN OUT [WINDOW] [PORT]
PLAN: one hex payload per line. Payload bytes 2..5 are overwritten with the line
number (the sequence tag the NP leaves untouched). OUT: 'index hexpayload' for
every reply, '-' for packets that never came back (after ROUNDS tries).
usage: python3 pump.py PLAN OUT [WINDOW] [PORT] [ROUNDS]
"""
import select
import socket
import struct
import sys
import time

plan_path, out_path = sys.argv[1], sys.argv[2]
window = int(sys.argv[3]) if len(sys.argv) > 3 else 64
port = int(sys.argv[4]) if len(sys.argv) > 4 else 7778
rounds = int(sys.argv[5]) if len(sys.argv) > 5 else 3

plan = []
for i, line in enumerate(open(plan_path)):
    p = bytearray.fromhex(line.strip())
    p[2:6] = struct.pack('>I', i)
    plan.append(bytes(p))

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)
s.bind(('192.168.1.2', 0))
s.connect(('192.168.1.1', port))
s.setblocking(False)

res = [None] * len(plan)
t0 = time.time()
for rnd in range(rounds):
    todo = [i for i, r in enumerate(res) if r is None]
    if not todo:
        break
    k, inflight = 0, 0
    while k < len(todo) or inflight > 0:
        while k < len(todo) and inflight < window:
            try:
                s.send(plan[todo[k]])
            except BlockingIOError:
                break
            except OSError:  # ICMP unreachable from an earlier packet; just retry
                break
            k += 1
            inflight += 1
        r, _, _ = select.select([s], [], [], 0.3)
        if not r:
            inflight = 0  # the rest are lost; continue with the next ones
            continue
        while True:
            try:
                data = s.recv(4096)
            except (BlockingIOError, socket.timeout):
                break
            except OSError:
                continue
            if len(data) >= 6:
                i = struct.unpack_from('>I', data, 2)[0]
                if i < len(res) and res[i] is None:
                    res[i] = data
                    inflight = max(0, inflight - 1)
dt = time.time() - t0
with open(out_path, 'w') as f:
    for i, r in enumerate(res):
        f.write(f'{i} {r.hex() if r else "-"}\n')
got = sum(r is not None for r in res)
print(f'pump: {got}/{len(res)} replies in {dt:.2f}s', file=sys.stderr)
