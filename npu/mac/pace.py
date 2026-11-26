"""Mac side: send bench packets on a time schedule and record replies with timestamps.

usage: python3 pace.py PLAN OUT [PORT]
PLAN: one 'T HEXPAYLOAD' per line, T = send time in seconds from the start (sorted).
Payload bytes 2..5 are overwritten with the line number. OUT: 'i t_send t_recv hex'
per line ('-' for t_recv / hex when no reply came back within 0.5 s of the last send)."""
import select
import socket
import struct
import sys
import time

plan = []
for line in open(sys.argv[1]):
    t, h = line.split()
    plan.append((float(t), bytes.fromhex(h)))
out_path = sys.argv[2]
port = int(sys.argv[3]) if len(sys.argv) > 3 else 7778
n = len(plan)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)
s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 22)
s.bind(('192.168.1.2', 0))
s.connect(('192.168.1.1', port))
s.setblocking(False)

tsend, trecv, data = [None] * n, [None] * n, [None] * n
t0 = time.perf_counter()
k, last = 0, 0.0
while True:
    now = time.perf_counter() - t0
    while k < n and plan[k][0] <= now:
        p = bytearray(plan[k][1])
        p[2:6] = struct.pack('>I', k)
        try:
            s.send(p)
        except (BlockingIOError, OSError):
            break
        tsend[k] = last = time.perf_counter() - t0
        k += 1
    if k >= n and now - last > 0.5:
        break
    wait = 0.0005 if k < n else 0.05
    if k < n:
        wait = max(0.0, min(wait, plan[k][0] - now))
    r, _, _ = select.select([s], [], [], wait)
    if r:
        while True:
            try:
                d = s.recv(4096)
            except (BlockingIOError, socket.timeout):
                break
            except OSError:
                continue
            if len(d) >= 6:
                i = struct.unpack_from('>I', d, 2)[0]
                if i < n and data[i] is None:
                    data[i] = d
                    trecv[i] = time.perf_counter() - t0
with open(out_path, 'w') as f:
    for i in range(n):
        f.write(f'{i} {tsend[i] if tsend[i] is not None else -1:.6f} '
                f'{trecv[i] if trecv[i] is not None else -1:.6f} {data[i].hex() if data[i] else "-"}\n')
print(f'pace: {sum(d is not None for d in data)}/{n} replies, last send {last:.3f}s', file=sys.stderr)
