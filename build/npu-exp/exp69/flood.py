import socket, time, threading
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
s.bind(('192.168.1.2', 0)); s.connect(('192.168.1.1', 7777)); s.settimeout(0.5)
N = 50000; got = 0; done = False
def rx():
    global got
    while True:
        try: s.recv(2048); got += 1
        except socket.timeout:
            if done: return
        except OSError: pass
t = threading.Thread(target=rx); t.start()
msg = b'x' * 64
t0 = time.time()
for i in range(N):
    try: s.send(msg)
    except OSError: pass
dt = time.time() - t0
time.sleep(1); done = True; t.join()
print(f'sent {N} in {dt:.2f}s ({N/dt:.0f} pps), replies {got} ({100*got/N:.1f}%)')
