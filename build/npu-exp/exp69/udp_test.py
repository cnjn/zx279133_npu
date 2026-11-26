import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1.5)
s.bind(('192.168.1.2', 0)); s.connect(('192.168.1.1', 7777))
ok = 0
for i in range(5):
    msg = f'hello NP {i} {time.time():.3f}'.encode()
    s.send(msg)
    try:
        data, addr = s.recvfrom(2048)
        ok += data == msg
        print('reply', addr, data)
    except socket.timeout:
        print('timeout')
    except OSError as e:
        print('error', e)
print('matched', ok, 'of 5')
