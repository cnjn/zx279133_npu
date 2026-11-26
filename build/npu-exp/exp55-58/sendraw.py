"""Send hand-built Ethernet frames on macOS through BPF (needs root).
usage: sudo python3 sendraw.py IFACE   -- sends one frame of each type to the board."""
import fcntl
import os
import socket
import struct
import sys
import time

BIOCSETIF = 0x8020426C
BIOCSHDRCMPLT = 0x80044275
BOARD = bytes.fromhex('00d0d0616201')
ME = bytes.fromhex('00e041680d86')
BCAST = b'\xff' * 6
V6MC = bytes.fromhex('333300000001')
IP4_ME, IP4_BOARD = socket.inet_aton('192.168.1.2'), socket.inet_aton('192.168.1.1')
IP6_ME = socket.inet_pton(socket.AF_INET6, 'fe80::2e0:41ff:fe68:d86')
IP6_BOARD = socket.inet_pton(socket.AF_INET6, 'fe80::2d0:d0ff:fe61:6201')
IP6_ALL = socket.inet_pton(socket.AF_INET6, 'ff02::1')
PAY = bytes(range(256))[:240]


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack(f'!{len(b) // 2}H', b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ip4(proto, src, dst, l4):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), 0x1234, 0, 64, proto, 0, src, dst)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + l4


def l4(proto, src, dst, sport, dport, pseudo6=False):
    if proto == 17:
        seg = struct.pack('!HHHH', sport, dport, 8 + len(PAY), 0) + PAY
        off = 6
    else:
        seg = struct.pack('!HHIIBBHHH', sport, dport, 1, 1, 5 << 4, 0x18, 1024, 0, 0) + PAY
        off = 16
    if pseudo6:
        ph = src + dst + struct.pack('!IxxxB', len(seg), proto)
    else:
        ph = src + dst + struct.pack('!BBH', 0, proto, len(seg))
    c = csum(ph + seg) or 0xffff
    return seg[:off] + struct.pack('!H', c) + seg[off + 2:]


def ip6(proto, src, dst, seg):
    return struct.pack('!IHBB16s16s', 6 << 28, len(seg), proto, 64, src, dst) + seg


def eth(dst, etype, body, vlan=None):
    tag = struct.pack('!HH', 0x8100, vlan) if vlan is not None else b''
    return dst + ME + tag + struct.pack('!H', etype) + body


def frames():
    u4 = ip4(17, IP4_ME, IP4_BOARD, l4(17, IP4_ME, IP4_BOARD, 40000, 9))
    yield 'v4_udp', eth(BOARD, 0x0800, u4)
    bc = ip4(17, IP4_ME, b'\xff' * 4, l4(17, IP4_ME, b'\xff' * 4, 40000, 9))
    yield 'v4_udp_bcast', eth(BCAST, 0x0800, bc)
    yield 'v4_tcp', eth(BOARD, 0x0800, ip4(6, IP4_ME, IP4_BOARD, l4(6, IP4_ME, IP4_BOARD, 40001, 22)))
    yield 'v6_udp_mcast', eth(V6MC, 0x86dd, ip6(17, IP6_ME, IP6_ALL, l4(17, IP6_ME, IP6_ALL, 40000, 9, True)))
    yield 'v6_tcp', eth(BOARD, 0x86dd, ip6(6, IP6_ME, IP6_BOARD, l4(6, IP6_ME, IP6_BOARD, 40001, 22, True)))
    yield 'vlan100_v4_udp', eth(BOARD, 0x0800, u4, vlan=100)
    yield 'vlan100_v6_udp', eth(V6MC, 0x86dd, ip6(17, IP6_ME, IP6_ALL, l4(17, IP6_ME, IP6_ALL, 40000, 9, True)), vlan=100)
    ppp = struct.pack('!BBHHH', 0x11, 0, 0x0001, len(u4) + 2, 0x0021) + u4
    yield 'pppoe_v4_udp', eth(BOARD, 0x8864, ppp)


def main():
    iface = sys.argv[1]
    for i in range(256):
        try:
            fd = os.open(f'/dev/bpf{i}', os.O_RDWR)
            break
        except OSError:
            continue
    fcntl.ioctl(fd, BIOCSETIF, struct.pack('16s16x', iface.encode()))
    fcntl.ioctl(fd, BIOCSHDRCMPLT, struct.pack('I', 1))
    for name, f in frames():
        os.write(fd, f)
        print(name, len(f))
        time.sleep(0.4)


if __name__ == '__main__':
    main()
