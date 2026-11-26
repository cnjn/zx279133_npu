"""VM side: build test frames, run rawtest.py on the Mac, decode what comes back."""
import socket
import struct
import subprocess
import tempfile
from pathlib import Path

import board

BOARD = bytes.fromhex('00d0d0616201')   # board eth0 / LAN MAC
MAC = bytes.fromhex('00e041680d86')     # the Mac (en8)
FAKE = bytes.fromhex('020000000002')    # test source MAC, registered in #50 only for tests
IFACE = 'en8'
MAGIC = b'ACLT'


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack(f'!{len(b) // 2}H', b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def udp4(src, dst, sport, dport, seq=0, tos=0, ttl=64, smac=FAKE, dmac=BOARD, extra=b''):
    s, d = socket.inet_aton(src), socket.inet_aton(dst)
    pay = MAGIC + struct.pack('!I', seq) + extra + bytes(24)
    seg = struct.pack('!HHHH', sport, dport, 8 + len(pay), 0) + pay
    c = csum(s + d + struct.pack('!BBH', 0, 17, len(seg)) + seg) or 0xffff
    seg = seg[:6] + struct.pack('!H', c) + seg[8:]
    h = struct.pack('!BBHHHBBH4s4s', 0x45, tos, 20 + len(seg), 0x1234, 0, ttl, 17, 0, s, d)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return dmac + smac + b'\x08\x00' + h + seg


def decode(f):
    """Decode an Ethernet frame into a dict (IPv4/IPv6/UDP aware, VLAN and PPPoE tags listed)."""
    d = {'dmac': f[0:6].hex(':'), 'smac': f[6:12].hex(':'), 'len': len(f)}
    off, et = 12, struct.unpack_from('!H', f, 12)[0]
    tags = []
    while et in (0x8100, 0x88a8, 0x9100):
        tags.append(f'{et:04x}:{struct.unpack_from("!H", f, off + 2)[0]:04x}')
        off += 4
        et = struct.unpack_from('!H', f, off)[0]
    d['tags'] = tags
    off += 2
    if et == 0x8864:
        d['pppoe'] = f[off:off + 8].hex()
        off += 8
        et = 0x0800 if f[off - 2:off] == b'\x00\x21' else 0x86dd
    d['etype'] = f'{et:04x}'
    if et == 0x0800:
        ihl = (f[off] & 15) * 4
        h = f[off:off + ihl]
        d.update(ip_tos=h[1], ip_len=struct.unpack_from('!H', h, 2)[0], ip_id=struct.unpack_from('!H', h, 4)[0],
                 ttl=h[8], proto=h[9], sip=socket.inet_ntoa(h[12:16]), dip=socket.inet_ntoa(h[16:20]),
                 ip_csum_ok=csum(h) == 0)
        l4, proto, ps = off + ihl, h[9], h[12:20]
    elif et == 0x86dd:
        h = f[off:off + 40]
        d.update(v6_first=h[:4].hex(), plen=struct.unpack_from('!H', h, 4)[0], nh=h[6], hlim=h[7],
                 sip=socket.inet_ntop(socket.AF_INET6, h[8:24]), dip=socket.inet_ntop(socket.AF_INET6, h[24:40]))
        l4, proto, ps = off + 40, h[6], h[8:40]
    else:
        return d
    if proto == 17:
        sport, dport, ln, c = struct.unpack_from('!HHHH', f, l4)
        seg = f[l4:l4 + ln]
        if et == 0x0800:
            ph = ps + struct.pack('!BBH', 0, 17, ln)
        else:
            ph = ps + struct.pack('!IxxxB', ln, 17)
        d.update(sport=sport, dport=dport, udp_len=ln, udp_csum=f'{c:04x}', udp_csum_ok=(c == 0 or csum(ph + seg) == 0))
        i = f.find(MAGIC, l4)
        if i >= 0:
            d['seq'] = struct.unpack_from('!I', f, i + 4)[0]
    elif proto in (4, 41):
        d['inner'] = decode(b'\0' * 12 + (b'\x08\x00' if proto == 4 else b'\x86\xdd') + f[l4:])
    return d


def send(frames, gap=0.01, wait=1.0):
    """Send frames from the Mac, return (decoded captured frames, raw output)."""
    p = Path(tempfile.gettempdir()) / 'acl_frames.txt'
    p.write_text(''.join(f.hex() + '\n' for f in frames))
    subprocess.run(['scp', '-q', str(p), str(Path(__file__).with_name('rawtest.py')),
                    f'{board.bench.MAC}:/tmp/'], check=True)
    out = board.bench.mac(f'python3 /tmp/rawtest.py {IFACE} /tmp/acl_frames.txt {gap} {wait}',
                          60 + int(len(frames) * gap + wait))
    rx = []
    for line in out.splitlines():
        if line.startswith('RX '):
            _, t, h = line.split()
            d = decode(bytes.fromhex(h))
            d['t'] = float(t)
            d['raw'] = h
            rx.append(d)
    return rx, out


def udp6(src, dst, sport, dport, seq=0, tc=0, hlim=64, smac=FAKE, dmac=BOARD, extra=b''):
    s, d = socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst)
    pay = MAGIC + struct.pack('!I', seq) + extra + bytes(24)
    seg = struct.pack('!HHHH', sport, dport, 8 + len(pay), 0) + pay
    c = csum(s + d + struct.pack('!IxxxB', len(seg), 17) + seg) or 0xffff
    seg = seg[:6] + struct.pack('!H', c) + seg[8:]
    h = struct.pack('!IHBB16s16s', 6 << 28 | tc << 20, len(seg), 17, hlim, s, d)
    return dmac + smac + b'\x86\xdd' + h + seg


def crc32_be(data, crc=0, poly=0x04c11db7):
    """MSB-first CRC-32, init 0, no reflection, no final xor (mainline zx279133_ipv6_crc32)."""
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            crc = ((crc << 1) ^ poly) if crc & 0x80000000 else crc << 1
            crc &= 0xffffffff
    return crc


def v6digest(src, dst, mode):
    """(sip32, dip32) for the HGU key. mode 'zx133' (verified): CRC(addr || 16 zero bytes);
    'single': each address alone; 'pair': mainline full-tuple (SPA mode 0)."""
    s, d = socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst)
    if mode == 'zx133':   # board-verified (exp101): SPA compress mode 1, address then 16 zero bytes
        return crc32_be(s + bytes(16)), crc32_be(d + bytes(16))
    if mode == 'single':
        return crc32_be(s), crc32_be(d)
    return crc32_be(d, crc32_be(s)), crc32_be(s, crc32_be(d))
