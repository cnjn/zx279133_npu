"""Raw test frames: build them here, send and capture them on the Mac (mac/rawtest.py, BPF),
decode what comes back.  Frames carry MAGIC + a sequence number so the capture can find them.

The usual setup (NPU_MCODE.md 实验 101): frames come from cfg.test.fake_sa (registered in MAC
table #50 for the LAN port) to the board's MAC (registered as pointing at the uplink port),
so the stock microcode treats them as LAN->WAN traffic and runs the fast path."""
import ipaddress
import struct
import tempfile
from pathlib import Path

from . import link
from .config import cfg, mac_bytes

MAGIC = b'ACLT'


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack(f'!{len(b) // 2}H', b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def _macs(smac, dmac):
    c = cfg()
    return mac_bytes(dmac or c.board.addr), mac_bytes(smac or c.test.fake_sa)


def udp4(src, dst, sport, dport, seq=0, tos=0, ttl=64, smac=None, dmac=None, extra=b''):
    d_mac, s_mac = _macs(smac, dmac)
    s, d = ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed
    pay = MAGIC + struct.pack('!I', seq) + extra + bytes(24)
    seg = struct.pack('!HHHH', sport, dport, 8 + len(pay), 0) + pay
    c = csum(s + d + struct.pack('!BBH', 0, 17, len(seg)) + seg) or 0xffff
    seg = seg[:6] + struct.pack('!H', c) + seg[8:]
    h = struct.pack('!BBHHHBBH4s4s', 0x45, tos, 20 + len(seg), 0x1234, 0, ttl, 17, 0, s, d)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return d_mac + s_mac + b'\x08\x00' + h + seg


def udp6(src, dst, sport, dport, seq=0, tc=0, hlim=64, smac=None, dmac=None, extra=b''):
    d_mac, s_mac = _macs(smac, dmac)
    s, d = ipaddress.IPv6Address(src).packed, ipaddress.IPv6Address(dst).packed
    pay = MAGIC + struct.pack('!I', seq) + extra + bytes(24)
    seg = struct.pack('!HHHH', sport, dport, 8 + len(pay), 0) + pay
    c = csum(s + d + struct.pack('!IxxxB', len(seg), 17) + seg) or 0xffff
    seg = seg[:6] + struct.pack('!H', c) + seg[8:]
    h = struct.pack('!IHBB16s16s', 6 << 28 | tc << 20, len(seg), 17, hlim, s, d)
    return d_mac + s_mac + b'\x86\xdd' + h + seg


def udp(src, dst, sport, dport, **kw):
    return (udp6 if ':' in src else udp4)(src, dst, sport, dport, **kw)


def decode(f):
    """Decode an Ethernet frame: MACs, VLAN tags, PPPoE, IPv4/IPv6 (+checksum checks), UDP,
    and an inner packet for IPIP / IPv4-in-IPv6 / IPv6-in-IPv4."""
    d = {'dmac': f[0:6].hex(':'), 'smac': f[6:12].hex(':'), 'len': len(f)}
    off, et = 12, struct.unpack_from('!H', f, 12)[0]
    tags = []
    while et in (0x8100, 0x88a8, 0x9100):
        tags.append(f'{et:04x}:{struct.unpack_from("!H", f, off + 2)[0]:04x}')
        off += 4
        et = struct.unpack_from('!H', f, off)[0]
    if tags:
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
        d.update(ip_tos=h[1], ip_len=struct.unpack_from('!H', h, 2)[0], ttl=h[8], proto=h[9],
                 sip=str(ipaddress.IPv4Address(h[12:16])), dip=str(ipaddress.IPv4Address(h[16:20])),
                 ip_csum_ok=csum(h) == 0)
        l4, proto, ps = off + ihl, h[9], h[12:20]
    elif et == 0x86dd:
        h = f[off:off + 40]
        d.update(v6_first=h[:4].hex(), plen=struct.unpack_from('!H', h, 4)[0], nh=h[6], hlim=h[7],
                 sip=str(ipaddress.IPv6Address(h[8:24])), dip=str(ipaddress.IPv6Address(h[24:40])))
        l4, proto, ps = off + 40, h[6], h[8:40]
    else:
        return d
    if proto == 17:
        sport, dport, ln, c = struct.unpack_from('!HHHH', f, l4)
        seg = f[l4:l4 + ln]
        ph = ps + (struct.pack('!BBH', 0, 17, ln) if et == 0x0800 else struct.pack('!IxxxB', ln, 17))
        d.update(sport=sport, dport=dport, udp_csum_ok=(c == 0 or csum(ph + seg) == 0))
        i = f.find(MAGIC, l4)
        if i >= 0:
            d['seq'] = struct.unpack_from('!I', f, i + 4)[0]
    elif proto in (4, 41):
        d['inner'] = decode(bytes(12) + (b'\x08\x00' if proto == 4 else b'\x86\xdd') + f[l4:])
    return d


def send(frames, gap=0.01, wait=1.0):
    """Send frames from the Mac's lab interface; returns (decoded captured frames, raw output).
    Only frames that carry MAGIC are captured (promiscuous mode, own transmissions excluded)."""
    c = cfg()
    p = Path(tempfile.gettempdir()) / 'npukit_frames.txt'
    p.write_text(''.join(f.hex() + '\n' for f in frames))
    remote = f'{link.workdir()}/frames.txt'
    link.mac_put(p, remote)
    out = link.mac(f'cd {link.workdir()} && python3 rawtest.py {c.mac.iface} frames.txt {gap} {wait}',
                   60 + int(len(frames) * gap + wait))
    rx = []
    for line in out.splitlines():
        if line.startswith('RX '):
            _, t, h = line.split()
            d = decode(bytes.fromhex(h))
            d['t'] = float(t)
            rx.append(d)
    if 'SUMMARY' not in out:
        raise link.LinkError('rawtest.py failed on the Mac: ' + out.strip()[-400:])
    return rx, out
