"""ACL / HGU fast path of the stock ZX133 microcode (NPU_MCODE.md 实验 101).

Layout rule (board-verified for every table below): an entry is one big integer; the
fields are listed from bit 0 upward (the order `echo help > acl_*_set` prints them);
the microcode receives the entry big-endian, i.e. the first result register r(32+4S)
holds the top 32 bits.  `se_debug/cpu_get_eram_by_table_width` prints in that register
order; the driver's "writing eram128" debug line prints the memory order (reversed).

Rule construction goes through the driver (acl_debug/acl_hgu_table_set), which allocates
the source / next-hop / VLAN / IPv6-MAC entries itself from inline fields."""
import ipaddress
import json
import re
import socket
import struct
import time

from .config import STATE


class Layout:
    def __init__(self, name, sdt, width, fields, note=''):
        self.name, self.sdt, self.width, self.note = name, sdt, width, note
        self.fields, pos = {}, 0
        for fname, bits in fields:
            self.fields[fname] = (pos, bits)
            pos += bits
        if pos != width:
            raise ValueError(f'{name}: fields cover {pos} bits, entry is {width}')

    def pack(self, **vals):
        v = 0
        for k, x in vals.items():
            pos, bits = self.fields[k]
            if not 0 <= x < 1 << bits:
                raise ValueError(f'{self.name}.{k} = {x:#x} does not fit in {bits} bits')
            v |= x << pos
        return v

    def unpack(self, value, skip_zero_rsv=True):
        out = {}
        for k, (pos, bits) in self.fields.items():
            x = value >> pos & ((1 << bits) - 1)
            if skip_zero_rsv and x == 0 and 'rsv' in k:
                continue
            out[k] = x
        return out

    def words(self, value):
        """Microcode register order: most significant 32 bits first."""
        n = self.width // 32
        return [value >> (32 * (n - 1 - i)) & 0xffffffff for i in range(n)]

    def value(self, words):
        v = 0
        for w in words:
            v = v << 32 | w
        return v

    def bits(self, field):
        """(register index from the first result register, high bit, low bit) of a field."""
        pos, n = self.fields[field]
        top = self.width - 1 - (pos + n - 1)
        return top // 32, 31 - top % 32, (31 - top % 32) - n + 1


def _f(spec):
    return [(n, int(b)) for n, b in (x.split(':') for x in spec.split())]


HGU_KEY = Layout('hgu_key', 164, 256, _f(
    'k_sip:32 k_dip:32 k_l4_dport:16 k_l4_sport:16 k_ip_protocol:8 k_dscp_tc:8 '
    'k_outer_vid:12 k_outer_cfi:1 k_outer_pri:3 k_inner_vid:12 k_inner_cfi:1 k_inner_pri:3 '
    'k_tag_level:3 k_pppoe_flag:1 k_inner_udp_flag:1 k_inner_ip_flag:1 k_ipv6_flag:1 k_ipv4_flag:1 '
    'k_flag_rsv:2 k_in_port:6 k_sa_l32:32 k_sa_h16:16 k_da_l16:16 k_da_h32:32'),
    'Key bytes 0..31 as built at PC 730-749 (IPv4) / 983-1002 (IPv6). The microcode sets '
    'k_pppoe_flag for PPPoE, k_inner_udp_flag for tunnel inner keys, k_inner_ip_flag for IPv6 '
    'and k_ipv6_flag for IPv4 (board-checked with key_last_info): the driver names are shifted by one.')

HGU_RESULT = Layout('hgu_result', 164, 256, _f(
    'r_rsv_hard_age_index:18 r_rsv_hard_table_info:8 r_rsv4:6 r_pkt_len_change_val:7 r_rsv3:25 '
    'r_gem_port:16 r_out_port_is_wifi_flag:1 r_out_port:6 r_out_que:9 r_rsv2:2 r_mtu_val:12 '
    'r_ratelimit_bucket_id:6 r_stat_flow_id:12 r_rsv1:1 r_stat_wan_id:5 r_dscp_tc:8 '
    'r_acl_next_hop_table_index:9 r_acl_source_table_index:9 r_l4_dport:16 r_l4_sport:16 r_rsv0:4 '
    'r_cla_vlan_table_index:10 r_vlan_action:4 r_cla_encap_index:8 r_wan_link_id:6 r_flag_rsv:10 '
    'r_encap_decap_flag:1 r_mtu_en:1 r_dmac_change_en:1 r_dip_change_en:1 r_smac_change_en:1 '
    'r_sip_change_en:1 r_l4_dport_change_en:1 r_l4_sport_change_en:1 r_pkt_len_is_del_flag:1 '
    'r_pkt_len_change_en:1 r_dscp_tc_modify_en:1 r_stat_wan_id_en:1 r_stat_flow_id_after_modify_en:1 '
    'r_stat_flow_id_en:1 r_ratelimit_en:1 r_drop_en:1 r_pri:5 r_hash_hit:1'),
    'r32..r39. r_hash_hit (r32.31) reads 1 on a miss. For IPv6 flows r_rsv3 bits 8:0 '
    '(r38[15:7]) carry the #114 index.')

TABLES = {t.name: t for t in [
    Layout('vlan', 111, 128, _f(
        'inner_vid:12 inner_cfi:1 inner_pri:3 inner_tpid:16 outer_vid:12 outer_cfi:1 outer_pri:3 '
        'outer_tpid:16 rsv2:32 rsv1:16 inner_rsv2:3 inner_vid_en:1 inner_cfi_en:1 inner_pri_en:1 '
        'inner_rsv1:1 inner_tpid_en:1 outer_rsv2:3 outer_vid_en:1 outer_cfi_en:1 outer_pri_en:1 '
        'outer_rsv1:1 outer_tpid_en:1'), 'r40 = enable bits, r42 = outer tag word, r43 = inner tag word'),
    Layout('source', 112, 128, _f('rsv1:32 sipv4:32 mac_l32:32 mac_h16:16 rsv0:16'), 'IPv4 view'),
    Layout('source_v6', 112, 128, _f('ipv6:128'), 'IPv6 view: new source address'),
    Layout('next_hop', 113, 128, _f('rsv1:32 dipv4:32 mac_l32:32 mac_h16:16 rsv0:16'), 'IPv4 view'),
    Layout('next_hop_v6', 113, 128, _f('ipv6:128'), 'IPv6 view: new destination address'),
    Layout('ipv6_mac', 114, 128, _f('smac_l32:32 smac_h16:16 pad1:16 dmac_l32:32 dmac_h16:16 pad0:16')),
    Layout('wan_link', 116, 64, _f(
        'rsv0:32 pppoe_session_id:16 rsv1:2 vxlan_del_flag:1 l2tp_del_flag:1 v6rd_del_flag:1 '
        'ds_lite_del_flag:1 pppoe_del_flag:1 del_flag:1 rsv2:2 vxlan_add_flag:1 l2tp_add_flag:1 '
        'v6rd_add_flag:1 ds_lite_add_flag:1 pppoe_add_flag:1 add_flag:1')),
    Layout('ip_encap_v4', 117, 128, _f(
        'identification:16 init_checksum:16 sip:32 dip:32 ipv4_protocol:8 ttl:8 tos:8 header_len:4 ip_ver:4'),
        'outer IPv4 header template (6rd)'),
    Layout('ip_encap_v6', 117, 128, _f('rsv:80 hop_limit:8 next_head:8 flow_label:20 tc:8 ip_ver:4'),
        'outer IPv6 header template (DS-Lite); layout from the microcode, the driver help is wrong'),
    Layout('local_ipv6', 118, 128, _f('ipv6:128')),
    Layout('remote_ipv6', 119, 128, _f('ipv6:128')),
    Layout('udp_encap', 120, 32, _f('dport:16 sport:16')),
    Layout('l2tp_vxlan', 121, 128, _f('info3:32 info2:32 info1:32 info0:32')),
    Layout('mac_encap', 122, 128, _f('inner_tag:32 outer_tag:32 dmac_l32:32 dmac_h16:16 rsv:14 inner_tag_en:1 outer_tag_en:1')),
]}

VLAN_ACTIONS = {0: 'none', 1: 'pop 1 tag', 2: 'pop 2 tags', 3: 'pop inner tag', 4: 'push 1 tag (outer)',
                5: 'push 2 tags', 6: 'push 1 tag (variant)', 7: 'modify outer by enable bits',
                8: 'modify inner by enable bits'}


def ipv4_init_checksum(f):
    """init_checksum the driver stores for an IPv4 template (total length counted as 0)."""
    hdr = struct.pack('!BBHHHBBH4s4s', f['ip_ver'] << 4 | f['header_len'], f['tos'], 0, f['identification'], 0,
                      f['ttl'], f['ipv4_protocol'], 0, f['sip'].to_bytes(4, 'big'), f['dip'].to_bytes(4, 'big'))
    s = sum(struct.unpack('!10H', hdr))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


# ---------------------------------------------------------------- IPv6 key digests
def crc32_be(data, crc=0, poly=0x04c11db7):
    """MSB-first CRC-32, init 0, no reflection, no final xor."""
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xffffffff if crc & 0x80000000 else (crc << 1) & 0xffffffff
    return crc


def v6digest(src, dst, mode=1):
    """(sip32, dip32) the SPA puts into h3+60 / h3+56 for an IPv6 packet.
    mode 1 (this board, ipv6_compress_to_ip32 'SIPV6_OR_DIPV6'): CRC(address || 16 zero bytes);
    mode 0 (mainline / SR1010 setting): CRC(own || other address)."""
    s, d = (ipaddress.IPv6Address(x).packed for x in (src, dst))
    if mode == 1:
        return crc32_be(s + bytes(16)), crc32_be(d + bytes(16))
    return crc32_be(s + d), crc32_be(d + s)


# ---------------------------------------------------------------- rule building
def _mac(m):
    h = m.replace(':', '').replace('-', '').lower()
    if len(h) != 12:
        raise ValueError(f'bad MAC address {m!r}')
    return h[:4], h[4:]


def _v6words(a):
    p = ipaddress.IPv6Address(a).packed
    return [int.from_bytes(p[i:i + 4], 'big') for i in (0, 4, 8, 12)]


PROTOS = {'udp': 17, 'tcp': 6, 'icmp': 1, 'icmpv6': 58, 'gre': 47}


def _num(x):
    if isinstance(x, int):
        return x
    return int(x, 0)


class Rule:
    """One HGU fast-path rule. Match fields left as None are masked out."""

    def __init__(self, sip=None, dip=None, proto=None, sport=None, dport=None, in_port=None, tos=None,
                 out_port=None, out_que=0, set_sip=None, set_dip=None, set_smac=None, set_dmac=None,
                 set_sport=None, set_dport=None, vlan_push=None, vlan_push2=None, vlan_pop=None,
                 wan_link=None, drop=False, pri=None, extra=(), v6=None):
        self.__dict__.update(locals())
        del self.__dict__['self']
        addrs = [a for a in (sip, dip, set_sip, set_dip) if a]
        if v6 is None:
            self.v6 = any(':' in a for a in addrs)
        if self.v6 and (sip is None) != (dip is None):
            raise ValueError('IPv6 rules need both --sip and --dip: the key holds digests of both addresses')

    def driver_fields(self):
        f = []
        k = lambda name, val, bits: f.append(f'{name}={val:x}:{(1 << bits) - 1:x}')
        if self.v6:
            if self.sip:
                s32, d32 = v6digest(self.sip, self.dip)
                k('k_sip', s32, 32)
                k('k_dip', d32, 32)
        else:
            if self.sip:
                k('k_sip', int(ipaddress.IPv4Address(self.sip)), 32)
            if self.dip:
                k('k_dip', int(ipaddress.IPv4Address(self.dip)), 32)
        if self.proto is not None:
            k('k_ip_protocol', PROTOS.get(str(self.proto).lower(), None) or _num(self.proto), 8)
        if self.sport is not None:
            k('k_l4_sport', _num(self.sport), 16)
        if self.dport is not None:
            k('k_l4_dport', _num(self.dport), 16)
        if self.in_port is not None:
            k('k_in_port', _num(self.in_port), 6)
        if self.tos is not None:
            k('k_dscp_tc', _num(self.tos), 8)
        if not [x for x in f if x.startswith('k_')] and not [x for x in self.extra if x.startswith('k_')]:
            raise ValueError('a rule needs at least one match field')
        r = lambda name, val: f.append(f'{name}={val:x}')
        if self.drop:
            r('r_drop_en', 1)
        if self.out_port is not None:
            r('r_out_port', _num(self.out_port))
            r('r_out_que', _num(self.out_que))
        if self.pri is not None:
            r('r_pri', _num(self.pri))
        if self.set_sport is not None:
            r('r_l4_sport_change_en', 1)
            r('r_l4_sport', _num(self.set_sport))
        if self.set_dport is not None:
            r('r_l4_dport_change_en', 1)
            r('r_l4_dport', _num(self.set_dport))
        if self.v6:
            if self.set_dmac and not (self.set_smac or self.set_sip):
                raise ValueError('IPv6: the new destination MAC comes from the #114 lookup, which the microcode '
                                 'only does when the source IP or source MAC also changes (PC 893); add --set-smac')
            if self.set_sip:
                r('r_sip_change_en', 1)
                for i, w in enumerate(_v6words(self.set_sip)):
                    r(f's_v6_ipv6_addr{i}', w)
            if self.set_dip:
                r('r_dip_change_en', 1)
                for i, w in enumerate(_v6words(self.set_dip)):
                    r(f'n_h6_ipv6_addr{i}', w)
            if self.set_smac:
                h, l = _mac(self.set_smac)
                f.extend(['r_smac_change_en=1', f's_v6_smac_h16={h}', f's_v6_smac_l32={l}'])
            if self.set_dmac:
                h, l = _mac(self.set_dmac)
                f.extend(['r_dmac_change_en=1', f's_v6_dmac_h16={h}', f's_v6_dmac_l32={l}'])
        else:
            if self.set_sip:
                r('r_sip_change_en', 1)
                r('s_v4_sipv4', int(ipaddress.IPv4Address(self.set_sip)))
            if self.set_smac:
                h, l = _mac(self.set_smac)
                f.extend(['r_smac_change_en=1', f's_v4_mac_h16={h}', f's_v4_mac_l32={l}'])
            if self.set_dip:
                r('r_dip_change_en', 1)
                r('n_h4_dipv4', int(ipaddress.IPv4Address(self.set_dip)))
            if self.set_dmac:
                h, l = _mac(self.set_dmac)
                f.extend(['r_dmac_change_en=1', f'n_h4_mac_h16={h}', f'n_h4_mac_l32={l}'])
        if self.vlan_push:
            tpid, pri, vid = (_num(x) for x in self.vlan_push.split(':'))
            f.extend(['r_vlan_action=4', f'vl_outer_tpid={tpid:x}', f'vl_outer_pri={pri:x}', f'vl_outer_vid={vid:x}'])
        if self.vlan_push2:
            outer, inner = self.vlan_push2.split(',')
            (ot, op, ov), (it, ip_, iv) = ((_num(x) for x in t.split(':')) for t in (outer, inner))
            f.extend(['r_vlan_action=5', f'vl_outer_tpid={ot:x}', f'vl_outer_pri={op:x}', f'vl_outer_vid={ov:x}',
                      f'vl_inner_tpid={it:x}', f'vl_inner_pri={ip_:x}', f'vl_inner_vid={iv:x}'])
        if self.vlan_pop:
            n = _num(self.vlan_pop)
            if n not in (1, 2):
                raise ValueError('--vlan-pop takes 1 or 2')
            f.append(f'r_vlan_action={n}')
        if self.wan_link is not None:
            f.extend([f'r_wan_link_id={_num(self.wan_link):x}', 'r_encap_decap_flag=1'])
        f.extend(self.extra)
        return f

    def command(self):
        return 'echo ' + ' '.join(self.driver_fields()) + ' > acl_debug/acl_hgu_table_set'


def wanlink_commands(index, pppoe=None, dslite=None, hop_limit=64, del_pppoe=False, del_dslite=False):
    """Commands that prepare WAN link INDEX (#116, and #117-#119 for DS-Lite).
    pppoe: session id to add; dslite: (local_ipv6, remote_ipv6) to add. The del_* flags
    (decapsulation) are encoded but not yet tested on the board."""
    if not 0 <= index < 32:
        raise ValueError('use WAN link 0..31: #117-#119 are indexed by the low 5 bits')
    flags = []
    if pppoe is not None:
        flags += ['pppoe_add_flag=1', f'pppoe_session_id={_num(pppoe):x}']
    if dslite:
        flags.append('ds_lite_add_flag=1')
    if del_pppoe:
        flags.append('pppoe_del_flag=1')
    if del_dslite:
        flags.append('ds_lite_del_flag=1')
    if not flags:
        raise ValueError('nothing to configure')
    cmds = [f'echo table_index={index:x} ' + ' '.join(flags) + ' > acl_debug/acl_wan_link_table_set']
    if dslite:
        local, remote = dslite
        cmds.append(f'echo table_index={index:x} ipv6.ip_ver=6 ipv6.next_head=4 ipv6.hop_limit={hop_limit:x}'
                    ' > acl_debug/acl_wan_link_ip_encap_table_set')
        for name, a in (('local', local), ('remote', remote)):
            w = _v6words(a)
            cmds.append(f'echo table_index={index:x} ' + ' '.join(f'ipv6_addr{i}={x:x}' for i, x in enumerate(w))
                        + f' > acl_debug/acl_wan_link_{name}_ipv6_table_set')
    return cmds


DEL_RE = re.compile(r'echo (multi_info=[0-9a-f]+ node_info=[0-9a-f]+) > acl_hgu_table_del')


def parse_set_output(text):
    """(delete handle or None, list of error lines) from acl_hgu_table_set output."""
    m = DEL_RE.findall(text)
    errs = [l.strip() for l in text.splitlines()
            if re.search(r'error|fail|illegal|invalid|unknown', l, re.I) and 'sucess' not in l and 'success' not in l]
    return (m[-1] if m else None), errs


# ---------------------------------------------------------------- local state
class State:
    """Delete handles of rules added by this tool (the driver prints them only once)."""

    path = STATE / 'fast_rules.json'

    def __init__(self):
        self.data = json.loads(self.path.read_text()) if self.path.exists() else {'boot_id': None, 'rules': []}

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=1))

    def sync_boot(self, boot_id):
        """Forget rules from an earlier boot (a reboot clears the tables)."""
        if self.data.get('boot_id') != boot_id:
            dropped = len(self.data['rules'])
            self.data = {'boot_id': boot_id, 'rules': []}
            self.save()
            return dropped
        return 0

    def add(self, handle, command, desc):
        rid = max([r['id'] for r in self.data['rules']] + [0]) + 1
        self.data['rules'].append({'id': rid, 'handle': handle, 'command': command, 'desc': desc,
                                   'time': time.strftime('%Y-%m-%d %H:%M:%S')})
        self.save()
        return rid

    def remove(self, rid):
        self.data['rules'] = [r for r in self.data['rules'] if r['id'] != rid]
        self.save()


def decode_key(key):
    """Named fields of a 32-byte HGU key; IPv6 digests are left as numbers."""
    return HGU_KEY.unpack(int.from_bytes(key[:32], 'big'), skip_zero_rsv=False)


def fmt_fields(d):
    out = []
    for k, v in d.items():
        if k.endswith(('sip', 'dip', 'sipv4', 'dipv4')) and v < 1 << 32:
            out.append(f'{k}={v:#x} ({socket.inet_ntoa(v.to_bytes(4, "big"))})')
        elif k == 'ipv6':
            out.append(f'{k}={ipaddress.IPv6Address(v)}')
        else:
            out.append(f'{k}={v:#x}')
    return out
