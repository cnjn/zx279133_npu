"""Layouts and rule building against values captured on the board in exp101
(driver 'writing eram128' lines are memory order = reversed microcode order)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from npukit import acl  # noqa: E402
from npukit.config import EXP  # noqa: E402

T = acl.TABLES


def mem(table, **f):
    """Driver memory order of an entry (lowest 32 bits first)."""
    t = T[table]
    return list(reversed(t.words(t.pack(**f))))


class LayoutVectors(unittest.TestCase):
    def test_widths(self):
        for t in list(T.values()) + [acl.HGU_KEY, acl.HGU_RESULT]:
            self.assertEqual(sum(n for _, n in t.fields.values()), t.width, t.name)

    def test_mac_encap(self):
        self.assertEqual(mem('mac_encap', inner_tag=0x11223344, outer_tag=0x55667788, dmac_l32=0x99aabbcc,
                             dmac_h16=0xddee, inner_tag_en=1), [0x11223344, 0x55667788, 0x99aabbcc, 0x4000ddee])
        self.assertEqual(mem('mac_encap', outer_tag_en=1), [0, 0, 0, 0x80000000])

    def test_vlan(self):
        f = dict(outer_vid=0x123, outer_tpid=0x88a8, outer_pri=5, inner_vid=0x456, inner_tpid=0x8100, inner_pri=3,
                 inner_cfi=1, outer_vid_en=1, outer_tpid_en=1, outer_pri_en=1, inner_vid_en=1, inner_tpid_en=1,
                 inner_pri_en=1, inner_cfi_en=1)
        self.assertEqual(mem('vlan', **f), [0x81007456, 0x88a8a123, 0, 0xa8b80000])
        # microcode: r42 is the outer tag word pushed as is (PC 2440)
        self.assertEqual(T['vlan'].words(T['vlan'].pack(**f))[2], 0x88a8a123)

    def test_source_next_hop(self):
        self.assertEqual(mem('source', mac_h16=0x0a0b, mac_l32=0x0c0d0e0f, sipv4=0xc0a80101),
                         [0, 0xc0a80101, 0x0c0d0e0f, 0x0a0b])
        self.assertEqual(mem('next_hop', mac_h16=0x1a1b, mac_l32=0x1c1d1e1f, dipv4=0xc0a80102),
                         [0, 0xc0a80102, 0x1c1d1e1f, 0x1a1b])
        self.assertEqual(T['source'].bits('sipv4'), (2, 31, 0))          # r42, PC 794 st h5+12, r42
        self.assertEqual(mem('source_v6', ipv6=0x20010db8000800000000000000000008), [8, 0, 0x80000, 0x20010db8])

    def test_ipv6_mac(self):
        self.assertEqual(mem('ipv6_mac', smac_l32=0x21222324, smac_h16=0x2526, dmac_l32=0x31323334, dmac_h16=0x3536),
                         [0x21222324, 0x2526, 0x31323334, 0x3536])

    def test_wan_link_flags(self):
        w = lambda **f: T['wan_link'].words(T['wan_link'].pack(**f))[0]
        self.assertEqual(w(add_flag=1, pppoe_add_flag=1), 0xc0000000)
        self.assertEqual(w(add_flag=1, ds_lite_add_flag=1), 0xa0000000)
        self.assertEqual(w(add_flag=1, v6rd_add_flag=1), 0x90000000)
        self.assertEqual(w(add_flag=1, l2tp_add_flag=1), 0x88000000)
        self.assertEqual(w(add_flag=1, vxlan_add_flag=1), 0x84000000)
        self.assertEqual(w(del_flag=1, pppoe_del_flag=1), 0x00c00000)
        self.assertEqual(w(del_flag=1, ds_lite_del_flag=1), 0x00a00000)
        self.assertEqual(w(del_flag=1, vxlan_del_flag=1), 0x00840000)
        self.assertEqual(w(pppoe_session_id=0x1234), 0x1234)

    def test_small_tables(self):
        self.assertEqual(T['udp_encap'].pack(dport=0x1111, sport=0x2222), 0x22221111)
        self.assertEqual(mem('l2tp_vxlan', info0=0xa0a0a0a0, info1=0xb1b1b1b1, info2=0xc2c2c2c2, info3=0xd3d3d3d3),
                         [0xd3d3d3d3, 0xc2c2c2c2, 0xb1b1b1b1, 0xa0a0a0a0])
        self.assertEqual(mem('local_ipv6', ipv6=0x20010db8111111112222222233333333),
                         [0x33333333, 0x22222222, 0x11111111, 0x20010db8])

    def test_ip_encap(self):
        f = dict(ip_ver=4, header_len=5, tos=0xa1, ttl=0xb2, ipv4_protocol=0xc3, dip=0xd4d5d6d7, sip=0xe4e5e6e7,
                 identification=0x0102)
        self.assertEqual(acl.ipv4_init_checksum(f), 0x8f1d)              # what the driver stored
        self.assertEqual(mem('ip_encap_v4', init_checksum=0x8f1d, **f), [0x8f1d0102, 0xe4e5e6e7, 0xd4d5d6d7, 0x45a1b2c3])
        self.assertEqual(mem('ip_encap_v6', ip_ver=6, next_head=4, hop_limit=0x40), [0, 0, 0x04400000, 0x60000000])

    def test_result_positions_used_by_microcode(self):
        r = acl.HGU_RESULT
        self.assertEqual(r.bits('r_sip_change_en'), (0, 15, 15))           # [r32.15]
        self.assertEqual(r.bits('r_encap_decap_flag'), (0, 10, 10))        # [r32.10] br L2319
        self.assertEqual(r.bits('r_wan_link_id'), (1, 31, 26))             # r33[31:26]
        self.assertEqual(r.bits('r_vlan_action'), (1, 17, 14))             # r33[17:14]
        self.assertEqual(r.bits('r_acl_source_table_index'), (3, 31, 23))  # r35[31:23]
        self.assertEqual(r.bits('r_acl_next_hop_table_index'), (3, 22, 14))
        self.assertEqual(r.bits('r_mtu_val'), (4, 13, 2))                  # r36[13:2]
        self.assertEqual(r.bits('r_out_port'), (5, 22, 17))                # r37[22:17]
        self.assertEqual(r.bits('r_pkt_len_change_val'), (6, 6, 0))        # r38[6:0]
        self.assertEqual(r.bits('r_hash_hit'), (0, 31, 31))

    def test_key_from_board(self):
        # ppu_debug/key_last_info after an IPv6 UDP frame 2001:db8:1::2:40001 -> 2001:db8:2::2:7781
        words = [0x00d0d061, 0x62010200, 0x00000002, 0x14200000, 0x00000011, 0x9c411e65, 0x917fa934, 0xefa00008]
        k = acl.decode_key(b''.join(w.to_bytes(4, 'big') for w in words))
        self.assertEqual((k['k_da_h32'], k['k_da_l16'], k['k_sa_h16'], k['k_sa_l32']), (0x00d0d061, 0x6201, 0x0200, 2))
        self.assertEqual((k['k_in_port'], k['k_inner_ip_flag'], k['k_ip_protocol']), (5, 1, 17))
        self.assertEqual((k['k_l4_sport'], k['k_l4_dport']), (40001, 7781))
        self.assertEqual((k['k_sip'], k['k_dip']), acl.v6digest('2001:db8:1::2', '2001:db8:2::2'))


class Rules(unittest.TestCase):
    @staticmethod
    def tokens(fields):
        out = {}
        for t in fields:
            name, val = t.split('=')
            v, _, m = val.partition(':')
            out[name] = (int(v, 16), int(m, 16) if m else None)
        return out

    def test_nat44_matches_board_command(self):
        board = ('k_sip=0a010102:ffffffff k_dip=0a020202:ffffffff k_ip_protocol=11:ff k_l4_sport=9c41:ffff '
                 'k_l4_dport=1e65:ffff r_out_port=5 r_out_que=0 r_sip_change_en=1 r_smac_change_en=1 '
                 'r_dip_change_en=1 r_dmac_change_en=1 r_l4_sport_change_en=1 r_l4_sport=1111 '
                 'r_l4_dport_change_en=1 r_l4_dport=2222 n_h4_mac_h16=00e0 n_h4_mac_l32=41680d86 '
                 'n_h4_dipv4=0a090909 s_v4_mac_h16=00d0 s_v4_mac_l32=d0616201 s_v4_sipv4=0a080808').split()
        r = acl.Rule(sip='10.1.1.2', dip='10.2.2.2', proto='udp', sport=40001, dport=7781, out_port=5,
                     set_sip='10.8.8.8', set_dip='10.9.9.9', set_smac='00:d0:d0:61:62:01',
                     set_dmac='00:e0:41:68:0d:86', set_sport=0x1111, set_dport=0x2222)
        self.assertEqual(self.tokens(r.driver_fields()), self.tokens(board))

    def test_nat66_uses_digests_and_v6_fields(self):
        r = acl.Rule(sip='2001:db8:1::2', dip='2001:db8:2::2', proto='udp', sport=40001, dport=7781, out_port=5,
                     set_sip='2001:db8:8::8', set_dip='2001:db8:9::9', set_smac='00:d0:d0:61:62:01',
                     set_dmac='00:e0:41:68:0d:86')
        t = self.tokens(r.driver_fields())
        self.assertEqual(t['k_sip'], (0xefa00008, 0xffffffff))
        self.assertEqual(t['k_dip'], (0x917fa934, 0xffffffff))
        self.assertEqual([t[f's_v6_ipv6_addr{i}'][0] for i in range(4)], [0x20010db8, 0x00080000, 0, 8])
        self.assertEqual(t['s_v6_dmac_l32'][0], 0x41680d86)

    def test_v6_dmac_needs_smac(self):
        r = acl.Rule(sip='2001:db8:1::2', dip='2001:db8:2::2', set_dmac='00:e0:41:68:0d:86')
        self.assertRaises(ValueError, r.driver_fields)

    def test_v6_needs_both_addresses(self):
        self.assertRaises(ValueError, acl.Rule, sip='2001:db8:1::2')

    def test_wanlink_dslite(self):
        cmds = acl.wanlink_commands(3, dslite=('2001:db8::1', '2001:db8::2'))
        self.assertIn('ds_lite_add_flag=1', cmds[0])
        self.assertIn('ipv6.next_head=4 ipv6.hop_limit=40', cmds[1])
        self.assertIn('ipv6_addr0=20010db8 ipv6_addr1=0 ipv6_addr2=0 ipv6_addr3=1', cmds[2])
        self.assertRaises(ValueError, acl.wanlink_commands, 40, pppoe=1)

    def test_parse_set_output(self):
        log = EXP / 'acl/exp101_hgu2.txt'
        if not log.exists():
            self.skipTest('exp101 log not present')
        handle, errs = acl.parse_set_output(log.read_text())
        self.assertEqual(handle, 'multi_info=ffffffc01e190780 node_info=ffffffc01e1a2580')


if __name__ == '__main__':
    unittest.main()
