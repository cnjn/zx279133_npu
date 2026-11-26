"""exp101 step 1: write ACL eRAM entries through acl_debug with distinctive field values,
read the raw words back with se_debug/cpu_get_eram_by_table_width, then free them.
Never call acl_*_table_get: acl_vlan_table_get recursed until the kernel stack overflowed (panic, reboot).

Output: exp101_layout.txt (raw board log)."""
import board

A = 'acl_debug'
W = [  # (table, sdt, words, index, set-args)  index None = allocated by the driver
    ('mac_encap', 122, 4, 0x3f, 'inner_tag=11223344 outer_tag=55667788 dmac_l32=99aabbcc dmac_h16=ddee inner_tag_en=1 outer_tag_en=0'),
    ('mac_encap', 122, 4, 0x3e, 'outer_tag_en=1'),
    ('wan_link_udp_encap', 120, 1, 1, 'dport=1111 sport=2222'),
    ('l2tp_vxlan_encap', 121, 4, 1, 'info0=a0a0a0a0 info1=b1b1b1b1 info2=c2c2c2c2 info3=d3d3d3d3'),
    ('wan_link_local_ipv6', 118, 4, 1, 'ipv6_addr0=20010db8 ipv6_addr1=11111111 ipv6_addr2=22222222 ipv6_addr3=33333333'),
    ('wan_link_remote_ipv6', 119, 4, 1, 'ipv6_addr0=20010db9 ipv6_addr1=44444444 ipv6_addr2=55555555 ipv6_addr3=66666666'),
    ('wan_link_ip_encap', 117, 4, 1, 'ipv4.ip_ver=4 ipv4.header_len=5 ipv4.tos=a1 ipv4.ttl=b2 ipv4.ipv4_protocol=c3 '
                                     'ipv4.dip=d4d5d6d7 ipv4.sip=e4e5e6e7 ipv4.init_checksum=f1f2 ipv4.identification=0102'),
    ('wan_link_ip_encap', 117, 4, 2, 'ipv6.ip_ver=6 ipv6.dscp=a1 ipv6.hop_limit=b2 ipv6.next_head=c3 ipv6.flow_lable=12345'),
]
FLAGS = ['add_flag', 'pppoe_add_flag', 'ds_lite_add_flag', 'v6rd_add_flag', 'l2tp_add_flag', 'vxlan_add_flag',
         'del_flag', 'pppoe_del_flag', 'ds_lite_del_flag', 'v6rd_del_flag', 'l2tp_del_flag', 'vxlan_del_flag']
for i, f in enumerate(FLAGS):
    W.append(('wan_link', 116, 2, i + 1, f'{f}=1'))
W.append(('wan_link', 116, 2, 20, 'pppoe_session_id=1234'))

ALLOC = [  # tables whose set allocates or takes reserve_index
    ('source', 112, 4, 1, 'reserve_index=1 mac_h16=0a0b mac_l32=0c0d0e0f sipv4=c0a80101'),
    ('next_hop', 113, 4, 1, 'reserve_index=1 mac_h16=1a1b mac_l32=1c1d1e1f dipv4=c0a80102'),
    ('vlan', 111, 4, None, 'outer_vid_en=1 outer_vid=123 outer_tpid_en=1 outer_tpid=88a8 outer_pri_en=1 outer_pri=5 '
                          'inner_vid_en=1 inner_vid=456 inner_tpid_en=1 inner_tpid=8100 inner_pri_en=1 inner_pri=3 '
                          'inner_cfi_en=1 inner_cfi=1'),
    ('ipv6_mac', 114, 4, None, 'smac_l32=21222324 smac_h16=2526 dmac_l32=31323334 dmac_h16=3536'),
]

cmds = []
for t, sdt, n, idx, args in W:
    cmds.append(f'echo table_index={idx:x} {args} > {A}/acl_{t}_table_set')
    cmds.append(f'echo {sdt} {idx} {n} > se_debug/cpu_get_eram_by_table_width')
for t, sdt, n, idx, args in ALLOC:
    cmds.append(f'echo {args} > {A}/acl_{t}_table_set')
for t, sdt, n, idx, args in ALLOC:
    for i in range(0, 4):
        cmds.append(f'echo {sdt} {i} {n} > se_debug/cpu_get_eram_by_table_width')
# free everything again
for t, sdt, n, idx, args in W:
    cmds.append(f'echo {idx} > {A}/acl_{t}_table_free')
for t in ('source', 'next_hop', 'vlan', 'ipv6_mac'):
    for i in range(4):
        cmds.append(f'echo {i} > {A}/acl_{t}_table_free')
for t, sdt, n, idx, args in W[:2] + ALLOC:
    cmds.append(f'echo {sdt} {idx or 0} {n} > se_debug/cpu_get_eram_by_table_width')

if __name__ == '__main__':
    out = board.script(cmds, 300, name='exp101')
    open('exp101_layout.txt', 'w').write(out)
    print(out[-3000:])
