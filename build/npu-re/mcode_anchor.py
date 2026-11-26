"""Locate well-known protocol constants inside 64-bit microcode words (bit position stats)."""
import struct, sys, collections
def main_words(p):
    d = open(p, 'rb').read(); n = struct.unpack('>I', d[12:16])[0]
    return [struct.unpack('>Q', d[16 + 8 * i:24 + 8 * i])[0] for i in range(n)]
consts = {'ETH_IPV4 0800': 0x0800, 'ETH_IPV6 86dd': 0x86dd, 'ETH_VLAN 8100': 0x8100,
          'ETH_QINQ 88a8': 0x88a8, 'ETH_ARP 0806': 0x0806, 'PPPOE_S 8864': 0x8864,
          'PPPOE_D 8863': 0x8863, 'PPP_IPV4 0021': 0x0021, 'PPP_IPV6 0057': 0x0057}
for path in sys.argv[1:]:
    w = main_words(path)
    print(f'== {path}: {len(w)} words')
    for nm, c in consts.items():
        pos = collections.Counter()
        for x in w:
            for sh in range(0, 49):
                if (x >> sh) & 0xffff == c: pos[sh] += 1
        print(f'  {nm}: {sum(pos.values()):3d} hits, bit offsets {pos.most_common(4)}')
