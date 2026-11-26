"""Static checks: 0x075/0x055 build hash keys whose length is the SDT param0; no device."""
import unittest
from collections import Counter
from pathlib import Path

from mcode_key075 import key_write, rows, writes_before
from mcode_preps import regions
from sdt_dump import load_driver

ROOT = Path(__file__).resolve().parents[2]
COLS = 'pc family sdt name param0 writes key_end overlap layout'.split()


def table(img, ko):
    segs = regions((ROOT / img).read_bytes())
    r = list(rows(segs, load_driver((ROOT / ko).read_bytes())))
    return segs[0][2], [dict(zip(COLS, x)) for x in r[1:]]


class KeyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sr_w, cls.sr = table('zte_zxslc_sr1010/mcode_intel.bin', 'zte_zxslc_sr1010/kmodule/np.ko')
        cls.zx_w, cls.zx = table('extracted/kernel1/rootfs/etc/mcode/mcode_133.bin',
                                 'extracted/kernel1/rootfs/kmodule/np_133.ko')

    def test_hash_keys_never_exceed_param0(self):
        for rs, exact, total in ((self.sr, 27, 34), (self.zx, 17, 20)):
            t4 = [r for r in rs if r['family'] == 'T4']
            self.assertEqual(len(t4), total)
            sized = [r for r in t4 if r['param0']]          # ZX133 tables 54/164/165 have param0 0
            self.assertTrue(all(r['key_end'] <= r['param0'] for r in sized))
            self.assertEqual(sum(r['key_end'] == r['param0'] for r in sized), exact)
        # T5 descriptors use param0 differently: keep as a counter-example, not a failure.
        self.assertTrue(all(r['key_end'] > r['param0'] for r in self.sr if r['family'] == 'T5'))

    def test_mac_key_is_prefix_plus_address(self):
        macs = [r for r in self.sr if r['name'] == 'SDT_NO_MAC']
        self.assertEqual(len(macs), 10)
        for r in macs:
            self.assertEqual(r['param0'], 8)
            self.assertIn(r['layout'], ('055:D0+2@s0x60 075:D2+6@b1+0', '055:D0+2@s0x60 075:D2+6@b1+6'))
        # PC 77 takes the source MAC (offset 6), PC 106 the destination (offset 0).
        by = {r['pc']: r['layout'] for r in macs}
        self.assertTrue(by[77].endswith('@b1+6') and by[106].endswith('@b1+0'))

    def test_ipv6_multicast_copies_both_addresses_contiguously(self):
        ws = writes_before(self.sr_w, 1642)
        self.assertEqual([(k.dest, k.size, k.base, k.offset) for k in ws],
                         [(2, 8, 5, 8), (10, 6, 5, 16), (16, 8, 5, 22), (24, 8, 5, 30), (32, 2, 5, 38)])
        for k in ws:
            self.assertEqual(k.offset - k.dest, 6)     # packet bytes 8..39 -> key bytes 2..33
        self.assertEqual(ws[-1].dest + ws[-1].size, 34)  # SDT_NO_MULTICASTV6 param0 = 0x22

    def test_overlap_is_predicated_alternative(self):
        w = self.sr_w
        for base in (133, 644):  # two copies before SDT_NO_FAST_256b
            v4 = [key_write(pc, w[pc]) for pc in (base, base + 1)]
            v6 = [key_write(pc, w[pc]) for pc in (base + 2, base + 3, base + 4)]
            self.assertEqual([(k.dest, k.offset) for k in v4], [(0, 9), (1, 12)])  # proto, IPv4 addrs
            self.assertEqual((v6[0].dest, v6[0].offset), (0, 6))                    # IPv6 next header
            self.assertEqual({w[k.pc] & 0xff8 for k in v4}, {0x880})
            self.assertEqual({w[k.pc] & 0xff8 for k in v6}, {0x860})
            self.assertEqual(w[base + 5] & 0xff8, 0x520)  # ports: unconditional

    def test_predicate_field_scope(self):
        """bits 11:3 == 0x520>>3 is common only in some opcode classes; others use the bits otherwise."""
        for w in (self.sr_w, self.zx_w):
            c = Counter(x >> 52 for x in w if x and x & 0xff8 == 0x520)
            for op in (0x040, 0x001, 0x020):
                self.assertEqual(c[op], 0)
            self.assertTrue(all(c[op] for op in (0x010, 0x050, 0x054, 0x055, 0x070, 0x075)))


if __name__ == '__main__':
    unittest.main()
