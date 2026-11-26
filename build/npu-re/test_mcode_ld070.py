"""Static checks of the 0x070 field-load hypothesis; no device."""
import random
import unittest
from collections import Counter
from pathlib import Path

from mcode_ld070 import decode, is_load, pairs
from mcode_preps import regions

ROOT = Path(__file__).resolve().parents[2]


class LoadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.zx = regions((ROOT / 'extracted/kernel1/rootfs/etc/mcode/mcode_133.bin').read_bytes())[0][2]
        cls.sr = regions((ROOT / 'zte_zxslc_sr1010/mcode_intel.bin').read_bytes())[0][2]

    def loads(self, w):
        return [decode(pc, x) for pc, x in enumerate(w) if is_load(x)]

    def test_field_layout_holds_for_every_word(self):
        for w, total in ((self.zx, 269), (self.sr, 405)):
            ls = self.loads(w)
            self.assertEqual(len(ls), total)
            self.assertTrue(all((ld.word >> 30) & 0x3fff == 0 for ld in ls))   # bits 43:30 unused
            # A load never crosses a 32-bit word, same rule as the 0290 operand.
            self.assertTrue(all(ld.dest % 4 + ld.size <= 4 or ld.dest % 4 == 0 for ld in ls))
            self.assertLessEqual(sum(ld.word & 0xff8 != 0x520 for ld in ls), 6)

    def test_known_protocol_fields(self):
        sr, zx = self.sr, self.zx
        got = lambda w, pc: (lambda d: (d.base, d.offset, d.size, d.dest))(decode(pc, w[pc]))
        self.assertEqual(got(sr, 2893), (1, 12, 2, 12))   # EtherType from frame start
        self.assertEqual(got(sr, 2900), (1, 16, 2, 12))   # EtherType after one VLAN tag
        self.assertEqual(got(sr, 2846), (5, 9, 1, 12))    # IPv4 Protocol
        self.assertEqual(got(sr, 2858), (5, 6, 1, 12))    # IPv6 Next Header
        self.assertEqual(got(sr, 2865), (5, 0, 4, 52))    # GRE flags+protocol
        self.assertEqual(got(zx, 1369), (5, -2, 4, 84))   # PPP protocol just before L3
        self.assertEqual(got(zx, 1448), (5, 6, 1, 84))    # IPv6 Next Header -> UDP/TCP

    def test_compare_reads_what_was_loaded(self):
        for w in (self.zx, self.sr):
            fed = {c.pc: (ld.pc, c.source - ld.dest * 8) for c, ld in pairs(w) if ld}
            if w is self.sr:
                self.assertEqual(fed[2896], (2893, 0))
                self.assertEqual(fed[2867], (2865, 16))   # first two GRE bytes = high half
                self.assertEqual(fed[2868], (2865, 0))
            else:
                self.assertEqual(fed[1371], (1369, 16))
        self.assertEqual(sum(ld is not None for _, ld in pairs(self.zx)), 22)
        self.assertEqual(sum(ld is not None for _, ld in pairs(self.sr)), 27)

    def test_shuffled_destinations_feed_fewer_compares(self):
        for w, real in ((self.zx, 22), (self.sr, 27)):
            idx = [pc for pc, x in enumerate(w) if is_load(x)]
            ds = [(w[pc] >> 44) & 0xff for pc in idx]
            random.Random(7).shuffle(ds)
            fake = list(w)
            for pc, d in zip(idx, ds):
                fake[pc] = (w[pc] & ~(0xff << 44)) | (d << 44)
            self.assertLess(sum(ld is not None for _, ld in pairs(fake)), real * 0.6)

    def test_base_offsets_are_plausible(self):
        # Frame-start and current-header bases stay within a header; base 3 reaches far.
        for w in (self.zx, self.sr):
            by = Counter()
            for ld in self.loads(w):
                by[ld.base] = max(by[ld.base], ld.offset)
            self.assertLessEqual(by[1], 16)
            self.assertLessEqual(by[5], 32)
            self.assertGreater(by[3], 128)


if __name__ == '__main__':
    unittest.main()
