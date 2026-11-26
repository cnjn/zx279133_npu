"""Static checks of the 0x050 bit-move hypothesis; no device."""
import random
import unittest
from pathlib import Path

from mcode_mv050 import decode, is_move, summary
from mcode_preps import regions

ROOT = Path(__file__).resolve().parents[2]


class MoveTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.zx = regions((ROOT / 'extracted/kernel1/rootfs/etc/mcode/mcode_133.bin').read_bytes())[0][2]
        cls.sr = regions((ROOT / 'zte_zxslc_sr1010/mcode_intel.bin').read_bytes())[0][2]
        cls.s = {'zx': summary(cls.zx), 'sr': summary(cls.sr)}

    def test_width_is_low_five_bits(self):
        # 0x520 / 0x528 / 0x53f are one predicate (bits 11:5 = 0x29) with W = 1..8, 9..16, 32.
        for w in (self.zx, self.sr):
            ms = [decode(pc, x) for pc, x in enumerate(w) if is_move(x)]
            lows = {m.word & 0xfff for m in ms if m.main_class}
            self.assertTrue({0x520, 0x527, 0x528, 0x52f, 0x53f} <= lows)
            self.assertTrue(all(lo & 0xfe0 == 0x520 for lo in lows))

    def test_bit_ranges_never_cross_a_word(self):
        for k, n in (('zx', 911), ('sr', 933)):
            s = self.s[k]
            self.assertEqual((s['main'], s['dst_in_word'], s['src_in_word']), (n, n, n))
        # Control: the same addresses with shuffled widths break the rule.
        for w in (self.zx, self.sr):
            ms = [decode(pc, x) for pc, x in enumerate(w) if is_move(x) and decode(pc, x).main_class]
            ws = [m.width for m in ms]
            random.Random(1).shuffle(ws)
            self.assertLess(sum(m.src % 32 + v <= 32 for m, v in zip(ms, ws)), 0.92 * len(ms))

    def test_writable_low_region_readable_high_region(self):
        for k in ('zx', 'sr'):
            self.assertLessEqual(self.s[k]['max_dst_word'], 32)
            self.assertGreaterEqual(self.s[k]['max_src_word'], 44)
        for w in (self.zx, self.sr):
            self.assertLessEqual(max(((x >> 44) & 0xff) >> 2 for x in w if x >> 52 == 0x070), 31)

    def test_loaded_fields_are_moved_on(self):
        for k, real in (('zx', 128), ('sr', 229)):
            self.assertEqual(self.s[k]['from_070'][0], real)
            self.assertGreater(real, 1.5 * self.s[k]['from_070_shuffled'][0])

    def test_mac_key_prefix_is_a_12_bit_move(self):
        m = decode(2885, self.sr[2885])
        self.assertEqual((m.dst, m.src, m.width), (0x60, 0x270, 12))   # not the main class
        self.assertEqual((self.sr[2887] >> 30) & 0x7ff, 0x60)          # 055 copies it into key[0..1]


if __name__ == '__main__':
    unittest.main()
