"""Static checks of the 0100..0107 write-immediate hypothesis; no device."""
import unittest
from pathlib import Path

from mcode_imm010 import ALWAYS, decode, is_imm, summary
from mcode_preps import regions

ROOT = Path(__file__).resolve().parents[2]


class ImmTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.zx = regions((ROOT / 'extracted/kernel1/rootfs/etc/mcode/mcode_133.bin').read_bytes())[0][2]
        cls.sr = regions((ROOT / 'zte_zxslc_sr1010/mcode_intel.bin').read_bytes())[0][2]

    def test_immediate_always_fits_width(self):
        for w, n in ((self.zx, 724), (self.sr, 490)):
            s = summary(w)
            self.assertEqual((s['count'], s['unused_24_16'], s['imm_fits'], s['dst_in_word']), (n, 0, n, n))
            self.assertLess(s['imm_fits_shuffled_w'], 0.85 * n)   # control
            self.assertLessEqual(s['max_dst_word'], 31)            # writable low region

    def test_condition_field_spans_bits_14_5(self):
        for w in (self.zx, self.sr):
            xs = [decode(pc, x) for pc, x in enumerate(w) if is_imm(x)]
            for x in xs:
                self.assertEqual(x.cond == ALWAYS, (x.word >> 12) & 7 == 0 and (x.word >> 5) & 0x7f == 0x29)
        # 0108's 0x4be0 is condition 0x25f under the same split (bit 15 there belongs to B).
        self.assertEqual((0x4be0 >> 5) & 0x3ff, 0x25f)

    def test_gre_header_lengths(self):
        # After IPv4/IPv6 Protocol==47, the fall-through writes 20 / 40 into the byte the
        # protocol had been loaded to (0x070 D=12 -> bit 0x60).
        for pc, n in ((2849, 20), (2861, 40)):
            x = decode(pc, self.sr[pc])
            self.assertEqual((x.dst, x.width, x.imm), (0x60, 8, n))
        self.assertEqual((self.sr[2846] >> 44) & 0xff, 12)

    def test_jump_is_not_decoded_here(self):
        self.assertFalse(is_imm(0x0108000083be0520))
        with self.assertRaises(ValueError):
            decode(0, 0x0108000083be0520)


if __name__ == '__main__':
    unittest.main()
