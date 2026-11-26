"""Static checks of the split literal hypothesis; no firmware writes or device."""
import unittest
from pathlib import Path

from mcode_cmp0290 import VALUE_MASK, decode, run_rows, runs, site_rows, variation
from mcode_pc_fields import fields
from mcode_preps import regions
from mcode_stat_index import BASE_FIELD, sites

ROOT = Path(__file__).resolve().parents[2]


def cases(words, *pcs):
    return [decode(pc, words[pc]) for pc in pcs]


class CompareTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.zx = regions((ROOT / 'extracted/kernel1/rootfs/etc/mcode/mcode_133.bin').read_bytes())
        cls.sr = regions((ROOT / 'zte_zxslc_sr1010/mcode_intel.bin').read_bytes())

    def test_four_way_literal_and_target_are_separate(self):
        w = self.sr[0][2]
        for start, src, dests in [(296, 0x496, [320, 300, 310, 318]),
                                  (814, 0x496, [838, 818, 828, 836]),
                                  (3584, 0x136, [3608, 3588, 3598, 3606])]:
            cs = cases(w, *range(start, start+4))
            self.assertEqual(variation(cs), 0x60)
            self.assertEqual({(c.source, c.width, c.mode) for c in cs}, {(src, 2, 0)})
            self.assertEqual([c.value for c in cs], [0, 1, 2, 3])
            self.assertEqual([c.target for c in cs], dests)
        # Values need not count up, nor do different values need distinct destinations.
        self.assertEqual([c.value for c in cases(self.zx[0][2], 2586, 2587, 2588)], [3, 1, 2])
        self.assertEqual([(c.value, c.target) for c in cases(w, 2450, 2451, 2452)],
                         [(0x49, 2454), (0x4a, 2454), (0x4b, 2454)])

    def test_six_stat_triplets_vs_known_driver_ranges(self):
        w = self.zx[0][2]
        triples = [s for s in sites(self.zx) if len(s.upstream) == 3]
        self.assertEqual(len(triples), 6)
        for s in triples:
            first = s.upstream[0][0]
            cs = cases(w, first-2, first-1)
            self.assertEqual({(c.source, c.width, c.mode) for c in cs}, {(0x1d8, 2, 0)})
            self.assertEqual([c.value for c in cs], [0, 1])
            base = 0xc0 if s.pc in (251, 310, 3429) else 0
            self.assertEqual([(w[c.target] & BASE_FIELD) >> 14 for c in cs], [base, base+0x40])
            self.assertEqual((w[first] & BASE_FIELD) >> 14, base+0x80)  # sequential arm, not literal 2

    def test_ethertype_retest_and_standard_header_offsets(self):
        w = self.sr[0][2]
        cs = cases(w, 2896, 2897, 2898)
        self.assertEqual({(c.source, c.width, c.mode) for c in cs}, {(0x60, 16, 0)})
        self.assertEqual([(c.value, c.target) for c in cs],
                         [(0x8100, 2900), (0x0800, 2906), (0x86dd, 2920)])
        self.assertEqual(w[2897:2899], w[2903:2905])  # inside the candidate VLAN arm
        self.assertEqual([(w[i] >> 17) & 0xff for i in (2893, 2900, 2908, 2922)], [12, 16, 9, 6])
        self.assertEqual([(w[i] >> 25) & 0xffff for i in (2894, 2901)], [14, 18])

    def test_ppp_and_separate_mode(self):
        w = self.zx[0][2]
        self.assertEqual([(c.value, c.width, c.mode, c.target) for c in cases(w, 1360, 1371, 1372)],
                         [(0xff03, 16, 1, 1374), (0x21, 16, 0, 1376), (0x57, 16, 0, 1415)])
        self.assertEqual([w[i] >> 14 & 0xffff for i in (1361, 1374)], [4, 2])
        self.assertEqual(fields(w[1375]).target, 1362)
        for a, b in [(1399, 1400), (1451, 1452)]:
            self.assertEqual([(c.value, c.width, c.target) for c in cases(w, a, b)],
                             [(17, 8, 1403), (6, 8, 1409)])
        c0, c1 = cases(w, 3416, 3430)
        self.assertEqual((c0.source, c0.width, c0.value), (c1.source, c1.width, c1.value))
        self.assertEqual((c0.mode, c1.mode, variation([c0, c1])), (0, 1, 1 << 10))

    def test_width_holds_before_any_fit_or_run_filter(self):
        for seg, n, all_runs, multi, same, too_wide_no_plus_one in [
                (self.zx, 151, 118, 31, 21, 29), (self.sr, 234, 177, 37, 18, 86)]:
            groups = [g for _, g in runs(seg)]
            cs = [c for g in groups for c in g]
            self.assertEqual((len(cs), len(groups)), (n, all_runs))
            self.assertTrue(all(c.fits and c.within_word for c in cs))
            self.assertEqual(sum(c.value.bit_length() > c.width-1 for c in cs), too_wide_no_plus_one)
            many = [g for g in groups if len(g) > 1]
            uniform = [g for g in many if not (variation(g) & ~VALUE_MASK)]
            self.assertEqual((len(many), len(uniform)), (multi, same))
            self.assertTrue(all(len({c.value for c in g}) == len(g) for g in uniform))

    def test_outliers_and_maximal_runs_are_not_pruned(self):
        # Width=2, start=31, literal=0x801f: violates both observed corpus properties.
        raw = (0x0290 << 48) | (31 << 30) | (0x400 << 19) | (31 << 5) | 1
        seg = [('one', 17, (raw, raw, 0, raw)), ('two', 128, (raw, raw ^ (1 << 10)))]
        rows = iter(site_rows(seg)); names = next(rows)
        out = [dict(zip(names, r)) for r in rows]
        self.assertEqual([r['pc'] for r in out], [17, 18, 20, 128, 129])
        self.assertTrue(all((r['fits_width'], r['within_32'], r['literal']) == (0, 0, '0x801f') for r in out))
        rows = iter(run_rows(seg)); names = next(rows)
        out = [dict(zip(names, r)) for r in rows]
        self.assertEqual([(r['start'], r['count'], r['same_setup'], r['distinct_literals']) for r in out],
                         [(17, 2, 1, 1), (20, 1, 1, 1), (128, 2, 0, 1)])
        with self.assertRaises(ValueError):
            decode(0, 0x0690000000000001)  # no generalization to sibling prefixes

    def test_gre_mode1_fallthrough_keeps_parsing(self):
        """M=1 with a known GRE literal: the PC+1 side advances, C is a shared exit."""
        w = self.sr[0][2]
        b24_17 = lambda pc: (w[pc] >> 17) & 0xff
        b40_25 = lambda pc: (w[pc] >> 25) & 0xffff
        # IPv4 Protocol (byte 9) / IPv6 Next Header (byte 6) is loaded, then compared with 47.
        for load, cmp_pc, step in [(2846, 2848, 2849), (2858, 2860, 2861)]:
            c = decode(cmp_pc, w[cmp_pc])
            self.assertEqual((c.source, c.width, c.mode, c.value, c.target),
                             (0x060, 8, 1, 47, 2977))
            self.assertEqual(b24_17(load), {2846: 9, 2858: 6}[load])
            # Fall-through skips the IP header: 20 bytes for IPv4, 40 for IPv6.
            self.assertEqual(b40_25(step), {2849: 20, 2861: 40}[step])
        self.assertEqual(fields(w[2852]).target, 2865)  # IPv4 arm joins IPv6 at 2865
        # GRE header: flags/version must be 0 and protocol 0x6558 (Ethernet), else 2979.
        gre = cases(w, 2867, 2868)
        self.assertEqual([(c.width, c.mode, c.value, c.target) for c in gre],
                         [(15, 1, 0, 2979), (16, 1, 0x6558, 2979)])
        # Only the fall-through side reaches the inner EtherType switch at 2896.
        self.assertEqual([c.value for c in cases(w, 2896, 2897, 2898)], [0x8100, 0x0800, 0x86dd])
        self.assertEqual((w[2899] >> 15) & 0xffff, 2979)
        self.assertNotIn(w[2977] >> 48, (0x0290,))  # C side immediately leaves via 0108

    def test_gre_inner_path_has_no_other_exit(self):
        """2869..2895: every word with an address field either exits to 2979 or reconverges."""
        w = self.sr[0][2]
        ctl = {}
        for pc in range(2869, 2896):
            pre = w[pc] >> 48
            if pre == 0x0290:
                ctl[pc] = ('cmp', decode(pc, w[pc]).target)
            elif pre == 0x0108:
                ctl[pc] = ('0108', (w[pc] >> 15) & 0xffff, w[pc] & 0x7fff)
        self.assertEqual(ctl, {2876: ('cmp', 2979), 2877: ('cmp', 2979), 2881: ('cmp', 2979),
                               2890: ('0108', 2892, 0x4be0)})
        self.assertEqual(w[2889] >> 48, 0x0018)  # the conditional 0108 follows a lookup
        self.assertEqual([pc for pc in range(2869, 2896) if w[pc] >> 48 == 0x0110], [2882, 2892])

    def test_fast_table_cascade_0108_4be0_jumps_on_miss(self):
        """SR1010: FAST_256b lookup, 0x4be0 jump to FAST_512b lookup; both fall-throughs reconverge."""
        w = self.sr[0][2]
        J = lambda pc: (w[pc] >> 48, w[pc] & 0x7fff, (w[pc] >> 15) & 0xffff)
        for pc in (142, 653, 2949, 3398):
            self.assertEqual(w[pc], 0x0018000560800004)        # T4 id 43 = SDT_NO_FAST_256b
            self.assertEqual(J(pc+1), (0x0108, 0x4be0, pc+8))  # -> second table
            self.assertEqual(w[pc+8], 0x00180001c0800004)      # T4 id 14 = SDT_NO_FAST_512b
            self.assertEqual(J(pc+7), (0x0108, 0x0520, pc+12))  # first fall-through skips it
            self.assertEqual(J(pc+9)[:2], (0x0108, 0x4be0))     # 512b: same condition, far exit
            # Each fall-through handles a result with the same two words, roles swapped.
            self.assertEqual((w[pc+5], w[pc+6]), (0x050701380000053f, 0x050741580000053f))
            self.assertEqual((w[pc+10], w[pc+11]), (0x050701580000053f, 0x050741380000053f))
        self.assertEqual([J(pc+9)[2] for pc in (142, 653, 2949, 3398)], [1545, 1545, 2979, 3444])

    def test_0110_payload_is_not_a_word_address(self):
        """Counter-check before treating 0110 as straight-line: its 16-bit field overruns code."""
        w = self.sr[0][2]
        xs = [(pc, x) for pc, x in enumerate(w) if x >> 48 == 0x0110]
        self.assertEqual(len(xs), 99)
        self.assertEqual(sum((x >> 14) & 0xffff >= len(w) for _, x in xs), 40)
        self.assertTrue(all((x >> 30) & 0x3ffff == 0 for _, x in xs))
        vals = {(x >> 14) & 0xffff for _, x in xs if x & 0x3fff == 0x31e0}
        # Two step-12 series (4972.. and 5220..) plus one outlier; none needs to be code.
        self.assertEqual({v % 12 for v in vals if v != 4043}, {4972 % 12, 5220 % 12})
        self.assertEqual(sorted(v for v in vals if v % 12 == 5220 % 12), [5220, 5232, 5244, 5256])


if __name__ == '__main__':
    unittest.main()
