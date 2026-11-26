"""Static PC-field checks; no firmware modification or device dependency."""
import unittest
from pathlib import Path

from mcode_pc_fields import field_rows, fields, layout_rows
from mcode_preps import regions
from mcode_stat_index import sites

ROOT = Path(__file__).resolve().parents[2]


def records(rows):
    header = next(rows)
    return [dict(zip(header, row)) for row in rows]


class PcFieldsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.zx = regions((ROOT / 'extracted/kernel1/rootfs/etc/mcode/mcode_133.bin').read_bytes())
        cls.sr = regions((ROOT / 'zte_zxslc_sr1010/mcode_intel.bin').read_bytes())

    def test_full_corpus_not_just_in_range_hits(self):
        for seg, n8, n9, distinct_b, distinct_c, cross_result in [
                (self.zx, 474, 151, 240, 120, (75, 35, 2)),
                (self.sr, 503, 234, 298, 154, (132, 49, 2))]:
            rows = records(field_rows(seg))
            b = [r for r in rows if r['prefix'] == '0108']
            c = [r for r in rows if r['prefix'] == '0290']
            self.assertEqual((len(b), len(c)), (n8, n9))
            self.assertTrue(all(r['a'] == r['pc']+1 for r in b))
            self.assertTrue(all(r['region'] == r['target_region'] == 'main' for r in rows))
            n = len(seg[0][2])
            self.assertEqual([(r['pc'], r['a'], r['a_region']) for r in b if r['a_region'] != 'main'],
                             [(n-1, n, 'one_past_main')])
            dests = {r['b_or_c'] for r in b}
            self.assertEqual((len(dests), len({r['b_or_c'] for r in c})), (distinct_b, distinct_c))
            # On cross-page sites compare literal C with the *same low six bits* in the PC's page.
            cross = [(r['pc'], r['b_or_c']) for r in c if r['pc']//64 != r['b_or_c']//64]
            self.assertEqual((len(cross), sum(t in dests for _, t in cross),
                              sum(((pc & ~63) | (t & 63)) in dests for pc, t in cross)), cross_result)

    def test_six_independently_identified_stat_groups(self):
        w = self.zx[0][2]
        triples = [s for s in sites(self.zx) if len(s.upstream) == 3]
        self.assertEqual([s.pc for s in triples], [251, 310, 3429, 4097, 5063, 5183])
        for s in triples:
            first, middle, last = (pc for pc, _ in s.upstream)
            join = s.pc - 7
            c0, c1 = fields(w[first-2]), fields(w[first-1])
            self.assertEqual((c0.target, c1.target), (last, middle))
            self.assertEqual((c0.remainder, c1.remainder), (0x0290007600000001, 0x0290007600000021))
            for pc, a in ((first+1, middle), (middle+1, last)):
                self.assertEqual(fields(w[pc]), (a, join, 0x0108000000000520))
            self.assertEqual(w[join], 0x001780000000001f)

    def test_prefix_layout_includes_non_stat_and_nonmatching_cases(self):
        zx = records(layout_rows(self.zx))
        self.assertEqual([r['start'] for r in zx if r['matches_local_layout']],
                         [237, 296, 3399, 3415, 4083, 5049, 5169])
        extra = next(r for r in zx if r['start'] == 3399)
        self.assertEqual((extra['next_0018_pc'], extra['next_0018_word']), (3411, '00180005e1000003'))
        self.assertEqual([r['start'] for r in zx if not r['matches_local_layout']], [5083])
        self.assertEqual([(r['start'], r['matches_local_layout']) for r in records(layout_rows(self.sr))],
                         [(289, 0)])

    def test_sr_copy_moves_by_518_even_across_a_low_field_carry(self):
        w = self.sr[0][2]
        # Find copies using 18 uninterpreted words and just the prefixes of the other six.
        # Neither the proposed address fields nor the rest of those six words selects the copy.
        signature = [x & (0xffff << 48) if x >> 48 in (0x0108, 0x0290) else x for x in w]
        length = 24
        key = signature[296:296+length]
        starts = [i for i in range(len(w)-length+1) if signature[i:i+length] == key]
        self.assertEqual(starts, [296, 814])
        before, after = starts
        for off, dest_off in [(0, 24), (1, 4), (2, 14), (3, 22), (13, 24), (21, 24)]:
            f, g = fields(w[before+off]), fields(w[after+off])
            self.assertEqual((f.target, g.target), (before+dest_off, after+dest_off))
            self.assertEqual(f.remainder, g.remainder)
            if f.a is not None:
                self.assertEqual(g.a - f.a, after-before)
        self.assertEqual([fields(w[pc]).target & 63 for pc in (299, 817)], [62, 4])

    def test_unmapped_values_and_region_edges(self):
        fake = (('main', 0, (0x0290000000000000,)), ('high', 0x2fad, (0x01087fffffffffff,)))
        c, b = records(field_rows(fake))
        self.assertEqual((c['a'], c['b_or_c'], c['target_region']), ('', 0, 'main'))
        self.assertEqual((b['pc'], b['a'], b['b_or_c'], b['target_region']),
                         (0x2fad, 65535, 65535, 'outside_regions'))
        w = self.zx[0][2][3415:3423]
        self.assertEqual(records(layout_rows((('one', 3415, w[:6]), ('two', 3421, w[6:])))), [])
        last, = records(layout_rows((('one', 3415, w[:7]),)))
        self.assertEqual((last['matches_local_layout'], last['join_word'], last['next_0018_pc']), (0, '', ''))


if __name__ == '__main__':
    unittest.main()
