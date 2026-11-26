"""ZX133 table-48 corpus checks and a synthetic non-match/region-boundary case."""
import unittest
from collections import Counter
from pathlib import Path

from debug_stat_reads import driver_reads
from mcode_preps import regions
from mcode_stat_index import ALTERNATE, BASE_FIELD, FIELD, FIXED, joined_rows, sites

ZX = Path(__file__).resolve().parents[2] / 'extracted/kernel1/rootfs'


class StatIndexTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reads = driver_reads(ZX / 'kmodule/np_133.ko')
        cls.fixed = {r.index: r for r in cls.reads if r.index is not None}
        cls.segments = regions((ZX / 'etc/mcode/mcode_133.bin').read_bytes())
        cls.sites = list(sites(cls.segments))

    def test_driver_uses_success_prints_and_separates_loops(self):
        self.assertEqual((len(self.reads), len(self.fixed)), (65, 57))
        self.assertEqual([(self.fixed[i].call, self.fixed[i].label) for i in (0x18a, 0x1f2, 0x1f4)],
                         [(0xbec88, 'protocol action trap cnt'),
                          (0xbf890, 'woe rx np1 to np2 pkt cnt'),
                          (0xbf8dc, 'woe tx trap cpu pkt cnt')])  # shared printk
        loops = [r for r in self.reads if r.index is None]
        self.assertEqual([r.call for r in loops],
                         [0xbe70c, 0xbe760, 0xbe7b4, 0xbf6c0, 0xbf710, 0xbf760, 0xbf7cc, 0xbf838])
        self.assertEqual(loops[-1].w1, 'add w1, w20, #0x1c8')  # offset != fixed index

    def test_sites_selected_independently_of_the_prep_word(self):
        self.assertEqual(Counter(s.form for s in self.sites), {'fixed_candidate': 70, 'other_source': 8})
        # Reverse check: the complete forms do not occur elsewhere in either instruction region.
        hits = {(r, b+i) for r, b, w in self.segments for i, x in enumerate(w)
                if (x & ~FIELD) in (FIXED, ALTERNATE)}
        self.assertEqual(hits, {(s.region, s.pc-6) for s in self.sites})
        w = self.segments[0][2]
        self.assertEqual(len({(w[s.pc-7], *w[s.pc-5:s.pc+1]) for s in self.sites}), 1)

    def test_fixed_matches_unknowns_and_density_control(self):
        imm = [s for s in self.sites if s.index is not None]
        self.assertEqual({s.pc: s.index for s in imm if s.index not in self.fixed},
                         {83: 0x1a8, 3378: 0x1a9, 3387: 0x1aa, 4812: 0x1ac})
        values = {s.index for s in imm}
        self.assertEqual((len(values), len(values & self.fixed.keys())), (50, 46))
        self.assertEqual(sum(s.index == 0x18a for s in imm), 17)
        self.assertEqual([sum(s.index+delta in self.fixed for s in imm) for delta in (-1, 0, 1)],
                         [63, 66, 64])

    def test_other_form_only_gives_upstream_base_candidates(self):
        alt = [s for s in self.sites if s.form == 'other_source']
        groups = {s.pc: tuple((w & BASE_FIELD) >> 14 for _, w in s.upstream) for s in alt}
        self.assertEqual(groups, {**dict.fromkeys((251, 310, 3429), (0x140, 0x100, 0xc0)),
                                  **dict.fromkeys((4097, 5063, 5183), (0x80, 0x40, 0)),
                                  3680: (0x1c2,), 3905: (0x1c8,)})
        rows = iter(joined_rows(self.segments, self.reads))
        header = next(rows)
        for values in rows:
            row = dict(zip(header, values))
            if row['form'] == 'other_source':
                self.assertEqual((row['index_candidate'], row['get_call'], row['driver_label']), ('', '', ''))

    def test_region_start_and_unrecognized_form_are_not_dropped(self):
        t = 0x0018000601000003
        # No backreference into the preceding region or via a negative Python index.
        segs = [('one', 0, (FIXED,) + (0,)*5), ('two', 90, (t, FIXED ^ 1) + (0,)*5 + (t,)),
                ('controls', 160, (FIXED,) + (0,)*5 + (t ^ (1 << 29), t ^ 1))]
        self.assertEqual([(s.pc, s.form, s.prep, s.index) for s in sites(segs)],
                         [(90, 'unknown', None, None), (97, 'unknown', FIXED ^ 1, None)])


if __name__ == '__main__':
    unittest.main()
