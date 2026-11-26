import unittest

from mcode_preps import rows


def prep(prefix, k):
    return (prefix << 48) | (k << 46) | 0x523


def records(segments, view):
    data = iter(rows(segments, view))
    header = next(data)
    return [dict(zip(header, r)) for r in data]


class PrepsTest(unittest.TestCase):
    def setUp(self):
        # A non-target closer, a gapped/repeated k=3 run, an orphan, and a
        # target without a candidate across a segment boundary.
        other = (0x18 << 48) | 2
        t3 = (0x18 << 48) | (1 << 23) | 3
        self.regions = [('main', 0, [prep(0x148, 1), other, prep(0x548, 3),
                                     0, prep(0x148, 3), t3, prep(0x548, 2)]),
                        ('high', 0x2fad, [t3])]

    def test_hits_do_not_require_a_t3_or_a_full_triple(self):
        h = records(self.regions, 'hits')
        self.assertEqual([(r['pc'], r['k'], r['close_kind'], r['distance']) for r in h],
                         [(0, 1, 'OTHER_0018', 1), (2, 3, 'T3', 3),
                          (4, 3, 'T3', 1), (6, 2, 'END', '')])
        self.assertEqual((h[0]['prev_word'], h[-1]['next_word']), ('', ''))

    def test_gaps_duplicates_and_empty_target(self):
        w = records(self.regions, 'windows')
        t, empty = [r for r in w if r['close_kind'] == 'T3']
        self.assertEqual((t['prep_pcs'], t['k_seq'], t['distances'],
                          t['adjacent_suffix'], t['repeated_k']), ('2,4', '3,3', '3,1', 1, 1))
        self.assertEqual((empty['prev_0018_pc'], empty['close_pc'], empty['n_prep']),
                         ('', 0x2fad, 0))


if __name__ == '__main__':
    unittest.main()
