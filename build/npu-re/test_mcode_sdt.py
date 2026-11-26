"""Offline cross-checks against the two project images and their own drivers."""
import unittest
from collections import Counter
from pathlib import Path

from mcode_preps import regions
from mcode_sdt import HEADER, xrefs
from sdt_dump import load_driver

ROOT = Path(__file__).resolve().parents[2]


def corpus(img, ko):
    segments = regions((ROOT / img).read_bytes())
    driver = load_driver((ROOT / ko).read_bytes())
    by_pc = {r[1]: dict(zip(HEADER, r)) for r in xrefs(segments, driver)}
    return driver, segments[0][2], by_pc


class SdtTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sr = corpus('zte_zxslc_sr1010/mcode_intel.bin', 'zte_zxslc_sr1010/kmodule/np.ko')
        cls.zx = corpus('extracted/kernel1/rootfs/etc/mcode/mcode_133.bin',
                        'extracted/kernel1/rootfs/kmodule/np_133.ko')

    def test_sr_minimal_pair(self):
        d, w, sites = self.sr
        self.assertEqual(d.array, 'g_core_sdt_info_133')  # not the .bss pointer
        self.assertEqual(w[86:94], w[912:920])
        self.assertEqual(w[94] ^ w[920], 1 << 29)
        for pc, no, side in [(94, 62, 'TX'), (920, 63, 'RX'), (1976, 63, 'RX')]:
            self.assertEqual((sites[pc]['id36_29'], sites[pc]['driver_name']),
                             (no, 'SDT_NO_STAT_MAC_' + side))
            self.assertEqual(d.tables[no], (4, 2048, 0x40000000))

    def test_all_t3_vs_independent_descriptor_arrays(self):
        for (d, _, sites), n, distinct in [(self.sr, 95, 11), (self.zx, 113, 5)]:
            t3 = [r for r in sites.values() if r['family'] == 'T3']
            self.assertEqual(len(t3), n)
            ids = {r['id36_29'] for r in t3}
            self.assertEqual(len(ids), distinct)
            self.assertTrue(ids <= {no for no, (kind, _, _) in d.tables.items() if kind == 4})

    def test_sibling_controls_are_not_filtered_to_matches(self):
        _, _, sites = self.sr
        self.assertEqual(Counter(r['driver_type'] for r in sites.values() if r['family'] == 'T2'),
                         {'eram': 26, 'wram': 4, 'not_in_core': 1})
        self.assertEqual({r['id36_29'] for r in sites.values()
                          if r['family'] == 'T4' and r['bits39_37'] == 4}, {13, 67})

    def test_zx_same_table_different_index_candidates(self):
        d, w, sites = self.zx
        self.assertEqual(d.tables[48], (4, 512, 0x20000000))
        self.assertEqual([sites[i]['id36_29'] for i in (3429, 4006, 4016)], [48]*3)
        self.assertEqual([a ^ b for a, b in zip(w[3999:4007], w[4009:4017])],
                         [0, 1 << 25, 0, 0, 0, 0, 0, 0])
        self.assertEqual([(w[i] >> 25) & 0xffff for i in (4000, 4010)], [0x181, 0x180])


if __name__ == '__main__':
    unittest.main()
