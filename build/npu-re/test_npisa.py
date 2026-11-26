"""Evidence behind the newer npisa formats (st, xmov, addi/subi, add/sub, compare variants, csum, cp)."""
import unittest
from npisa import FLAG
from collections import Counter
from pathlib import Path

from npdis import split
from npisa import Bcmp, Bcmpr, Csum, Op110, Op510, St, code_targets, decode, dispatch_bases, parse, sx

ROOT = Path(__file__).resolve().parents[2]


def words(path):
    return split((ROOT / path).read_bytes())[1]


def text(w, pc):
    f, d = decode(w[pc], pc)
    return f.text(d, lambda t: f'#{t}') if f else None


class SemanticsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.zx = words('extracted/kernel1/rootfs/etc/mcode/mcode_133.bin')
        cls.sr = words('zte_zxslc_sr1010/mcode_intel.bin')

    def test_st_mirrors_the_load_of_the_same_register(self):
        for w, pairs, same in ((self.zx, 144, 124), (self.sr, 169, 143)):
            p = s = 0
            for i, y in enumerate(w):
                if y >> 48 != 0x0400:
                    continue
                st = St.fields(y, i)
                for j in range(i - 1, max(i - 40, 0) - 1, -1):
                    x = w[j]
                    if x >> 52 == 0x070 and (x >> 44) & 0xff == st['a']:
                        p += 1
                        s += ((x >> 27) & 7, sx((x >> 17) & 0x3ff, 10), (x & 31) + 1) == \
                             (st['base'], st['off'], st['n'])
                        break
            self.assertEqual((p, s), (pairs, same))
        self.assertEqual([text(self.sr, pc) for pc in (3256, 3259)],
                         ['movi r3[15:0], 0x800', 'st h5-2, r3[15:0]'])  # EtherType := IPv4

    def test_index_operand_slots_precede_stat_lookups(self):
        self.assertEqual([text(self.zx, pc) for pc in range(3426, 3430)],
                         ['xmovi idx[132..135], 0x0', 'xmovi idx[136..139], 0x0',
                          'xmov idx[128..131], r30', 'lkup.stat s2, #48'])

    def test_add_sub_immediate(self):
        for w in (self.zx, self.sr):
            ys = [y for y in w if y >> 52 in (0x020, 0x021)]
            self.assertTrue(all(((y >> 14) & 0xffff).bit_length() <= (y & 31) + 1 for y in ys))
            self.assertTrue(all((y >> 5) & 31 == y & 31 for y in ys))
            self.assertTrue(all((y >> 10) & 15 == 0 for y in ys))
        # IPv6 hop limit and IPv4 TTL decrement by one.
        self.assertEqual(text(self.zx, 966), 'ld r20[23:16], h5+7')
        self.assertEqual(text(self.zx, 968), 'subi r20[23:16], r20[23:16], 0x1')
        self.assertEqual(text(self.sr, 238), 'subi r3[31:24], r3[15:8], 0x1')
        # Table 48: category base added to the port number.
        self.assertEqual([text(self.zx, pc) for pc in (3417, 3419, 3421)],
                         ['addi r0[15:0], r0[15:0], 0x140', 'addi r0[15:0], r0[15:0], 0x100',
                          'addi r0[15:0], r0[15:0], 0xc0'])

    def test_add_sub_register_source_is_not_an_immediate(self):
        for w in (self.zx, self.sr):
            for op, fits_all in ((0x020, True), (0x021, True), (0x060, False), (0x061, False)):
                ys = [y for y in w if y >> 52 == op]
                fit = sum(((y >> 14) & 0xffff).bit_length() <= (y & 31) + 1 for y in ys)
                self.assertEqual(fit == len(ys), fits_all, hex(op))
            self.assertTrue(all((y >> 10) & 0x1ff == 0 for y in w if y >> 52 in (0x060, 0x061)))

    def test_fttr_masks_are_ored_into_the_same_descriptor_halfword(self):
        masks = {324: 0x3, 332: 0x4, 370: 0x4, 456: 0x8, 475: 0x20, 503: 0x10}
        sites = [i for i, y in enumerate(self.zx) if y >> 52 == 0x022]
        self.assertEqual(sites, list(masks))
        for pc, mask in masks.items():
            self.assertEqual([text(self.zx, i) for i in (pc - 2, pc, pc + 2)],
                             ['ld r20[15:0], h3+108', f'ori r20[15:0], r20[15:0], {mask:#x}',
                              'st h3+108, r20[15:0]'])
        self.assertEqual(text(self.zx, 463), 'lkup.hash s0, #56')
        self.assertEqual(text(self.zx, 464), '[r32.31] br #501')  # 0x10 miss vs 0x20 hit

    def test_register_logic_clears_then_merges_nat66_prefix(self):
        for pc, off in ((251, 24), (266, 8), (769, 24), (784, 8)):
            self.assertEqual(text(self.sr, pc), f'ld {{r30, r31}}, h5+{off}')
            self.assertEqual([text(self.sr, pc + j) for j in (4, 5, 7, 8)],
                             ['andn r4, r30, r50', 'andn r24, r31, r51', 'or r4, r4, r48', 'or r24, r24, r49'])
            self.assertEqual([text(self.sr, pc + j) for j in (10, 11)],
                             [f'st h5+{off}, r4', f'st h5+{off + 4}, r24'])
        self.assertEqual(text([self.sr[255] ^ (2 << 10)], 0), 'nor r4, r30, r50')  # mode 3 = nor (board exp90)
        with self.assertRaises(ValueError):
            parse('or r4, r4, r48[15:0]', 0, {})

    def test_immediate_shift_contexts(self):
        self.assertEqual(text(self.zx, 1378), 'mov.x r29[3:0], r21[11:8]')
        self.assertEqual(text(self.zx, 1380), 'shli r29[7:0], r29[7:0], 0x2')  # IPv4 IHL in bytes
        self.assertEqual(text(self.zx, 1382), 'add r22[31:16], r22[15:0], r29[15:0]')
        self.assertEqual(text(self.sr, 3206), 'shri r1[23:16], r8[7:0], 0x3')
        self.assertEqual(text(self.sr, 3209), 'cp.x h1+0, h5+0, 8 {r=0x40000000}')
        self.assertEqual(text(self.sr, 4312), 'shli r3, r24, 0x4')
        with self.assertRaises(ValueError):
            parse('shli r33[7:0], r0[7:0], 0x2', 0, {})

    def test_xld_fills_high_bytes_of_direct_index(self):
        sites = [i for i, y in enumerate(self.sr) if y >> 52 == 0x074]
        self.assertEqual(len(sites), 2)
        for i in sites:
            self.assertEqual([text(self.sr, j) for j in range(i - 1, i + 2)],
                             ['xmovi idx[0..1], 0x0', 'xld idx[2..3], h3+24', 'lkup.idx s0, #3'])

    def test_op110_references_dispatch_table_base(self):
        for w, pc in ((self.zx, 834), (self.zx, 2722), (self.sr, 1306)):
            f, d = decode(w[pc], pc)
            self.assertIs(f, Op110)
            self.assertEqual(code_targets(f, d), (pc + 1,))
            self.assertEqual(d['val'] & 1, 0)
            self.assertIn('addi r1[15:0], r1[15:0], 0x6', [text(w, j) for j in range(pc + 1, pc + 6)])
            self.assertEqual(w[pc + 6], 0x0510000800000520)
            self.assertTrue(all(text(w, j).startswith('br ') for j in range(pc + 7, pc + 23)))
        self.assertEqual(dispatch_bases(self.zx), [835, 2723])
        self.assertEqual(dispatch_bases(self.sr), [1307])
        self.assertEqual(sum(decode(y, i)[0] is Op510 for i, y in enumerate(self.zx)), 8)
        self.assertIsNone(decode(Op510.fixed_val ^ 1, 0)[0])  # non-observed word stays opaque

    def test_op110_condition_is_the_full_ten_bit_field(self):
        self.assertEqual(text(self.zx, 1149), '[r40.22] call #1013')
        self.assertEqual(text(self.zx, 1143), 'crc32 s2')
        self.assertEqual(text(self.sr, 160), '[r36.13] call #2334')
        self.assertEqual(text(self.sr, 150), 'lkup.hash s1, #14')
        self.assertEqual(text(self.sr, 4884), '[r44.26] call #5038')
        self.assertEqual(text(self.sr, 4881), 'lkup.hash s3, #110')
        self.assertEqual(parse('op110 0x12c0, 2027', 1149, {}), self.zx[1149])  # raw syntax
        self.assertEqual(parse('op110 0x12c0, #1013, 1', 1149, {}), self.zx[1149])  # split-label syntax
        self.assertEqual(parse('[s2.22] call #1013', 1149, {}), self.zx[1149])  # earlier condition syntax
        self.assertEqual(code_targets(*decode(parse('op110 0x521, 2027', 0, {}), 0)), ())

    def test_compare_variants(self):
        for w in (self.zx, self.sr):
            for i, y in enumerate(w):
                for f in (Bcmp, Bcmpr):
                    d = f.match(y, i)
                    if d:
                        self.assertLess(d['target'], len(w))
            modes = Counter((y >> 10) & 7 for y in w if y >> 48 == 0x0298)
            self.assertEqual(set(modes), {4, 5, 6, 7} & set(modes))
            self.assertFalse({0, 1} & set(modes))
        # TTL <= 1 goes to the exception path before the decrement.
        self.assertEqual([text(self.sr, pc) for pc in (235, 237, 238)],
                         ['ld.x r3[15:8], h5+8', 'b.le r3[15:8], 0x1, #1579',
                          'subi r3[31:24], r3[15:8], 0x1'])

    def test_checksum_update(self):
        for w, n in ((self.zx, 34), (self.sr, 67)):
            ds = [Csum.match(y, i) for i, y in enumerate(w)]
            ds = [d for d in ds if d]
            self.assertEqual(len(ds), n)
            self.assertTrue(all(d['dst'] == d['src'] and d['old'] % 16 == 0 and
                                d['new'] % 32 != d['old'] % 32 for d in ds))
        self.assertEqual([text(self.sr, pc) for pc in (240, 241, 242)],
                         ['csum r25[15:0], r25[15:0], r3[15:0], r3[31:16]',
                          'st h5+8, r3[31:24]', 'st h5+10, r25[15:0]'])  # IPv4 checksum field

    def test_movi32_builds_vlan_tags_and_default_mac_key_fields(self):
        expected = {17: 0x81000000, 590: 0x07020100, 594: 0x81000ffe, 4584: 0}  # board exp32: 594 = VID 4094
        for pc, imm in expected.items():
            self.assertEqual(text(self.zx, pc), f'movw r20, {imm:#x}')
            self.assertEqual(parse(f'movi32 r20, {imm:#x}', pc, {}), self.zx[pc])  # earlier name
        self.assertEqual(text(self.zx, 18), 'b.eq r15[31:24], 0x0, #20')
        self.assertEqual(text(self.zx, 19), 'ld r20, h1+12')
        self.assertEqual(text(self.zx, 21), 'mov r30[27:16], r20[11:0]')
        self.assertEqual(text(self.zx, 593), '[r9.0] br #596')
        self.assertEqual(text(self.zx, 596), 'mov r17[27:16], r20[11:0]')
        self.assertEqual(text(self.zx, 597), 'st h1+12, r20')
        self.assertEqual(text(self.zx, 4587), 'kmov key[6..7], r20[15:0]')
        self.assertEqual(text(self.zx, 4588), 'lkup.hash s0, #50')

    def test_movi32_in_sibling_image_and_restricted_layout(self):
        from npisa import _writes, hazards
        examples = {pc: 'r4, 0x1' for pc in (87, 327, 672, 913, 1663, 1838, 1969, 1989, 3613, 3855)}
        examples.update({1678: 'r5, 0x0', 1689: 'r5, 0x0', 1700: 'r5, 0x0', 1854: 'r5, 0x0',
                         2866: 'r3, 0x4', 2875: 'r30, 0xffffffff', 2912: 'r25, 0x14', 2926: 'r25, 0x28',
                         3293: 'r30, 0xffffffff', 4301: 'r24, 0x0', 4832: 'r31, 0xf4240'})  # 4832 = 1,000,000
        actual = {i: f.text(d, str) for i, y in enumerate(self.sr)
                  for f, d in [decode(y, i)] if f and f.name == 'movw'}
        self.assertEqual(actual, {pc: 'movw ' + args for pc, args in examples.items()})
        self.assertEqual(text(self.sr, 2969), 'add r6[7:0], r6[23:16], r25[7:0]')
        self.assertEqual(text(self.sr, 4835), 'b.le r5, r31, #4839')
        self.assertEqual(text(self.sr, 4837), 'sub r5, r5, r31')
        self.assertEqual(_writes(*decode(self.sr[4832], 4832)), set(range(31 * 32, 32 * 32)))
        self.assertEqual(hazards([self.sr[4832], self.sr[4835]]), [1])
        # board exp79: any destination / width (r28[11:4] <- 0xef etc.)
        for s in ('movw r28[11:4], 0xef', 'movw r28[31:20], 0xeef', 'movw r28[22:0], 0x2dbeef'):
            self.assertEqual(text([parse(s, 0, {})], 0), s)
        for invalid in ('movi32 r20[15:0], 0x81000000', 'movi32 r32, 0', 'movi32 r20, 0x100000000',
                        '[r8.1] movi32 r20, 1', 'movi32.x r20, 1', 'movw r32, 0'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                parse(invalid, 0, {})

    def test_068a_mac_pair_sets_the_two_flags_consumed_together(self):
        from npisa import _reads, _writes
        from sdt_dump import load_driver
        d = load_driver((ROOT / 'zte_zxslc_sr1010/kmodule/np.ko').read_bytes())
        self.assertEqual((d.names[9], d.names[43], d.names[14]),
                         ('SDT_NO_MAC', 'SDT_NO_FAST_256b', 'SDT_NO_FAST_512b'))
        w = self.sr
        for pc, off, fallback, lookup in ((2878, 0, 2979, 2949), (3296, 16, 3444, 3398)):
            self.assertEqual(text(w, pc - 4), f'ld {{r4[15:0], r5}}, h1+{off}')
            self.assertEqual(text(w, pc - 2), f'b.eq r4[15:8], 0x1, #{fallback}')
            self.assertEqual(text(w, pc - 1), f'b.eq r4[15:0], 0x3333, #{fallback}')
            self.assertEqual(text(w, pc), 'cset.eq r8[0], r4[15:0], r30[15:0]')
            self.assertEqual(text(w, pc + 1), 'cset.eq r8[1], r5, r30')
            self.assertEqual(text(w, pc + 2), 'nop')
            # the consumer reads exactly the two written register bits (flags are registers, exp70)
            self.assertEqual(text(w, pc + 3), f'b.eq r8[1:0], 0x3, #{fallback}')
            self.assertEqual(text(w, lookup), 'lkup.hash s1, #43')
            self.assertEqual(_reads(*decode(w[pc], pc)), set(range(128, 144)) | set(range(960, 976)))
            self.assertEqual(_writes(*decode(w[pc], pc)), {8 * 32})
            self.assertEqual(_writes(*decode(w[pc+1], pc+1)), {8 * 32 + 1})
            self.assertEqual(text(w, pc - 3), 'movw r30, 0xffffffff')  # broadcast MAC (board exp32 layout)

    def test_068a_is_the_register_form_of_cset(self):
        from npisa import CsetR
        w = self.sr
        self.assertEqual(text(w, 2234), 'cset.tst r8[0], r3[27], r3[28]')
        self.assertEqual(text(w, 2236), '[r8.0] movi.x r4[4:0], 0xe')
        self.assertEqual(text(w, 3287), 'cset.lor r10[21], r4[25], r5[0]')
        self.assertEqual(text(w, 3289), 'b.eq r10[21], 0x1, #3444')
        self.assertEqual([i for i, y in enumerate(w) if y >> 49 == 0x068a >> 1 and decode(y, i)[0] is not CsetR], [])
        self.assertEqual(parse('cset.eq r8[0], r4[15:0], r31[15:0]', 0, {}) ^ w[2878], 32 << 19)
        # board exp79: relation codes 0-9 (both forms), 10-15 give 0
        self.assertEqual(text([parse('cset.lorn r12[7], r20[15:0], r21[15:0]', 0, {})], 0),
                         'cset.lorn r12[7], r20[15:0], r21[15:0]')
        for invalid in ('cset.eq r7[0], r4[15:0], r30[15:0]', 'cset.eq r8[1:0], r5, r30',
                        '[r8.0] cset.eq r8[1], r5, r30', 'cset.ge r8[1], r5, r30'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                parse(invalid, 0, {})

    def test_policer_colour_bit_is_inverted_around_each_sr1010_policer(self):
        from npisa import LogicReg, _reads, _writes
        from sdt_dump import load_driver
        w = self.sr
        d = load_driver((ROOT / 'zte_zxslc_sr1010/kmodule/np.ko').read_bytes())
        zx = load_driver((ROOT / 'extracted/kernel1/rootfs/kmodule/np_133.ko').read_bytes())
        self.assertEqual(d.names[26], 'SDT_NO_RTLMT')
        self.assertEqual(d.tables[26], (4, 1, 0x60000000))
        self.assertEqual(zx.tables[252], d.tables[26])
        sites = [i for i, y in enumerate(w) if y == 0x0018000340000003]
        self.assertEqual(len(sites), 21)
        nots = {i for i, y in enumerate(w) if decode(y, i)[0] is LogicReg and text(w, i).startswith('not ')}
        self.assertEqual(nots, {i + off for i in sites for off in (-3, 2)})
        for i in sites:
            # board exp91: the word inverts (r10[0] = 0 -> r5[14] = 1); earlier read as a copy
            self.assertEqual(text(w, i - 3), 'not r5[14], r10[0]')
            self.assertEqual(text(w, i - 1), 'xmov idx[132..139], m[0x0a0:+64]')
            self.assertEqual(text(w, i + 1), 'b.eq r32[16:15], 0x2, #4118')
            self.assertEqual(text(w, i + 2), 'not r10[0], r32[15]')
        self.assertEqual(parse('movbit r5[14], r10[0]', 0, {}), w[2285])  # earlier name
        self.assertEqual(_reads(*decode(w[2285], 2285)), {10 * 32})
        self.assertEqual(_writes(*decode(w[2285], 2285)), {5 * 32 + 14})

    def test_logic_ops_cover_the_measured_truth_tables(self):
        # board exp90/92: bit 51 set -> mode bits 12:10 = and andn andc nor nand orc orn or;
        # bit 51 clear -> xor (mode 0) / xnor (mode 1)
        from npisa import LOGIC_OPS
        for op in LOGIC_OPS + ('xor', 'xnor'):
            for s in (f'{op} r28, r20, r21', f'{op}i r28[15:0], r20[15:0], 0x5a3c'):
                self.assertEqual(text([parse(s, 0, {})], 0), s)
        y = self.sr[2285]
        self.assertEqual(text([y ^ (3 << 10)], 0), 'and r5[14], r10[0], r10[0]')  # mode 3 -> 0
        for invalid in ('not r32[0], r10[0]', 'and r5[15:14], r10[1:0], r10[0]', 'movbit r5[15:14], r10[1:0]'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                parse(invalid, 0, {})

    def test_mux_index_is_a_wide_immediate(self):
        from npisa import _writes, bits
        from sdt_dump import load_driver
        tables = load_driver((ROOT / 'extracted/kernel1/rootfs/kmodule/np_133.ko').read_bytes()).tables
        self.assertEqual(tables[47], (4, 3, 0x20000000))
        self.assertEqual(tables[48], (4, 512, 0x20000000))
        w = self.zx
        self.assertEqual(text(w, 3399), 'b.eq r14[25:24], 0x0, #3405')
        self.assertEqual(text(w, 3400), 'b.eq r14[25:24], 0x1, #3403')
        self.assertEqual(text(w, 3402), 'br #3406')
        self.assertEqual(text(w, 3404), 'br #3406')
        self.assertEqual(text(w, 3406), 'movi r31[27:23], 0x16')
        self.assertEqual(text(w, 3410), 'xmov idx[128..131], r31')
        self.assertEqual(text(w, 3411), 'lkup.stat s2, #47')
        for i, pc in enumerate((3405, 3403, 3401)):
            self.assertEqual(bits(w[pc], 50, 41), 31 * 32)
            self.assertEqual(text(w, pc), f'movw r31[22:0], {i:#x}')  # board exp73: r31[31:23] kept
            self.assertEqual(parse(f'muxidx {i}', pc, {}), w[pc])     # earlier name
            self.assertEqual(_writes(*decode(w[pc], pc)), set(range(31 * 32, 31 * 32 + 23)))
        for invalid in ('muxidx', 'muxidx 1, 2', 'muxidx.x 2', '[r8.1] muxidx 1', 'muxidx 1 {r=0x20}'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                parse(invalid, 0, {})

    def test_028b_sets_the_udp_zero_checksum_writeback_guard(self):
        from npisa import _reads, _writes
        w = self.zx
        for read, cmp_, tcp, skip, join in ((775, 777, 874, 828, 833), (886, 888, 978, 974, 977)):
            self.assertEqual(text(w, read), 'ld r23[31:16], h5+6')
            self.assertEqual(text(w, cmp_), 'cset.eq r12[30], r23[31:16], 0x0')  # 028b: K = 4 -> r12
            self.assertEqual(_reads(*decode(w[cmp_], cmp_)), set(range(23 * 32 + 16, 24 * 32)))
            self.assertEqual(_writes(*decode(w[cmp_], cmp_)), {12 * 32 + 30})
            self.assertEqual(text(w, tcp), 'ld r23[31:16], h5+16')
            self.assertEqual(text(w, tcp + 1), f'br #{cmp_ + 1}')  # TCP skips just the compare
            self.assertEqual(text(w, skip), f'[r12.30] br #{join}')
            self.assertIn('st h5+6, r23[31:16]', [text(w, pc) for pc in range(skip + 1, join)])
        # board exp74: bit 10 selects 'ne', bit 46 moves the result to r13
        self.assertEqual(text([w[777] ^ (1 << 10)], 0), 'cset.ne r12[30], r23[31:16], 0x0')
        self.assertEqual(text([w[777] ^ (1 << 46)], 0), 'cset.eq r13[30], r23[31:16], 0x0')
        s = 'cset.eq r12[29], r23[15:0], 0x1234'
        self.assertEqual(text([parse(s, 0, {})], 0), s)
        self.assertEqual(text([parse('cset.eq r12[30], r23[31:16], 0x0 {r=0x20}', 0, {})], 0),
                         'cset.eq r12[30], r23[31:16], 0x0 {r=0x20}')  # unused bits 9:5 stay raw

    def test_028b_following_predicates_select_transport_port_rewrites(self):
        w = self.zx
        for pc, sa, da in ((778, 2333, 2338), (889, 2356, 2361)):
            self.assertEqual([text(w, pc), text(w, pc + 1)], [f'[r32.17] br #{sa}', f'[r32.16] br #{da}'])
            self.assertEqual(text(w, sa + 2), 'st h5+0, r34[31:16]')
            self.assertEqual(text(w, da + 2), 'st h5+2, r34[15:0]')
            self.assertEqual(text(w, sa + 3), 'csum r23[31:16], r23[31:16], r29[15:0], r29[31:16]')

    def test_packet_copy_moves_l2_header(self):
        c = Counter(text(self.zx, i) for i, y in enumerate(self.zx) if y >> 48 == 0x0408)
        self.assertEqual(c['cp h5+6, h1+6, 6'], 21)
        self.assertEqual(c['cp h5+0, h1+0, 6'], 21)

    def test_store_immediate_protocol_constants(self):
        c = Counter(text(self.sr, i) for i, y in enumerate(self.sr) if y >> 52 == 0x030)
        self.assertEqual(c['sti h1+12, 0x8100, 2'], 2)          # VLAN TPID
        self.assertEqual(c['sti h1+0, 0x88641100, 4'], 1)       # PPPoE EtherType + ver/type/code
        z = Counter(text(self.zx, i) for i, y in enumerate(self.zx) if y >> 52 == 0x030)
        self.assertEqual((z['sti h5-2, 0x86dd, 2'], z['sti h5-2, 0x800, 2']), (3, 3))  # EtherType

    def test_condition_selectors_9_to_11_read_the_slot_result_word(self):
        # board exp77/78: selectors 9/10/11 read r36/r40/r44 (slot 1/2/3 word 0); slot 0 is
        # selector 7 (r32). ZX133: 113 of 115 such conditions follow a matching lookup.
        w = self.zx
        D = [decode(y, i) for i, y in enumerate(w)]
        n = hit = 0
        for i, (f, d) in enumerate(D):
            if f and 8 <= d.get('cond', 0x029) >> 6 <= 11:
                n += 1
                slots = {(w[j] >> 23) & 3 for j in range(max(i - 30, 0), i) if w[j] >> 48 == 0x0018}
                hit += (d['cond'] >> 6) - 8 in slots
        self.assertEqual((n, hit), (115, 113))
        # Fast-table cascade: lkup s1 then [r36.31] br (miss).
        self.assertEqual(text(self.sr, 142), 'lkup.hash s1, #43')
        self.assertEqual(text(self.sr, 143), '[r36.31] br #150')
        self.assertEqual(parse('[s1.31] br #150', 143, {}), self.sr[143])  # earlier syntax
        self.assertEqual(parse('[!r44.15] br #0', 0, {}) >> 5 & 0x3ff, 0x2ef)  # old [s3.47]

    def test_slot_results_are_read_from_their_own_words(self):
        # After lkup sS, the most-read word lies in 32+4S .. 35+4S.
        # SR1010 slot 2 is weak (words 20/32/18 dominate, 40 is 4th), so only slots 0-1 there.
        for w, slots in ((self.zx, (0, 1, 2)), (self.sr, (0, 1))):
            D = [decode(y, i) for i, y in enumerate(w)]
            for slot in slots:
                c = Counter()
                for i, (f, d) in enumerate(D):
                    if f and f.name == 'lkup' and d['slot'] == slot:
                        for k in range(1, 11):
                            g, e = D[i + k] if i + k < len(D) else (None, None)
                            if g and g.name in ('lkup', 'cmd', 'crc32', 'end'):  # next lookup or thread end
                                break
                            if g and 'src' in e:
                                c[e['src'] >> 5] += 1
                hot = [wd for wd, _ in c.most_common(3)]
                self.assertTrue(any(32 + 4 * slot <= wd < 36 + 4 * slot for wd in hot), (slot, hot))

    def test_register_bit_conditions_are_packet_type_flags(self):
        sr, zx = self.sr, self.zx
        # SR1010: r10.3 IPv6, r10.4 IPv4 (fast-table key from Next Header vs Protocol).
        self.assertEqual(text(sr, 133), '[r10.4] kld key[0..0], h5+9')
        self.assertEqual(text(sr, 135), '[r10.3] kld key[0..0], h5+6')
        # r10.5 UDP / r10.6 TCP: checksum offset 6 / 16, header length 8 / 20.
        self.assertEqual([text(sr, pc) for pc in (185, 186)],
                         ['[r10.5] movi.x r7[9:0], 0x6', '[r10.6] movi.x r7[9:0], 0x10'])
        self.assertEqual([text(sr, pc) for pc in (401, 402)],
                         ['[r10.6] movi.x r3[7:0], 0x14', '[r10.5] movi.x r3[7:0], 0x8'])
        # After rewriting EtherType to IPv4 the flags are updated by plain register writes.
        self.assertEqual([text(sr, pc) for pc in range(3256, 3260)],
                         ['movi r3[15:0], 0x800', 'movi r10[4], 0x1', 'movi r10[3], 0x0',
                          'st h5-2, r3[15:0]'])
        # ZX133 keeps the same pair in r8.26 (IPv6) / r8.27 (IPv4): IP version nibble 6 / 4.
        z = Counter(text(zx, i) for i in range(len(zx)))
        self.assertGreaterEqual(z['[r8.26] movi r30[31:28], 0x6'], 2)
        self.assertGreaterEqual(z['[r8.27] movi r30[31:28], 0x4'], 2)

    def test_clr_only_uses_its_fields(self):
        from npisa import Clr
        for w, n in ((self.zx, 185), (self.sr, 125)):
            ys = [y for y in w if y >> 52 == 0x001 and (y >> 48) & 15 != 8]
            self.assertEqual(len(ys), n)
            self.assertTrue(all(Clr.match(y, 0) and not Clr.match(y, 0)['rest'] for y in ys))
        # board exp77: `op01.7 s2, 32` (earlier name) clears r30 before the counter index is built
        self.assertEqual(parse('op01.7 s2, 32', 0, {}), parse('clr r30', 0, {}))
        self.assertEqual([text(self.zx, pc) for pc in (4879, 4880)], ['clr r30', 'movi r30[15:0], 0x18e'])
        # SR1010: clear r3, then a slot-3 result condition.
        self.assertEqual([text(self.sr, pc) for pc in (72, 73)],
                         ['clr r3', '[r44.16] mov r3[11:0], r19[27:16]'])

    def test_kmovi_fills_key_prefix(self):
        self.assertEqual([text(self.sr, pc) for pc in (2031, 2032)],
                         ['kmovi key[0..1], 0x0', 'kld key[2..7], h1+0'])  # MINIOLT key = 8 bytes

    def test_cset_flag_is_tested_afterwards(self):
        from npisa import Cset, CsetR, cond_reads
        for w, n, used in ((self.zx, 6, 4), (self.sr, 65, 24)):
            D = [decode(y, i) for i, y in enumerate(w)]
            k = u = 0
            for i, (f, d) in enumerate(D):
                if f in (Cset, CsetR):
                    k += 1
                    bit = (8 + d['k']) * 32 + d['idx']
                    u += any(D[j][0] and cond_reads(D[j][1].get('cond', 0x029)) == bit
                             for j in range(i + 1, min(i + 11, len(w))))
            self.assertEqual((k, u), (n, used))
        self.assertEqual([text(self.sr, pc) for pc in (1508, 1509, 1510, 1511)],
                         ['cset.eq r8[0], r37[31:29], 0x7', 'cset.eq r8[2], r37[31:29], 0x5',
                          '[r8.0] br #1513', '[r8.2] br #1526'])

    def test_wide_header_loads_and_stores_use_preceding_words(self):
        from npisa import _reads, _writes, hazards, loaded_ranges
        self.assertEqual(list(loaded_ranges(4 * 27 + 2, 3)), [(27 * 32 + 16, 16), (26 * 32, 8)])
        bits_used = set(range(26 * 32, 28 * 32))
        f, d = decode(self.zx[5000], 5000)
        self.assertEqual(text(self.zx, 5000), 'ld {r26, r27}, h3+44')
        self.assertEqual(_writes(f, d), bits_used)
        f, d = decode(parse('st h3+44, {r26, r27}', 0, {}), 0)
        self.assertEqual(_reads(f, d), bits_used)
        # A use of the upper word is a true RAW; a read of r28 is unrelated.
        lut = lambda s: parse(s, 0, {})
        self.assertEqual(hazards([self.zx[5000], lut('mov r0, r26')]), [1])
        self.assertEqual(hazards([self.zx[5000], lut('mov r0, r28')]), [])

    def test_results_need_one_slot_before_use(self):
        from npisa import hazards
        self.assertEqual(hazards(self.zx), [2718])
        self.assertEqual(hazards(self.sr), [482, 1035, 1229, 1740])  # 2082 was a register/flag mix-up (exp44)

    def test_0522_has_one_word_and_six_identical_descriptor_templates(self):
        from npisa import _reads, _writes
        word = 0x05223ea5dbe80520
        pcs = [i for i, y in enumerate(self.zx) if y >> 52 == 0x052]
        self.assertEqual(pcs, [3314, 3508, 3580, 4452, 5002, 5100])
        self.assertFalse(any(y >> 52 == 0x052 for y in self.sr))
        for pc in pcs:
            self.assertEqual(self.zx[pc], word)
            self.assertEqual(text(self.zx, pc), 'bmov r8.8=r20.29, r8.31=r20.31')  # board exp74
            self.assertEqual(text(self.zx, pc - 6), 'ld r20, h3+8')
            self.assertEqual(text(self.zx, pc - 2), 'ld {r26, r27}, h3+44')
            self.assertEqual(text(self.zx, pc + 1), 'mov r14[6:0], r20[27:21]')
        f, d = decode(word, 0)
        self.assertEqual(_writes(f, d), {8 * 32 + 8, 8 * 32 + 31})
        self.assertEqual(_reads(f, d), {20 * 32 + 29, 20 * 32 + 31})
        self.assertEqual(parse('op052 r8[31], r20[31]', 0, {}), word)  # earlier name
        # the 0522 form carries a condition in bits 14:5 (flip bit 10: never)
        self.assertEqual(text([word ^ (1 << 10)], 0), '[0.9] bmov r8.8=r20.29, r8.31=r20.31')

    def test_disposition_commands(self):
        from npisa import parse
        cases = {0x0018000000000000: 'send', 0x0018000000000020: 'drop',
                 0x0018000000000040: 'drop.err 0', 0x00180000000001e0: 'drop.err 13',
                 0x0018000000000201: 'dup 1', 0x0018000000000007: 'dup.req', 0x0018000000000801: 'dup 4', 0x0088000000000000: 'end'}
        for w, t in cases.items():
            f, d = decode(w, 0)
            self.assertEqual(f.text(d, str), t)
            self.assertEqual(parse(t, 0, {}), w)
        for w, t in ((0x0018000000000009, 'crc32 s0'), (0x0018000001000009, 'crc32 s2')):
            f, d = decode(w, 0)
            self.assertEqual(f.text(d, str), t)
            self.assertEqual(parse(t, 0, {}), w)
        # unconfirmed command codes and real table lookups stay lkup
        for w in (0x0018000000400009, 0x0018000000000003, 0x0018000000800000):
            self.assertEqual(decode(w, 0)[0].name, 'lkup')
        # the dup entries the ZX133 driver configures start right after the dup commands
        self.assertEqual([i for i, y in enumerate(self.zx) if y in (0x0018000000000201, 0x0018000000000401)],
                         [3190, 3264])

    def test_bmov_copies_descriptor_bits_into_r8(self):
        from npisa import Bmov3
        w = self.zx
        D = [decode(y, i) for i, y in enumerate(w)]
        texts = Counter(f.text(d, str) for f, d in D if f is Bmov3)
        # board exp73/74: three independent bit moves each (entry templates, 6 copies)
        self.assertEqual(texts, Counter({t: 6 for t in (
            'bmov r8.9=r25.24, r8.27=r25.23, r8.26=r25.22',    # PC 5009: IPv4 / IPv6 from h3+40
            'bmov r8.24=r25.16, r8.23=r25.15, r8.28=r25.0',    # PC 5015: TCP / UDP from h3+40
            'bmov r8.10=r27.29, r8.22=r27.19, r8.21=r27.18',
            'bmov r8.13=r29.7, r8.12=r29.6, r8.15=r29.0')}))
        self.assertEqual(parse('bmov r8.9=!r25.24, r8.27=0@23, r8.26=1@22', 0, {}) ^ w[5009],
                         (1 << 5) | (1 << 34) | (1 << 27) | (1 << 26))


    def test_cop_ops_11_12_15_match_board_results(self):
        # exp98b/c: ops 11/12/15 are table-independent coprocessor functions of key[].
        import json

        def crc(data, n, poly):
            c, top, mask = 0, 1 << (n - 1), (1 << n) - 1
            for b in data:
                c ^= b << (n - 8)
                for _ in range(8):
                    c = ((c << 1) ^ poly) & mask if c & top else (c << 1) & mask
            return c

        def cksum(data):
            s = sum(data[i] << 8 | data[i + 1] for i in range(0, len(data), 2))
            while s >> 16:
                s = (s & 0xffff) + (s >> 16)
            return ~s & 0xffff

        def kb(v):
            return b''.join(x.to_bytes(4, 'big') for x in v)

        def predict(op, v):
            k = kb(v)
            if op == 15:
                return [cksum(k[4:4 + k[0]]) << 16, 0]
            c = crc(k[3:3 + k[2]], 16, 0x8005) if op in (8, 11) else crc(k[3:3 + k[2]], 32, 0x04C11DB7)
            d = k[0] << 8 | k[1]
            return [c, 0] if op in (8, 9) else [c // d, c % d]
        for name, op in (('crc16div', 11), ('crc32div', 12), ('cksum', 15)):
            self.assertEqual(parse(f'lkup.{name} s1, #0', 0, {}) & 31, op)
            self.assertEqual(text([parse(f'lkup s1, {op:#x}, #0', 0, {})], 0), f'lkup.{name} s1, #0')
        run = json.loads((ROOT / 'build/npu-exp/oracle/runs/exp98c.json').read_text())
        n = 0
        for r in run['rows']:
            k = kb([r['w0']] + run['data'][1:])
            L = k[0] if r['op'] == 15 else k[2]
            ok = (L % 2 == 0 and 2 <= L <= 40) if r['op'] == 15 else 1 <= L <= 45
            if r['op'] in (11, 12) and k[0] << 8 | k[1] == 0:
                ok = False
            self.assertEqual(r['got'], predict(r['op'], [r['w0']] + run['data'][1:]) if ok else None, r)
            n += r['got'] is not None
        self.assertEqual(n, 150)


if __name__ == '__main__':
    unittest.main()
