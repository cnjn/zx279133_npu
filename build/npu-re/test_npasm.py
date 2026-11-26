"""Toolchain checks: npdis -> npasm must reproduce both images byte-for-byte."""
import unittest
from pathlib import Path

from npasm import assemble
from npdis import code, disassemble, split
from npisa import FORMATS, code_targets, decode, parse

ROOT = Path(__file__).resolve().parents[2]
IMAGES = ('extracted/kernel1/rootfs/etc/mcode/mcode_133.bin', 'zte_zxslc_sr1010/mcode_intel.bin')


class ToolchainTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.blobs = [(ROOT / p).read_bytes() for p in IMAGES]

    def test_whole_image_round_trip(self):
        for blob in self.blobs:
            self.assertEqual(assemble(disassemble(blob)), blob)

    def test_every_decoded_word_round_trips_alone(self):
        for blob in self.blobs:
            _, main, _, high, _ = split(blob)
            for base, words in ((0, main), (0x2fad, high)):
                for i, w in enumerate(words):
                    f, d = decode(w, base + i)
                    if f is None:
                        continue
                    lab = lambda t: f'#{t}'
                    self.assertEqual(parse(f.text(d, lab), base + i, {}), w, f'{base + i}: {w:016x}')

    def test_formats_cover_all_bits(self):
        for f in FORMATS:
            self.assertEqual(f.fixed_mask & f.used, 0, f.name)

    def test_edit_changes_only_the_field(self):
        blob = self.blobs[1]
        src = disassemble(blob)
        line = next(l for l in src.splitlines() if l.split(';')[-1].split()[:1] == ['2898'])
        self.assertIn('b.eq r3[15:0], 0x86dd, L2920', line)
        out = assemble(src.replace(line, line.replace('0x86dd', '0x88b5')))
        old = int.from_bytes(blob[16 + 8 * 2898:16 + 8 * 2899], 'big')
        new = int.from_bytes(out[16 + 8 * 2898:16 + 8 * 2899], 'big')
        self.assertEqual(old ^ new, ((0x86dd ^ 0x88b5) >> 5 << 19) | ((0x86dd ^ 0x88b5) & 31) << 5)
        self.assertEqual(out[:16 + 8 * 2898], blob[:16 + 8 * 2898])
        self.assertEqual(out[16 + 8 * 2899:], blob[16 + 8 * 2899:])

    def test_edit_vlan_literal_only_changes_its_immediate_bits(self):
        from npasm import preprocess
        blob = self.blobs[0]
        src = disassemble(blob, symbolic=True)
        self.assertIn('movw r20, 0x81000ffe', src)
        out = assemble(preprocess(src.replace('movw r20, 0x81000ffe', 'movw r20, 0x81000fff', 1)))
        offset = 16 + 8 * 594
        expected = bytearray(blob)
        expected[offset + 6] ^= 1  # bit 8 is the literal LSB (board exp31)
        self.assertEqual(out, expected)

    def test_inserting_code_relocates_every_target(self):
        """Edit as assembly: insert a new instruction mid-program and rebuild."""
        blob = self.blobs[1]
        src = disassemble(blob).splitlines()
        k = 2896  # before the inner EtherType switch of the GRE path
        at = next(i for i, l in enumerate(src) if l.split(';')[-1].split()[:1] == [str(k)])
        src.insert(at, '    movi r3[15:0], 0x1234        ; inserted')
        out = assemble('\n'.join(src) + '\n', fit_gap=True)
        self.assertEqual(len(out), len(blob))
        _, old, _, oh, _ = split(blob)
        _, new, _, nh, _ = split(out)
        self.assertEqual(len(new), len(old) + 1)
        self.assertEqual(nh, oh)                                  # high region untouched
        self.assertEqual(decode(new[k], k)[1]['imm'], 0x1234)
        mv = lambda a: a + (a >= k)
        n = 0
        for pc, w in enumerate(old):
            f, d = decode(w, pc)
            g, e = decode(new[mv(pc)], mv(pc))
            self.assertIs(g, f, pc)
            if f is None:
                self.assertEqual(new[mv(pc)], w)                  # undecoded words copied verbatim
                continue
            self.assertEqual(code_targets(g, e), tuple(mv(a) for a in code_targets(f, d)), pc)
            n += bool(code_targets(f, d))
        self.assertGreater(n, 700)
        # Trailer entry tables (bdbdbdbd / cccccccc / bbbbbbbb) move with the code.
        from npdis import records, ENTRY_TAGS
        ot, nt = records(split(blob)[4]), records(split(out)[4])
        moved = 0
        for (t0, v0), (t1, v1) in zip(ot, nt):
            self.assertEqual(t0, t1)
            if t0 in ENTRY_TAGS and v0 and 0 < v0 & 0xffff < len(old):
                self.assertEqual(v1, (v0 & ~0xffff) | mv(v0 & 0xffff))
                moved += (v0 & 0xffff) >= k
            else:
                self.assertEqual(v1, v0)
        self.assertGreater(moved, 3)

    def test_op110_relocates_address_without_changing_condition(self):
        blob = self.blobs[0]
        src = disassemble(blob)
        self.assertIn('[r40.22] call L1013', src)
        out = assemble(src.replace('L1013:\n', '    nop ; insert before target\nL1013:\n', 1), fit_gap=True)
        old, new = split(blob)[1], split(out)[1]
        self.assertEqual(new[1150] ^ old[1149], (1014 ^ 1013) << 15)
        f, d = decode(new[1150], 1150)
        self.assertEqual(code_targets(f, d), (1014,))
        self.assertEqual(d['cond'], 0x296)
        self.assertEqual(new[834], old[834])  # the earlier dispatcher did not move

    def test_dispatch_guard_allows_moving_the_table_as_a_unit(self):
        from npisa import dispatch_bases
        for blob, bases in zip(self.blobs, ([835, 2723], [1307])):
            src = disassemble(blob).replace('.main\n', '.main\n    nop\n', 1)
            self.assertIn('.dispatch', src)
            new = split(assemble(src, fit_gap=True))[1]
            self.assertEqual(dispatch_bases(new), [base + 1 for base in bases])

    def test_dispatch_guard_rejects_spacing_and_stride_changes(self):
        src = disassemble(self.blobs[0])
        self.assertIn('L0835, L0841, L0857', src)
        for label in ('L0835:', 'L0841:', 'L0857:'):
            with self.subTest(label=label), self.assertRaisesRegex(SyntaxError, r'\.dispatch layout changed'):
                assemble(src.replace(label, f'    nop\n{label}', 1), fit_gap=True)
        lines = src.splitlines()
        i = lines.index('L0841:') + 1
        lines[i] = '    nop'  # same length, but no longer a branch slot
        with self.assertRaisesRegex(SyntaxError, r'\.dispatch layout changed'):
            assemble('\n'.join(lines))

    def test_auto_nop_restores_a_removed_nop(self):
        from npasm import auto_nop
        from npisa import hazards
        blob = self.blobs[0]
        src = disassemble(blob).splitlines()
        main = split(blob)[1]
        # pick the first nop that separates a dependent pair (written then read)
        k = next(i for i in range(1, len(main) - 1) if main[i] == 0 and hazards([main[i - 1], main[i + 1]]))
        at = next(i for i, l in enumerate(src) if l.split(';')[-1].split()[:1] == [str(k)])
        self.assertIn('nop', src[at])
        del src[at]
        broken = '\n'.join(src) + '\n'
        self.assertEqual(len(hazards(split(assemble(broken, fit_gap=True))[1])), 2)  # stock 1 + ours
        self.assertEqual(assemble(auto_nop(broken), fit_gap=True), blob)

    def test_stat_macro_and_equ_reproduce_stock(self):
        from npasm import preprocess
        blob = self.blobs[0]
        src = disassemble(blob).splitlines()
        first = next(i for i, l in enumerate(src) if l.split(';')[-1].split()[:1] == ['4879'])
        last = next(i for i, l in enumerate(src) if l.split(';')[-1].split()[:1] == ['4886'])
        src[first:last + 1] = ['    stat SA_FAIL                ; count "mac sa lookup fail"']
        src.insert(0, '.equ SA_FAIL, 0x18e')
        self.assertEqual(assemble(preprocess('\n'.join(src) + '\n')), blob)

    def test_symbolic_listing_round_trips(self):
        from npasm import preprocess
        for blob in self.blobs:
            text = disassemble(blob, symbolic=True)
            self.assertEqual(assemble(preprocess(text)), blob)
        text = disassemble(self.blobs[0], symbolic=True)
        self.assertIn('b.ne r32[13:8], in_port, L4879', text)
        self.assertIn('"mac sa lookup fail cnt"', text)

    def test_named_output_marks_the_observed_mux_indices(self):
        lines = disassemble(self.blobs[0], symbolic=True).splitlines()
        for pc, idx, kind in ((3405, 0, 'unicast'), (3403, 1, 'multicast'), (3401, 2, 'broadcast')):
            line = next(s for s in lines if ';' in s and s.split(';', 1)[1].split()[:1] == [str(pc)])
            self.assertEqual(line.split(';', 1)[0].strip(), f'movw r31[22:0], {idx:#x}')
            self.assertIn(f'stat #47 index {idx} (PON mux {kind})', line)
        self.assertTrue(any('lkup.stat s2, #47' in s and '[up-PON MAC mux counters]' in s for s in lines))
        self.assertTrue(any('mov r0[5:0], out_port' in s for s in lines))

    def test_edit_mux_index_changes_only_the_two_index_bits(self):
        blob = self.blobs[0]
        src = disassemble(blob)
        self.assertEqual(src.count('movw r31[22:0], 0x2'), 1)
        out = assemble(src.replace('movw r31[22:0], 0x2', 'movw r31[22:0], 0x1'))
        expected = bytearray(blob)
        expected[16 + 8 * 3401 + 6] ^= 3  # 2 XOR 1 at bits 9:8
        self.assertEqual(out, expected)

    def test_unknown_label_is_an_error(self):
        src = disassemble(self.blobs[1]).replace('br L2979', 'br Lnowhere', 1)
        with self.assertRaises(SyntaxError):
            assemble(src)

    def test_labels_only_for_targets(self):
        _, main, _, _, _ = split(self.blobs[1])
        lines = code(main, 0)
        labels = {l[:-1] for l in lines if l.endswith(':')}
        targets = {f'L{a:04d}' for i, w in enumerate(main)
                   for f, d in [decode(w, i)] if f for a in code_targets(f, d) if a < len(main)}
        self.assertEqual(labels, targets)


if __name__ == '__main__':
    unittest.main()
