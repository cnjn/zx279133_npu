"""Test candidate word-address fields in the ZX133/SR1010 microcode (offline).

0108 A/B and 0290 C are observed numeric fields, not a decoded branch ISA.
Keep one-past-end, out-of-region and non-matching examples. The layout view
selects by four opcode prefixes *before* inspecting any address or arm word.
"""
import argparse
import csv
import sys
from pathlib import Path
from typing import NamedTuple

from mcode_preps import regions


AB_MASK = (0xffff << 31) | (0xffff << 15)
C_MASK = (0x7f << 41) | (0x3f << 13)


class Fields(NamedTuple):
    a: int | None
    target: int         # B for 0108, C for 0290; not an observed next PC
    remainder: int      # original word with just the candidate address fields cleared


def fields(word):
    if word >> 48 == 0x0108:
        return Fields((word >> 31) & 0xffff, (word >> 15) & 0xffff, word & ~AB_MASK)
    if word >> 48 == 0x0290:
        c = (((word >> 41) & 0x7f) << 6) | ((word >> 13) & 0x3f)
        return Fields(None, c, word & ~C_MASK)
    return None


def location(segments, addr):
    if addr is None:
        return ''
    for region, base, words in segments:
        if base <= addr < base + len(words):
            return region
    for region, base, words in segments:
        if addr == base + len(words):
            return f'one_past_{region}'
    return 'outside_regions'


def field_rows(segments):
    yield 'region pc word prefix a a_region a_minus_pc b_or_c target_region target_minus_pc remainder'.split()
    for region, base, words in segments:
        for i, w in enumerate(words):
            f = fields(w)
            if f is None:
                continue
            pc = base + i
            yield (region, pc, f'{w:016x}', f'{w >> 48:04x}', '' if f.a is None else f.a,
                   location(segments, f.a), '' if f.a is None else f.a-pc,
                   f.target, location(segments, f.target), f.target-pc, f'{f.remainder:016x}')


def layout_rows(segments):
    yield ('region start arms_pc:word c0 c1 a3 b3 a5 b5 expected_join join_word '
           'matches_local_layout next_0018_pc next_0018_word').split()
    for region, base, words in segments:
        for i in range(len(words) - 6):
            if tuple(words[i+j] >> 48 for j in (0, 1, 3, 5)) != (0x0290, 0x0290, 0x0108, 0x0108):
                continue
            p = base + i
            c0, c1, f3, f5 = (fields(words[i+j]) for j in (0, 1, 3, 5))
            got = (c0.target, c1.target, f3.a, f3.target, f5.a, f5.target)
            # Two different entries (arms 2 and 1), two sequential PCs and one common join.
            match = got == (p+6, p+4, p+4, p+7, p+6, p+7) and i+7 < len(words)
            arms = ','.join(f'{p+j}:{words[i+j]:016x}' for j in (2, 4, 6))
            # Static context, not a claim that the putative join or the 0018 word executes.
            end = next((k for k in range(i+7, len(words)) if words[k] >> 48 == 0x0018), None)
            yield (region, p, arms, *got, p+7, f'{words[i+7]:016x}' if i+7 < len(words) else '',
                   int(match), '' if end is None else base+end, '' if end is None else f'{words[end]:016x}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--view', choices=('fields', 'layouts'), default='fields')
    args = parser.parse_args()
    segments = regions(args.image.read_bytes())
    out = csv.writer(sys.stdout, delimiter='\t', lineterminator='\n')
    out.writerows(field_rows(segments) if args.view == 'fields' else layout_rows(segments))
