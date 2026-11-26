"""Inventory the candidate compare operands of 0290, without inferring branch direction.

Select by prefix only. A run is a maximal sequence of adjacent 0290 words in
one instruction region, not a basic block. PCs/targets are decimal word addresses.
The size and 32-bit-boundary checks annotate *all* sites; they are not filters.
"""
import argparse
import csv
import sys
from itertools import groupby
from pathlib import Path
from typing import NamedTuple

from mcode_pc_fields import C_MASK, fields
from mcode_preps import regions

VALUE_MASK = (0x7ff << 19) | (0x1f << 5)


class Case(NamedTuple):
    pc: int
    word: int
    target: int
    source: int  # bits 40:30; not necessarily a packet offset
    width: int   # candidate source width, not the number of encoded literal bits
    mode: int    # bits 12:10, deliberately not named EQ/NE
    value: int

    @property
    def fits(self):
        return self.value.bit_length() <= self.width

    @property
    def within_word(self):
        return (self.source & 31) + self.width <= 32


def decode(pc, word):
    if word >> 48 != 0x0290:
        raise ValueError('expected 0290')
    value = (((word >> 19) & 0x7ff) << 5) | ((word >> 5) & 31)
    return Case(pc, word, fields(word).target, (word >> 30) & 0x7ff,
                (word & 31) + 1, (word >> 10) & 7, value)


def runs(segments):
    for region, base, words in segments:
        for hit, group in groupby(enumerate(words, base), lambda p: p[1] >> 48 == 0x0290):
            if hit:
                yield region, tuple(decode(pc, word) for pc, word in group)


def variation(run):
    """Bits varying anywhere in the run after removing the candidate C address."""
    changed = 0
    for c in run[1:]:
        changed |= c.word ^ run[0].word
    return changed & ~C_MASK


def site_rows(segments):
    yield ('region pc raw_word run_start target_c source40_30 offset_mod32 width mode12_10 '
           'v_hi11 v_lo5 literal fits_width within_32').split()
    for region, run in runs(segments):
        for c in run:
            yield (region, c.pc, f'{c.word:016x}', run[0].pc, c.target, hex(c.source),
                   c.source & 31, c.width, c.mode, hex(c.value >> 5), hex(c.value & 31),
                   f'0x{c.value:04x}', int(c.fits), int(c.within_word))


def run_rows(segments):
    yield ('region start count vary_except_c same_setup literal_seq target_seq '
           'distinct_literals distinct_targets').split()
    for region, run in runs(segments):
        vary = variation(run)
        yield (region, run[0].pc, len(run), f'{vary:016x}', int((vary & ~VALUE_MASK) == 0),
               ','.join(f'0x{c.value:04x}' for c in run), ','.join(str(c.target) for c in run),
               len({c.value for c in run}), len({c.target for c in run}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--view', choices=('sites', 'runs'), default='sites')
    args = parser.parse_args()
    segs = regions(args.image.read_bytes())
    out = csv.writer(sys.stdout, delimiter='\t', lineterminator='\n')
    out.writerows(site_rows(segs) if args.view == 'sites' else run_rows(segs))
