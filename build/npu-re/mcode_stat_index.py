"""Blind cross-check of the ZX133 table-48 index hypothesis (offline only).

Select *all* T3/table-48 words before classifying PC-6. Unknown fixed values
and non-immediate forms stay in the output. PCs are decimal word addresses;
driver calls are hexadecimal .text byte offsets. No control flow is assumed.
"""
import argparse
import csv
import sys
from pathlib import Path
from typing import NamedTuple

from debug_stat_reads import driver_reads
from mcode_preps import regions


FIELD = 0xffff << 25
FIXED, ALTERNATE = 0x010780000000052f, 0x050780000000052f
BASE_FIELD = 0xffff << 14
UPSTREAM = {0x02000000000001ef, 0x020500a0000001ef}


class Site(NamedTuple):
    region: str
    pc: int
    word: int
    prep: int | None
    form: str
    index: int | None
    upstream: tuple     # (absolute PC, raw word); possible range bases, not final indices


def sites(segments):
    for region, base, words in segments:
        for i, word in enumerate(words):
            if word >> 48 != 0x18 or word & 0x7fffff != 3 or (word >> 29) & 0xff != 48:
                continue
            prep = words[i-6] if i >= 6 else None
            key = None if prep is None else prep & ~FIELD
            form, index, upstream = 'unknown', None, ()
            if key == FIXED:
                form, index = 'fixed_candidate', (prep & FIELD) >> 25
            elif key == ALTERNATE:
                form = 'other_source'
                # Five words immediately before the shared eight-word sequence.
                upstream = tuple((base+j, words[j]) for j in range(max(0, i-12), i-7)
                                 if (words[j] & ~BASE_FIELD) in UPSTREAM)
            yield Site(region, base+i, word, prep, form, index, upstream)


def joined_rows(segments, reads):
    fixed = {r.index: r for r in reads if r.index is not None}
    if len(fixed) != sum(r.index is not None for r in reads):
        raise ValueError('ambiguous fixed index in debug_stat_show')
    yield ('region t3_pc t3_word prep_pc prep_word form field40_25 index_candidate '
           'get_call driver_label upstream_pc:word:base').split()
    for s in sites(segments):
        match = fixed.get(s.index)
        yield (s.region, s.pc, f'{s.word:016x}', '' if s.prep is None else s.pc-6,
               '' if s.prep is None else f'{s.prep:016x}', s.form,
               '' if s.prep is None else hex((s.prep & FIELD) >> 25),
               '' if s.index is None else hex(s.index), hex(match.call) if match else '',
               match.label if match else '',
               ','.join(f'{pc}:{w:016x}:{(w & BASE_FIELD) >> 14:#x}' for pc, w in s.upstream))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('module', type=Path, help='ZX133 np_133.ko')
    parser.add_argument('--image', type=Path, help='join microcode sites; without this, list driver reads')
    parser.add_argument('--objdump', help='GNU objdump with AArch64 support (or set OBJDUMP)')
    args = parser.parse_args()
    reads = driver_reads(args.module, args.objdump)
    out = csv.writer(sys.stdout, delimiter='\t', lineterminator='\n')
    if args.image:
        out.writerows(joined_rows(regions(args.image.read_bytes()), reads))
    else:
        out.writerow('get_call w1_setup fixed_index fmt_str1_1_offset driver_label'.split())
        out.writerows((hex(r.call), r.w1, '' if r.index is None else hex(r.index),
                       hex(r.fmt_off), r.label) for r in reads)
