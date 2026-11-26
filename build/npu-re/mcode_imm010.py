"""Decode the candidate write-immediate opcode 0x010 (prefixes 0100..0107) offline.

0108 (jump) shares the 12-bit opcode but has its own layout; it is excluded here.
As with 07xx, the 16-bit prefix's low nibble is the top of the destination:

    DST  = bits 51:41   destination bit address (same space as 0x050 DST / 0290 S)
    IMM  = bits 40:25   16-bit immediate; always fits in W bits
    W    = bits 4:0 + 1 width in bits
    COND = bits 14:5    0x029 = always (the recurring low-12 0x520)
    bit 15              flag, meaning unknown; bits 24:16 are always 0
"""
import argparse
import random
from collections import Counter
from pathlib import Path
from typing import NamedTuple

from mcode_preps import regions

ALWAYS = 0x029


class Imm(NamedTuple):
    pc: int
    word: int
    dst: int
    imm: int
    width: int
    cond: int
    flag15: int


def is_imm(word):
    return word >> 52 == 0x010 and (word >> 48) & 0xf < 8


def decode(pc, word):
    if not is_imm(word):
        raise ValueError('expected 0100..0107')
    return Imm(pc, word, (word >> 41) & 0x7ff, (word >> 25) & 0xffff, (word & 31) + 1,
               (word >> 5) & 0x3ff, (word >> 15) & 1)


def summary(words, seed=4):
    xs = [decode(pc, w) for pc, w in enumerate(words) if is_imm(w)]
    ws = [x.width for x in xs]
    random.Random(seed).shuffle(ws)
    return {
        'count': len(xs),
        'unused_24_16': sum((x.word >> 16) & 0x1ff != 0 for x in xs),
        'imm_fits': sum(x.imm.bit_length() <= x.width for x in xs),
        'imm_fits_shuffled_w': sum(x.imm.bit_length() <= v for x, v in zip(xs, ws)),
        'dst_in_word': sum(x.dst % 32 + x.width <= 32 for x in xs),
        'max_dst_word': max(x.dst >> 5 for x in xs),
        'always': sum(x.cond == ALWAYS for x in xs),
        'cond_ne_always_with_bits14_12': sum(x.cond != ALWAYS and (x.cond >> 7) != 0 for x in xs),
        'cond': Counter(hex(x.cond) for x in xs).most_common(6),
    }


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('image', type=Path)
    a = ap.parse_args()
    for k, v in summary(regions(a.image.read_bytes())[0][2]).items():
        print(f'{k}\t{v}')
