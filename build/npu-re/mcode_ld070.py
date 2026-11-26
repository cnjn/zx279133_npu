"""Decode the candidate field-load opcode 0x070 and pair it with 0290 compares (offline).

Select by bits 63:52 == 0x070 only. The 16-bit prefixes 0700..07ff are NOT
separate opcodes: their low byte is the top of D. Fields (bit 0 = LSB):

    D    = bits 51:44   destination byte address; bit k of the loaded value
                        lands at bit address D*8 + k (the 0290 S operand)
    BASE = bits 29:27   which header pointer the offset is relative to
    OFF  = bits 26:17   signed 10-bit byte offset
    N    = bits 2:0 + 1 bytes loaded (big-endian value)

A pair is the nearest earlier 0x070 (within LOOK words, by address only)
whose loaded bits cover the compare's S..S+W-1. Address adjacency, not a trace.
"""
import argparse
import csv
import sys
from pathlib import Path
from typing import NamedTuple

from mcode_cmp0290 import decode as decode_cmp
from mcode_preps import regions

LOOK = 12


class Load(NamedTuple):
    pc: int
    word: int
    dest: int
    base: int
    offset: int
    size: int

    @property
    def bits(self):
        return range(self.dest * 8, (self.dest + self.size) * 8)


def is_load(word):
    return word >> 52 == 0x070


def decode(pc, word):
    if not is_load(word):
        raise ValueError('expected opcode 0x070')
    off = (word >> 17) & 0x3ff
    if off & 0x200:
        off -= 0x400
    return Load(pc, word, (word >> 44) & 0xff, (word >> 27) & 7, off, (word & 7) + 1)


def pairs(words, look=LOOK):
    """Yield (compare, load or None) for every 0290 in the region."""
    for pc, word in enumerate(words):
        if word >> 48 != 0x0290:
            continue
        c = decode_cmp(pc, word)
        found = None
        for j in range(pc - 1, max(pc - look, 0) - 1, -1):
            if is_load(words[j]):
                ld = decode(j, words[j])
                if c.source in ld.bits and c.source + c.width - 1 in ld.bits:
                    found = ld
                    break
        yield c, found


def rows(words):
    yield ('cmp_pc cmp_word S W M V load_pc load_word D base off n bit_in_value').split()
    for c, ld in pairs(words):
        tail = ['', '', '', '', '', '', ''] if ld is None else [
            ld.pc, f'{ld.word:016x}', ld.dest, ld.base, ld.offset, ld.size, c.source - ld.dest * 8]
        yield [c.pc, f'{c.word:016x}', hex(c.source), c.width, c.mode, hex(c.value), *tail]


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('image', type=Path)
    args = ap.parse_args()
    main = regions(args.image.read_bytes())[0][2]
    csv.writer(sys.stdout, delimiter='\t', lineterminator='\n').writerows(rows(main))
