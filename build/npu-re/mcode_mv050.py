"""Decode the candidate bit-move opcode 0x050 and measure dataflow links (offline).

Fields (bit 0 = LSB), all addresses in the 0290 S bit space:
    DST  = bits 51:41   destination bit address
    SRC  = bits 40:30   source bit address (not an immediate: see tests)
    W    = bits 4:0 + 1 width in bits (1..32)
    COND = bits 11:5    0x29 (low 12 = 0x520 with W bits clear) = always
    bits 15:12          0 in the main class; bit 15 meaning unknown
Links are found by address adjacency (look-back window), not by a trace.
"""
import argparse
import random
import sys
from collections import Counter
from pathlib import Path
from typing import NamedTuple

from mcode_preps import regions

ALWAYS = 0x29
LOOK = 16


class Move(NamedTuple):
    pc: int
    word: int
    dst: int
    src: int
    width: int
    cond: int
    flags: int  # bits 15:12

    @property
    def main_class(self):
        return self.cond == ALWAYS and self.flags & 7 == 0


def is_move(word):
    return word >> 52 == 0x050


def decode(pc, word):
    if not is_move(word):
        raise ValueError('expected opcode 0x050')
    return Move(pc, word, (word >> 41) & 0x7ff, (word >> 30) & 0x7ff, (word & 31) + 1,
                (word >> 5) & 0x7f, (word >> 12) & 0xf)


def writers(words):
    """pc -> (lo, hi) bit range written, for 0x070 loads and 0x050 moves."""
    out = {}
    for pc, w in enumerate(words):
        if w >> 52 == 0x070:
            lo = ((w >> 44) & 0xff) * 8
            out[pc] = (lo, lo + 8 * ((w & 7) + 1))
        elif is_move(w):
            m = decode(pc, w)
            out[pc] = (m.dst, m.dst + m.width)
    return out


def fed(words, wmap, kinds=(0x070,), look=LOOK):
    """Count 0x050 whose SRC..SRC+W is fully written by the nearest earlier writer of `kinds`."""
    hit = total = 0
    for pc, w in enumerate(words):
        if not is_move(w):
            continue
        total += 1
        m = decode(pc, w)
        for j in range(pc - 1, max(pc - look, 0) - 1, -1):
            if j in wmap and words[j] >> 52 in kinds:
                lo, hi = wmap[j]
                if lo <= m.src and m.src + m.width <= hi:
                    hit += 1
                    break
    return hit, total


def shuffled(wmap, seed):
    keys = list(wmap)
    spans = [hi - lo for lo, hi in wmap.values()]
    los = [lo for lo, _ in wmap.values()]
    random.Random(seed).shuffle(los)
    return {k: (lo, lo + s) for k, lo, s in zip(keys, los, spans)}


def summary(words):
    ms = [decode(pc, w) for pc, w in enumerate(words) if is_move(w)]
    main = [m for m in ms if m.main_class]
    wm = writers(words)
    return {
        'moves': len(ms), 'main': len(main),
        'dst_in_word': sum(m.dst % 32 + m.width <= 32 for m in main),
        'src_in_word': sum(m.src % 32 + m.width <= 32 for m in main),
        'max_dst_word': max(m.dst >> 5 for m in ms),
        'max_src_word': max(m.src >> 5 for m in ms),
        'from_070': fed(words, wm, (0x070,)),
        'from_070_shuffled': fed(words, shuffled(wm, 2), (0x070,)),
        'width': sorted(Counter(m.width for m in main).items()),
    }


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('image', type=Path)
    a = ap.parse_args()
    for k, v in summary(regions(a.image.read_bytes())[0][2]).items():
        print(f'{k}\t{v}', file=sys.stdout)
