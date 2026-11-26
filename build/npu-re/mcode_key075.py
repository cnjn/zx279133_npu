"""Tile the lookup key written by 0x075 / 0x055 before each 0018 and compare with SDT param0 (offline).

Hypothesis (bit 0 = LSB; same BASE/OFF/N layout as 0x070 in mcode_ld070):
    0x075: key[D .. D+N) <- packet bytes at BASE+OFF        D = bits 51:44
    0x055: key[D .. D+N) <- bits starting at SRC = bits 40:30 (the 0290 S space)
    0x015: key[D .. D+N) <- immediate (shown as @imm in the layout)

Walk back from each 0018 by address, stopping at the previous 0018 / 0108 / 0290
or after LOOK words. This is adjacency, not a trace: writes made before the
window, or on another path, are invisible, so a short key is not a contradiction.
An overlap or a key longer than param0 would be.
"""
import argparse
import csv
import sys
from pathlib import Path
from typing import NamedTuple

from mcode_preps import regions
from mcode_sdt import xrefs
from sdt_dump import load_driver

LOOK = 12
STOP = (0x0018, 0x0108, 0x0290)


class KeyWrite(NamedTuple):
    pc: int
    op: int
    dest: int
    size: int
    base: int
    offset: int
    src: int  # 0x055 only


def key_write(pc, w):
    op = w >> 52
    if op not in (0x075, 0x055, 0x015):  # 0x015: key <- immediate (kmovi)
        return None
    off = (w >> 17) & 0x3ff
    off = off - 0x400 if off & 0x200 else off
    return KeyWrite(pc, op, (w >> 44) & 0xff, (w & 7) + 1, (w >> 27) & 7, off,
                    (w >> 30) & 0x7ff if op == 0x055 else -1)


def writes_before(words, pc, look=LOOK):
    out = []
    for j in range(pc - 1, max(pc - look, 0) - 1, -1):
        if words[j] >> 48 in STOP:
            break
        kw = key_write(j, words[j])
        if kw:
            out.append(kw)
    return out[::-1]


def tile(ws):
    """Return (end, overlap): highest key byte written + 1, and whether bytes collide."""
    seen = set()
    overlap = False
    for kw in ws:
        span = set(range(kw.dest, kw.dest + kw.size))
        overlap |= bool(seen & span)
        seen |= span
    return (max(seen) + 1 if seen else 0), overlap


def rows(segments, driver):
    words = segments[0][2]
    yield 'pc family sdt name param0 writes key_end overlap layout'.split()
    for r in xrefs(segments, driver):
        region, pc, _, fam, _, no, kind, name, p0, _ = r
        if region != 'main':
            continue
        ws = writes_before(words, pc)
        if not ws:
            continue
        end, ov = tile(ws)
        layout = ' '.join(f'{kw.op:03x}:D{kw.dest}+{kw.size}' +
                          (f'@b{kw.base}{kw.offset:+d}' if kw.op == 0x075 else
                           '@imm' if kw.op == 0x015 else f'@s{kw.src:#x}')
                          for kw in ws)
        yield [pc, fam, no, name, int(p0, 16) if p0 else '', len(ws), end, int(ov), layout]


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('image', type=Path)
    ap.add_argument('module', type=Path)
    a = ap.parse_args()
    out = csv.writer(sys.stdout, delimiter='\t', lineterminator='\n')
    out.writerows(rows(regions(a.image.read_bytes()), load_driver(a.module.read_bytes())))
