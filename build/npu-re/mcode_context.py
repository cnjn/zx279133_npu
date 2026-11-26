"""Emit contexts of main-program words with high 16 bits 0018 and low 24 bits (apart from bit 23) equal to 3."""
import argparse
import csv
import struct
import sys
from pathlib import Path


def contexts(blob):
    magic, _, ram, n = struct.unpack_from('>4I', blob)
    if magic != 0xffffaaaa or not 0 < n <= ram:
        raise ValueError('unexpected microcode header')
    words = struct.unpack_from(f'>{n}Q', blob, 16)
    for pc, w in enumerate(words):
        if w >> 48 != 0x18 or w & 0x7fffff != 3:
            continue
        yield (pc, f'{w >> 24 & 0xffff:04x}', w >> 29 & 0x7ff, w >> 23 & 1,
               *(f'{words[j]:016x}' if 0 <= j < n else '' for j in range(pc-4, pc+2)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    out = csv.writer(sys.stdout, delimiter='\t', lineterminator='\n')
    out.writerow('pc field39_24 x39_29 bit23 prev4 prev3 prev2 prev1 word next1'.split())
    out.writerows(contexts(parser.parse_args().image.read_bytes()))
