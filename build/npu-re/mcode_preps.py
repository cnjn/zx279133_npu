"""Inventory 0148/0548 words independently of their neighbours in ZX v3 microcode.

Windows are intervals in *address* order, ending at any 0018 word or the end
of an executable region. Neither a control-flow edge nor a data dependency is
assumed. All PCs in the TSVs are decimal word addresses; raw words are hex.
"""
import argparse
import csv
import struct
import sys
from pathlib import Path


PRE = {0x0148, 0x0548}
HIT_HEADER = ('region pc word prefix k prev_word next_word prev_0018_pc '
              'close_kind close_pc close_word distance').split()
WINDOW_HEADER = ('region prev_0018_pc close_kind close_pc close_word '
                 'n_prep prep_pcs k_seq distances adjacent_suffix repeated_k').split()


def regions(blob):
    # Known loader layout (NPU_MCODE.md). Do not decode padding or tagged data.
    if len(blob) < 16:
        raise ValueError('truncated header')
    magic, version, ram, n = struct.unpack_from('>4I', blob)
    if (magic, version, ram) != (0xffffaaaa, 3, 0x3000):
        raise ValueError('not the supported v3 / 0x3000-word layout')
    high_off = 0x17d90
    if not n or 16 + 8 * n > high_off or len(blob) < high_off + 8 * 80:
        raise ValueError('invalid instruction region bounds')
    return (('main', 0, struct.unpack_from(f'>{n}Q', blob, 16)),
            ('high', 0x2fad, struct.unpack_from('>80Q', blob, high_off)))


def windows(words):
    prev, hits = None, []
    for i, word in enumerate(words):
        if word >> 48 in PRE:
            hits.append(i)
        elif word >> 48 == 0x0018:
            yield prev, i, hits
            prev, hits = i, []
    yield prev, None, hits  # retain orphan hits, do not cross the gap in IRAM


def rows(segments, view):
    yield HIT_HEADER if view == 'hits' else WINDOW_HEADER
    for region, base, words in segments:
        def hx(i):
            return f'{words[i]:016x}' if i is not None and 0 <= i < len(words) else ''

        for prev, end, hits in windows(words):
            prev_pc = '' if prev is None else base + prev
            end_pc = '' if end is None else base + end
            kind = ('END' if end is None else
                    'T3' if words[end] & 0x7fffff == 3 else 'OTHER_0018')
            ks = [(words[i] >> 46) & 3 for i in hits]
            if view == 'hits':
                for i, k in zip(hits, ks):
                    yield (region, base+i, hx(i), f'{words[i] >> 48:04x}', k,
                           hx(i-1), hx(i+1), prev_pc, kind, end_pc, hx(end),
                           '' if end is None else end-i)
            else:
                suffix = 0
                if end is not None:
                    for i in reversed(hits):
                        if i != end - 1 - suffix:
                            break
                        suffix += 1
                yield (region, prev_pc, kind, end_pc, hx(end), len(hits),
                       ','.join(str(base+i) for i in hits), ','.join(map(str, ks)),
                       '' if end is None else ','.join(str(end-i) for i in hits),
                       '' if end is None else suffix, int(len(ks) != len(set(ks))))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--view', choices=('hits', 'windows'), default='hits')
    args = parser.parse_args()
    writer = csv.writer(sys.stdout, delimiter='\t', lineterminator='\n')
    writer.writerows(rows(regions(args.image.read_bytes()), args.view))
