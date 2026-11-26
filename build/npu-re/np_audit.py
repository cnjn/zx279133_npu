"""Inventory the shipped NP images: loaded words, trailer entries and open ISA semantics.

Read-only. Decodable is not synonymous with understood, and absence from the
issues report is not a proof of semantics. File offsets are byte offsets; PCs
are word addresses. Driver references and evidence grades are in NPU_AUDIT.md.
"""
import argparse
import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

from npdis import ENTRY_TAGS, HIGH_BASE, HIGH_N, HIGH_OFF, records, split
from npisa import ALWAYS, Bcmp, Bcmpr, bits, code_targets, decode
from npnames import RAW_NOTES

ROOT = Path(__file__).resolve().parents[2]
IMAGES = {
    'zx133': ROOT / 'extracted/kernel1/rootfs/etc/mcode/mcode_133.bin',
    'sr1010': ROOT / 'zte_zxslc_sr1010/mcode_intel.bin',
}
# Conditions, arithmetic, and memory addressing have distinct evidence even on
# the same instruction. Record only the known open aspects, not a blanket grade.
NEUTRAL = {
    'op01': ('P', 'slot-associated control; effect of subcode, width and suffix flags'),
    'op110': ('P', 'address and condition fields; transfer/link and continuation state'),
    'op510': ('P', 'dispatch/return candidate; target formula and linkage'),
    'loop': ('P', 'two address fields and constant; exact loop count and exit rules'),
    'fset2': ('P', 'flag-pair candidate; result formula and all bank/width effects'),
    'fsetr': ('P', 'consumer-anchored result bit; actual comparison/logic formula'),
    'muxidx': ('S', 'stat #47 index only; write width, possible other effects'),
}
TRAILER_ROLES = dict(zip(ENTRY_TAGS, ('packet type', 'duplication', 'ingress port')))


def segments(main, high):
    return (('main', 0, 16, main), ('high', HIGH_BASE, HIGH_OFF, high))


def raw_candidates(word, region):
    if region == 'high':
        op = word >> 48
        if 0x98 <= op <= 0x99:
            return f'equal indices [48:44]={bits(word,48,44)} [24:20]={bits(word,24,20)}; behavior unknown'
        if 0x2fa <= op <= 0x2fb:
            return f'equal indices [48:44]={bits(word,48,44)} [40:36]={bits(word,40,36)}; behavior unknown'
        return 'fixed singleton; role unknown'
    op = word >> 48
    if op == 0x0522:
        return 'candidate bit addresses (51:41,40:30,29:19) = ' + ','.join(
            f'{bits(word, hi, lo):#x}' for hi, lo in ((51, 41), (40, 30), (29, 19)))
    if op == 0x068a:
        return (f'layout K={bits(word,47,46)} IDX={bits(word,45,41)} '
                f'A={bits(word,40,30):#x} B={bits(word,29,19):#x} '
                f'mode={bits(word,18,10):#x} W={bits(word,4,0)+1}/{bits(word,9,5)+1}; result unresolved')
    if op in (0x0009, 0x000f):
        return (f'movi32-like D={bits(word,50,41):#x} candidate literal[40:9]={bits(word,40,9):#x}; '
                'bit 8 set, not movi32')
    return 'no validated operand layout'


def issues(tag, region, word, fmt, d):
    if fmt is None:
        note = RAW_NOTES.get(tag, {}).get(f'{word:016x}')
        candidate = raw_candidates(word, region)
        yield 'U', candidate + (f'; {note}' if note else '')
        return
    name = fmt.name
    if name in NEUTRAL:
        yield NEUTRAL[name]
    if d.get('rest'):
        yield 'P', f'unexplained bits {d["rest"]:#x}'
    if d.get('x') or d.get('y'):
        yield 'P', 'instruction suffix effect (.x/.y) not fully established'
    c = d.get('cond', ALWAYS)
    if c >> 8 == 3:
        yield 'P', f'condition {c:#x}: source and/or polarity unresolved'
    if c >> 8 == 2 and c & 63 != 31:
        yield 'P', f'slot condition {c:#x}: result meaning depends on command/table'
    if fmt in (Bcmp, Bcmpr) and (d['mode'] not in (0, 1) or d['o']):
        yield 'P', 'compare order semantics supported in tested contexts; numeric domain/corner cases unverified'
    if name == 'cset' and d['op']:
        yield 'P', f'comparison mode {d["op"]:#x} and summary flags'
    if name == 'lkup':
        fam = d['fam']
        if region == 'high' or fam not in (2, 3, 4):
            yield 'P', f'lkup-shaped family {fam:#x}; exact command and effects not resolved'
        else:
            yield 'S', 'table kind/slot identified; per-table input/output fields and side effects not exhaustively mapped'
    if name in ('ld', 'st', 'sti', 'kld', 'xld', 'cp'):
        for key in ('base', 'sbase'):
            if d.get(key) in (0, 2, 3, 4, 5, 6, 7):
                yield 'P', f'{key}=h{d[key]}: pointer provenance/updates not fully characterized'


def issue_rows(tag, main, high):
    for region, base, start, words in segments(main, high):
        for i, word in enumerate(words):
            pc = base + i
            f, d = decode(word, pc)
            opened = list(issues(tag, region, word, f, d))
            if opened:
                yield (tag, region, pc, hex(start + 8*i), f'{word:016x}',
                       f.text(d, lambda a: f'L{a}') if f else '.word',
                       json.dumps(d or {}, sort_keys=True, separators=(',', ':')),
                       ','.join(sorted({grade for grade, _ in opened})),
                       ' | '.join(note for _, note in opened))


def entry_rows(tag, trailer, n):
    index = Counter()
    for i, (kind, value) in enumerate(records(trailer)):
        if kind not in ENTRY_TAGS:
            continue
        j = index[kind]
        index[kind] += 1
        # Driver input bit 25 gates port/type records; duplication uses bit 23.
        enable = bool(value & (1 << (23 if kind == 0xcccccccc else 25)))
        pc = value & (0x3fff if kind == 0xbdbdbdbd else 0xffff)
        state = ('disabled' if not enable else 'pc-zero' if pc == 0 else
                 'explicit-main' if pc < n else 'outside-main')
        yield (tag, TRAILER_ROLES[kind], j, hex(HIGH_OFF + HIGH_N*8 + 8*i),
               f'{value:08x}', int(enable), pc, state)


def region_rows(tag, blob, header, main, gap, high, trailer):
    for region, base, start, w in segments(main, high):
        decoded = [decode(word, base+i) for i, word in enumerate(w)]
        refs = [(base+i, a) for i, (f, d) in enumerate(decoded) if f
                for a in code_targets(f, d) if not base <= a < base+len(w)]
        yield (tag, region, hex(start), hex(start+len(w)*8), f'{base}..{base+len(w)-1}',
               f'{len(w)} words; {sum(bool(word) for word in w)} nonzero; '
               f'{sum(f is None for f, _ in decoded)} raw; {len(refs)} explicit targets outside this region')
    yield (tag, 'header', '0x0', '0x10', '-', 'magic=%#x version=%d ram=%#x' % header)
    stock_padding = gap == b'\x00\x18\x00\x00\x00\x00\x00\x40' * (len(gap)//8)
    yield (tag, 'gap', hex(16+8*len(main)), hex(HIGH_OFF), '-',
           f'{len(gap)} bytes not loaded; ' +
           ('all 0018000000000040' if stock_padding else 'nonuniform or nonstock padding'))
    tags = Counter(f'{t:08x}' for t, _ in records(trailer))
    yield (tag, 'trailer', hex(HIGH_OFF+8*len(high)), hex(len(blob)), '-',
           f'{len(trailer)} config/version bytes; {dict(tags)}')
    yield (tag, 'image', '0x0', hex(len(blob)), '-', 'sha256=' + hashlib.sha256(blob).hexdigest())


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('view', choices=('regions', 'entries', 'issues'))
    p.add_argument('--image', choices=tuple(IMAGES), help='default: both stock images')
    args = p.parse_args()
    out = csv.writer(sys.stdout, delimiter='\t', lineterminator='\n')
    out.writerow({'regions': 'image region start_offset end_offset_exclusive pcs details',
                  'entries': 'image table record file_offset word enabled pc_field classification',
                  'issues': 'image region pc file_offset word instruction decoded_fields evidence unresolved'}[args.view].split())
    for tag in (args.image,) if args.image else IMAGES:
        blob = IMAGES[tag].read_bytes()
        header, main, gap, high, trailer = split(blob)
        if args.view == 'regions':
            out.writerows(region_rows(tag, blob, header, main, gap, high, trailer))
        elif args.view == 'entries':
            out.writerows(entry_rows(tag, trailer, len(main)))
        else:
            out.writerows(issue_rows(tag, main, high))


if __name__ == '__main__':
    main()
