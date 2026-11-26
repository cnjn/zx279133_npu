"""Cross-check 0018 microcode fields against the matching driver's SDT descriptors.

T3 is the family under test. Keep neighbouring T2/T4/T5 encodings and
missing descriptors as controls. A match identifies a candidate table, not
whether the instruction reads, updates or commits it.
"""
import argparse
import csv
import sys
from pathlib import Path

from mcode_preps import regions
from sdt_dump import TYPES, load_driver


HEADER = 'region pc word family bits39_37 id36_29 driver_type driver_name param0 param1'.split()


def xrefs(segments, driver):
    for region, base, words in segments:
        for i, w in enumerate(words):
            family = w & 0x7fffff  # bit 23 is not part of the family filter
            if w >> 48 != 0x0018 or family not in (2, 3, 4, 5):
                continue
            no = (w >> 29) & 0xff  # se_sdt_core_sdt_init bounds sdt_no at 255
            desc = driver.tables.get(no)
            kind, a, b = ('not_in_core', '', '') if desc is None else (
                TYPES.get(desc[0], desc[0]), f'{desc[1]:08x}', f'{desc[2]:08x}')
            yield (region, base+i, f'{w:016x}', f'T{family}', (w >> 37) & 7, no,
                   kind, driver.names.get(no, ''), a, b)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('module', type=Path)
    args = parser.parse_args()
    out = csv.writer(sys.stdout, delimiter='\t', lineterminator='\n')
    out.writerow(HEADER)
    out.writerows(xrefs(regions(args.image.read_bytes()), load_driver(args.module.read_bytes())))
