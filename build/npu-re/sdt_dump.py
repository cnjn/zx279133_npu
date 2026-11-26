"""Read the two shipped drivers' core SDT arrays from ELF64 LE AArch64 .ko files.

se_sdt_core_sdt_init walks 16-byte records and passes &record[8] (not a
pointer loaded from record[8]) to the constructor for that type. Keep the
last two u32s raw: their meaning depends on the constructor.
"""
import argparse
import struct
from pathlib import Path
from typing import NamedTuple

TYPES = {1: 'eram', 2: 'ddr', 3: 'hash', 4: 'stat', 5: 'wram'}


class Driver(NamedTuple):
    array: str
    tables: dict  # sdt_no -> (constructor type, param0, param1)
    names: dict   # if present, actual driver sdt_no_to_str lookup, not string order


def load_driver(blob):
    if blob[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<HH', blob, 16) != (1, 183):
        raise ValueError('expected a relocatable little-endian AArch64 ELF64 module')
    shoff, = struct.unpack_from('<Q', blob, 0x28)
    entsize, nsec = struct.unpack_from('<HH', blob, 0x3a)
    sec = [struct.unpack_from('<IIQQQQIIQQ', blob, shoff + i*entsize) for i in range(nsec)]

    def offset(sh, val, size):
        s = sec[sh]
        if s[1] == 8 or val < 0 or val + size > s[5] or s[4] + s[5] > len(blob):
            raise ValueError('not a file-backed range in section')
        return s[4] + val

    def string(sh, val):
        start = offset(sh, val, 1)
        return blob[start:blob.index(b'\0', start, sec[sh][4]+sec[sh][5])].decode()

    si = next(i for i, s in enumerate(sec) if s[1] == 2)  # SHT_SYMTAB
    s = sec[si]
    symbols = list(struct.iter_unpack('<IBBHQQ', blob[s[4]:s[4]+s[5]]))
    named = {string(s[6], name): (sh, val, size) for name, _, _, sh, val, size in symbols
             if name and 0 < sh < nsec}

    def relocations(sh, lo, hi):
        for r in sec:
            if (r[1], r[6], r[7]) != (4, si, sh):  # SHT_RELA, uses our symtab, applies to sh
                continue
            for at, info, add in struct.iter_unpack('<QQq', blob[r[4]:r[4]+r[5]]):
                if lo <= at < hi:
                    sym = symbols[info >> 32]
                    yield at, info & 0xffffffff, sym[3], sym[4] + add

    # The SR module's unsuffixed symbol is a .bss pointer, not the array.
    array = 'g_core_sdt_info_133' if 'g_core_sdt_info_133' in named else 'g_core_sdt_info'
    sh, val, size = named[array]
    start = offset(sh, val, size)
    if not size or size % 16:
        raise ValueError(f'{array} is not an array of 16-byte descriptors')
    if array == 'g_core_sdt_info':
        count, = struct.unpack_from('<I', blob, offset(*named['g_core_sdt_num']))
        if count != size // 16:
            raise ValueError('descriptor count disagrees with symbol size')
    tables = {}
    for no, kind, a, b in struct.iter_unpack('<4I', blob[start:start+size]):
        if no > 255 or no in tables:
            raise ValueError(f'invalid or duplicate SDT number {no}')
        tables[no] = kind, a, b

    names = {}
    if 'sdt_no_to_str' in named:
        fn_sh, fn, fn_size = named['sdt_no_to_str']
        sh, base, size = named['CSWTCH.13']  # SR module; verify the xref rather than trusting the name
        if not any((kind, dest, value) == (275, sh, base)  # ADR_PREL_PG_HI21
                   for _, kind, dest, value in relocations(fn_sh, fn, fn+fn_size)):
            raise ValueError('sdt_no_to_str does not reference expected name array')
        for at, kind, dest, value in relocations(sh, base, base+size):
            if kind != 257 or (at-base) % 8:  # R_AARCH64_ABS64 pointers
                raise ValueError('unexpected name table relocation')
            names[(at-base)//8] = string(dest, value)
        if len(names)*8 != size:
            raise ValueError('incomplete SDT name lookup')
    return Driver(array, tables, names)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('module', type=Path)
    d = load_driver(parser.parse_args().module.read_bytes())
    print(f'{d.array}: {len(d.tables)} descriptors')
    for no, (kind, a, b) in sorted(d.tables.items()):
        print(f'sdt {no:3} {TYPES.get(kind, kind):5} params {a:08x} {b:08x} {d.names.get(no, "")}')
