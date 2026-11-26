"""Disassemble an NP microcode container (v3, 0x3000-word RAM) into npasm text.

The output re-assembles byte-for-byte with npasm.py. Sections:
    .header   magic version ram          (main length is recomputed)
    .main     loaded at word 0            instructions, labels L<pc>
    .dispatch checks the spacing of recognized dense jump tables (no bytes)
    .gap      bytes between main and the high region; not loaded by the driver
    .high     loaded at word 0x2fad       80 instructions
    .trailer  tag/value records after the high region; code entry addresses in the
              bdbdbdbd / cccccccc / bbbbbbbb tables are written as labels (.entry)
Comments after ';' are ignored by the assembler. With --ko, lookups are
annotated with the driver's SDT names (comment only).
"""
import argparse
import struct
import sys
from pathlib import Path

from npisa import DISPATCH_DELTA, DISPATCH_ENTRIES, Lkup, code_targets, decode, dispatch_bases, hazards

HIGH_OFF, HIGH_BASE, HIGH_N = 0x17d90, 0x2fad, 80


def split(blob):
    magic, version, ram, n = struct.unpack_from('>4I', blob)
    main = struct.unpack_from(f'>{n}Q', blob, 16)
    gap = blob[16 + 8 * n:HIGH_OFF]
    high = struct.unpack_from(f'>{HIGH_N}Q', blob, HIGH_OFF)
    trailer = blob[HIGH_OFF + 8 * HIGH_N:]
    return (magic, version, ram), main, gap, high, trailer


def quads(data):
    """Emit .quad lines, folding zero runs into .zero."""
    out, i = [], 0
    while i < len(data):
        j = i
        while j < len(data) and data[j:j + 8] == b'\0' * 8:
            j += 8
        if j > i:
            out.append(f'    .zero {j - i}')
            i = j
            continue
        out.append(f'    .quad {int.from_bytes(data[i:i + 8], "big"):#018x}')
        i += 8
    return out


ENTRY_TAGS = (0xbdbdbdbd, 0xcccccccc, 0xbbbbbbbb)


def records(trailer):
    return [struct.unpack_from('>II', trailer, i) for i in range(0, len(trailer) - 7, 8)]


def entry_addrs(trailer, n):
    """Code entry addresses in the trailer tables: the low 16 bits of non-zero
    bdbdbdbd (packet-type entry table, known 3999/4009), cccccccc and bbbbbbbb
    records. Nearly all land right after an unconditional branch."""
    return {v & 0xffff for t, v in records(trailer) if t in ENTRY_TAGS and v and 0 < v & 0xffff < n}


def trailer_lines(trailer, n):
    out = []
    for t, v in records(trailer):
        if t in ENTRY_TAGS and v and 0 < v & 0xffff < n:
            out.append(f'    .entry {t:#010x}, {v >> 16:#x}, L{v & 0xffff:04d}')
        else:
            out.append(f'    .rec {t:#010x}, {v:#010x}')
    rest = trailer[len(records(trailer)) * 8:]
    return out + quads(rest)


def code(words, base, names=None, raw=False, extra=()):
    decoded = [decode(w, base + i) for i, w in enumerate(words)]
    lo, hi = base, base + len(words)
    targets = {a for f, d in decoded if f for a in code_targets(f, d) if lo <= a < hi}
    targets |= {a for a in extra if lo <= a < hi}

    def lab(t):
        return f'L{t:04d}' if t in targets else f'#{t}'

    ok = set(hazards(words, base))   # stock read-after-write without nop: keep, mark
    out = []
    for i, (w, (f, d)) in enumerate(zip(words, decoded)):
        pc = base + i
        if pc in targets:
            out.append(f'L{pc:04d}:')
        text = f.text(d, lab) if f else f'.word {w:#018x}'
        note = f'{pc:5d}'
        if raw:
            note += f' {w:016x}'
        if f is Lkup and names and d['id'] in names:
            note += f' {names[d["id"]]}'
        if pc in ok:
            note += ' !hazard-ok'
        out.append(f'    {text:<44} ; {note}')
    return out


def apply_names(lines, tag):
    """Replace known operands/conditions by symbolic names and add comments."""
    import re
    from npnames import ALIASES, MUX_INDEX_NAMES, RAW_NOTES, TABLES, stat_labels
    alias = ALIASES.get(tag, {})
    tables = TABLES.get(tag, {})
    raw_notes = RAW_NOTES.get(tag, {})
    stats = stat_labels() if tag == 'zx133' else {}
    out = [f'.equ {n}, {o}' for o, n in alias.items()]
    for line in lines:
        code, sep, comment = line.partition(';')
        raw = re.fullmatch(r'\.word 0x([0-9a-f]{16})', code.strip())
        if raw and raw[1] in raw_notes:
            comment += f' [{raw_notes[raw[1]]}]'
        mux = re.fullmatch(r'movw r31\[22:0\], 0x([0-2])', code.strip())
        if mux and tag == 'zx133':
            idx = int(mux[1])
            comment += f' [stat #47 index {idx} (PON mux {MUX_INDEX_NAMES[idx]})]'
        if code.startswith('    ') and not code.lstrip().startswith('.'):
            for o, n in alias.items():
                code = re.sub(rf'(?<![\w.]){re.escape(o)}(?![\w\[])', n, code)
            m = re.search(r'movi r30\[15:0\], (0x[0-9a-f]+)', code)
            if m and int(m[1], 16) in stats:
                comment += f' "{stats[int(m[1], 16)]}"'
            m = re.search(r'lkup\.\S+ s\d, #(\d+)', code)
            if m and int(m[1]) in tables:
                comment += f' [{tables[int(m[1])]}]'
            code = code.rstrip().ljust(48)
        out.append(code + sep + comment if sep else code.rstrip())
    return out


def disassemble(blob, names=None, raw=False, symbolic=False):
    (magic, version, ram), main, gap, high, trailer = split(blob)
    out = [f'.header {magic:#x} {version} {ram:#x}', '', '.main']
    dispatches = [(base, base + DISPATCH_DELTA, base + DISPATCH_DELTA + DISPATCH_ENTRIES)
                  for base in dispatch_bases(main)]
    dispatch_labels = {pc for table in dispatches for pc in table}
    out += code(main, 0, names, raw, extra=entry_addrs(trailer, len(main)) | dispatch_labels)
    if dispatches:
        out += ['', '.dispatch   ; base, first slot, end (exclusive); layout check only']
        out += ['    ' + ', '.join(f'L{pc:04d}' for pc in table) for table in dispatches]
    out += ['', '.gap'] + quads(gap)
    out += ['', f'.high {HIGH_BASE:#x}'] + code(high, HIGH_BASE, names, raw)
    out += ['', '.trailer'] + trailer_lines(trailer, len(main))
    if symbolic:
        from npnames import which
        out = apply_names(out, which(len(main)))
    return '\n'.join(out) + '\n'


def stats(blob):
    _, main, _, high, _ = split(blob)
    total = sum(1 for w in main if w)
    known = sum(1 for i, w in enumerate(main) if w and decode(w, i)[0])
    return known, total


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('image', type=Path)
    ap.add_argument('--ko', type=Path, help='driver module for SDT names (comments only)')
    ap.add_argument('--raw', action='store_true', help='append the raw word to each comment')
    ap.add_argument('--stats', action='store_true')
    ap.add_argument('--names', action='store_true', help='symbolic names for known fields (npnames.py)')
    a = ap.parse_args()
    blob = a.image.read_bytes()
    if a.stats:
        k, t = stats(blob)
        print(f'decoded {k}/{t} non-zero main words ({k / t:.2%})')
        sys.exit()
    names = None
    if a.ko:
        from sdt_dump import load_driver
        names = load_driver(a.ko.read_bytes()).names
    sys.stdout.write(disassemble(blob, names, a.raw, a.names))
