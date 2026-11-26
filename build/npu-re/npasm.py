"""Assemble npasm text (as produced by npdis.py) back into an NP microcode container."""
import argparse
import re
import struct
import sys
from pathlib import Path

from npisa import DISPATCH_DELTA, DISPATCH_ENTRIES, dispatch_shape, hazards, parse

HIGH_OFF = 0x17d90


def strip(line):
    return line.split(';', 1)[0].rstrip()


STAT_MACRO = [  # the stock "count table-48 entry" idiom (e.g. PC 4879-4886)
    'clr r30', 'movi r30[15:0], {idx}', 'movi r30[27:23], 0x16', 'movi r30[28], 0x1',
    'xmovi idx[132..135], 0x0', 'xmovi idx[136..139], 0x0', 'xmov idx[128..131], r30',
    'lkup s2, 0x3, #48']


def preprocess(text):
    """Source-level conveniences, expanded before assembly:
      .equ NAME, VALUE      textual constant (whole-word replacement)
      stat IDX              table-48 counter increment (8 instructions)
    """
    equ, out = {}, []
    for line in text.splitlines():
        code, sep, comment = line.partition(';')
        s = code.strip()
        if s.startswith('.equ'):
            name, val = (x.strip() for x in s[4:].split(',', 1))
            equ[name] = val
            continue
        for name, val in equ.items():
            code = re.sub(rf'(?<![\w.]){re.escape(name)}(?![\w])', val, code)
        s = code.strip()
        if s.startswith('stat '):
            out += [f'    {m.format(idx=s[5:].strip())}' for m in STAT_MACRO]
            continue
        out.append(code + sep + comment)
    return '\n'.join(out) + '\n'


def auto_nop(text, limit=1000):
    """Insert a nop before every instruction that reads a result of the previous one."""
    from npisa import hazards
    for _ in range(limit):
        blob = assemble(text, fit_gap=True)
        n = struct.unpack_from('>I', blob, 12)[0]
        lines = text.splitlines()
        sec = sections(text)
        pcs = [no for no, s in sec['main']['lines'] if not re.fullmatch(r'\w+:', s)]
        hz = [pc for pc in hazards(struct.unpack_from(f'>{n}Q', blob, 16))
              if '!hazard-ok' not in lines[pcs[pc] - 1]]
        if not hz:
            return text
        no = pcs[hz[0]]                       # 1-based source line of the offending instruction
        lines.insert(no - 1, '    nop                 ; auto-nop')
        text = '\n'.join(lines) + '\n'
    raise ValueError('auto-nop did not converge')


def sections(text):
    cur, out = None, {}
    for no, line in enumerate(text.splitlines(), 1):
        s = strip(line)
        if not s.strip():
            continue
        if s.startswith('.header'):
            out['header'] = s.split()[1:]
        elif s.split()[0] in ('.main', '.dispatch', '.gap', '.high', '.trailer'):
            cur = s.split()[0][1:]
            out[cur] = {'args': s.split()[1:], 'lines': []}
        else:
            out[cur]['lines'].append((no, s.strip()))
    return out


def data(lines):
    buf = bytearray()
    for no, s in lines:
        op, arg = s.split(None, 1)
        if op == '.quad':
            buf += int(arg, 16).to_bytes(8, 'big')
        elif op == '.zero':
            buf += bytes(int(arg))
        else:
            raise SyntaxError(f'line {no}: expected .quad/.zero, got {s!r}')
    return bytes(buf)


def trailer(lines, labels):
    buf = bytearray()
    for no, s in lines:
        op, _, arg = s.partition(' ')
        a = [x.strip() for x in arg.split(',')]
        if op == '.rec':
            buf += struct.pack('>II', int(a[0], 16), int(a[1], 16))
        elif op == '.entry':
            if a[2] not in labels:
                raise SyntaxError(f'line {no}: unknown label {a[2]!r}')
            buf += struct.pack('>II', int(a[0], 16), int(a[1], 16) << 16 | labels[a[2]])
        else:
            buf += data([(no, s)])
    return bytes(buf)


def code(lines, base, want_labels=False):
    labels, insns, pc = {}, [], base
    for no, s in lines:
        m = re.fullmatch(r'(\w+):', s)
        if m:
            labels[m[1]] = pc
            continue
        insns.append((no, pc, s))
        pc += 1
    words = []
    for no, pc, s in insns:
        try:
            words.append(parse(s, pc, labels))
        except (ValueError, IndexError) as e:
            raise SyntaxError(f'line {no}: {e}: {s!r}') from None
    return (words, labels) if want_labels else words


def check_dispatches(lines, words, labels):
    """Fail closed if a declared fixed-step jump table is split by an edit."""
    for no, s in lines:
        names = [a.strip() for a in s.split(',')]
        if len(names) != 3 or any(name not in labels for name in names):
            raise SyntaxError(f'line {no}: expected three known .dispatch labels: {s!r}')
        base, first, end = (labels[name] for name in names)
        if first - base != DISPATCH_DELTA or end - first != DISPATCH_ENTRIES or not dispatch_shape(words, base):
            raise SyntaxError(f'line {no}: .dispatch layout changed: {s}')


def assemble(text, fit_gap=False):
    """Build the container. With fit_gap, a main section whose length changed is
    accommodated by trimming / zero-padding the unloaded gap so that the high
    region stays at its fixed file offset (the driver loads it from there)."""
    sec = sections(text)
    magic, version, ram = (int(x, 0) for x in sec['header'])
    main, labels = code(sec['main']['lines'], 0, want_labels=True)
    if 'dispatch' in sec:
        check_dispatches(sec['dispatch']['lines'], main, labels)
    high_base = int(sec['high']['args'][0], 0)
    high = code(sec['high']['lines'], high_base)
    gap = data(sec['gap']['lines'])
    if fit_gap:
        room = HIGH_OFF - 16 - 8 * len(main)
        if room < 0:
            raise ValueError(f'main has {len(main)} words; at most {(HIGH_OFF - 16) // 8} fit')
        gap = (gap + bytes(max(0, room - len(gap))))[:room]
    trailer = globals()['trailer'](sec['trailer']['lines'], labels)
    blob = struct.pack('>4I', magic, version, ram, len(main))
    blob += struct.pack(f'>{len(main)}Q', *main) + gap
    if len(blob) != HIGH_OFF:
        raise ValueError(f'main+gap end at {len(blob):#x}, high region must start at {HIGH_OFF:#x}')
    blob += struct.pack(f'>{len(high)}Q', *high) + trailer
    return blob


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('source', type=Path)
    ap.add_argument('-o', '--output', type=Path, required=True)
    ap.add_argument('--fit-gap', action='store_true',
                    help='allow a longer/shorter main section by resizing the unloaded gap')
    ap.add_argument('--no-hazard-check', action='store_true')
    ap.add_argument('--auto-nop', action='store_true',
                    help='insert nops for read-after-write hazards (implies --fit-gap)')
    a = ap.parse_args()
    try:
        src = preprocess(a.source.read_text())
        if a.auto_nop:
            src = auto_nop(src)
        blob = assemble(src, a.fit_gap or a.auto_nop)
    except SyntaxError as e:
        sys.exit(f'{a.source}: {e}')
    if not a.no_hazard_check:
        n = struct.unpack_from('>I', blob, 12)[0]
        lines = src.splitlines()
        pcs = [no for no, s in sections(src)['main']['lines'] if not re.fullmatch(r'\w+:', s)]
        for pc in hazards(struct.unpack_from(f'>{n}Q', blob, 16)):
            if '!hazard-ok' in lines[pcs[pc] - 1]:
                continue
            print(f'warning: pc {pc} reads a result of pc {pc - 1} with no nop in between',
                  file=sys.stderr)
    a.output.write_bytes(blob)
