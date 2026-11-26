"""Instruction formats of the ZXIC NP (PPU) microcode, as far as decoded (offline).

Every format is lossless by construction: fields plus fixed bits plus a `rest`
catch-all cover all 64 bits, and `rest` is printed whenever non-zero. A word
that matches no format (or fails a format's sanity check) becomes `.word`.
Field meanings are the hypotheses documented in NPU_MCODE.md; a mnemonic is a
reading aid, not a claim about the vendor's ISA names.

Operand syntax
    r3[15:0]      bits 15..0 of 32-bit word 3 of the bit-addressed space
                  (bit address 3*32+0, width 16); r3 alone = whole word
    m[0x360:+64]  same space, raw bit range that crosses a 32-bit word
    {r4[15:0], r5}  multi-word 0x070 load: low 32 bits in the word of D, higher bits in
                  the preceding word(s)
    h1+12         header pointer 1 plus byte offset 12 (BASE field)
    key[2..7]     lookup-key bytes 2 through 7 (hash tables)
    idx[128..131] index-operand bytes (precede T2/T3 direct and stat tables)
    [r10.3] ...   execution condition: register bit (word 10, bit 3); see cond_text
    [s1.31] ...   condition: status bit 31 of lookup slot 1 (31 = miss)
    [c317] ...    condition of unknown class, raw; 0x029 (always) is omitted
    .x            flag bit 15 on mov/movi: write the field and clear the rest of that
                  register (zero-extend); board exp51-52. Without .x the other bits
                  are kept (exp40).
    {r=0x..}      bits not explained by the format
"""
import re

ALWAYS = 0x029
MASK64 = (1 << 64) - 1


def bits(w, hi, lo):
    return (w >> lo) & ((1 << (hi - lo + 1)) - 1)


def put(v, hi, lo):
    n = hi - lo + 1
    if not 0 <= v < (1 << n):
        raise ValueError(f'value {v:#x} does not fit bits {hi}:{lo}')
    return v << lo


def span(*ranges):
    m = 0
    for hi, lo in ranges:
        m |= ((1 << (hi - lo + 1)) - 1) << lo
    return m


# ---------------------------------------------------------------- operands

def reg(addr, width):
    word, lo = divmod(addr, 32)
    if lo + width <= 32:
        if width == 32:
            return f'r{word}'
        if width == 1:
            return f'r{word}[{lo}]'
        return f'r{word}[{lo + width - 1}:{lo}]'
    return f'm[{addr:#05x}:+{width}]'


REG_RE = r'(?:r\d+(?:\[\d+(?::\d+)?\])?|m\[0x[0-9a-f]+:\+\d+\])'


def parse_reg(s):
    m = re.fullmatch(r'r(\d+)(?:\[(\d+)(?::(\d+))?\])?', s)
    if m:
        word = int(m[1])
        if m[2] is None:
            return word * 32, 32
        hi = int(m[2])
        lo = hi if m[3] is None else int(m[3])
        return word * 32 + lo, hi - lo + 1
    m = re.fullmatch(r'm\[(0x[0-9a-f]+):\+(\d+)\]', s)
    if m:
        return int(m[1], 16), int(m[2])
    raise ValueError(f'bad register operand {s!r}')


def loaded_ranges(d, n):
    """Register bit ranges for an N-byte header transfer, least significant first.

    The first slice starts at byte D. The remaining bytes go into preceding
    words, not a contiguous ascending bit range. Applies to both ld and st.
    """
    q, o = divmod(d, 4)
    left = n * 8
    while left > 0:
        if q < 0:
            raise ValueError('load wraps below word 0')
        width = min(32 - o * 8, left)
        yield q * 32 + o * 8, width
        left -= width
        q, o = q - 1, 0


def loaded(d, n):
    """Register view of an N-byte header transfer as a Verilog-style concatenation."""
    parts = [reg(a, width) for a, width in loaded_ranges(d, n)]
    return parts[0] if len(parts) == 1 else '{' + ', '.join(reversed(parts)) + '}'


def parse_loaded(s):
    """Inverse of loaded(): return (D, N)."""
    if not s.startswith('{'):
        addr, width = parse_reg(s)
        return addr // 8, width // 8
    parts = [parse_reg(x.strip()) for x in s[1:-1].split(',')]
    addr, _ = parts[-1]
    return addr // 8, sum(w for _, w in parts) // 8


def split_ops(s):
    out, depth, cur = [], 0, ''
    for ch in s:
        if ch in '{[':
            depth += 1
        elif ch in '}]':
            depth -= 1
        if ch == ',' and depth == 0:
            out.append(cur.strip())
            cur = ''
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def hdr(base, off):
    return f'h{base}{off:+d}'


def parse_hdr(s):
    m = re.fullmatch(r'h(\d)([+-]\d+)', s)
    if not m:
        raise ValueError(f'bad header operand {s!r}')
    return int(m[1]), int(m[2])


def keyb(d, n):
    return f'key[{d}..{d + n - 1}]'


def parse_key(s):
    m = re.fullmatch(r'key\[(\d+)\.\.(\d+)\]', s)
    if not m:
        raise ValueError(f'bad key operand {s!r}')
    return int(m[1]), int(m[2]) - int(m[1]) + 1


def sx(v, n):
    return v - (1 << n) if v >> (n - 1) & 1 else v


# ---------------------------------------------------------------- formats
# Each format: match(w, pc) -> dict | None ; text(d, label) -> str ;
# encode(d) -> int ; FIELDS mask (for rest) ; parse(mnemonic, operands) -> dict

class Fmt:
    name = ''
    fixed_mask = 0
    fixed_val = 0
    used = 0          # mask of bits carried by named fields

    @classmethod
    def rest_mask(cls):
        return MASK64 & ~(cls.fixed_mask | cls.used)

    @classmethod
    def match(cls, w, pc):
        if w & cls.fixed_mask != cls.fixed_val:
            return None
        d = cls.fields(w, pc)
        if d is None:
            return None
        d['rest'] = w & cls.rest_mask()
        return d


def suffix(d):
    out = ''
    if d.get('x'):
        out += '.x'
    if d.get('y'):
        out += '.y'
    return out


# Condition selector -> register word (board exp70/77/78, NPU_MCODE.md exp70-79).
# Selector 0 reads constant 0; 8 always read 0 so far; 15 tracks r41 (inferred).
COND_SEL = {1: 12, 2: 2, 3: 8, 4: 9, 5: 10, 6: 11, 7: 32, 9: 36, 10: 40, 11: 44, 12: 0, 13: 1, 14: 13}
SEL_OF_REG = {r: s for s, r in COND_SEL.items()}


def cond_text(c):
    """10-bit execution condition (bits 14:5 of most formats), board exp70:
    bits 9:6 select a 32-bit word, bit 5 inverts, bits 4:0 pick the bit.
        [r8.27]   r8 bit 27 set         [!r8.27]  r8 bit 27 clear
        [0.B]     never (constant 0)    [!0.B]    always; 0x029 = [!0.9] is omitted
        [q8.B]    selector 8 (reads 0 so far)    [q15.B]  selector 15 (r41-like)
    Old listings wrote fW.B (W = 2*sel + inv) and sS.B (sel 8+S, B up to 63)."""
    sel, inv, bit = c >> 6, (c >> 5) & 1, c & 31
    neg = '!' if inv else ''
    if sel == 0:
        return f'{neg}0.{bit}'
    r = COND_SEL.get(sel)
    return f'{neg}r{r}.{bit}' if r is not None else f'{neg}q{sel}.{bit}'


def parse_cond(t):
    m = re.fullmatch(r'(!?)(r|q)(\d+)\.(\d+)', t)
    if m:
        n, bit = int(m[3]), int(m[4])
        if m[2] == 'r':
            if n not in SEL_OF_REG:
                raise ValueError(f'r{n} cannot be tested by a condition')
            sel = SEL_OF_REG[n]
        else:
            sel = n
        return sel << 6 | (m[1] == '!') << 5 | put(bit, 4, 0)
    m = re.fullmatch(r'(!?)0\.(\d+)', t)
    if m:
        return (m[1] == '!') << 5 | put(int(m[2]), 4, 0)
    if t.startswith('f'):  # old listings: fW.B
        word, bit = t[1:].split('.')
        return int(word) << 5 | int(bit)
    if t.startswith('s'):  # old listings: sS.B
        slot, bit = t[1:].split('.')
        return 0x200 | int(slot) << 6 | int(bit)
    return int(t[1:], 16)


def cond_reads(c):
    """Register bit read by a condition (None for constants / unknown selectors)."""
    r = COND_SEL.get(c >> 6)
    return None if r is None else r * 32 + (c & 31)


def prefix(d):
    c = d.get('cond', ALWAYS)
    return '' if c == ALWAYS else f'[{cond_text(c)}] '


def tail(d):
    return f' {{r={d["rest"]:#x}}}' if d.get('rest') else ''


class Nop(Fmt):
    name = 'nop'
    fixed_mask = MASK64
    fixed_val = 0

    @staticmethod
    def fields(w, pc):
        return {}

    @staticmethod
    def text(d, lab):
        return 'nop'

    @staticmethod
    def encode(d):
        return 0


class Br(Fmt):
    """0108: A = PC+1 (implicit), B = target, COND bits 14:5."""
    name = 'br'
    fixed_mask = span((63, 48))
    fixed_val = 0x0108 << 48
    used = span((46, 31), (30, 15), (14, 5))

    @staticmethod
    def fields(w, pc):
        if bits(w, 46, 31) != pc + 1:
            return None
        return {'pc': pc, 'target': bits(w, 30, 15), 'cond': bits(w, 14, 5)}

    @staticmethod
    def text(d, lab):
        return f'{prefix(d)}br {lab(d["target"])}{tail(d)}'

    @staticmethod
    def encode(d):
        return (Br.fixed_val | put(d['pc'] + 1, 46, 31) | put(d['target'], 30, 15)
                | put(d['cond'], 14, 5) | d.get('rest', 0))


# Compare codes: (bit 51, M bits 12:10) -> name. Measured on the board (exp7/exp8,
# PC 3415, value 15 vs V = 14/15/16). Every combination was tested; the ones the
# stock code uses are (0,0) (0,1) (0,4) (1,4)..(1,7). Others keep a raw name.
# (bit 51, bits 12:10) -> relation, board exp72 (all 16, reg and imm forms, unsigned)
CMP_OPS = {(0, 0): 'eq', (0, 1): 'ne', (0, 2): 'z', (0, 3): 'nz',          # a==b, a!=b, a==0, a!=0
           (0, 4): 'tst', (0, 5): 'tstn', (0, 6): 'ntst', (0, 7): 'land',  # a&b!=0, a&~b!=0, a&b==0, a&&b
           (1, 0): 'lnand', (1, 1): 'landn', (1, 2): 'lor', (1, 3): 'lnor',  # !(a&&b), a&&!b, a||b, !(a||b)
           (1, 4): 'gt', (1, 5): 'ge', (1, 6): 'lt', (1, 7): 'le'}
CMP_CODES = {v: k for k, v in CMP_OPS.items()}
CMP_CODES.update({'ge.o': (1, 5), 'lt.o': (1, 6)})  # names in earlier listings


def cmp_op(mode, o):
    return 'b.' + CMP_OPS.get((o, mode), f'm{mode}' + ('.o' if o else ''))


def parse_cmp_op(mn):
    name = mn[2:]
    if name in CMP_CODES:
        o, mode = CMP_CODES[name]
        return mode, o
    o = name.endswith('.o')
    return int(name[1:].split('.')[0]), int(o)  # b.mN[.o]


class Bcmp(Fmt):
    """0290 / 0298: compare W bits at S with literal V, branch to C.

    The compare code is (bit 51, M bits 12:10), measured on the board for all
    16 combinations, see CMP_OPS (e.g. M=4 is >= without bit 51, > with it).
    """
    name = 'b'
    fixed_mask = span((63, 52), (50, 48))
    fixed_val = 0x029 << 52
    used = span((51, 51), (47, 0))

    @staticmethod
    def fields(w, pc):
        return {'target': (bits(w, 47, 41) << 6) | bits(w, 18, 13),
                'value': (bits(w, 29, 19) << 5) | bits(w, 9, 5),
                'src': bits(w, 40, 30), 'width': bits(w, 4, 0) + 1, 'mode': bits(w, 12, 10),
                'o': bits(w, 51, 51)}

    @staticmethod
    def text(d, lab):
        return (f'{cmp_op(d["mode"], d["o"])} {reg(d["src"], d["width"])}, {d["value"]:#x}, '
                f'{lab(d["target"])}')

    @staticmethod
    def encode(d):
        t, v = d['target'], d['value']
        return (Bcmp.fixed_val | put(d.get('o', 0), 51, 51) | put(t >> 6, 47, 41) | put(t & 63, 18, 13)
                | put(v >> 5, 29, 19) | put(v & 31, 9, 5) | put(d['src'], 40, 30)
                | put(d['width'] - 1, 4, 0) | put(d['mode'], 12, 10))


class Bcmpr(Fmt):
    """0690 / 0698: compare W bits at S with W2 bits at register S2 (bits 29:19), branch to C."""
    name = 'b'
    fixed_mask = span((63, 52), (50, 48))
    fixed_val = 0x069 << 52
    used = span((51, 51), (47, 41), (40, 30), (29, 19), (18, 13), (12, 10), (9, 5), (4, 0))

    @staticmethod
    def fields(w, pc):
        return {'target': (bits(w, 47, 41) << 6) | bits(w, 18, 13), 'src': bits(w, 40, 30),
                'width': bits(w, 4, 0) + 1, 'src2': bits(w, 29, 19), 'width2': bits(w, 9, 5) + 1,
                'mode': bits(w, 12, 10), 'o': bits(w, 51, 51)}

    @staticmethod
    def text(d, lab):
        return (f'{cmp_op(d["mode"], d["o"])} {reg(d["src"], d["width"])}, '
                f'{reg(d["src2"], d["width2"])}, {lab(d["target"])}{tail(d)}')

    @staticmethod
    def encode(d):
        t = d['target']
        return (Bcmpr.fixed_val | put(d.get('o', 0), 51, 51) | put(t >> 6, 47, 41) | put(t & 63, 18, 13)
                | put(d['src'], 40, 30) | put(d['width'] - 1, 4, 0) | put(d['src2'], 29, 19)
                | put(d['width2'] - 1, 9, 5) | put(d['mode'], 12, 10) | d.get('rest', 0))


class Loop(Fmt):
    """02c0: counted loop, `loop A, B, K`. Board exp36-39: if r1[23:16] != 0 it is
    decremented and control goes to A, otherwise to B; it never falls through to PC+1.
    The stock code loads the count first (e.g. PC 3186 movi r1[23:16], 0x4 = 5 tries
    of dup.req; PC 1597 a byte count reduced by 7 + 1 per 8-byte cp). K (bits 47:32)
    is 8 in every stock word; its meaning (perhaps the counter field) is untested.
    """
    name = 'loop'
    fixed_mask = span((63, 48))
    fixed_val = 0x02c0 << 48
    used = span((47, 32), (31, 16), (15, 0))

    @staticmethod
    def fields(w, pc):
        return {'start': bits(w, 31, 16), 'target': bits(w, 15, 0), 'k': bits(w, 47, 32)}

    @staticmethod
    def text(d, lab):
        return f'loop {lab(d["start"])}, {lab(d["target"])}, {d["k"]:#x}'

    @staticmethod
    def encode(d):
        return Loop.fixed_val | put(d['k'], 47, 32) | put(d['start'], 31, 16) | put(d['target'], 15, 0)


class _ByteOp(Fmt):
    """Shared layout of 0x070 / 0x075: D bits 51:44, BASE 29:27, OFF 26:17, N-1 bits 4:0."""
    fixed_mask = span((63, 52))
    used = span((51, 44), (29, 27), (26, 17), (15, 15), (14, 5), (4, 0))

    @classmethod
    def fields(cls, w, pc):
        return {'d': bits(w, 51, 44), 'base': bits(w, 29, 27), 'off': sx(bits(w, 26, 17), 10),
                'n': bits(w, 4, 0) + 1, 'cond': bits(w, 14, 5), 'x': bits(w, 15, 15)}

    @classmethod
    def encode(cls, d):
        return (cls.fixed_val | put(d['d'], 51, 44) | put(d['base'], 29, 27)
                | put(d['off'] & 0x3ff, 26, 17) | put(d['n'] - 1, 4, 0) | put(d['cond'], 14, 5)
                | put(d['x'], 15, 15) | d.get('rest', 0))


class Ld(_ByteOp):
    """0x070: register bytes at D <- N packet bytes at BASE+OFF (big-endian value)."""
    name = 'ld'
    fixed_val = 0x070 << 52

    @staticmethod
    def text(d, lab):
        return f'{prefix(d)}ld{suffix(d)} {loaded(d["d"], d["n"])}, {hdr(d["base"], d["off"])}{tail(d)}'


class St(Fmt):
    """0400: N packet bytes at BASE+OFF <- register bytes at A (mirror of 0x070 ld).

    BASE = {bit 16, bits 4:3}, OFF = bits 14:5 (signed), N-1 = bits 2:0,
    A = bits 40:33. Bit 15 (.x) is a flag of unknown meaning.
    """
    name = 'st'
    fixed_mask = span((63, 48))
    fixed_val = 0x0400 << 48
    used = span((40, 33), (16, 16), (15, 15), (14, 5), (4, 3), (2, 0))

    @staticmethod
    def fields(w, pc):
        return {'a': bits(w, 40, 33), 'base': bits(w, 16, 16) << 2 | bits(w, 4, 3),
                'off': sx(bits(w, 14, 5), 10), 'n': bits(w, 2, 0) + 1, 'x': bits(w, 15, 15)}

    @staticmethod
    def text(d, lab):
        return f'st{suffix(d)} {hdr(d["base"], d["off"])}, {loaded(d["a"], d["n"])}{tail(d)}'

    @staticmethod
    def encode(d):
        return (St.fixed_val | put(d['a'], 40, 33) | put(d['base'] >> 2, 16, 16)
                | put(d['base'] & 3, 4, 3) | put(d['off'] & 0x3ff, 14, 5) | put(d['n'] - 1, 2, 0)
                | put(d['x'], 15, 15) | d.get('rest', 0))


class Cp(Fmt):
    """0408: copy N packet bytes from SBASE+SOFF to DBASE+DOFF.

    Source as in ld (BASE bits 29:27, OFF bits 26:17); destination as in st
    (BASE {bit 16, bits 4:3}, OFF bits 14:5); N-1 bits 2:0. Most common uses
    move the MAC addresses and EtherType from h1 to h5 (re-encapsulation).
    """
    name = 'cp'
    fixed_mask = span((63, 48))
    fixed_val = 0x0408 << 48
    used = span((29, 27), (26, 17), (16, 16), (15, 15), (14, 5), (4, 3), (2, 0))

    @staticmethod
    def fields(w, pc):
        return {'sbase': bits(w, 29, 27), 'soff': sx(bits(w, 26, 17), 10),
                'base': bits(w, 16, 16) << 2 | bits(w, 4, 3), 'off': sx(bits(w, 14, 5), 10),
                'n': bits(w, 2, 0) + 1, 'x': bits(w, 15, 15)}

    @staticmethod
    def text(d, lab):
        return (f'cp{suffix(d)} {hdr(d["base"], d["off"])}, {hdr(d["sbase"], d["soff"])}, '
                f'{d["n"]}{tail(d)}')

    @staticmethod
    def encode(d):
        return (Cp.fixed_val | put(d['sbase'], 29, 27) | put(d['soff'] & 0x3ff, 26, 17)
                | put(d['base'] >> 2, 16, 16) | put(d['base'] & 3, 4, 3) | put(d['off'] & 0x3ff, 14, 5)
                | put(d['n'] - 1, 2, 0) | put(d['x'], 15, 15) | d.get('rest', 0))


class Sti(Fmt):
    """0x030: N packet bytes at BASE+OFF <- immediate (bits 50:19, up to 32 bits).

    Destination fields as in st. Samples: h5-2 <- 0x86dd / 0x0800 (EtherType),
    h1+12 <- 0x8100 (VLAN TPID), h1+0 <- 0x88641100 (PPPoE header, 4 bytes).
    """
    name = 'sti'
    fixed_mask = span((63, 52))
    fixed_val = 0x030 << 52
    used = span((50, 19), (16, 16), (15, 15), (14, 5), (4, 3), (2, 0))

    @staticmethod
    def fields(w, pc):
        return {'imm': bits(w, 50, 19), 'base': bits(w, 16, 16) << 2 | bits(w, 4, 3),
                'off': sx(bits(w, 14, 5), 10), 'n': bits(w, 2, 0) + 1, 'x': bits(w, 15, 15)}

    @staticmethod
    def text(d, lab):
        return f'sti{suffix(d)} {hdr(d["base"], d["off"])}, {d["imm"]:#x}, {d["n"]}{tail(d)}'

    @staticmethod
    def encode(d):
        return (Sti.fixed_val | put(d['imm'], 50, 19) | put(d['base'] >> 2, 16, 16)
                | put(d['base'] & 3, 4, 3) | put(d['off'] & 0x3ff, 14, 5) | put(d['n'] - 1, 2, 0)
                | put(d['x'], 15, 15) | d.get('rest', 0))


class Kld(_ByteOp):
    """0x075: key[D..D+N) <- N packet bytes at BASE+OFF."""
    name = 'kld'
    fixed_val = 0x075 << 52

    @staticmethod
    def text(d, lab):
        return f'{prefix(d)}kld{suffix(d)} {keyb(d["d"], d["n"])}, {hdr(d["base"], d["off"])}{tail(d)}'


class Kmov(Fmt):
    """0x055: key[D..D+N) <- 8N bits from bit address SRC."""
    name = 'kmov'
    fixed_mask = span((63, 52))
    fixed_val = 0x055 << 52
    used = span((51, 44), (40, 30), (15, 15), (14, 5), (4, 0))

    @staticmethod
    def fields(w, pc):
        return {'d': bits(w, 51, 44), 'src': bits(w, 40, 30), 'n': bits(w, 4, 0) + 1,
                'cond': bits(w, 14, 5), 'x': bits(w, 15, 15)}

    @staticmethod
    def text(d, lab):
        return f'{prefix(d)}kmov{suffix(d)} {keyb(d["d"], d["n"])}, {reg(d["src"], d["n"] * 8)}{tail(d)}'

    @staticmethod
    def encode(d):
        return (Kmov.fixed_val | put(d['d'], 51, 44) | put(d['src'], 40, 30) | put(d['n'] - 1, 4, 0)
                | put(d['cond'], 14, 5) | put(d['x'], 15, 15) | d.get('rest', 0))


class Kmovi(Fmt):
    """0x015: key[D..D+N) <- immediate, big-endian within the N bytes.

    Board exp34-35 (key read back through key_last_info after a #50 lookup): the
    immediate is the contiguous field bits 40:12 (word bit 12 = value bit 0), so the
    stock `kmovi key[0..2], 0x20` writes 00 00 20 = 32, the byte count of the crc32
    input. Bits 11:5 are 0x29 in every stock word (the 'always' pattern of other
    formats); no conditional form is known, so only that value decodes.
    """
    name = 'kmovi'
    fixed_mask = span((63, 52), (11, 5))
    fixed_val = 0x015 << 52 | ALWAYS << 5
    used = span((51, 44), (40, 12), (4, 0))

    @staticmethod
    def fields(w, pc):
        return {'d': bits(w, 51, 44), 'imm': bits(w, 40, 12), 'n': bits(w, 4, 0) + 1}

    @staticmethod
    def text(d, lab):
        return f'kmovi {keyb(d["d"], d["n"])}, {d["imm"]:#x}{tail(d)}'

    @staticmethod
    def encode(d):
        if d.get('cond', ALWAYS) != ALWAYS or d.get('x') or d.get('y'):
            raise ValueError('kmovi has no condition or suffix')
        return (Kmovi.fixed_val | put(d['d'], 51, 44) | put(d['imm'], 40, 12) | put(d['n'] - 1, 4, 0)
                | d.get('rest', 0))


class Xld(_ByteOp):
    """0x074: copy packet/descriptor bytes to the lookup index buffer.

    Like kld (0x075) but with the index destination of xmov (0x054).
    Both SR1010 sites fill idx[2..3] from h3+24 between zeroing idx[0..1]
    and looking up table 3 by direct index.
    """
    name = 'xld'
    fixed_val = 0x074 << 52

    @staticmethod
    def text(d, lab):
        return (f'{prefix(d)}xld{suffix(d)} idx[{d["d"]}..{d["d"] + d["n"] - 1}], '
                f'{hdr(d["base"], d["off"])}{tail(d)}')


class Xmov(Fmt):
    """0x054: index operand bytes idx[D..D+N) <- 8N bits at SRC (precedes T2/T3 lookups)."""
    name = 'xmov'
    fixed_mask = span((63, 52))
    fixed_val = 0x054 << 52
    used = span((51, 44), (40, 30), (15, 15), (14, 5), (4, 0))

    @staticmethod
    def fields(w, pc):
        return {'d': bits(w, 51, 44), 'src': bits(w, 40, 30), 'n': bits(w, 4, 0) + 1,
                'cond': bits(w, 14, 5), 'x': bits(w, 15, 15)}

    @staticmethod
    def text(d, lab):
        return (f'{prefix(d)}xmov{suffix(d)} idx[{d["d"]}..{d["d"] + d["n"] - 1}], '
                f'{reg(d["src"], d["n"] * 8)}{tail(d)}')

    @staticmethod
    def encode(d):
        return (Xmov.fixed_val | put(d['d'], 51, 44) | put(d['src'], 40, 30) | put(d['n'] - 1, 4, 0)
                | put(d['cond'], 14, 5) | put(d['x'], 15, 15) | d.get('rest', 0))


class Xmovi(Fmt):
    """0x014: index operand bytes idx[D..D+N) <- 18-bit immediate (board exp81/82).

    Measured by looking up our own 64-entry table with the written index:
    value bits 17:3 = word bits 29:15, value bits 2:0 = word bits 4:2; N-1 = bits 1:0
    (1..4 bytes); condition bits 14:5. Bits 40:30 and 13:12 have no visible effect.
    The stock code only ever writes 0; prefer xmov from a register for new code.
    """
    name = 'xmovi'
    fixed_mask = span((63, 52))
    fixed_val = 0x014 << 52
    used = span((51, 44), (29, 15), (14, 5), (4, 2), (1, 0))

    @staticmethod
    def fields(w, pc):
        return {'d': bits(w, 51, 44), 'imm': bits(w, 29, 15) << 3 | bits(w, 4, 2), 'n': bits(w, 1, 0) + 1,
                'cond': bits(w, 14, 5)}

    @staticmethod
    def text(d, lab):
        return f'{prefix(d)}xmovi idx[{d["d"]}..{d["d"] + d["n"] - 1}], {d["imm"]:#x}{tail(d)}'

    @staticmethod
    def encode(d):
        if d.get('x') or not 1 <= d['n'] <= 4:
            raise ValueError('xmovi writes 1..4 bytes and has no .x')
        imm = d['imm']
        put(imm, 17, 0)
        return (Xmovi.fixed_val | put(d['d'], 51, 44) | put(imm >> 3, 29, 15) | put(imm & 7, 4, 2)
                | put(d['n'] - 1, 1, 0) | put(d['cond'], 14, 5) | d.get('rest', 0))


class Mov(Fmt):
    """0x050: W bits at DST <- W bits at SRC; other bits kept, or cleared with .x (board exp40/52)."""
    name = 'mov'
    fixed_mask = span((63, 52))
    fixed_val = 0x050 << 52
    used = span((51, 41), (40, 30), (15, 15), (14, 5), (4, 0))

    @staticmethod
    def fields(w, pc):
        return {'dst': bits(w, 51, 41), 'src': bits(w, 40, 30), 'width': bits(w, 4, 0) + 1,
                'cond': bits(w, 14, 5), 'x': bits(w, 15, 15)}

    @staticmethod
    def text(d, lab):
        # Destination >= r32 is control, not a register write: dst 1024 jumps to the
        # address in the source (board exp79: r30; stock `jr r1` after dup / as return).
        if d['dst'] == 1024 and d['width'] == 1 and d['src'] % 32 == 0 and not d['x']:
            return f'{prefix(d)}jr r{d["src"] // 32}{tail(d)}'
        return (f'{prefix(d)}mov{suffix(d)} {reg(d["dst"], d["width"])}, '
                f'{reg(d["src"], d["width"])}{tail(d)}')

    @staticmethod
    def encode(d):
        return (Mov.fixed_val | put(d['dst'], 51, 41) | put(d['src'], 40, 30)
                | put(d['width'] - 1, 4, 0) | put(d['cond'], 14, 5) | put(d['x'], 15, 15)
                | d.get('rest', 0))


class Movi(Fmt):
    """0x010 with bits 51:48 < 8 (0100..0107): W bits at DST <- 16-bit immediate; other
    bits kept, or the rest of the register cleared with .x (board exp40/52)."""
    name = 'movi'
    fixed_mask = span((63, 52), (51, 51))
    fixed_val = 0x010 << 52
    used = span((50, 41), (40, 25), (15, 15), (14, 5), (4, 0))

    @staticmethod
    def fields(w, pc):
        return {'dst': bits(w, 51, 41), 'imm': bits(w, 40, 25), 'width': bits(w, 4, 0) + 1,
                'cond': bits(w, 14, 5), 'x': bits(w, 15, 15)}

    @staticmethod
    def text(d, lab):
        return f'{prefix(d)}movi{suffix(d)} {reg(d["dst"], d["width"])}, {d["imm"]:#x}{tail(d)}'

    @staticmethod
    def encode(d):
        return (Movi.fixed_val | put(d['dst'], 50, 41) | put(d['imm'], 40, 25)
                | put(d['width'] - 1, 4, 0) | put(d['cond'], 14, 5) | put(d['x'], 15, 15)
                | d.get('rest', 0))


class Movw(Fmt):
    """Wide immediate (bits 63:51 = 0...01): W bits at DST <- immediate, other bits kept.

    DST bits 50:41 (below r32), width-1 bits 4:0, immediate layout measured on the
    board (exp29-32): imm[31:8] = bits 40:17, imm[7] = bit 16, imm[6:0] = bits 14:8.
    Board exp79: any destination / width works (r28[11:4], r28[31:20], ...). The stock
    `movi32 rN` (width 32) and the three PON-mux index words (r31[22:0] <- 0/1/2,
    r31[31:23] kept, exp73) are instances. Bits 15 and 7:5 are zero in every stock word.
    """
    name = 'movw'
    fixed_mask = span((63, 51), (15, 15), (7, 5))
    fixed_val = 1 << 51
    used = span((50, 41), (40, 16), (14, 8), (4, 0))

    @staticmethod
    def fields(w, pc):
        imm = bits(w, 40, 17) << 8 | bits(w, 16, 16) << 7 | bits(w, 14, 8)
        return {'dst': bits(w, 50, 41), 'width': bits(w, 4, 0) + 1, 'imm': imm}

    @staticmethod
    def text(d, lab):
        return f'movw {reg(d["dst"], d["width"])}, {d["imm"]:#x}'

    @classmethod
    def encode(cls, d):
        if d.get('cond', ALWAYS) != ALWAYS or any(d.get(k) for k in ('x', 'y', 'rest')):
            raise ValueError('movw does not support a condition, suffix, or raw bits')
        imm = d['imm']
        put(imm, 31, 0)
        return (cls.fixed_val | put(d['dst'], 50, 41) | put(imm >> 8, 40, 17)
                | put(imm >> 7 & 1, 16, 16) | put(imm & 0x7f, 14, 8) | put(d['width'] - 1, 4, 0))


def _bmov_moves(w, which):
    """(dst bit, src bit, inv, en) for the move groups of 02aa / 0522 (board exp74)."""
    groups = {1: ((11, 7), (4, 0), 5, 6), 2: ((20, 16), (32, 28), 33, 34), 3: ((45, 41), (25, 21), 26, 27)}
    out = []
    for g in which:
        (dh, dl), (sh, sl), inv, en = groups[g]
        out.append((bits(w, dh, dl), bits(w, sh, sl), bits(w, inv, inv), bits(w, en, en)))
    return out


def _bmov_put(moves, which):
    groups = {1: ((11, 7), (4, 0), 5, 6), 2: ((20, 16), (32, 28), 33, 34), 3: ((45, 41), (25, 21), 26, 27)}
    w = 0
    for g, (db, sb, inv, en) in zip(which, moves):
        (dh, dl), (sh, sl), i, e = groups[g]
        w |= put(db, dh, dl) | put(sb, sh, sl) | put(inv, i, i) | put(en, e, e)
    return w


def _bmov_text(dreg, sreg, moves):
    parts = []
    for db, sb, inv, en in moves:
        if en:
            rhs = f'{"!" if inv else ""}r{sreg}.{sb}'
        else:
            rhs = f'{inv}' + (f'@{sb}' if sb else '')
        parts.append(f'r{dreg}.{db}={rhs}')
    return ', '.join(parts)


def _bmov_parse(ops):
    dreg = sreg = None
    moves = []
    for o in ops:
        m = re.fullmatch(r'r(\d+)\.(\d+)=(?:(!?)r(\d+)\.(\d+)|([01])(?:@(\d+))?)', o.replace(' ', ''))
        if not m:
            raise ValueError(f'bmov: bad move {o!r}')
        if dreg not in (None, int(m[1])):
            raise ValueError('bmov: all moves need the same destination register')
        dreg = int(m[1])
        if m[4] is not None:
            if sreg not in (None, int(m[4])):
                raise ValueError('bmov: all moves need the same source register')
            sreg = int(m[4])
            moves.append((int(m[2]), int(m[5]), int(m[3] == '!'), 1))
        else:
            moves.append((int(m[2]), int(m[7] or 0), int(m[6]), 0))
    return dreg, (sreg or 0), moves


class Bmov3(Fmt):
    """02aa: three independent single-bit moves into r(8+K) (board exp73/74/79).

    K bits 48:46, source register bits 40:35 (any of r0..r63), then per move a
    destination bit, source bit, invert and enable:
        move 1: dst 11:7,  src 4:0,   inv 5,  en 6
        move 2: dst 20:16, src 32:28, inv 33, en 34
        move 3: dst 45:41, src 25:21, inv 26, en 27
    result = en ? src ^ inv : inv. Bit 15 (.x) clears the rest of the destination
    register; bits 14:12 have no visible effect. The entry template uses four of
    these to copy packet-class bits from the descriptor words r25/r27/r29 into r8
    (e.g. PC 5009: r8.27 <- r25.23 IPv4, r8.26 <- r25.22 IPv6). Shown as
    `bmov r8.9=r25.24, ...`; a disabled move is written `r8.9=0` / `r8.9=1`.
    """
    name = 'bmov'
    fixed_mask = span((63, 49))
    fixed_val = 0x02aa << 48
    used = span((48, 46), (45, 41), (40, 35), (34, 16), (15, 15), (11, 0))
    which = (1, 2, 3)

    @classmethod
    def fields(cls, w, pc):
        return {'k': bits(w, 48, 46), 'sreg': bits(w, 40, 35), 'x': bits(w, 15, 15),
                'moves': _bmov_moves(w, cls.which)}

    @classmethod
    def text(cls, d, lab):
        return (f'{prefix(d)}bmov{suffix(d)} {_bmov_text(8 + d["k"], d["sreg"], d["moves"])}{tail(d)}')

    @classmethod
    def encode(cls, d):
        return (cls.fixed_val | put(d['k'], 48, 46) | put(d['sreg'], 40, 35) | put(d.get('x', 0), 15, 15)
                | _bmov_put(d['moves'], cls.which) | d.get('rest', 0))


class Bmov2(Bmov3):
    """0522: conditional form with two moves (groups 2 and 3 of 02aa), condition in
    bits 14:5 (board exp74: flipping bit 10 turns the stock word into a no-op).
    The stock word copies r20.29 -> r8.8 and r20.31 -> r8.31 (descriptor h3+8)."""
    fixed_val = 0x0522 << 48
    used = span((48, 46), (45, 41), (40, 35), (34, 16), (15, 15), (14, 5))
    which = (2, 3)

    @classmethod
    def fields(cls, w, pc):
        d = super().fields.__func__(cls, w, pc)
        d['cond'] = bits(w, 14, 5)
        return d

    @classmethod
    def encode(cls, d):
        return super().encode.__func__(cls, d) | put(d.get('cond', ALWAYS), 14, 5)


class _AluImm(Fmt):
    """0x020 / 0x021: DST (W bits) <- SRC OP IMM.

    DST bits 51:41, SRC bits 40:30, IMM bits 29:14, dst width bits 4:0 + 1,
    src width bits 9:5 + 1 (always equal in both images). 0x021 decrements
    IPv4 TTL / IPv6 hop limit by 1 (so: subtract); 0x020 adds the table-48
    category bases (so: add).
    """
    fixed_mask = span((63, 52))
    used = span((51, 41), (40, 30), (29, 14), (9, 5), (4, 0))

    @staticmethod
    def fields(w, pc):
        return {'dst': bits(w, 51, 41), 'src': bits(w, 40, 30), 'imm': bits(w, 29, 14),
                'width': bits(w, 4, 0) + 1, 'swidth': bits(w, 9, 5) + 1}

    @classmethod
    def text(cls, d, lab):
        return (f'{cls.name} {reg(d["dst"], d["width"])}, {reg(d["src"], d["swidth"])}, '
                f'{d["imm"]:#x}{tail(d)}')

    @classmethod
    def encode(cls, d):
        return (cls.fixed_val | put(d['dst'], 51, 41) | put(d['src'], 40, 30) | put(d['imm'], 29, 14)
                | put(d['width'] - 1, 4, 0) | put(d['swidth'] - 1, 9, 5) | d.get('rest', 0))


class Addi(_AluImm):
    name = 'addi'
    fixed_val = 0x020 << 52


class Subi(_AluImm):
    name = 'subi'
    fixed_val = 0x021 << 52


LOGIC_OPS = ('and', 'andn', 'andc', 'nor', 'nand', 'orc', 'orn', 'or')
# board exp90 (bit 51 set, mode bits 12:10): a&b, a&~b, ~a&b, ~(a|b), ~(a&b), ~a|b, a|~b, a|b;
# bit 13 has no effect; bit 51 clear: a^b, inverted when the mode bits have odd parity
# (exp92); decoded as xor (mode 0) / xnor (mode 1).


class LogicImm(_AluImm):
    """0x022: bitwise DST <- SRC op IMM (board exp90). Bit 51 set: op = LOGIC_OPS[bits 12:10];
    bit 51 clear with bits 13:10 = 0: xor. Printed with an 'i' suffix (andi, ori, xori...).
    Stock: ZX133 FTTR flag merges `ori r20[15:0], r20[15:0], 0x3` etc."""
    name = 'logici'
    fixed_mask = span((63, 52), (13, 13))
    fixed_val = 0x022 << 52
    used = span((51, 41), (40, 30), (29, 14), (12, 10), (9, 5), (4, 0))

    @staticmethod
    def fields(w, pc):
        d = _AluImm.fields(w & ~(1 << 51), pc)
        b51, mode = bits(w, 51, 51), bits(w, 12, 10)
        if not b51 and mode > 1:
            return None
        d['op'] = LOGIC_OPS[mode] if b51 else ('xor', 'xnor')[mode]
        return d

    @staticmethod
    def text(d, lab):
        return (f'{d["op"]}i {reg(d["dst"], d["width"])}, {reg(d["src"], d["swidth"])}, '
                f'{d["imm"]:#x}{tail(d)}')

    @staticmethod
    def encode(d):
        if d['dst'] >= 1 << 10:
            raise ValueError('logic op: destination must be below r32')
        b51, mode = (0, ('xor', 'xnor').index(d['op'])) if d['op'] in ('xor', 'xnor') else (1, LOGIC_OPS.index(d['op']))
        return (LogicImm.fixed_val | put(b51, 51, 51) | put(d['dst'], 50, 41) | put(d['src'], 40, 30)
                | put(d['imm'], 29, 14) | put(mode, 12, 10) | put(d['swidth'] - 1, 9, 5)
                | put(d['width'] - 1, 4, 0) | d.get('rest', 0))


class _ShiftImm(_AluImm):
    """Immediate shifts, bit 51 set, bits 13:10 zero (they have no effect, exp90)."""
    fixed_mask = span((63, 51), (13, 10))
    used = span((50, 41), (40, 30), (29, 14), (9, 5), (4, 0))

    @staticmethod
    def fields(w, pc):
        d = _AluImm.fields(w & ~(1 << 51), pc)
        if d['width'] != d['swidth'] or d['imm'] > 31:
            return None
        return d

    @classmethod
    def encode(cls, d):
        if d['dst'] >= 1 << 10 or d['width'] != d['swidth'] or not 0 <= d['imm'] <= 31:
            raise ValueError(f'{cls.name}: expected a low destination, equal widths and shift 0..31')
        return super().encode(d)


class Shli(_ShiftImm):
    """0x024, bit 51 set: shift left within the field (board exp90/91), e.g. IPv4 IHL in
    bytes (ZX133 1380)."""
    name = 'shli'
    fixed_val = 0x0248 << 48


class Maski(_ShiftImm):
    """0x024, bit 51 clear: DST <- SRC & (2^N - 1), keep the low N bits (board exp92)."""
    name = 'maski'
    fixed_val = 0x0240 << 48


class Rotli(_ShiftImm):
    """0x025, bit 51 set: rotate left within the field width (board exp90/91)."""
    name = 'rotli'
    fixed_val = 0x0258 << 48


class Shri(_ShiftImm):
    """0x025, bit 51 clear: logical shift right (board exp92), e.g. byte length to 8-byte
    copy count (SR1010 3206)."""
    name = 'shri'
    fixed_val = 0x0250 << 48


class _AluReg(Fmt):
    """0x060 / 0x061: DST <- SRC OP SRC2, SRC2 a register at bits 29:19 (bits 18:10 always 0).

    Register counterparts of addi/subi (the middle opcode nibble gains the
    'register source' bit, as 0x010 -> 0x050 and 0290 -> 0690).
    """
    fixed_mask = span((63, 52))
    used = span((51, 41), (40, 30), (29, 19), (9, 5), (4, 0))

    @staticmethod
    def fields(w, pc):
        return {'dst': bits(w, 51, 41), 'src': bits(w, 40, 30), 'src2': bits(w, 29, 19),
                'width': bits(w, 4, 0) + 1, 'swidth': bits(w, 9, 5) + 1}

    @classmethod
    def text(cls, d, lab):
        # Board exp33: the first source has the destination's width; bits 9:5 size SRC2.
        return (f'{cls.name} {reg(d["dst"], d["width"])}, {reg(d["src"], d["width"])}, '
                f'{reg(d["src2"], d["swidth"])}{tail(d)}')

    @classmethod
    def encode(cls, d):
        return (cls.fixed_val | put(d['dst'], 51, 41) | put(d['src'], 40, 30) | put(d['src2'], 29, 19)
                | put(d['width'] - 1, 4, 0) | put(d['swidth'] - 1, 9, 5) | d.get('rest', 0))


class Add(_AluReg):
    name = 'add'
    fixed_val = 0x060 << 52


class Sub(_AluReg):
    name = 'sub'
    fixed_val = 0x061 << 52


class LogicReg(_AluReg):
    """0x062: bitwise DST <- SRC op SRC2, equal widths (board exp90/91). Bit 51 set:
    op = LOGIC_OPS[bits 12:10], bits 18:13 zero; bit 51 clear and bits 18:10 zero: xor.
    `nor` with tied sources is printed `not dst, src` (SR1010 policer colour words,
    earlier called movbit; exp91 shows they invert)."""
    name = 'logic'
    fixed_mask = span((63, 52), (18, 13))
    fixed_val = 0x062 << 52
    used = span((51, 41), (40, 30), (29, 19), (12, 10), (9, 5), (4, 0))

    @staticmethod
    def fields(w, pc):
        d = _AluReg.fields(w & ~(1 << 51), pc)
        b51, mode = bits(w, 51, 51), bits(w, 12, 10)
        if d['width'] != d['swidth'] or (not b51 and mode > 1):
            return None
        d['op'] = LOGIC_OPS[mode] if b51 else ('xor', 'xnor')[mode]
        return d

    @staticmethod
    def text(d, lab):
        if d['op'] == 'nor' and d['src'] == d['src2']:
            return f'not {reg(d["dst"], d["width"])}, {reg(d["src"], d["width"])}{tail(d)}'
        return (f'{d["op"]} {reg(d["dst"], d["width"])}, {reg(d["src"], d["width"])}, '
                f'{reg(d["src2"], d["swidth"])}{tail(d)}')

    @staticmethod
    def encode(d):
        if d['dst'] >= 1 << 10 or d['width'] != d['swidth']:
            raise ValueError('logic op: destination below r32 and equal operand widths')
        b51, mode = (0, ('xor', 'xnor').index(d['op'])) if d['op'] in ('xor', 'xnor') else (1, LOGIC_OPS.index(d['op']))
        return (LogicReg.fixed_val | put(b51, 51, 51) | put(d['dst'], 50, 41) | put(d['src'], 40, 30)
                | put(d['src2'], 29, 19) | put(mode, 12, 10) | put(d['swidth'] - 1, 9, 5)
                | put(d['width'] - 1, 4, 0) | d.get('rest', 0))


class _ShiftReg(_AluReg):
    """0x064 / 0x065: register-amount counterparts of shli/maski/rotli/shri; the amount is
    SRC2 with its own width (bits 9:5), bits 18:10 zero (board exp90/92)."""
    fixed_mask = span((63, 51), (18, 10))
    used = span((50, 41), (40, 30), (29, 19), (9, 5), (4, 0))

    @staticmethod
    def fields(w, pc):
        return _AluReg.fields(w & ~(1 << 51), pc)

    @classmethod
    def text(cls, d, lab):
        return (f'{cls.name} {reg(d["dst"], d["width"])}, {reg(d["src"], d["width"])}, '
                f'{reg(d["src2"], d["swidth"])}{tail(d)}')

    @classmethod
    def encode(cls, d):
        if d['dst'] >= 1 << 10:
            raise ValueError(f'{cls.name}: destination must be below r32')
        return super().encode(d)


class Shl(_ShiftReg):
    name = 'shl'
    fixed_val = 0x0648 << 48


class Mask(_ShiftReg):
    name = 'mask'
    fixed_val = 0x0640 << 48


class Rotl(_ShiftReg):
    name = 'rotl'
    fixed_val = 0x0658 << 48


class Shr(_ShiftReg):
    name = 'shr'
    fixed_val = 0x0650 << 48


class Csum(Fmt):
    """0x068 with bits 13:0 = 0x000f: 16-bit incremental checksum update (RFC 1624 style).

    DST bits 51:41 <- SRC bits 40:30 adjusted for OLD (bits 29:19) replaced by NEW,
    NEW = same 32-bit word as OLD at bit offset bits 18:14. In both images
    DST == SRC, OLD is 16-bit aligned and NEW sits in the other half; the result
    is stored to the IPv4 header checksum (h5+10) after TTL / TOS rewrites.
    """
    name = 'csum'
    fixed_mask = span((63, 51), (13, 0))
    fixed_val = 0x068 << 52 | 0x000f
    used = span((50, 41), (40, 30), (29, 19), (18, 14))

    @staticmethod
    def fields(w, pc):
        return {'dst': bits(w, 50, 41), 'src': bits(w, 40, 30), 'old': bits(w, 29, 19),
                'new': (bits(w, 29, 19) & ~31) | bits(w, 18, 14)}

    @staticmethod
    def text(d, lab):
        return (f'csum {reg(d["dst"], 16)}, {reg(d["src"], 16)}, {reg(d["old"], 16)}, '
                f'{reg(d["new"], 16)}{tail(d)}')

    @staticmethod
    def encode(d):
        if d['new'] >> 5 != d['old'] >> 5:
            raise ValueError('csum: new value must be in the same 32-bit word as old')
        return (Csum.fixed_val | put(d['dst'], 50, 41) | put(d['src'], 40, 30) | put(d['old'], 29, 19)
                | put(d['new'] & 31, 18, 14) | d.get('rest', 0))


CSET_REL = ('eq', 'ne', 'z', 'nz', 'tst', 'tstn', 'land', 'landn', 'lor', 'lorn')
# board exp79: a==b, a!=b, a==0, a!=0, a&b!=0, a&~b!=0, a&&b, a&&!b, a||b, a||!b; 10-15 give 0


def cset_rel(code):
    return CSET_REL[code] if code < len(CSET_REL) else f'c{code}'


def parse_cset_rel(name):
    return CSET_REL.index(name) if name in CSET_REL else int(name[1:])


class Cset(Fmt):
    """028a/028b: one bit of r(8 + K) <- (W bits at SRC) REL IMM (board exp73/74/79).

    K bits 48:46 (r8..r15), bit index 45:41, SRC 40:30, IMM 29:14, relation code
    bits 13:10 (see CSET_REL), W-1 bits 4:0; bits 9:5 are unused (zero). Only the
    'positive' relations exist; the complement is read with an inverted condition.
    Example: SR1010 PC 365 `cset.tst r8[0], r20[15:0], 0x7fc0` (IPv4 fragment bits).
    """
    name = 'cset'
    fixed_mask = span((63, 49))
    fixed_val = 0x028a << 48
    used = span((48, 46), (45, 41), (40, 30), (29, 14), (13, 10), (4, 0))

    @staticmethod
    def fields(w, pc):
        return {'k': bits(w, 48, 46), 'idx': bits(w, 45, 41), 'src': bits(w, 40, 30),
                'imm': bits(w, 29, 14), 'code': bits(w, 13, 10), 'width': bits(w, 4, 0) + 1}

    @staticmethod
    def text(d, lab):
        dst = reg((8 + d['k']) * 32 + d['idx'], 1)
        return (f'cset.{cset_rel(d["code"])} {dst}, {reg(d["src"], d["width"])}, '
                f'{d["imm"]:#x}{tail(d)}')

    @classmethod
    def encode(cls, d):
        return (cls.fixed_val | put(d['k'], 48, 46) | put(d['idx'], 45, 41) | put(d['src'], 40, 30)
                | put(d['imm'], 29, 14) | put(d['code'], 13, 10) | put(d['width'] - 1, 4, 0)
                | d.get('rest', 0))


class CsetR(Fmt):
    """068a/068b: register form of cset (board exp74/79): SRC2 bits 29:19 with its
    width in bits 9:5, relation code bits 13:10; bits 18:14 unused (zero)."""
    name = 'cset'
    fixed_mask = span((63, 49))
    fixed_val = 0x068a << 48
    used = span((48, 46), (45, 41), (40, 30), (29, 19), (13, 10), (9, 5), (4, 0))

    @staticmethod
    def fields(w, pc):
        return {'k': bits(w, 48, 46), 'idx': bits(w, 45, 41), 'src': bits(w, 40, 30),
                'src2': bits(w, 29, 19), 'code': bits(w, 13, 10), 'width': bits(w, 4, 0) + 1,
                'swidth': bits(w, 9, 5) + 1}

    @staticmethod
    def text(d, lab):
        dst = reg((8 + d['k']) * 32 + d['idx'], 1)
        return (f'cset.{cset_rel(d["code"])} {dst}, {reg(d["src"], d["width"])}, '
                f'{reg(d["src2"], d["swidth"])}{tail(d)}')

    @classmethod
    def encode(cls, d):
        return (cls.fixed_val | put(d['k'], 48, 46) | put(d['idx'], 45, 41) | put(d['src'], 40, 30)
                | put(d['src2'], 29, 19) | put(d['code'], 13, 10) | put(d['swidth'] - 1, 9, 5)
                | put(d['width'] - 1, 4, 0) | d.get('rest', 0))


class Cmd(Fmt):
    """0018 with table id 0, slot 0 and no other bits: packet-disposition commands
    (board exp18-20, PC 3443/3429 swapped while pinging):
      fam 0x0              send      normal end of the thread, the packet goes out
      fam 0x20             drop      packet discarded, no drop-reason counter
      fam 0x40 + 0x20*k    drop.err k  discarded and ppu drop_status reason k is set
                           (0 illegal_instr, 1 rsp drop, 2 memory overflow, 3 busy,
                           4 err flownum/dup table, 5 packet slice error; 6..13 no counter)
      fam (n << 9) | 1     dup n     replicate via dup table entry n (static: ZX133 entries
                           1/2 start at PC 3194/3300, right after the two dup commands)
      fam 0x7              dup.req   precedes every dup; sets slot-0 status bit 31 (r14.31),
                           which the stock code requires before dup, retrying up to 8 times
                           (board exp23: r14.31 0 -> 1; 'resource request' is inferred)
    The vendor fills unloaded RAM with drop.err 0, so a stray jump reports illegal_instr."""
    name = 'cmd'
    fixed_mask = MASK64 & ~span((22, 0))
    fixed_val = 0x0018 << 48

    @staticmethod
    def fields(w, pc):
        fam = bits(w, 22, 0)
        if fam in (0, 0x20):
            return {'op': ('send', 'drop')[fam >> 5]}
        if fam == 7:
            return {'op': 'dup.req'}
        if fam & 0x1f == 0 and 2 <= fam >> 5 <= 15:
            return {'op': 'drop.err', 'k': (fam >> 5) - 2}
        if fam & 0x1ff == 1 and fam >> 9 < 16:
            return {'op': 'dup', 'k': fam >> 9}
        return None

    @staticmethod
    def text(d, lab):
        return d['op'] + (f' {d["k"]}' if 'k' in d else '')

    @staticmethod
    def encode(d):
        op, k = d['op'], d.get('k', 0)
        fam = {'send': 0, 'drop': 0x20, 'dup.req': 7}.get(op)
        if op == 'drop.err':
            fam = put(k, 3, 0) * 0x20 + 0x40
        elif op == 'dup':
            fam = put(k, 3, 0) << 9 | 1
        if fam is None:
            raise ValueError(f'bad cmd {op!r}')
        return Cmd.fixed_val | fam


class Crc(Fmt):
    """0018 with table id 0 and fam 0x9: CRC-32 of the 32 key bytes key[3..34] into the
    slot's result word (s0 -> r32). Board exp22: poly 0x04C11DB7, MSB first, init 0,
    xorout 0; all-zero key -> 0; a single 0x20 byte (kmovi field bit 17, see Kmovi) at
    key[34] / key[6] gave x^37 / x^261 mod P, i.e. exactly the CRC of those bytes. The
    3-byte prefix written by the stock code is 32 = the input length. Used to compress IPv6 addresses
    for the #164 fast-path key (driver: tm_set_ipv6_crc_compress_mode)."""
    name = 'crc32'
    fixed_mask = MASK64 & ~span((24, 23))
    fixed_val = 0x0018 << 48 | 0x9

    @staticmethod
    def fields(w, pc):
        return {'slot': bits(w, 24, 23)}

    @staticmethod
    def text(d, lab):
        return f'crc32 s{d["slot"]}'

    @staticmethod
    def encode(d):
        return Crc.fixed_val | put(d['slot'], 24, 23)


class End(Fmt):
    """0088000000000000 (high section only): ends the thread without sending; on the
    board (exp19, PC 3429) the packet vanished and no drop reason was set."""
    name = 'end'
    fixed_mask = MASK64
    fixed_val = 0x0088 << 48

    @staticmethod
    def fields(w, pc):
        return {}

    @staticmethod
    def text(d, lab):
        return 'end'

    @staticmethod
    def encode(d):
        return End.fixed_val


LKUP_OPS = {2: 'idx', 3: 'stat', 4: 'hash', 5: 'ins', 6: 'dpi', 7: 'ptr', 8: 'crc16', 9: 'crc32',
            10: 'div', 11: 'crc16div', 12: 'crc32div', 13: 'rnddiv', 14: 'mul16', 15: 'cksum',
            16: 'and64', 17: 'glock17', 18: 'glock18'}
LKUP_NAMES = {v: k for k, v in LKUP_OPS.items()}


class Lkup(Fmt):
    """0018: search-engine request. ID bits 36:29 = SDT number, SLOT bits 24:23, FAM
    bits 22:0 (board exp80-91): bits 4:0 = operation (LKUP_OPS), bit 22 = result in the
    upper half of the slot (+2 words, '.h'), bits 21:5 = further fields (shown raw).
    The result lands in r(32+4*SLOT) (+2 with .h).
      idx: eRAM by idx[0..3]; stat: counter, word 1 = value; hash: key[], miss = bit 31;
      ins: insert key[] + data (key absent only);
      crc16/crc32: CRC of key[3..3+L), L = key[2] in 1..45, key[0..1] ignored (exp98c);
      crc16div/crc32div: that CRC divided by key[0..1]: word 0 = quotient, word 1 =
      remainder; divisor 0 drops (exp98b/c); cksum: ~ones-complement sum of key[4..4+L),
      L = key[0], even, 2..40, in word 0 [31:16] (exp98b/c); the table id is ignored by
      all of ops 8-16. div: k0 / k1, k0 % k1; rnddiv: random / k0, random % k0;
      mul16: k0[31:16] * k0[15:0]; and64: key[0..7] & key[8..15];
      dpi / ptr / glock: SE channels of those names.
    Op 19 (0x13, SR1010 only) breaks the path to the CPU when misused (exp88)."""
    name = 'lkup'
    fixed_mask = span((63, 48))
    fixed_val = 0x0018 << 48
    used = span((36, 29), (24, 23), (22, 0))

    @staticmethod
    def fields(w, pc):
        return {'id': bits(w, 36, 29), 'fam': bits(w, 22, 0), 'slot': bits(w, 24, 23)}

    @staticmethod
    def text(d, lab):
        fam = d['fam']
        op = fam & 31
        name = LKUP_OPS.get(op, f'op{op}')
        h = '.h' if fam >> 22 & 1 else ''
        fx = fam >> 5 & 0x1ffff
        return f'lkup.{name}{h} s{d["slot"]}, #{d["id"]}' + (f', {fx:#x}' if fx else '') + tail(d)

    @staticmethod
    def encode(d):
        return (Lkup.fixed_val | put(d['id'], 36, 29) | put(d['fam'], 22, 0) | put(d['slot'], 24, 23)
                | d.get('rest', 0))


class Clr(Fmt):
    """0x001 with bit 51 clear: W bits at DST <- 0 (board exp77/79).

    DST bits 50:41 (11-bit bit address, below r32), W-1 bits 4:0. Bit 16 (.hi) also
    clears everything above the field up to bit 31 of that register (exp79). With a
    destination >= r32 the same opcode is the lookup / command group (0018).
    Earlier listings wrote this as op01.N[.a][.b] sS, W (the address split in pieces);
    e.g. `op01.7 s2, 32` = `clr r30`, the first instruction of the counter idiom.
    """
    name = 'clr'
    fixed_mask = span((63, 51))
    fixed_val = 0x001 << 52
    used = span((50, 41), (16, 16), (4, 0))

    @staticmethod
    def fields(w, pc):
        return {'dst': bits(w, 50, 41), 'width': bits(w, 4, 0) + 1, 'hi': bits(w, 16, 16)}

    @staticmethod
    def text(d, lab):
        return f'clr{".hi" if d["hi"] else ""} {reg(d["dst"], d["width"])}{tail(d)}'

    @staticmethod
    def encode(d):
        return (Clr.fixed_val | put(d['dst'], 50, 41) | put(d.get('hi', 0), 16, 16)
                | put(d['width'] - 1, 4, 0) | d.get('rest', 0))


class Op110(Fmt):
    """0110: conditional call. Target in bits 29:15, condition in bits 14:5.

    Board exp28: jumps to the target and sets r1[15:0] = PC+1 (read back exactly);
    op510 then returns there. Printed as `call`. Encodings whose low bits do not fit
    the condition form stay raw as `op110 SEL, VAL`.
    """
    name = 'op110'
    fixed_mask = span((63, 48))
    fixed_val = 0x0110 << 48
    used = span((29, 14), (13, 0))

    @classmethod
    def fields(cls, w, pc):
        d = {'val': bits(w, 29, 14), 'sel': bits(w, 13, 0)}
        if not w & (cls.rest_mask() | 31):
            d['cond'] = bits(w, 14, 5)
        return d

    @staticmethod
    def address(d):
        if 'cond' in d:
            return d['val'] >> 1
        return None

    @staticmethod
    def text(d, lab):
        addr = Op110.address(d)
        if addr is not None:
            return f'{prefix(d)}call {lab(addr)}'
        return f'op110 {d["sel"]:#x}, {d["val"]}{tail(d)}'

    @staticmethod
    def encode(d):
        return Op110.fixed_val | put(d['val'], 29, 14) | put(d['sel'], 13, 0) | d.get('rest', 0)


class Op510(Fmt):
    """Exact 0510 word: jump to r1[15:0] (board exp28), i.e. return after `call`.
    Before the VLAN dispatch tables the code first adds an action number and 6 to
    r1[15:0], making it a computed jump. Printed as `ret`; only this encoding."""
    name = 'op510'
    fixed_mask = MASK64
    fixed_val = 0x0510000800000520

    @staticmethod
    def fields(w, pc):
        return {}

    @staticmethod
    def text(d, lab):
        return 'ret'

    @classmethod
    def encode(cls, d):
        return cls.fixed_val


FORMATS = (Nop, Br, Bcmp, Bcmpr, Loop, Ld, St, Sti, Cp, Kld, Kmov, Kmovi, Xld, Xmov, Xmovi, Mov, Movi, Movw,
           Bmov2, Addi, Subi, LogicImm, Shli, Maski, Rotli, Shri, Add, Sub, LogicReg, Shl, Mask, Rotl, Shr, Csum, Cset, CsetR, Bmov3,
           Cmd, Crc, End, Lkup, Clr, Op110, Op510)
BRANCHES = (Br, Bcmp, Bcmpr, Loop)


def code_targets(f, d):
    """All code addresses carried by a decoded instruction (for labels / relocation)."""
    if f is Loop:
        return (d['start'], d['target'])
    if f in BRANCHES:
        return (d['target'],)
    if f is Op110 and (addr := f.address(d)) is not None:
        return (addr,)
    return ()


def decode(w, pc):
    for f in FORMATS:
        d = f.match(w, pc)
        if d is not None and f.encode(d) == w:  # belt and braces: never lose a bit
            return f, d
    return None, None


# Three stock dispatchers use an explicit base and fixed-step table. These
# checks protect the layout but do not model the general semantics of op510.
DISPATCH_DELTA = 6
DISPATCH_ENTRIES = 16


def dispatch_shape(words, base):
    """Observed dispatcher at `base - 1`, with 16 contiguous branch slots."""
    first = base + DISPATCH_DELTA
    end = first + DISPATCH_ENTRIES
    if base < 1 or end >= len(words) or words[first - 1] != Op510.fixed_val:
        return False
    d = Op110.match(words[base - 1], base - 1)
    if not d or d.get('cond') != ALWAYS or Op110.address(d) != base:
        return False
    offset = {'dst': 32, 'src': 32, 'width': 16, 'swidth': 16, 'imm': DISPATCH_DELTA, 'rest': 0}
    if not any(Addi.match(words[i], i) == offset for i in range(base, first - 1)):
        return False
    return all((d := Br.match(words[i], i)) and d['cond'] == ALWAYS for i in range(first, end))


def dispatch_bases(words):
    return [i - DISPATCH_DELTA + 1 for i, w in enumerate(words)
            if w == Op510.fixed_val and dispatch_shape(words, i - DISPATCH_DELTA + 1)]


# ---------------------------------------------------------------- parsing

COND_RE = re.compile(r'^\[(!?[rq]\d+\.\d+|!?0\.\d+|c[0-9a-f]{3}|s[0-3]\.\d+|f\d+\.\d+)\]\s+')
REST_RE = re.compile(r'\s*\{r=(0x[0-9a-f]+)\}$')


def parse(text, pc, labels):
    """Parse one instruction (no label, no comment) at `pc`; return the 64-bit word."""
    s = text.strip()
    d = {'cond': ALWAYS, 'rest': 0, 'x': 0}
    m = COND_RE.match(s)
    if m:
        d['cond'] = parse_cond(m[1])
        s = s[m.end():]
    m = REST_RE.search(s)
    if m:
        d['rest'] = int(m[1], 16)
        s = s[:m.start()]
    mn, _, ops = s.partition(' ')
    ops = split_ops(ops)
    if mn.endswith('.y'):
        d['y'] = 1
        mn = mn[:-2]
    if mn.endswith('.x'):
        d['x'] = 1
        mn = mn[:-2]

    def target(o):
        if o in labels:
            return labels[o]
        if o.startswith('#'):
            return int(o[1:])
        raise ValueError(f'unknown label {o!r}')

    if mn == '.word':
        return int(ops[0], 16)
    if mn == 'nop':
        return 0
    if mn == 'loop':
        return Loop.encode({'start': target(ops[0]), 'target': target(ops[1]), 'k': int(ops[2], 0)})
    if mn == 'br':
        return Br.encode({**d, 'pc': pc, 'target': target(ops[0])})
    if mn.startswith('b.'):
        mode, o = parse_cmp_op(mn)
        src, width = parse_reg(ops[0])
        if ops[1].startswith(('r', 'm[')):
            src2, width2 = parse_reg(ops[1])
            return Bcmpr.encode({**d, 'target': target(ops[2]), 'src': src, 'width': width,
                                 'src2': src2, 'width2': width2, 'mode': mode, 'o': o})
        return Bcmp.encode({'target': target(ops[2]), 'value': int(ops[1], 0), 'src': src,
                            'width': width, 'mode': mode, 'o': o})
    if mn in ('ld', 'kld', 'xld'):
        base, off = parse_hdr(ops[1])
        if mn == 'ld':
            dd, n = parse_loaded(ops[0])
        elif mn == 'kld':
            dd, n = parse_key(ops[0])
        else:
            m = re.fullmatch(r'idx\[(\d+)\.\.(\d+)\]', ops[0])
            if not m:
                raise ValueError('xld: expected an index byte range')
            dd, n = int(m[1]), int(m[2]) - int(m[1]) + 1
        f = {'ld': Ld, 'kld': Kld, 'xld': Xld}[mn]
        return f.encode({**d, 'd': dd, 'n': n, 'base': base, 'off': off})
    if mn == 'st':
        base, off = parse_hdr(ops[0])
        a, n = parse_loaded(ops[1])
        return St.encode({**d, 'a': a, 'n': n, 'base': base, 'off': off})
    if mn == 'sti':
        base, off = parse_hdr(ops[0])
        return Sti.encode({**d, 'base': base, 'off': off, 'imm': int(ops[1], 0), 'n': int(ops[2])})
    if mn == 'cp':
        base, off = parse_hdr(ops[0])
        sbase, soff = parse_hdr(ops[1])
        return Cp.encode({**d, 'base': base, 'off': off, 'sbase': sbase, 'soff': soff,
                          'n': int(ops[2])})
    if mn == 'kmovi':
        dd, n = parse_key(ops[0])
        return Kmovi.encode({**d, 'd': dd, 'n': n, 'imm': int(ops[1], 0)})
    if mn == 'kmov':
        dd, n = parse_key(ops[0])
        src, _ = parse_reg(ops[1])
        return Kmov.encode({**d, 'd': dd, 'n': n, 'src': src})
    if mn in ('xmov', 'xmovi'):
        m = re.fullmatch(r'idx\[(\d+)\.\.(\d+)\]', ops[0])
        dd, n = int(m[1]), int(m[2]) - int(m[1]) + 1
        if mn == 'xmov':
            src, _ = parse_reg(ops[1])
            return Xmov.encode({**d, 'd': dd, 'n': n, 'src': src})
        return Xmovi.encode({**d, 'd': dd, 'n': n, 'imm': int(ops[1], 0)})
    if mn == 'mov':
        dst, width = parse_reg(ops[0])
        src, _ = parse_reg(ops[1])
        return Mov.encode({**d, 'dst': dst, 'src': src, 'width': width})
    if mn == 'jr':
        m = re.fullmatch(r'r(\d+)', ops[0]) if len(ops) == 1 else None
        if not m or d['x']:
            raise ValueError('jr expects one whole register')
        return Mov.encode({**d, 'dst': 1024, 'src': int(m[1]) * 32, 'width': 1})
    if mn in ('movbit', 'not'):  # movbit: earlier name of the SR1010 policer 'not' words
        if len(ops) != 2:
            raise ValueError(f'{mn} expects a destination and one source')
        dst, width = parse_reg(ops[0])
        src, swidth = parse_reg(ops[1])
        if mn == 'movbit' and (width != 1 or d['cond'] != ALWAYS or d['x']):
            raise ValueError('movbit (earlier name) only for one-bit operands')
        return LogicReg.encode({**d, 'op': 'nor', 'dst': dst, 'width': width, 'src': src, 'src2': src,
                                'swidth': swidth})
    if mn == 'movi':
        dst, width = parse_reg(ops[0])
        return Movi.encode({**d, 'dst': dst, 'width': width, 'imm': int(ops[1], 0)})
    if mn in ('movw', 'movi32'):
        dst, width = parse_reg(ops[0])
        if mn == 'movi32' and (dst % 32 or width != 32):
            raise ValueError('movi32 requires a whole destination register')
        if dst >= 1024:
            raise ValueError('movw: destination must be below r32')
        return Movw.encode({**d, 'dst': dst, 'width': width, 'imm': int(ops[1], 0)})
    if mn == 'op052':  # earlier listings
        if ops != ['r8[31]', 'r20[31]'] or d != {'cond': ALWAYS, 'rest': 0, 'x': 0}:
            raise ValueError('op052 only exists as the stock form op052 r8[31], r20[31]')
        return 0x05223ea5dbe80520
    if mn == 'muxidx':  # earlier listings: r31[22:0] <- 0/1/2
        if len(ops) != 1 or d != {'cond': ALWAYS, 'rest': 0, 'x': 0}:
            raise ValueError('muxidx expects one index operand')
        return Movw.encode({'dst': 31 * 32, 'width': 23, 'imm': int(ops[0], 0)})
    if mn == 'bmov':
        dreg, sreg, moves = _bmov_parse(ops)
        if not 8 <= dreg <= 15:
            raise ValueError('bmov writes r8..r15')
        if len(moves) == 3:
            if d['cond'] != ALWAYS:
                raise ValueError('the three-move bmov has no condition (use two moves)')
            return Bmov3.encode({**d, 'k': dreg - 8, 'sreg': sreg, 'moves': moves})
        if len(moves) == 2:
            return Bmov2.encode({**d, 'k': dreg - 8, 'sreg': sreg, 'moves': moves})
        raise ValueError('bmov has two (conditional) or three moves')
    if mn in ('add', 'sub', 'shl', 'mask', 'rotl', 'shr') or mn in LOGIC_OPS + ('xor', 'xnor'):
        dst, width = parse_reg(ops[0])
        src, w1 = parse_reg(ops[1])
        src2, swidth = parse_reg(ops[2])
        if w1 != width:
            raise ValueError(f'{mn}: the first source must have the destination width')
        if mn in ('add', 'sub', 'shl', 'mask', 'rotl', 'shr'):
            f = {'add': Add, 'sub': Sub, 'shl': Shl, 'mask': Mask, 'rotl': Rotl, 'shr': Shr}[mn]
            return f.encode({**d, 'dst': dst, 'width': width, 'src': src, 'swidth': swidth, 'src2': src2})
        if swidth != width:
            raise ValueError(f'{mn}: source operand widths must match')
        return LogicReg.encode({**d, 'op': mn, 'dst': dst, 'width': width, 'src': src, 'swidth': swidth,
                                'src2': src2})
    if mn in ('addi', 'subi', 'shli', 'maski', 'shri', 'rotli') or (mn.endswith('i') and mn[:-1] in LOGIC_OPS + ('xor', 'xnor')):
        dst, width = parse_reg(ops[0])
        src, swidth = parse_reg(ops[1])
        imm = int(ops[2], 0)
        if mn in ('addi', 'subi', 'shli', 'maski', 'shri', 'rotli'):
            f = {'addi': Addi, 'subi': Subi, 'shli': Shli, 'maski': Maski, 'shri': Shri, 'rotli': Rotli}[mn]
            return f.encode({**d, 'dst': dst, 'width': width, 'src': src, 'swidth': swidth, 'imm': imm})
        return LogicImm.encode({**d, 'op': mn[:-1], 'dst': dst, 'width': width, 'src': src, 'swidth': swidth,
                                'imm': imm})
    if mn == 'csum':
        regs = [parse_reg(o)[0] for o in ops]
        return Csum.encode({**d, 'dst': regs[0], 'src': regs[1], 'old': regs[2], 'new': regs[3]})
    if mn.startswith('cset.'):
        code = parse_cset_rel(mn[5:])
        bit, w1 = parse_reg(ops[0])
        if w1 != 1 or not 8 <= bit // 32 <= 15 or d['cond'] != ALWAYS or d['x'] or len(ops) != 3:
            raise ValueError('cset.REL rN[b], src, imm|reg  (rN in r8..r15, no condition)')
        src, width = parse_reg(ops[1])
        base = {'k': bit // 32 - 8, 'idx': bit % 32, 'src': src, 'width': width, 'code': code, 'rest': d['rest']}
        if ops[2].startswith(('r', 'm[')):
            src2, swidth = parse_reg(ops[2])
            return CsetR.encode({**base, 'src2': src2, 'swidth': swidth})
        return Cset.encode({**base, 'imm': int(ops[2], 0)})
    if mn == 'crc32':
        if d != {'cond': ALWAYS, 'rest': 0, 'x': 0} or len(ops) != 1:
            raise ValueError('crc32 takes one slot operand and no flags')
        return Crc.encode({'slot': int(ops[0][1:])})
    if mn in ('send', 'drop', 'drop.err', 'dup', 'dup.req', 'end'):
        if d != {'cond': ALWAYS, 'rest': 0, 'x': 0}:
            raise ValueError(f'{mn} takes no flags or condition')
        if mn == 'end':
            if ops:
                raise ValueError('end takes no operands')
            return End.fixed_val
        if (len(ops) == 1) != (mn in ('drop.err', 'dup')):
            raise ValueError(f'{mn}: wrong operand count')
        return Cmd.encode({'op': mn, 'k': int(ops[0], 0) if ops else 0})
    if mn == 'lkup':  # earlier listings: lkup sS, FAM, #T
        return Lkup.encode({**d, 'slot': int(ops[0][1:]), 'fam': int(ops[1], 0),
                            'id': int(ops[2].lstrip('#'))})
    if mn.startswith('lkup.'):
        parts = mn.split('.')[1:]
        h = parts[-1] == 'h'
        name = parts[0]
        op = LKUP_NAMES[name] if name in LKUP_NAMES else int(name[2:])
        fx = int(ops[2], 0) if len(ops) > 2 else 0
        fam = op | put(fx, 16, 0) << 5 | h << 22
        return Lkup.encode({**d, 'slot': int(ops[0][1:]), 'fam': fam, 'id': int(ops[1].lstrip('#'))})
    if mn in ('clr', 'clr.hi'):
        dst, width = parse_reg(ops[0])
        if dst >= 1024 or d['cond'] != ALWAYS or d['x']:
            raise ValueError('clr: destination below r32, no condition')
        return Clr.encode({**d, 'dst': dst, 'width': width, 'hi': int(mn == 'clr.hi')})
    if mn.startswith('op01.'):  # earlier listings: op01.SUB[.a][.b] sSLOT, W
        parts = mn.split('.')
        dst = int(parts[1]) << 7 | int(ops[0][1:]) << 5 | ('a' in parts[2:]) << 4
        return Clr.encode({**d, 'dst': dst, 'width': int(ops[1]), 'hi': int('b' in parts[2:])})
    if mn in ('op510', 'ret'):
        if ops or d != {'cond': ALWAYS, 'rest': 0, 'x': 0}:
            raise ValueError('op510 takes no operands, flags or condition')
        return Op510.fixed_val
    if mn in ('op110', 'call'):
        if d['x'] or d.get('y'):
            raise ValueError('op110 does not take .x or .y')
        if len(ops) == 1 and not d['rest']:
            cond = put(d['cond'], 9, 0)
            return Op110.encode({'sel': (cond & 0x1ff) << 5, 'val': target(ops[0]) << 1 | (cond >> 9)})
        if d['cond'] != ALWAYS:
            raise ValueError('op110: use a single operand with the condition-prefix syntax')
        sel = int(ops[0], 0)
        if len(ops) == 2 and re.fullmatch(r'\d+', ops[1]):
            # Keep compatibility with earlier listings (second operand was raw).
            val = int(ops[1])
        elif len(ops) in (2, 3) and not (sel & 31 or d['rest']):
            # Compatibility with the first label syntax, which split cond[9] off.
            cond_hi = int(ops[2], 0) if len(ops) == 3 else 0
            val = target(ops[1]) << 1 | put(cond_hi, 0, 0)
        else:
            raise ValueError('op110: expected a raw decimal value or a target with optional flag')
        return Op110.encode({**d, 'sel': sel, 'val': val})
    raise ValueError(f'unknown mnemonic {mn!r}')


# ---------------------------------------------------------------- hazards

FLAG = 1 << 16  # unknown condition selectors are modelled apart from register bits


def _writes(f, d):
    """Register bits written by one instruction."""
    if f is None:
        return set()
    out = set()
    if f.name in ('mov', 'movi', 'movw', 'addi', 'subi', 'logici', 'add', 'sub', 'logic',
                  'shli', 'maski', 'rotli', 'shri', 'shl', 'mask', 'rotl', 'shr', 'clr'):
        if f.name == 'mov' and d['dst'] >= 1024:
            return set()  # jr
        out = set(range(d['dst'], d['dst'] + d['width']))
        if f.name in ('mov', 'movi') and d.get('x'):  # .x clears the rest of the register
            out = set(range(d['dst'] // 32 * 32, d['dst'] // 32 * 32 + 32))
        if f.name == 'clr' and d.get('hi'):
            out |= set(range(d['dst'], d['dst'] // 32 * 32 + 32))
    elif f.name == 'csum':
        out = set(range(d['dst'], d['dst'] + 16))
    elif f in (Cset, CsetR):
        out = {(8 + d['k']) * 32 + d['idx']}
    elif f in (Bmov3, Bmov2):
        r = (8 + d['k']) * 32
        out = set(range(r, r + 32)) if d.get('x') else {r + m[0] for m in d['moves']}
    elif f.name == 'ld':
        out = {b for a, width in loaded_ranges(d['d'], d['n']) for b in range(a, a + width)}
    return out


def _reads(f, d):
    if f is None:
        return set()
    out = set()
    if f in (Bmov3, Bmov2):
        out |= {d['sreg'] * 32 + m[1] for m in d['moves'] if m[3]}
    elif 'src' in d:
        if f.name in ('kmov', 'xmov'):
            wd = d['n'] * 8
        elif f.name in ('add', 'sub'):
            wd = d['width']  # board exp33
        else:
            wd = d.get('swidth') if f.name != 'cset' else d['width']
            wd = wd or d.get('width') or 16
        out |= set(range(d['src'], d['src'] + wd))
    if 'src2' in d:
        out |= set(range(d['src2'], d['src2'] + (d.get('width2') or d.get('swidth') or 16)))
    if f.name == 'csum':
        out |= set(range(d['old'], d['old'] + 16)) | set(range(d['new'], d['new'] + 16))
    if f.name == 'st':
        out |= {b for a, width in loaded_ranges(d['a'], d['n']) for b in range(a, a + width)}
    c = d.get('cond', ALWAYS)
    if c != ALWAYS and c >> 6:
        b = cond_reads(c)
        out.add(FLAG + c if b is None else b)
    return out


def hazards(words, base=0):
    """PCs whose instruction reads a register bit written by the instruction just
    before it. The stock code virtually never does this (1/4196 ZX133, 5/4427
    SR1010 adjacent pairs) and puts a nop in between instead (62% of all nops),
    so a result is evidently not visible to the very next instruction."""
    out = []
    prev = (None, None)
    for i, w in enumerate(words):
        cur = decode(w, base + i)
        if _writes(*prev) & _reads(*cur):
            out.append(base + i)
        prev = cur
    return out
