"""Coverage probes: insert table-48 counter increments before chosen PCs and rebuild.

Probe k (0..63) counts an idle table-48 counter: k < 32 -> "port id (32+k) output
boardcast" (0x160+k), k >= 32 -> "port id k output multicast" (0x100+k). The probe sequence copies the stock stat idiom:

    movi r30[15:0], IDX ; movi r30[27:23], 0x16 ; movi r30[28], 0x1
    xmovi idx[132..135], 0x0 ; xmovi idx[136..139], 0x0
    xmov idx[128..131], r30 ; lkup s2, 0x3, #48

It clobbers r30, the index buffer and slot 2, so only PCs where r30 is dead
(written before read in straight-line code) are accepted.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'npu-re'))
from npdis import disassemble, split  # noqa: E402
from npisa import Op510, decode, _reads, _writes  # noqa: E402

R30 = set(range(30 * 32, 31 * 32))
CLOBBER = set(range(960, 976)) | set(range(983, 989))   # r30[15:0], r30[27:23], r30[28]


def index(k):
    return 0x160 + k if k < 32 else 0x100 + k


def counter_name(k):
    return f'port id {32 + k} output boardcast' if k < 32 else f'port id {k} output multicast'


def r30_live_in(words):
    """Backward dataflow over the CFG: bits of r30 that may be read before being
    written, at entry of each PC. Unknown words and op510 are assumed to read
    all of r30 (op510 has an unknown successor); conditional writes do not kill."""
    from npisa import code_targets
    n = len(words)
    D = [decode(w, i) for i, w in enumerate(words)]
    succ = []
    for i, (f, d) in enumerate(D):
        s = []
        uncond = f is not None and f.name in ('br', 'loop') and d.get('cond', 0x029) == 0x029
        if not uncond and i + 1 < n:
            s.append(i + 1)
        if f is not None:
            s += [a for a in code_targets(f, d) if a < n]
        succ.append(s)
    use = []
    kill = []
    for f, d in D:
        if f in (None, Op510):
            use.append(R30); kill.append(set()); continue
        use.append(_reads(f, d) & R30)
        cond = d.get('cond', 0x029) != 0x029
        kill.append(set() if cond else (_writes(f, d) & R30))
    live = [set() for _ in range(n)]
    changed = True
    while changed:
        changed = False
        for i in range(n - 1, -1, -1):
            out = set().union(*(live[j] for j in succ[i])) if succ[i] else set()
            new = use[i] | (out - kill[i])
            if new != live[i]:
                live[i] = new
                changed = True
    return live


def r30_dead(words, pc, look=40):
    """Conservative: walk forward in address order; r30 must be fully rewritten
    before any read, and we stop (as unknown) at the first branch."""
    covered = set()
    for i in range(pc, min(pc + look, len(words))):
        f, d = decode(words[i], i)
        if f in (None, Op510):
            return False
        if R30 & (_reads(f, d) - covered):
            return False
        covered |= _writes(f, d) & R30
        if covered >= R30 or (covered >= set(range(960, 976)) and covered >= set(range(983, 989))):
            return True                       # the stock stat idiom rewrites r30[15:0], [27:23], [28]
        if f.name in ('br', 'b', 'loop', 'lkup', 'op110'):
            return False
    return False


def probe_lines(k):
    return [f'    movi r30[15:0], {index(k):#x}        ; probe {k}',
            '    movi r30[27:23], 0x16',
            '    movi r30[28], 0x1',
            '    xmovi idx[132..135], 0x0',
            '    xmovi idx[136..139], 0x0',
            '    xmov idx[128..131], r30',
            '    lkup s2, 0x3, #48']


def build(stock, pcs):
    words = split(stock)[1]
    src = disassemble(stock).splitlines()
    where = {}
    for i, l in enumerate(src):
        tail = l.split(';')[-1].split()
        if tail and tail[0].isdigit() and not l.lstrip().startswith(('.', 'L')):
            where.setdefault(int(tail[0]), i)
    live = r30_live_in(words)
    accepted = [pc for pc in pcs if not (live[pc] & CLOBBER)][:64]
    assert all(pc in where for pc in accepted)
    # insert from the bottom so earlier line numbers stay valid; before the label if any
    for k, pc in sorted(enumerate(accepted), key=lambda t: -where[t[1]]):
        at = where[pc]
        src[at:at] = probe_lines(k)
    return '\n'.join(src) + '\n', accepted


def blocks(words):
    """Basic blocks as (start, end_exclusive) using branch targets and branch ends."""
    from npisa import code_targets
    D = [decode(w, i) for i, w in enumerate(words)]
    lead = {0} | {a for f, d in D if f for a in code_targets(f, d) if a < len(words)}
    for i, (f, d) in enumerate(D):
        if f is not None and f.name in ('br', 'b', 'loop') and i + 1 < len(words):
            lead.add(i + 1)
    lead = sorted(lead)
    return list(zip(lead, lead[1:] + [len(words)]))


BUILD = ('kld', 'kmov', 'kmovi', 'xld', 'xmov', 'xmovi')


def buffers_idle(words, a, pc):
    """True if, inside the block before pc, no key/index write is pending and no
    non-stat slot-2 lookup result may still be read (the probe clobbers both)."""
    for i in range(pc - 1, a - 1, -1):
        f, d = decode(words[i], i)
        if f in (None, Op510):
            return False
        if f.name == 'lkup':
            return not (d['slot'] == 2 and d['fam'] != 3)
        if f.name in BUILD:
            return False
    return True


def block_probe_sites(words):
    """For each basic block, the first PC where the probe's r30 bits are dead and
    the key/index buffers and slot 2 are idle."""
    live = r30_live_in(words)
    out = {}
    for a, b in blocks(words):
        for pc in range(a, b):
            if not (live[pc] & CLOBBER) and buffers_idle(words, a, pc):
                out[(a, b)] = pc
                break
    return out
