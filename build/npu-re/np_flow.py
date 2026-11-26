"""Control-flow summary of a microcode image: which exits each entry can reach.

usage: np_flow.py IMAGE [--entry PC ...]

Edges (static, conservative):
  br (unconditional)      -> target
  br/b.* (conditional)    -> target, PC+1
  loop A, B               -> A, B              (board exp39: r1[23:16] != 0 ? A : B)
  call T                  -> T, and PC+1 as the return site (board exp28: r1 = PC+1)
  ret at a dispatch base  -> the 16 contiguous table slots (r1 = base + 6 + index)
  ret elsewhere           -> 'ret' pseudo-exit (returns to the caller's PC+1)
  send/drop/drop.err/end  -> exit
  .word                   -> 'raw' pseudo-exit
  anything else           -> PC+1
Reachability is static: data-dependent conditions are not evaluated.
"""
import argparse
from collections import Counter
from pathlib import Path

from npdis import ENTRY_TAGS, records, split
from npisa import ALWAYS, DISPATCH_DELTA, DISPATCH_ENTRIES, decode, dispatch_bases

EXITS = ('send', 'drop', 'drop.err', 'end')


def graph(words):
    disp = {b + DISPATCH_DELTA - 1: b for b in dispatch_bases(words)}
    succ, kind = {}, {}
    for pc, w in enumerate(words):
        f, d = decode(w, pc)
        nxt = [pc + 1] if pc + 1 < len(words) else []
        if f is None:
            succ[pc], kind[pc] = [], 'raw'
        elif f.name == 'cmd' and d['op'] in EXITS or f.name == 'end':
            succ[pc], kind[pc] = [], d.get('op', 'end')
        elif f.name == 'br':
            succ[pc] = [d['target']] + (nxt if d['cond'] != ALWAYS else [])
        elif f.name == 'b':
            succ[pc] = [d['target']] + nxt
        elif f.name == 'loop':
            succ[pc] = [d['start'], d['target']]
        elif f.name == 'op110' and 'cond' in d:
            succ[pc] = [d['val'] >> 1] + nxt
        elif f.name == 'op510':
            if pc in disp:
                b = disp[pc]
                succ[pc] = [b + DISPATCH_DELTA + i for i in range(DISPATCH_ENTRIES)]
            else:
                succ[pc], kind[pc] = [], 'ret'
        else:
            succ[pc] = nxt
    return succ, kind


def reach(succ, start):
    seen, todo = set(), [start]
    while todo:
        pc = todo.pop()
        if pc in seen or pc not in succ:
            continue
        seen.add(pc)
        todo.extend(succ[pc])
    return seen


def entries(blob):
    out = {0: 'pc0'}
    for tag, val in records(split(blob)[4]):
        if tag in ENTRY_TAGS:
            out.setdefault(val & 0xffff, f'{tag:08x}')
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('image')
    ap.add_argument('--entry', type=int, nargs='*')
    a = ap.parse_args()
    blob = Path(a.image).read_bytes()
    words = split(blob)[1]
    succ, kind = graph(words)
    ents = {pc: 'cli' for pc in a.entry} if a.entry else entries(blob)
    allr = set()
    print('entry\tsource\treachable\texits')
    for pc, src in sorted(ents.items()):
        r = reach(succ, pc)
        allr |= r
        c = Counter(kind[p] for p in r if p in kind)
        print(f'{pc}\t{src}\t{len(r)}\t' + ', '.join(f'{k}={v}' for k, v in sorted(c.items())))
    print(f'union\t-\t{len(allr)} of {len(words)}')
    dead = [pc for pc in range(len(words)) if pc not in allr and words[pc]]
    print('nonzero words not reached from any entry:', len(dead))


if __name__ == '__main__':
    main()
