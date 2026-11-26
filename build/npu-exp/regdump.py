"""Register/flag dump via packet stores: hook a PC with `call`, run a probe in a
dead-code area that executes the hooked word, stores registers into the packet,
then `ret`. Captured on the board with tcpdump. Emits per-variant apply/restore
shell snippets.   usage: regdump.py OUTDIR"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'npu-re'))
from npdis import split  # noqa: E402
from npisa import parse  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
WORDS = split((ROOT / 'extracted/kernel1/rootfs/etc/mcode/mcode_133.bin').read_bytes())[1]
HOOK, AREA = 4879, 3569


def snippet(pairs):
    return ''.join(f'echo {pc:x} {w >> 32:x} {w & 0xffffffff:x} > $P;\n' for pc, w in pairs)


def variant(body, hook=HOOK, area=AREA, orig_last=False):
    """orig_last: run the probe first and end with the hooked word (for send/drop hooks)."""
    if orig_last:
        probe = body + [f'.word {WORDS[hook]:016x}']
    else:
        probe = [f'.word {WORDS[hook]:016x}'] + body + ['ret']
    L = {f'L{area}': area}
    ws = [(area + i, parse(x, area + i, L)) for i, x in enumerate(probe)]
    apply = ws + [(hook, parse(f'call L{area}', hook, L))]
    restore = [(hook, WORDS[hook])] + [(pc, WORDS[pc]) for pc, _ in ws]
    return snippet(apply), snippet(restore)


def main(out, variants, hook=HOOK, orig_last=False):
    out = Path(out)
    out.mkdir(exist_ok=True)
    names = []
    for name, body in variants.items():
        a, r = variant(body, hook, orig_last=orig_last)
        (out / f'{name}.apply').write_text('P=/sys/devices/platform/np/ppu_debug/inst_set\n' + a)
        (out / f'{name}.restore').write_text('P=/sys/devices/platform/np/ppu_debug/inst_set\n' + r)
        names.append(name)
    (out / 'list').write_text('\n'.join(names) + '\n')


def regs_at(first, count, off=64):
    return [f'st h1+{off + 4 * i}, r{first + i}' for i in range(count)]


def copy_at(base, start, count=64, off=64):
    return [f'cp h1+{off + i}, h{base}+{start + i}, 8' for i in range(0, count, 8)]


def flags_at(words, off=64):
    body = []
    for k, w in enumerate(words):
        body += ['movi32 r30, 0x0'] + [f'[f{w}.{b}] movi r30[{b}], 0x1' for b in range(32)]
        body += [f'st h1+{off + 4 * k}, r30']
    return body


def set_field(off, hi, lo, value, tmp='r30'):
    return [f'ld {tmp}, h3+{off}', 'nop', f'movi {tmp}[{hi}:{lo}], {value:#x}', 'nop', f'st h3+{off}, {tmp}']


if __name__ == '__main__':
    V = {'R4_port7_q0': set_field(20, 7, 2, 7) + set_field(8, 15, 7, 0, 'r29'),
         'R5_port0_q0': set_field(20, 7, 2, 0) + set_field(8, 15, 7, 0, 'r29'),
         'R6_port5_q1': set_field(20, 7, 2, 5) + set_field(8, 15, 7, 1, 'r29')}
    main(sys.argv[1], V, 3443, orig_last=True)
