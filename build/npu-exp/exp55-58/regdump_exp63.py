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


def variant(body, hook=HOOK, area=AREA):
    probe = [f'.word {WORDS[hook]:016x}'] + body + ['ret']
    L = {f'L{area}': area}
    ws = [(area + i, parse(x, area + i, L)) for i, x in enumerate(probe)]
    apply = ws + [(hook, parse(f'call L{area}', hook, L))]
    restore = [(hook, WORDS[hook])] + [(pc, WORDS[pc]) for pc, _ in ws]
    return snippet(apply), snippet(restore)


def main(out, variants, hook=HOOK):
    out = Path(out)
    out.mkdir(exist_ok=True)
    names = []
    for name, body in variants.items():
        a, r = variant(body, hook)
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


if __name__ == '__main__':
    hook = int(sys.argv[2]) if len(sys.argv) > 2 else HOOK
    save = ['mov r28, r7', 'nop']
    back = ['mov r7, r28', 'nop']
    V = {
        'F_r7lo_80': save + ['movi r7[8:0], 0x80', 'nop', 'cp h1+64, h3+0, 8', 'st h1+72, r7'] + back,
        'G_r7hi_8e': save + ['movi r7[24:16], 0x8e', 'nop', 'cp h1+64, h7+0, 8', 'st h1+72, r7'] + back,
        'H_r6_h0h2': ['cp h1+64, h0+0, 8', 'cp h1+72, h2+0, 8', 'cp h1+80, h4+0, 8', 'cp h1+88, h6+0, 8'],
    }
    main(sys.argv[1], V, hook)
