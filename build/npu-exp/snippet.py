"""Assemble a labelled npasm snippet at a fixed PC and hook it into the stock image.
usage: snippet.py SRC.s HOOK_PC BASE_PC OUTDIR NAME
Writes NAME.apply / NAME.restore (inst_set commands; the hook is written last and
restored first) and prints the listing. The hook word becomes `call <first label>`."""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'npu-re'))
from npdis import split  # noqa: E402
from npisa import decode, hazards, parse  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
WORDS = split((ROOT / 'extracted/kernel1/rootfs/etc/mcode/mcode_133.bin').read_bytes())[1]


def assemble(src, base):
    labels, insns, pc = {}, [], base
    for line in src.splitlines():
        line = line.split(';')[0].strip()
        if not line:
            continue
        m = re.match(r'^([A-Za-z_]\w*):$', line)
        if m:
            labels[m[1]] = pc
            continue
        insns.append((pc, line))
        pc += 1
    words = [(pc, parse(t, pc, labels)) for pc, t in insns]
    return labels, insns, words


def main():
    src, hook, base, out, name = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), Path(sys.argv[4]), sys.argv[5]
    labels, insns, words = assemble(Path(src).read_text(), base)
    entry = min(labels.values())
    for (pc, t), (_, w) in zip(insns, words):
        f, d = decode(w, pc)
        print(f'{pc:5}  {w:016x}  {f.text(d, lambda x: f"L{x}") if f else ".word"}')
    hz = hazards([w for _, w in words], base)
    print('words:', len(words), 'range:', base, '-', base + len(words) - 1, 'hazards:', hz)
    hookw = parse(f'call #{entry}', hook, {})
    cmd = lambda pairs: ''.join(f'echo {pc:x} {w >> 32:x} {w & 0xffffffff:x} > $P;\n' for pc, w in pairs)
    out.mkdir(exist_ok=True)
    hdr = 'P=/sys/devices/platform/np/ppu_debug/inst_set\n'
    (out / f'{name}.apply').write_text(hdr + cmd(words + [(hook, hookw)]))
    (out / f'{name}.restore').write_text(hdr + cmd([(hook, WORDS[hook])] + [(pc, WORDS[pc]) for pc, _ in words]))


if __name__ == '__main__':
    main()
