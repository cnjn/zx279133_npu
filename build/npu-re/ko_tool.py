"""Driver (np_133.ko, AArch64) reverse-engineering helpers.

usage:
  ko_tool.py dis [KO] [OUT]      disassemble the module with relocations (np_133.dis)
  ko_tool.py fn NAME [LINES]     print a function with string-literal references resolved
  ko_tool.py str TEXT            list functions that reference a string containing TEXT
  ko_tool.py var SYMBOL          print the initial 32-bit value of a .data symbol

Needs an AArch64 objdump for `dis`: aarch64-linux-gnu-objdump, aarch64-alpine-linux-musl-objdump,
or llvm-objdump (any of them on PATH; set $OBJDUMP to override)."""
import os
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
KO = ROOT / 'extracted/kernel1/rootfs/kmodule/np_133.ko'
DIS = HERE / 'np_133.dis'


class Elf:
    def __init__(self, path):
        self.b = Path(path).read_bytes()
        shoff, = struct.unpack_from('<Q', self.b, 0x28)
        es, n, si = struct.unpack_from('<HHH', self.b, 0x3a)
        sec = [struct.unpack_from('<IIQQQQIIQQ', self.b, shoff + i * es) for i in range(n)]
        name = lambda i: self.b[sec[si][4] + sec[i][0]:].split(b'\0')[0].decode()
        self.sec = {name(i): s for i, s in enumerate(sec)}
        self.secs = sec

    def section(self, name):
        s = self.sec[name]
        return self.b[s[4]:s[4] + s[5]]

    def cstr(self, section, off):
        data = self.section(section)
        return data[off:data.index(b'\0', off)].decode(errors='replace')

    def symbols(self):
        st = self.sec['.symtab']
        strtab = self.secs[st[6]]
        for i in range(st[5] // 24):
            nm, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', self.b, st[4] + i * 24)
            yield self.b[strtab[4] + nm:].split(b'\0')[0].decode(), shndx, value, size


def objdump():
    for c in [os.environ.get('OBJDUMP'), 'aarch64-linux-gnu-objdump', 'aarch64-alpine-linux-musl-objdump', 'llvm-objdump']:
        if c and shutil.which(c):
            return c
    raise SystemExit('no AArch64 objdump found (set $OBJDUMP)')


def cmd_dis(ko=KO, out=DIS):
    r = subprocess.run([objdump(), '-d', '-r', '--no-show-raw-insn', str(ko)], capture_output=True, text=True, check=True)
    Path(out).write_text(r.stdout)
    print(f'wrote {out} ({len(r.stdout.splitlines())} lines)')


def dis_lines():
    if not DIS.exists():
        cmd_dis()
    return DIS.read_text().splitlines()


def cmd_fn(name, count=400):
    elf, lines = Elf(KO), dis_lines()
    try:
        start = next(i for i, l in enumerate(lines) if l.endswith(f'<{name}>:'))
    except StopIteration:
        raise SystemExit(f'no function {name} (static functions are only reachable by address)')
    for l in lines[start:start + int(count)]:
        if re.match(r'^[0-9a-f]+ <', l) and l is not lines[start]:
            break
        m = re.search(r'R_AARCH64_ADR_PREL_PG_HI21\s+\.rodata\.str1\.1\+0x([0-9a-f]+)', l)
        if m:
            print('        STR:', repr(elf.cstr('.rodata.str1.1', int(m[1], 16))))
            continue
        if 'R_AARCH64_CALL26' in l:
            continue
        if 'R_AARCH64' in l:
            print('       ', l.strip())
            continue
        print(l[:110])


def cmd_str(text):
    elf = Elf(KO)
    data = elf.section('.rodata.str1.1')
    starts = {data.rfind(b'\0', 0, m.start()) + 1 for m in re.finditer(re.escape(text.encode()), data)}
    fn = None
    for l in dis_lines():
        m = re.match(r'^[0-9a-f]+ <([^>]+)>:', l)
        if m:
            fn = m[1]
        m = re.search(r'R_AARCH64_ADR_PREL_PG_HI21\s+\.rodata\.str1\.1\+0x([0-9a-f]+)', l)
        if m and int(m[1], 16) in starts:
            print(f'{fn:45} {elf.cstr(".rodata.str1.1", int(m[1], 16))[:70]!r}')


def cmd_var(symbol):
    elf = Elf(KO)
    for name, shndx, value, size in elf.symbols():
        if name == symbol:
            sec = elf.secs[shndx]
            v, = struct.unpack_from('<I', elf.b, sec[4] + value)
            print(f'{symbol} = {v:#x} ({v})')
            return
    raise SystemExit(f'no symbol {symbol}')


def main(argv):
    if not argv or argv[0] in ('-h', '--help'):
        print(__doc__)
        return
    cmd, args = argv[0], argv[1:]
    {'dis': cmd_dis, 'fn': cmd_fn, 'str': cmd_str, 'var': cmd_var}[cmd](*args)


if __name__ == '__main__':
    main(sys.argv[1:])
