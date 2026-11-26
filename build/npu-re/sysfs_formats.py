"""List every np_133.ko sysfs attribute with the sscanf format its store handler uses.
usage: sysfs_formats.py np_133.ko np_133.dis"""
import re
import struct
import sys

blob = open(sys.argv[1], 'rb').read()
dis = open(sys.argv[2]).read().splitlines()
shoff, = struct.unpack_from('<Q', blob, 0x28)
entsize, nsec, shstrndx = struct.unpack_from('<HHH', blob, 0x3a)
sec = [struct.unpack_from('<IIQQQQIIQQ', blob, shoff + i * entsize) for i in range(nsec)]


def cstr(o):
    return blob[o:blob.index(b'\0', o)].decode(errors='replace')


def secname(i):
    return cstr(sec[shstrndx][4] + sec[i][0])


si = next(i for i, s in enumerate(sec) if s[1] == 2)
symbols = list(struct.iter_unpack('<IBBHQQ', blob[sec[si][4]:sec[si][4] + sec[si][5]]))
data_idx = next(i for i in range(nsec) if secname(i) == '.data')
ro = next(i for i in range(nsec) if secname(i) == '.rodata.str1.1')
rel = {}
for r in sec:
    if r[1] == 4 and r[6] == si and r[7] == data_idx:
        for at, info, add in struct.iter_unpack('<QQq', blob[r[4]:r[4] + r[5]]):
            sy = symbols[info >> 32]
            rel[at] = (sy[3], sy[4] + add)
lineno = {}
for i, l in enumerate(dis):
    m = re.match(r'\s+([0-9a-f]+):\t', l)
    if m:
        lineno.setdefault(int(m[1], 16), i)
text_idx = next(i for i in range(nsec) if secname(i) == '.text')
out = []
for at, (sh, off) in sorted(rel.items()):
    if sh != ro:
        continue
    name = cstr(sec[ro][4] + off)
    st = rel.get(at + 24)
    if not re.fullmatch(r'[a-z0-9_]+', name) or not st or st[0] != text_idx:
        continue
    i = lineno.get(st[1])
    fmt = None
    if i is not None:
        last_str = None
        for l in dis[i:i + 200]:
            m = re.search(r'R_AARCH64_ADD_ABS_LO12_NC\s+\.rodata\.str1\.1\+0x([0-9a-f]+)', l)
            if m:
                last_str = int(m[1], 16)
            if 'sscanf' in l and 'bl' in l or 'kstrto' in l:
                if 'kstrto' in l:
                    fmt = '(kstrto*)'
                elif last_str is not None:
                    fmt = cstr(sec[ro][4] + last_str)
                break
            if re.search(r'\tret\b', l):
                break
    out.append((name, fmt))
for name, fmt in out:
    print(f'{name:45} {fmt!r}')
