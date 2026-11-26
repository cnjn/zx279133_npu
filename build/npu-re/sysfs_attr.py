"""Map sysfs attribute names in a .ko to their show/store functions (struct device_attribute)."""
import struct, sys
d = open(sys.argv[1], 'rb').read(); want = sys.argv[2:]
shoff, = struct.unpack_from('<Q', d, 0x28); shentsize, shnum, shstrndx = struct.unpack_from('<HHH', d, 0x3a)
secs = [struct.unpack_from('<IIQQQQIIQQ', d, shoff + i * shentsize) for i in range(shnum)]
nm = lambda off, tab: d[tab + off:d.index(b'\0', tab + off)].decode()
names = [nm(s[0], secs[shstrndx][4]) for s in secs]
symtab = secs[names.index('.symtab')]; strtab = secs[names.index('.strtab')][4]
syms = [struct.unpack_from('<IBBHQQ', d, symtab[4] + i * 24) for i in range(symtab[5] // 24)]
def target(sym, add):
    st_name, info, _, shndx, val, _ = syms[sym]
    return shndx, val + add, nm(st_name, strtab)
func_at = {}
for st_name, info, _, shndx, val, size in syms:
    if info & 0xf == 2: func_at[(shndx, val)] = nm(st_name, strtab)
for idx, s in enumerate(secs):
    if s[1] != 4: continue
    tsec = s[7]; rel = {}
    for i in range(s[5] // 24):
        off, info, add = struct.unpack_from('<QQq', d, s[4] + i * 24)
        rel[off] = target(info >> 32, add)
    for off, (sh, addr, sname) in rel.items():
        if names[sh].startswith('.rodata.str'):
            base = secs[sh][4] + addr
            s_ = d[base:d.index(b'\0', base)].decode(errors='replace')
            if s_ in want:
                out = []
                for k in (16, 24):   # attr.name @0, mode @8, show @16, store @24
                    t = rel.get(off + k)
                    out.append(f'{names[t[0]]}+{t[1]:#x}' + (f' ({func_at.get((t[0], t[1]), "")})' if t else '') if t else '-')
                print(f'{s_:16s} show={out[0]}  store={out[1]}')
