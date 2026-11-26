"""Search CRC parameterisations that reproduce observed result bits of `lkup 0x9`.

usage: crc_match.py KEYHEX BITS   BITS like '9=1,10=1,11=0,...' (bit index of r32)
Tries CRC-32 polys (normal/reflected), init/xorout 0 or ~0, every key sub-span,
and both output bit orders. Prints matches."""
import sys

POLYS = {'crc32': 0x04C11DB7, 'crc32c': 0x1EDC6F41, 'crc32k': 0x741B8CD7, 'crc32q': 0x814141AB,
         'crc16': 0x8005, 'ccitt': 0x1021}


def crc(data, poly, width, init, refin, refout, xorout):
    top, mask = 1 << (width - 1), (1 << width) - 1
    r = init
    for b in data:
        if refin:
            b = int(f'{b:08b}'[::-1], 2)
        r ^= b << (width - 8)
        for _ in range(8):
            r = ((r << 1) ^ poly) & mask if r & top else (r << 1) & mask
    if refout:
        r = int(f'{r:0{width}b}'[::-1], 2)
    return r ^ xorout


def main():
    key = bytes.fromhex(sys.argv[1])
    want = {int(k): int(v) for k, v in (x.split('=') for x in sys.argv[2].split(','))}
    hits = 0
    for name, poly in POLYS.items():
        width = 16 if poly < 0x10000 else 32
        mask = (1 << width) - 1
        for lo in range(len(key)):
            for hi in range(lo + 1, len(key) + 1):
                for init in (0, mask):
                    for ref in (0, 1):
                        for xo in (0, mask):
                            v = crc(key[lo:hi], poly, width, init, ref, ref, xo)
                            for sh in range(0, 33 - width if width < 32 else 1):
                                for bs in (0, 1):
                                    x = v << sh
                                    if bs:
                                        x = int.from_bytes(x.to_bytes(4, 'big'), 'little')
                                    if all((x >> b) & 1 == e for b, e in want.items()):
                                        hits += 1
                                        print(f'{name} key[{lo}:{hi}] init={init:#x} ref={ref} xorout={xo:#x} '
                                              f'shift={sh} byteswap={bs} -> {x:08x}')
    print('hits', hits)


if __name__ == '__main__':
    main()
