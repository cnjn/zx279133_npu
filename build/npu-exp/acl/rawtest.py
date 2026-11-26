"""Mac side (runs on the Mac, no root needed with access_bpf): send raw Ethernet frames on IFACE
through BPF and capture every frame that carries MAGIC while sending and for WAIT s after.

usage: python3 rawtest.py IFACE FRAMES_FILE [GAP_S] [WAIT_S]
FRAMES_FILE: one hex frame per line. Output: 'RX <t> <hex>' per captured frame, then a summary.
Own transmissions are not captured (BIOCSSEESENT 0)."""
import fcntl
import os
import select
import struct
import sys
import time

BIOCSETIF = 0x8020426C
BIOCIMMEDIATE = 0x80044270
BIOCPROMISC = 0x20004269
BIOCSHDRCMPLT = 0x80044275
BIOCGBLEN = 0x40044266
BIOCSSEESENT = 0x80044277
MAGIC = b'ACLT'


def open_bpf(iface):
    for i in range(256):
        try:
            fd = os.open(f'/dev/bpf{i}', os.O_RDWR)
            break
        except OSError:
            continue
    else:
        raise SystemExit('no free /dev/bpf')
    fcntl.ioctl(fd, BIOCSETIF, struct.pack('16s16x', iface.encode()))
    fcntl.ioctl(fd, BIOCIMMEDIATE, struct.pack('I', 1))
    fcntl.ioctl(fd, BIOCSHDRCMPLT, struct.pack('I', 1))
    fcntl.ioctl(fd, BIOCSSEESENT, struct.pack('I', 0))
    fcntl.ioctl(fd, BIOCPROMISC)
    blen = struct.unpack('I', fcntl.ioctl(fd, BIOCGBLEN, struct.pack('I', 0)))[0]
    return fd, blen


def frames(buf):
    off = 0
    while off + 18 <= len(buf):
        caplen, datalen, hdrlen = struct.unpack_from('<IIH', buf, off + 8)
        yield buf[off + hdrlen: off + hdrlen + caplen]
        off += (hdrlen + caplen + 3) & ~3


def main():
    iface, path = sys.argv[1], sys.argv[2]
    gap = float(sys.argv[3]) if len(sys.argv) > 3 else 0.01
    wait = float(sys.argv[4]) if len(sys.argv) > 4 else 1.0
    tx = [bytes.fromhex(l.strip()) for l in open(path) if l.strip()]
    fd, blen = open_bpf(iface)
    t0 = time.time()
    got, k, nxt = 0, 0, t0
    end = None
    while True:
        now = time.time()
        if k < len(tx) and now >= nxt:
            os.write(fd, tx[k])
            k += 1
            nxt = now + gap
            if k == len(tx):
                end = now + wait
        if end is not None and now >= end:
            break
        r, _, _ = select.select([fd], [], [], 0.002)
        if r:
            for f in frames(os.read(fd, blen)):
                if MAGIC in f:
                    got += 1
                    print(f'RX {time.time() - t0:.4f} {f.hex()}')
    print(f'SUMMARY sent {k} captured {got}')


if __name__ == '__main__':
    main()
