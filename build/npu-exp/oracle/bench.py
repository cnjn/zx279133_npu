"""NP oracle bench: run arbitrary instruction sequences on the board's NP with inputs
taken from a UDP packet, and get the register / flag state back in the reflected packet.

How it works
    The stock image is loaded whole (ppu_debug/mcode_download_file) with the bench
    appended after the main program (PC 5214 on) and PC 5047 changed to `call bench`.
    A UDP/IPv4 packet to 192.168.1.1:7778 (untagged, 20-byte IP header) is taken over:
      payload  0..1   block number          (h1+42)
               2..5   sequence tag, echoed  (h1+44)
               6..53  inputs r20..r31       (h1+48..h1+95, big-endian words)
    The block (8 words: up to 7 test words, padded with nop, then `br <page>`) runs
    with r20..r31 preloaded; the page routine stores state at h1+48..h1+127 (80 bytes)
    and the packet is swapped (MAC, IP, UDP ports; UDP checksum 0) and sent back out
    of the ingress port. Anything else returns to the stock code.
    Pages: 'hi' r20..r39, 'lo' r0..r19, 'top' r40..r59, 'flags' f0..f15 (f-words
    sampled with [fW.B] conditional movi, 64 bytes), 'top2' r60..r63.

Python use
    b = Bench()
    k = b.block(['add r28, r20, r21'], 'hi')       # returns the block number
    b.install()                                     # build, push, load
    res = b.run([(k, [1, 2] + [0] * 10)])           # list of (block, 12 inputs)
    b.restore()                                     # stock image back
"""
import json
import struct
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'npu-re'))
from npdis import split  # noqa: E402
from npisa import decode, hazards, parse  # noqa: E402

ROOT = HERE.parents[2]
STOCK_PATH = ROOT / 'extracted/kernel1/rootfs/etc/mcode/mcode_133.bin'
STOCK = STOCK_PATH.read_bytes()
WORDS = split(STOCK)[1]
HOOK, BASE, PORT = 5047, 5214, 7778
sys.path.insert(0, str(ROOT / 'npu'))
from npukit.config import cfg as _cfg  # noqa: E402  (lab settings: npu/config.toml)
MAC, SERDIR = _cfg().mac.host, _cfg().mac.workdir
IN_REGS = list(range(20, 32))
PAGES = {'hi': list(range(20, 40)), 'lo': list(range(0, 20)), 'top': list(range(40, 60)),
         'top2': list(range(60, 64))}


def flags_dump(words, off=48, tmp=30):
    body = []
    for k, w in enumerate(words):
        body += [f'movi32 r{tmp}, 0x0'] + [f'[f{w}.{b}] movi r{tmp}[{b}], 0x1' for b in range(32)]
        body += ['nop', f'st h1+{off + 4 * k}, r{tmp}']
    return body


COND_PAGES = {'c0': (0, 640), 'c1': (640, 1024)}


def cond_dump(codes, off=48, tmp=30):
    codes = list(codes)
    body = []
    for k in range(0, len(codes), 32):
        body += [f'movi32 r{tmp}, 0x0']
        body += [f'[c{c:03x}] movi r{tmp}[{i}], 0x1' for i, c in enumerate(codes[k:k + 32])]
        body += ['nop', f'st h1+{off + 4 * (k // 32)}, r{tmp}']
    return body


REFLECT = '''
reflect:
    ld r20[15:0], h1+0
    ld r21, h1+2
    ld r22[15:0], h1+6
    ld r23, h1+8
    ld r24, h1+26
    ld r25, h1+30
    ld r26[15:0], h1+34
    ld r27[15:0], h1+36
    ld r28, h3+44
    ld r29, h3+20
    ld r30, h3+8
    movi32 r31, 0x0
    nop
    st h1+0, r22[15:0]
    st h1+2, r23
    st h1+6, r20[15:0]
    st h1+8, r21
    st h1+26, r25
    st h1+30, r24
    st h1+34, r27[15:0]
    st h1+36, r26[15:0]
    st h1+40, r31[15:0]
    mov r29[7:2], r28[31:26]
    movi r30[15:7], 0x0
    nop
    st h3+20, r29
    st h3+8, r30
    send
'''


def assemble(lines, base):
    labels, insns, pc = {}, [], base
    for line in lines:
        line = line.split(';')[0].strip()
        if not line:
            continue
        if line.endswith(':') and ' ' not in line:
            labels[line[:-1]] = pc
            continue
        insns.append((pc, line))
        pc += 1
    out = []
    for p, t in insns:
        try:
            out.append(parse(t, p, labels))
        except Exception as e:
            raise ValueError(f'PC {p}: {t!r}: {e}') from None
    return labels, out


class Bench:
    def __init__(self, name='bench'):
        self.name = name
        self.blocks = []      # (lines, page)
        self.extra = []       # extra code (subroutines), placed after the reflect routine

    def block(self, lines, page='hi'):
        """Add a test block (any length). '@x' in a line is a block-local label.
        page: hi / lo / top / top2 (registers), flags0..3 / flags (f-words),
        c0 / c1 (raw 10-bit conditions 0..639 / 640..1023, one bit each), or
        self (the block stores its own results at h1+48.. and ends with `br reflect`)."""
        k = len(self.blocks)
        lines = [l.replace('@', f'b{k}_') for l in lines]
        if page.startswith('c:'):  # custom condition range c:LO:HI (hex)
            lo, hi = (int(x, 16) for x in page[2:].split(':'))
            assert hi - lo <= 640
            COND_PAGES[page] = (lo, hi)
        if not (page in PAGES or page in COND_PAGES or page == 'self' or page.startswith('flags')):
            raise ValueError(page)
        self.blocks.append((lines, page))
        return k

    # ------------------------------------------------------------ image
    def source(self, delta=0):
        L = ['bench:', '.word %016x' % WORDS[HOOK],
             '[f7.27] br pass', '[f7.23] br pass', 'b.ne r14[6:0], 0x22, pass',
             'ld r20[15:0], h1+36', 'nop', f'b.ne r20[15:0], {PORT:#x}, pass',
             'ld r2[15:0], h1+42']  # no bounds check: b.ge misbehaved (exp70)
        L += [f'ld r{r}, h1+{48 + 4 * i}' for i, r in enumerate(IN_REGS)]
        L += ['call here', 'here:', 'nop', 'add r1[15:0], r1[15:0], r2[15:0]', 'nop',
              f'addi r1[15:0], r1[15:0], {delta:#x}', 'nop', 'ret', 'pass:', 'ret']
        L += ['table:'] + [f'br blk{k}' for k in range(len(self.blocks))]
        used = {p for _, p in self.blocks}
        for page, regs in PAGES.items():
            if page in used:
                L += [f'page_{page}:'] + [f'st h1+{48 + 4 * i}, r{r}' for i, r in enumerate(regs)] + ['br reflect']
        for q in range(4):
            if f'flags{q}' in used:
                L += [f'page_flags{q}:'] + flags_dump(range(4 * q, 4 * q + 4)) + ['br reflect']
        if 'flags' in used:
            L += ['page_flags:'] + flags_dump(range(16)) + ['br reflect']
        for page, (lo, hi) in COND_PAGES.items():
            if page in used:
                L += [f'page_{page.replace(":", "_")}:'] + cond_dump(range(lo, hi)) + ['br reflect']
        L += REFLECT.splitlines()
        L += list(self.extra)
        for k, (lines, page) in enumerate(self.blocks):
            L += [f'blk{k}:'] + list(lines) + ([] if page == 'self' else [f'br page_{page.replace(":", "_")}'])
        return L

    def build(self):
        labels, _ = assemble(self.source(), BASE)
        delta = labels['table'] - labels['here']
        src = self.source(delta)
        labels, words = assemble(src, BASE)
        assert labels['table'] - labels['here'] == delta
        # pad so that BASE + len is a multiple of 4: the loader writes 4-word groups and a
        # trailing partial group is not loaded (exp89: the last block lost its final words)
        words += [0] * (-(BASE + len(words)) % 4 + 4)
        self.labels, self.words = labels, words
        magic, version, ram, n = struct.unpack_from('>4I', STOCK)
        assert n == BASE
        main = list(WORDS)
        main[HOOK] = parse(f'call #{BASE}', HOOK, {})
        body = b''.join(struct.pack('>Q', w) for w in main + words)
        gap_end = 0x17d90
        blob = struct.pack('>4I', magic, version, ram, n + len(words)) + body
        assert len(blob) <= gap_end
        blob += STOCK[len(blob):]
        Path(f'/tmp/{self.name}.bin').write_bytes(blob)
        Path(f'/tmp/{self.name}.s').write_text('\n'.join(src) + '\n')
        return blob

    def listing(self):
        out = []
        for i, w in enumerate(self.words):
            f, d = decode(w, BASE + i)
            out.append(f'{BASE + i:5} {w:016x} {f.text(d, lambda x: f"L{x}") if f else ".word"}')
        return '\n'.join(out)

    # ------------------------------------------------------------ board
    def install(self):
        self.build()
        mac_put(f'/tmp/{self.name}.bin', f'/tmp/{self.name}.bin')
        r = mac(f'cd {SERDIR} && sh push.sh /tmp/{self.name}.bin /tmp/{self.name}.bin 9177', 60)
        lines = r.split()
        if len(lines) < 4 or lines[1] != lines[3]:
            raise RuntimeError('push failed: ' + r)
        out = ser(f'dmesg -c >/dev/null; echo /tmp/{self.name}.bin > '
                  '/sys/devices/platform/np/ppu_debug/mcode_download_file; sleep 1; dmesg -c | tail -3', 30)
        return out

    def run(self, vectors, window=64, rounds=3, length=96):
        """length > 96: the payload is padded with a pattern, the 16-bit big-endian value
        (frame offset // 2) at every even frame offset (frame offset = payload offset + 42)."""
        lines = []
        for blk, ins in vectors:
            ins = list(ins) + [0] * (12 - len(ins))
            p = struct.pack('>HI', blk, 0) + b''.join(struct.pack('>I', x & 0xffffffff) for x in ins)
            p += bytes(96 - len(p))
            if length > 96:
                p += b''.join(struct.pack('>H', ((42 + o) // 2) & 0xffff) for o in range(96, length, 2))
                p = p[:length]
            lines.append(p.hex())
        Path(f'/tmp/{self.name}.plan').write_text('\n'.join(lines) + '\n')
        mac_put(f'/tmp/{self.name}.plan', f'/tmp/{self.name}.plan')
        mac_put(str(HERE / 'pump.py'), '/tmp/oracle_pump.py')
        err = mac(f'python3 /tmp/oracle_pump.py /tmp/{self.name}.plan /tmp/{self.name}.out {window} {PORT} {rounds}', 600)
        subprocess.run(['scp', '-q', f'{MAC}:/tmp/{self.name}.out', f'/tmp/{self.name}.out'], check=True)
        res = []
        for line, (blk, ins) in zip(Path(f'/tmp/{self.name}.out').read_text().splitlines(), vectors):
            i, h = line.split()
            if h == '-':
                res.append(None)
                continue
            p = bytes.fromhex(h)
            out = [struct.unpack_from('>I', p, 6 + 4 * k)[0] for k in range(20)]
            words, page = self.blocks[blk]
            if page == 'self':
                res.append({'w': out})
            elif page in COND_PAGES:
                lo, hi = COND_PAGES[page]
                res.append({'c': {c: (out[(c - lo) // 32] >> ((c - lo) % 32)) & 1 for c in range(lo, hi)}})
            elif page == 'flags':
                res.append({f'f{k}': out[k] for k in range(16)})
            elif page.startswith('flags'):
                q = int(page[5:])
                res.append({f'f{4 * q + k}': out[k] for k in range(4)})
            else:
                res.append({f'r{r}': out[k] for k, r in enumerate(PAGES[page])})
        self.last_err = err.strip()
        return res

    def restore(self):
        return ser('dmesg -c >/dev/null; echo /etc/mcode/mcode_133.bin > '
                   '/sys/devices/platform/np/ppu_debug/mcode_download_file; sleep 1; dmesg -c | tail -3', 30)


def health():
    """Packets taken by the PPU minus packets written back (= threads stuck, if idle)."""
    out = ser('dmesg -c >/dev/null; cat /sys/devices/platform/np/ppu_debug/cluster_stats; cat /sys/devices/platform/np/ppu_debug/me_idle_status_get; dmesg -c', 30)
    v = {}
    for line in out.splitlines():
        if ':' in line:
            k, _, x = line.rpartition(':')
            v[k.strip()] = x.strip()
    try:
        din = int(v['ppu_mec_group_desc_vld_l(0x9000)'])
        wb = int(v['cluster0_pbu0_wb_eop_l'])
    except (KeyError, ValueError):
        return None, out
    busy = sum('not idle' in l for l in out.splitlines())
    return din - wb, busy


def mac(cmd, timeout=60):
    r = subprocess.run(['ssh', '-o', 'BatchMode=yes', MAC, cmd], capture_output=True, text=True,
                       timeout=timeout)
    return r.stdout + r.stderr


def mac_put(local, remote):
    subprocess.run(['scp', '-q', local, f'{MAC}:{remote}'], check=True)


def ser(cmd, timeout=30):
    q = cmd.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$').replace('`', '\\`')
    return mac(f'cd {SERDIR} && NPU_SERIAL_DEV={_cfg().mac.serial_dev} python3 ser.py "{q}" {timeout}', timeout + 30)


if __name__ == '__main__':
    b = Bench('smoke')
    k0 = b.block([], 'hi')
    k1 = b.block(['add r28, r20, r21'], 'hi')
    k2 = b.block([], 'lo')
    k3 = b.block([], 'flags')
    b.build()
    print(b.listing()[:4000])
    print('words', len(b.words), 'hazards', hazards(b.words, BASE))
