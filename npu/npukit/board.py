"""Board operations: health, counters, microcode load/restore, reboot, SE table access.

Every function here is safe to call on a healthy board; dangerous driver interfaces
(acl_*_table_get, lookup opcode 19, unknown stat modes) are deliberately not wrapped.
See npu/SAFETY.md."""
import re
import struct
import tempfile
from pathlib import Path

from . import link
from .config import STOCK, cfg

NP = '/sys/devices/platform/np'


# ---------------------------------------------------------------- health
def ppu_threads():
    """(packets taken by the PPU minus packets written back, ME lines 'not idle').
    On an idle board the first number is the count of stuck threads; ~24 stop the NP."""
    out = link.ser(f'dmesg -c >/dev/null; cat {NP}/ppu_debug/cluster_stats; cat {NP}/ppu_debug/me_idle_status_get; dmesg -c', 30)
    v = {}
    for line in out.splitlines():
        if ':' in line:
            k, _, x = line.rpartition(':')
            v[k.strip()] = x.strip()
    try:
        stuck = int(v['ppu_mec_group_desc_vld_l(0x9000)']) - int(v['cluster0_pbu0_wb_eop_l'])
    except (KeyError, ValueError):
        return None, out
    return stuck, sum('not idle' in l for l in out.splitlines())


def cpu_path():
    """Counters of the NP -> CPU path: IDM DMA'd packets and eth0 received packets."""
    out = link.ser(f'dmesg -c >/dev/null; cat {NP}/idm_debug/stats >/dev/null 2>&1; '
                   'dmesg -c | grep "dma cpu pkt num"; grep eth0: /proc/net/dev', 30)
    dma = re.search(r'dma cpu pkt num\(60,32\):\s+(\d+)', out)
    eth = re.search(r'eth0:\s*\d+\s+(\d+)', out)
    return (int(dma[1]) if dma else None), (int(eth[1]) if eth else None)


def ping(count=3):
    out = link.mac(f'ping -c {count} -t {count + 3} {cfg().board.ip} | tail -2', 30)
    m = re.search(r'(\d+) packets received', out)
    return (int(m[1]) if m else 0), out.strip()


def health():
    """Dict with the basic checks; 'ok' is True when the board is usable."""
    stuck, busy = ppu_threads()
    got, ping_out = ping(3)
    dma, eth = cpu_path()
    ok = stuck is not None and stuck < 4 and got > 0
    return {'ok': ok, 'stuck_threads': stuck, 'me_not_idle': busy, 'ping_replies': got,
            'idm_dma_to_cpu': dma, 'eth0_rx': eth, 'ping': ping_out}


# ---------------------------------------------------------------- counters
def parse_stats(text):
    out = {}
    for line in text.splitlines():
        m = re.match(r'\s*(.*?)[:;]\s+(\d+)\s*$', line)
        if m:
            out[m[1].strip()] = int(m[2])
    return out


def stats():
    """Cumulative #48 counters by name (table_debug/debug_stat_show prints the first
    lines to the console and the rest to dmesg; both are read)."""
    return parse_stats(link.ser(f'dmesg -c >/dev/null; cat {NP}/table_debug/debug_stat_show; dmesg -c', 60))


def stats_diff(a, b):
    return {k: b[k] - a.get(k, 0) for k in b if b[k] != a.get(k, 0)}


# ---------------------------------------------------------------- microcode
def check_image(blob):
    """Header magic and the 4-word-group rule of the loader. Returns main word count."""
    magic, ver, ram, n = struct.unpack_from('>IIII', blob, 0)
    if magic != 0xffffaaaa:
        raise ValueError(f'not a microcode image (magic {magic:08x})')
    if n > ram:
        raise ValueError(f'main program ({n} words) larger than instruction RAM ({ram})')
    return n


def load(image):
    """Load a whole microcode image (file on this host) through ppu_debug/mcode_download_file."""
    blob = Path(image).read_bytes()
    check_image(blob)
    remote = '/tmp/npukit_mcode.bin'
    link.push(image, remote)
    return link.ser(f'dmesg -c >/dev/null; echo {remote} > {NP}/ppu_debug/mcode_download_file; sleep 1; dmesg -c | tail -3', 40)


def restore():
    """Reload the stock microcode from the board's own file system."""
    return link.ser(f'dmesg -c >/dev/null; echo {cfg().board.stock_mcode} > {NP}/ppu_debug/mcode_download_file; '
                    'sleep 1; dmesg -c | tail -3', 40)


def inst_get(pc):
    """The aligned group of 4 instruction words containing PC, as {pc: word}."""
    out = link.ser(f'dmesg -c >/dev/null; echo {pc:x} > {NP}/ppu_debug/inst_get; dmesg -c', 20)
    words = {}
    for m in re.finditer(r'inst(\d+):\s*0x([0-9a-f]{16})', out):
        words[(pc & ~3) + int(m[1])] = int(m[2], 16)
    return words, out


def inst_set(pc, word):
    return link.ser(f'echo {pc:x} {word >> 32:x} {word & 0xffffffff:x} > {NP}/ppu_debug/inst_set', 20)


def reboot(lan_only=False):
    """Reboot through the UART without touching U-Boot, then run lan1-up (mac/board_reboot.py).
    lan_only: do not reboot, only wait for the shell and run lan1-up (after a crash/reboot)."""
    import shlex
    flag = ' --no-reboot' if lan_only else ''
    return link.mac(f'cd {shlex.quote(link.workdir())} && {link._env()} python3 board_reboot.py{flag}', 600)


# ---------------------------------------------------------------- SE tables
def sdt(n):
    out = link.script([f'echo {n} > se_debug/sdt_get'], 60, name='npukit_sdt')
    fields = {}
    for m in re.finditer(r'^\s*(\w+)\s*:\s*(\S+)', out, re.M):
        fields[m[1]] = m[2]
    return fields


def se_read(sdt_no, index, words=4):
    """Read one eRAM entry. Returns its 32-bit words in microcode result order
    (first = most significant = r(32+4S)); WORDS = entry width / 32 (1, 2 or 4)."""
    # se_debug/eram_table_get reads non-destructively. NEVER use cpu_get_eram_by_table_width:
    # it reads with "free" (rd_mode 1) and clears the entry (SAFETY.md).
    out = link.ser(f'dmesg -c >/dev/null; echo {sdt_no} {index} > {NP}/se_debug/eram_table_get; dmesg -c', 20)
    m = re.search(r'eram_table\(word32_len is \d+\):((?:\s*0x[0-9a-f]+)+)', out)
    if not m:
        raise link.LinkError(f'eRAM read failed: {out.strip()[-300:]}')
    vals = [int(x, 16) for x in re.findall(r'0x([0-9a-f]+)', m[1])]
    return vals[-words:]          # narrower entries are right-aligned in the printed row


ACL_SDTS = range(111, 123)


def se_write(sdt_no, index, words, force=False):
    """Write one eRAM entry, words in microcode order (as se_read returns them).

    ACL tables (#111-#122) are refused: acl_debug keeps a shadow copy, and the next
    acl_*_set on an entry changed behind its back recurses until the kernel panics."""
    if sdt_no in ACL_SDTS and not force:
        raise ValueError(f'#{sdt_no} is an ACL table: write it through acl_debug (npu fast ...). A direct write '
                         'makes the next acl_*_set on this entry crash the kernel (SAFETY.md); use force to override')
    w = list(words) + [0] * (4 - len(words))
    return link.ser(f'echo {sdt_no} {index} {len(words)} ' + ' '.join(f'{x:x}' for x in w)
                    + f' > {NP}/se_debug/cpu_set_eram_by_table_width', 20)


def hash_op(sdt_no, key_hex, rsp_hex=None, op=0):
    """Insert (op 0) or delete (op 1) one hash entry through se_debug."""
    se = f'cd {NP}/se_debug; '
    link.ser(se + f'cat multi_hash_reset >/dev/null; echo 1 > multi_hash_sub_key_num; '
             f'echo 0 {len(key_hex) * 4} > multi_hash_sub_key_bit_len', 20)
    cmd = se + f'echo 0 {key_hex} > multi_hash_sub_key_str; '
    if rsp_hex is not None:
        cmd += f'echo {len(rsp_hex) // 2} {rsp_hex} > multi_hash_rsp_str; '
    return link.ser(cmd + f'dmesg -c >/dev/null; echo {sdt_no} {op} > single_hash_op; dmesg -c | tail -3', 20)


def mac50(mac, port, op=0):
    """MAC table #50 (source check and destination lookup): key = MAC + 0x0000,
    result word 0 bits 13:8 = port. Never add the jump Mac's own address (SAFETY.md)."""
    mac_hex = mac.replace(':', '').lower()
    if op == 0 and mac_hex == cfg().mac.addr.replace(':', '').lower():
        raise ValueError("refusing to put the Mac's own MAC into #50: its ARP broadcasts would be dropped")
    return hash_op(50, mac_hex + '0000', f'{port << 8:08x}00000000', op)


def key_last():
    """Last hash-lookup key and response seen by the PPU (ppu_debug/key_last_info):
    (key bytes, response words). Only the first 32 key bytes are meaningful for #164."""
    out = link.ser(f'dmesg -c >/dev/null; cat {NP}/ppu_debug/key_last_info; dmesg -c', 20)
    kw = {int(m[1]): int(m[2], 16) for m in re.finditer(r'e key last (\d+)\(0x[0-9a-f]+\):\s*:\s*0x([0-9a-f]+)', out)}
    rw = {int(m[1]): int(m[2], 16) for m in re.finditer(r'e key rsp last info (\d+)\(0x[0-9a-f]+\):\s*:\s*0x([0-9a-f]+)', out)}
    key = b''.join(struct.pack('>I', kw[i]) for i in sorted(kw, reverse=True))
    rsp = [rw[i] for i in sorted(rw, reverse=True)]
    return key, rsp, out


def _tmp(name):
    return Path(tempfile.gettempdir()) / name
