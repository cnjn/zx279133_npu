"""Extract the ZX133 CPU-side counter names, without looking at the microcode.

This recognizes the specific argument setup and success-print idioms in
np_133.ko:debug_stat_show, not arbitrary AArch64 code. Keep nonconstant w1
expressions as such. Never infer a label from string order or an error path.
"""
import os
import re
import shutil
import subprocess
from typing import NamedTuple


class StatRead(NamedTuple):
    call: int           # .text byte offset of bl se_stat_table_get
    w1: str             # actual index argument setup
    index: int | None   # only for mov w1, #imm
    fmt_off: int        # .rodata.str1.1 section offset
    label: str


def _argument(code, pc, reg):
    # The two argument assignments are local to the call block in this build.
    for at in range(pc - 4, pc - 36, -4):
        asm = code.get(at, ('', ''))[0]
        if not asm or re.match(r'(?:b(?:\.\w+|l|r|lr)?|[ct]bn?z|ret)\b', asm):
            break
        if re.match(rf'\w+ [wx]{reg}, ', asm):
            return asm
    raise ValueError(f'unknown argument {reg} at {pc:#x}')


def _success_format(code, pc):
    guard = re.fullmatch(r'cbnz w0, ([0-9a-f]+) <[^>]+>', code[pc+4][0])
    if not guard:
        raise ValueError(f'unknown return check at {pc:#x}')
    fail = int(guard[1], 16)
    arm = range(pc + 8, fail, 4)  # zero return, nonzero-count/log-level checks may skip the print

    def fmt_ref(inst, reloc):
        matches = [at for at in arm if code[at][0].startswith(inst)
                   and code[at][1].startswith(reloc + ' .rodata.str1.1+')]
        if len(matches) != 1:
            raise ValueError(f'expected one {reloc} for success format at {pc:#x}')
        at = matches[0]
        return at, int(code[at][1].split('+')[1], 0)

    hi, off = fmt_ref('adrp x0, ', 'R_AARCH64_ADR_PREL_PG_HI21')
    lo, off2 = fmt_ref('add x0, x0, ', 'R_AARCH64_ADD_ABS_LO12_NC')
    asm, target = code[lo+4]
    shared = re.fullmatch(r'b ([0-9a-f]+) <[^>]+>', asm)
    if shared:  # the last read branches directly to a shared printk
        asm, target = code[int(shared[1], 16)]
    if hi >= lo or off != off2 or not asm.startswith('bl ') or target != 'R_AARCH64_CALL26 printk':
        raise ValueError(f'mismatched success format/print at {pc:#x}')
    return off


def driver_reads(module, objdump=None):
    """Return all table-48 read call sites in debug_stat_show, including loops."""
    tool = (objdump or os.environ.get('OBJDUMP') or shutil.which('aarch64-linux-gnu-objdump')
            or shutil.which('aarch64-alpine-linux-musl-objdump') or 'objdump')
    dis = subprocess.check_output([tool, '-hdrw', '--no-show-raw-insn',
                                   '--disassemble=debug_stat_show', module],
                                  text=True, env={**os.environ, 'LC_ALL': 'C'})
    section = re.search(r'^\s*\d+\s+\.rodata\.str1\.1\s+(\w+)\s+\w+\s+\w+\s+(\w+)\s', dis, re.M)
    _, marker, body = dis.partition(' <debug_stat_show>:\n')
    if not marker or not section:
        raise ValueError('need the ZX133 module with debug_stat_show and .rodata.str1.1')
    size, start = (int(x, 16) for x in section.groups())
    with module.open('rb') as f:
        f.seek(start)
        strings = f.read(size)
    if len(strings) != size:
        raise ValueError('truncated .rodata.str1.1')

    # GNU objdump -w puts each relocation on the line of its instruction.
    code = {}
    for addr, stmt in re.findall(r'^\s*([0-9a-f]+):\s*(.+)$', body.split('\n\n', 1)[0], re.M):
        parts = re.split(r' [0-9a-f]+: ', ' '.join(stmt.split()), maxsplit=1)
        code[int(addr, 16)] = (parts[0].split(' //')[0], parts[1] if len(parts) == 2 else '')
    reads = []
    for pc, (asm, reloc) in code.items():
        if reloc != 'R_AARCH64_CALL26 se_stat_table_get' or not asm.startswith('bl '):
            continue
        if _argument(code, pc, 0) != 'mov w0, #0x30':
            raise ValueError(f'unexpected table argument at {pc:#x}')
        w1 = _argument(code, pc, 1)
        imm = re.fullmatch(r'mov w1, #(0x[0-9a-f]+|\d+)', w1)
        if not imm and not re.fullmatch(r'mov w1, w\d+|add w1, w\d+, #0x[0-9a-f]+', w1):
            raise ValueError(f'unknown index expression at {pc:#x}: {w1}')
        off = _success_format(code, pc)
        fmt = strings[off:strings.index(b'\0', off)].decode('ascii').strip()
        if not fmt.endswith('%u'):
            raise ValueError(f'unknown counter print format at {pc:#x}')
        reads.append(StatRead(pc, w1, int(imm[1], 0) if imm else None, off,
                              fmt[:-2].rstrip(' \t:;')))
    if not reads:
        raise ValueError('no relocated table reads found')
    return reads
