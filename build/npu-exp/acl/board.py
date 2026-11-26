"""Board helpers for the ACL experiments (exp101+): run sysfs commands and collect dmesg.

Long command lines lose characters on the serial console, so script() pushes a shell
script over LAN (push.sh on the Mac) and runs it from a file."""
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'oracle'))
import bench  # noqa: E402

NP = '/sys/devices/platform/np'


def script(cmds, timeout=120, level=3, name='acl'):
    """Run commands on the board from a pushed script with print_level LEVEL.

    Each command's output and dmesg follow a line '=== cmd'."""
    lines = ['#!/bin/sh', f'cd {NP}', 'dmesg -c >/dev/null', f'echo {level} > test/print_level']
    for c in cmds:
        q = c.replace("'", "")
        lines.append(f"echo '=== {q}'")
        lines.append(c)
        lines.append("dmesg -c | sed 's/^\\[[ 0-9.]*\\] //'")
    lines.append('echo 1 > test/print_level')
    local = Path(tempfile.gettempdir()) / f'{name}.sh'
    local.write_text('\n'.join(lines) + '\n')
    bench.mac_put(str(local), f'/tmp/{name}.sh')
    r = bench.mac(f'cd {bench.SERDIR} && sh push.sh /tmp/{name}.sh /tmp/{name}.sh 9178', 60)
    w = r.split()
    if len(w) < 4 or w[1] != w[3]:
        raise RuntimeError('push failed: ' + r)
    return bench.ser(f'sh /tmp/{name}.sh 2>&1', timeout)  # stream: output survives a crash


def blocks(out):
    """Split script() output into {command: text}."""
    res, cur, buf = {}, None, []
    for line in out.splitlines():
        m = re.match(r'=== (.*)', line)
        if m:
            if cur is not None:
                res[cur] = '\n'.join(buf)
            cur, buf = m[1], []
        elif cur is not None and not line.startswith('[exit'):
            buf.append(line)
    if cur is not None:
        res[cur] = '\n'.join(buf)
    return res


def hash_op(sdt, key_hex, rsp_hex=None, op=0, key_bits=None):
    """Insert (op 0) or delete (op 1) one hash entry with se_debug, using short serial commands."""
    se = f'cd {NP}/se_debug; '
    bits = key_bits or len(key_hex) * 4
    bench.ser(se + f'cat multi_hash_reset >/dev/null; echo 1 > multi_hash_sub_key_num; echo 0 {bits} > multi_hash_sub_key_bit_len', 20)
    cmd = se + f'echo 0 {key_hex} > multi_hash_sub_key_str; '
    if rsp_hex is not None:
        cmd += f'echo {len(rsp_hex) // 2} {rsp_hex} > multi_hash_rsp_str; '
    return bench.ser(cmd + f'dmesg -c >/dev/null; echo {sdt} {op} > single_hash_op; dmesg -c | grep -iE "success|fail|err" | tail -2', 20)


def mac50(mac_hex, port, op=0):
    """MAC table #50: key = MAC + 0x0000, result word 0 bits 13:8 = port."""
    return hash_op(50, mac_hex + '0000', f'{port << 8:08x}00000000', op)


def eth0_rx():
    out = bench.ser('grep eth0 /proc/net/dev', 10)
    for line in out.splitlines():
        if 'eth0:' in line:
            return int(line.split(':', 1)[1].split()[1])
    return None
