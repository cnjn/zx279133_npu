"""Talk to the jump Mac (ssh/scp) and to the board (UART via the Mac, files over LAN).

Board commands go through mac/ser.py on the Mac.  Keep single commands short: the UART
shell drops characters from long lines, so anything longer than ~200 characters should go
through script(), which pushes a shell script over LAN and runs it."""
import re
import shlex
import subprocess
import tempfile
from pathlib import Path

from .config import MAC_FILES, cfg


class LinkError(RuntimeError):
    pass


def _ssh_base():
    c = cfg()
    if not c.mac.host:
        raise LinkError('mac.host is not set; copy npu/config.example.toml to npu/config.toml')
    return ['ssh', *c.mac.ssh_options, c.mac.host]


def mac(cmd, timeout=60):
    """Run a shell command on the Mac; returns stdout + stderr."""
    r = subprocess.run(_ssh_base() + [cmd], capture_output=True, text=True, timeout=timeout)
    return r.stdout + r.stderr


def _scp(args, timeout=120):
    c = cfg()
    r = subprocess.run(['scp', '-q', *c.mac.ssh_options, *args], capture_output=True, text=True, timeout=timeout)
    if r.returncode:
        raise LinkError(f'scp failed: {r.stderr.strip()}')


def mac_put(local, remote):
    _scp([str(local), f'{cfg().mac.host}:{remote}'])


def mac_get(remote, local):
    _scp([f'{cfg().mac.host}:{remote}', str(local)])


def workdir():
    return cfg().mac.workdir


def _env():
    c = cfg()
    return f'NPU_SERIAL_DEV={shlex.quote(c.mac.serial_dev)} NPU_BOARD_IP={shlex.quote(c.board.ip)}'


def ser(cmd, timeout=30):
    """Run one shell command on the board's UART shell. Output ends with '[exit N]'
    (or '[TIMEOUT, raw tail]')."""
    if len(cmd) > 400:
        raise LinkError('command too long for the UART (characters get lost); use script()')
    return mac(f'cd {shlex.quote(workdir())} && {_env()} python3 ser.py {shlex.quote(cmd)} {timeout}', timeout + 30)


def ser_ok(out):
    m = re.search(r'\[exit (\d+)\]', out)
    return bool(m) and m[1] == '0'


def push(local, remote, port=None):
    """Copy a local file to the board (via the Mac, then nc over LAN); verifies sha256."""
    c = cfg()
    tmp = f'/tmp/npukit_{Path(remote).name}'
    mac_put(local, tmp)
    ser('killall nc 2>/dev/null; true', 15)       # stale listeners from failed pushes block the port
    out = mac(f'cd {shlex.quote(workdir())} && {_env()} sh push.sh {tmp} {shlex.quote(remote)} {port or c.board.push_port}', 90)
    w = out.split()
    if len(w) < 4 or w[1] != w[3]:
        raise LinkError(f'push of {local} failed (LAN path to the board down?): {out.strip()}')
    return remote


def script(cmds, timeout=120, level=3, name='npukit'):
    """Run commands on the board from a pushed script, with SE print_level LEVEL.

    Each command's output and the dmesg it produced follow a line '=== <command>'.
    Output streams over the UART, so it survives a kernel crash in the middle."""
    lines = ['#!/bin/sh', 'cd /sys/devices/platform/np', 'dmesg -c >/dev/null', f'echo {level} > test/print_level']
    for c in cmds:
        lines.append("echo '=== " + c.replace("'", '') + "'")
        lines.append(c)
        lines.append("dmesg -c | sed 's/^\\[[ 0-9.]*\\] //'")
    lines.append('echo 1 > test/print_level')
    local = Path(tempfile.gettempdir()) / f'{name}.sh'
    local.write_text('\n'.join(lines) + '\n')
    push(local, f'/tmp/{name}.sh')
    return ser(f'sh /tmp/{name}.sh 2>&1', timeout)


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


def mac_sync():
    """Copy npu/mac/* to the Mac work directory."""
    wd = workdir()
    mac(f'mkdir -p {shlex.quote(wd)}')
    files = sorted(p for p in MAC_FILES.iterdir() if p.is_file())
    _scp([*map(str, files), f'{cfg().mac.host}:{wd}/'])
    return [p.name for p in files]
