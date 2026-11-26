#!/usr/bin/env python3
"""Build a lab-only ZX279133 initramfs: static BusyBox and a physical UART shell."""

import argparse
import hashlib
import lzma
from pathlib import Path
import stat
import struct

from build_debug_rootfs import (OVERLAY, add_debug, archive_records, build, debug_files,
                                newc_record, require_static_arm)

# Only the physical PL011 tty receives a shell. No mount -a, mdev, ifup or stock rcS.
INITTAB = b'''# Lab UART only: do not start the vendor system or network services.
::sysinit:/bin/busybox mount -t proc proc /proc
::sysinit:/bin/busybox mount -t sysfs sysfs /sys
::sysinit:/bin/busybox mount -t tmpfs -o mode=1777,nosuid,nodev tmpfs /var/tmp
ttyAMA0::respawn:-/debug/bin/serial-shell
'''

# Intentionally weak lab password: openssl passwd -6 -salt ontlab-133 -- root
ROOT_HASH = (b'$6$ontlab-133$i9C4/73EeFM2F2CsX0wXCDL8htOW4SeN8MdncrtFlimAB0UWf2AAm3RTZ3n0'
             b'G1nmMXqy6vxeahjGO8s.R2QLE.')

EXTRA_APPLETS = ('ascii', 'crc32', 'getfattr', 'ipcalc', 'lsblk', 'sha384sum',
                 'tree', 'tsort', 'uuidgen', 'vmstat')
REPLACED = (b'bin/busybox', b'etc/inittab', b'etc/passwd', b'etc/shadow')

# Optional LAN1 + SSH bundle (--lan-ssh DIR, built by build_ssh.sh); started by hand.
LAN_SSH_SCRIPTS = ('lab-modules', 'lab-sshd', 'lan1-up')
LAN_SSH_BINARIES = {'lan1-register': 'debug/bin/lan1-register',
                    'dropbearmulti': 'debug/bin/dropbearmulti',
                    'sftp-server': 'debug/libexec/sftp-server'}
DROPBEAR_LINKS = ('dropbear', 'dropbearkey', 'scp', 'dbclient')


def replace_root_shadow(data):
    lines = data.splitlines(keepends=True)
    matches = [i for i, line in enumerate(lines) if line.startswith(b'root:')]
    if len(matches) != 1 or len(lines[matches[0]].rstrip(b'\r\n').split(b':')) != 9:
        raise ValueError('Expected one conventional root shadow record')
    # lastchg must be non-zero: BusyBox login rejects lastchg 0/empty (verified on the board).
    lines[matches[0]] = b'root:' + ROOT_HASH + b':1::::::\n'
    return b''.join(lines)


def lan_ssh_entries(binaries):
    """(path, mode, nlink, data) records for the LAN1/SSH bundle."""
    if set(binaries) != set(LAN_SSH_BINARIES):
        raise ValueError(f'--lan-ssh needs exactly {sorted(LAN_SSH_BINARIES)}')
    for name, data in binaries.items():
        try:
            require_static_arm(data)
        except (ValueError, struct.error) as exc:
            raise ValueError(f'{name}: {exc}') from exc
        if data[4] != 1 or not struct.unpack_from('<I', data, 36)[0] & 0x200:
            raise ValueError(f'{name}: must be ARM32 soft-float, matching the stock ABI')
    entries = [(f'debug/bin/{name}', stat.S_IFREG | 0o755, 1, (OVERLAY / name).read_bytes())
               for name in LAN_SSH_SCRIPTS]
    entries += [(LAN_SSH_BINARIES[name], stat.S_IFREG | 0o755, 1, binaries[name])
                for name in ('lan1-register', 'dropbearmulti')]
    entries += [(f'debug/bin/{name}', stat.S_IFLNK | 0o777, 1, b'dropbearmulti')
                for name in DROPBEAR_LINKS]
    entries += [('debug/libexec', stat.S_IFDIR | 0o755, 2, b''),
                (LAN_SSH_BINARIES['sftp-server'], stat.S_IFREG | 0o755, 1, binaries['sftp-server'])]
    return entries


def apply_serial(archive, busybox, lan_ssh=None):
    require_static_arm(busybox)
    if busybox[4] != 1 or not struct.unpack_from('<I', busybox, 36)[0] & 0x200:
        raise ValueError('BusyBox must be ARM32 soft-float, matching the stock ABI')

    records = {entry[0]: entry for entry in archive_records(archive)}

    def contents(name):
        _, _, payload, _, fields = records[name]
        return archive[payload:payload + fields[6]]

    # Both vendor rdinit=/sbin/init and the /init fallback already invoke BusyBox.
    for name, link in ((b'sbin/init', b'../bin/busybox'), (b'bin/sh', b'busybox')):
        if not stat.S_ISLNK(records[name][-1][1]) or contents(name).rstrip(b'\0') != link:
            raise ValueError(f'Unexpected stock symlink: {name!r}')
    tty = records[b'dev/ttyAMA0'][-1]
    if not stat.S_ISCHR(tty[1]) or tty[9:11] != (204, 64):
        raise ValueError('Expected the stock PL011 /dev/ttyAMA0 device node')
    passwd = contents(b'etc/passwd')
    roots = [line.split(b':') for line in passwd.splitlines() if line.startswith(b'root:')]
    if len(roots) != 1 or roots[0][1:4] != [b'x', b'0', b'0'] or roots[0][-1:] != [b'/bin/sh']:
        raise ValueError('Unexpected stock root passwd record')
    replacements = {b'bin/busybox': (0o755, busybox),
                    b'etc/inittab': (0o644, INITTAB),
                    b'etc/passwd': (0o644, passwd),
                    b'etc/shadow': (0o600, replace_root_shadow(contents(b'etc/shadow')))}
    path = 'debug/bin/serial-shell'
    aliases = [f'debug/applets/{name}' for name in EXTRA_APPLETS]
    added = [path, 'debug/applets'] + aliases
    extra = lan_ssh_entries(lan_ssh) if lan_ssh is not None else []
    added += [entry[0] for entry in extra]
    if any(name.encode() in records for name in added):
        raise ValueError('Unexpected existing serial profile path')
    for name in (b'debug', b'debug/bin'):
        if not stat.S_ISDIR(records[name][-1][1]):
            raise ValueError(f'Expected existing directory: {name!r}')
    trailer = records.pop(b'TRAILER!!!')
    max_ino = max(entry[-1][0] for entry in records.values())
    # For untouched paths keep raw headers, file bytes and inter-record padding.
    chunks = []
    view = memoryview(archive)
    for name, (_, start, _, end, fields) in records.items():
        if name in replacements:
            if not stat.S_ISREG(fields[1]) or fields[4] != 1:
                raise ValueError(f'Expected standalone regular file: {name!r}')
            mode, data = replacements[name]
            chunks.append(newc_record(name.decode('ascii'), fields[0], stat.S_IFREG | mode, 1, data))
        else:
            chunks.append(view[start:end])
    chunks.extend((newc_record(path, max_ino + 1, stat.S_IFREG | 0o755, 1,
                              (OVERLAY / 'serial-shell').read_bytes()),
                   newc_record('debug/applets', max_ino + 2, stat.S_IFDIR | 0o755, 2, b'')))
    chunks.extend(newc_record(name, max_ino + i, stat.S_IFLNK | 0o777, 1, b'/bin/busybox')
                  for i, name in enumerate(aliases, 3))
    chunks.extend(newc_record(name, max_ino + i, mode, nlink, data)
                  for i, (name, mode, nlink, data) in enumerate(extra, 3 + len(aliases)))
    chunks.append(view[trailer[1]:trailer[3]])
    output = b''.join(chunks)
    output = output.ljust((len(output) + 511) & ~511, b'\0')
    report = dict(profile='serial-shell', changed_paths=['/' + n.decode() for n in REPLACED],
                  serial_added_paths=['/' + n for n in added],
                  busybox_sha256=hashlib.sha256(busybox).hexdigest())
    if lan_ssh is not None:
        report['lan_ssh_sha256'] = {name: hashlib.sha256(data).hexdigest()
                                    for name, data in sorted(lan_ssh.items())}
    return output, report


def verify_serial(stock, candidate):
    records = {entry[0]: entry for entry in archive_records(candidate)}
    _, _, payload, _, fields = records[b'bin/busybox']
    busybox = candidate[payload:payload + fields[6]]
    lan_ssh = None
    if b'debug/bin/lan1-up' in records:
        lan_ssh = {}
        for key, path in LAN_SSH_BINARIES.items():
            _, _, payload, _, fields = records[path.encode()]
            lan_ssh[key] = candidate[payload:payload + fields[6]]
    bundle = {f'debug/bin/{n}'.encode() for n in LAN_SSH_SCRIPTS + ('lan1-register', 'dropbearmulti')}
    # Extra static tools from build-time --tool options, in archive order.
    files = debug_files([])
    for name, (_, _, payload, _, fields) in records.items():
        if (name.startswith(b'debug/bin/') and stat.S_ISREG(fields[1]) and name not in bundle and
                name not in (b'debug/bin/ont-info', b'debug/bin/serial-shell')):
            data = candidate[payload:payload + fields[6]]
            require_static_arm(data)
            files[name[len(b'debug/'):].decode('ascii')] = (0o755, data)
    expected, _ = apply_serial(add_debug(stock, files), busybox, lan_ssh)
    if expected != candidate:
        raise ValueError('Serial initramfs differs from the exact UART profile')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base', type=Path, help='extracted/kernel1')
    parser.add_argument('busybox', type=Path, help='trusted static ARM32 soft-float BusyBox')
    parser.add_argument('output', type=Path, help='new output directory')
    parser.add_argument('--tool', action='append', default=[], metavar='NAME=PATH',
                        help='add a trusted static ARM tool to /debug/bin, e.g. zx-fwslot')
    parser.add_argument('--lan-ssh', type=Path, metavar='DIR',
                        help='add lan1-up, lab-modules, lab-sshd and the build_ssh.sh '
                             'binaries from DIR (lan1-register, dropbearmulti, sftp-server)')
    args = parser.parse_args()
    try:
        binary = args.busybox.read_bytes()
        lan_ssh = None
        if args.lan_ssh is not None:
            lan_ssh = {name: (args.lan_ssh / name).read_bytes() for name in LAN_SSH_BINARIES}
        build(args.base, args.output, args.tool,
              transform=lambda cpio: apply_serial(cpio, binary, lan_ssh))
    except (OSError, ValueError, KeyError, struct.error, lzma.LZMAError) as exc:
        parser.exit(1, f'error: {exc}\n')


if __name__ == '__main__':
    main()
