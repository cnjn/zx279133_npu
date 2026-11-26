#!/usr/bin/env python3
"""Build a stock ZX279133 initramfs with only BusyBox and the root password replaced."""

import argparse
import hashlib
import lzma
from pathlib import Path
import stat
import struct

from build_debug_rootfs import (OVERLAY, align4, archive_records, build, newc_record,
                                require_static_arm)
from serial_rootfs import DROPBEAR_LINKS, replace_root_shadow

# Everything else, including inittab, passwd, init scripts and record metadata, stays stock.
REPLACED = (b'bin/busybox', b'etc/shadow')
# Vendor osgid bug: with no java process, getMainPidByTaskName("java") returns -1 and
# osgid has pc run "kill -9 -1", killing everything but init about a minute after boot.
# One byte: the format "kill -9 %d" becomes "kill -9 %u", so -1 prints as 4294967295
# (no such process); real PIDs print the same as before.
OSGID = b'bin/osgid'
OSGID_FORMAT = (0xa357, b'kill -9 %d\0', b'kill -9 %u\0')


def patch_osgid(data):
    offset, old, new = OSGID_FORMAT
    if data.count(old) != 1 or data[offset:offset + len(old)] != old:
        raise ValueError('Unexpected /bin/osgid: kill format string not found where expected')
    return data[:offset] + new + data[offset + len(new):]

# Optional SSH bundle (--ssh DIR from build_ssh.sh), appended under /debug; started by hand.
SSH_SCRIPTS = ('ssh-up', 'lab-sshd')
SSH_BINARIES = {'dropbearmulti': 'debug/bin/dropbearmulti',
                'sftp-server': 'debug/libexec/sftp-server'}


def ssh_entries(binaries):
    """(path, mode, nlink, data) records for the stock-system SSH bundle."""
    if set(binaries) != set(SSH_BINARIES):
        raise ValueError(f'--ssh needs exactly {sorted(SSH_BINARIES)}')
    for name, data in binaries.items():
        try:
            require_static_arm(data)
        except (ValueError, struct.error) as exc:
            raise ValueError(f'{name}: {exc}') from exc
        if data[4] != 1 or not struct.unpack_from('<I', data, 36)[0] & 0x200:
            raise ValueError(f'{name}: must be ARM32 soft-float, matching the stock ABI')
    entries = [('debug', stat.S_IFDIR | 0o755, 4, b''),
               ('debug/bin', stat.S_IFDIR | 0o755, 2, b'')]
    entries += [(f'debug/bin/{name}', stat.S_IFREG | 0o755, 1, (OVERLAY / name).read_bytes())
                for name in SSH_SCRIPTS]
    entries.append((SSH_BINARIES['dropbearmulti'], stat.S_IFREG | 0o755, 1, binaries['dropbearmulti']))
    entries += [(f'debug/bin/{name}', stat.S_IFLNK | 0o777, 1, b'dropbearmulti')
                for name in DROPBEAR_LINKS]
    entries += [('debug/libexec', stat.S_IFDIR | 0o755, 2, b''),
                (SSH_BINARIES['sftp-server'], stat.S_IFREG | 0o755, 1, binaries['sftp-server'])]
    return entries


def raw_record(name, fields, data):
    """Re-emit a newc record with its stock fields; only the file size changes."""
    fields = list(fields)
    fields[6] = len(data)
    name = name + b'\0'
    if fields[11] != len(name):
        raise ValueError(f'Unexpected newc name size: {name!r}')
    header = b'070701' + ''.join(f'{value:08x}' for value in fields).encode('ascii') + name
    return header.ljust(align4(len(header)), b'\0') + data.ljust(align4(len(data)), b'\0')


def apply_stock_busybox(archive, busybox, ssh=None):
    require_static_arm(busybox)
    if busybox[4] != 1 or not struct.unpack_from('<I', busybox, 36)[0] & 0x200:
        raise ValueError('BusyBox must be ARM32 soft-float, matching the stock ABI')
    records = {entry[0]: entry for entry in archive_records(archive)}
    if any(name == b'debug' or name.startswith(b'debug/') for name in records):
        raise ValueError('Expected a stock initramfs without /debug')
    for name in REPLACED:
        fields = records[name][-1]
        if not stat.S_ISREG(fields[1]) or fields[4] != 1:
            raise ValueError(f'Expected standalone regular file: {name!r}')
    _, _, payload, _, fields = records[b'etc/shadow']
    shadow = replace_root_shadow(archive[payload:payload + fields[6]])
    _, _, payload, _, fields = records[OSGID]
    if not stat.S_ISREG(fields[1]) or fields[4] != 1:
        raise ValueError('Expected standalone regular file: /bin/osgid')
    osgid = patch_osgid(archive[payload:payload + fields[6]])
    replacements = {b'bin/busybox': busybox, b'etc/shadow': shadow, OSGID: osgid}
    chunks = []
    view = memoryview(archive)
    extra = ssh_entries(ssh) if ssh is not None else []
    max_ino = max(entry[-1][0] for name, entry in records.items() if name != b'TRAILER!!!')
    for name, (_, start, _, end, fields) in records.items():
        if name == b'TRAILER!!!':
            chunks.extend(newc_record(path, max_ino + i, mode, nlink, data)
                          for i, (path, mode, nlink, data) in enumerate(extra, 1))
        if name in replacements:
            chunks.append(raw_record(name, fields, replacements[name]))
        else:
            chunks.append(view[start:end])
    output = b''.join(chunks)
    output = output.ljust((len(output) + 511) & ~511, b'\0')
    report = dict(profile='stock-busybox',
                  changed_paths=['/' + n.decode() for n in REPLACED + (OSGID,)],
                  busybox_sha256=hashlib.sha256(busybox).hexdigest())
    if ssh is not None:
        report['ssh_added_paths'] = ['/' + entry[0] for entry in extra]
        report['ssh_sha256'] = {name: hashlib.sha256(data).hexdigest()
                                for name, data in sorted(ssh.items())}
    return output, report


def verify_stock_busybox(stock, candidate):
    records = {entry[0]: entry for entry in archive_records(candidate)}
    _, _, payload, _, fields = records[b'bin/busybox']
    busybox = candidate[payload:payload + fields[6]]
    ssh = None
    if b'debug/bin/ssh-up' in records:
        ssh = {}
        for key, path in SSH_BINARIES.items():
            _, _, payload, _, fields = records[path.encode()]
            ssh[key] = candidate[payload:payload + fields[6]]
    expected, _ = apply_stock_busybox(stock, busybox, ssh)
    if expected != candidate:
        raise ValueError('Initramfs differs from the exact stock-busybox profile')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base', type=Path, help='extracted/kernel1')
    parser.add_argument('busybox', type=Path, help='trusted static ARM32 soft-float BusyBox')
    parser.add_argument('output', type=Path, help='new output directory')
    parser.add_argument('--ssh', type=Path, metavar='DIR',
                        help='add /debug/bin/ssh-up and the build_ssh.sh binaries from DIR '
                             '(dropbearmulti, sftp-server)')
    args = parser.parse_args()
    try:
        binary = args.busybox.read_bytes()
        ssh = None
        if args.ssh is not None:
            ssh = {name: (args.ssh / name).read_bytes() for name in SSH_BINARIES}
        build(args.base, args.output, [], overlay=False,
              transform=lambda cpio: apply_stock_busybox(cpio, binary, ssh))
    except (OSError, ValueError, KeyError, struct.error, lzma.LZMAError) as exc:
        parser.exit(1, f'error: {exc}\n')


if __name__ == '__main__':
    main()
