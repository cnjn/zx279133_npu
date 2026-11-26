#!/usr/bin/env python3
"""Repack/inspect the ZX279133 plain single-FIT OTA layout, offline only."""

import argparse
import hashlib
import json
import lzma
from pathlib import Path
import stat
import struct
import zlib

from build_debug_rootfs import BANK_BYTES, RAMDISK, archive_layout, stock_ramdisk
from extract_flash import BANK_MAGIC, FDT, fdt_nodes
from serial_rootfs import verify_serial
from stock_busybox_rootfs import verify_stock_busybox

HEADER_BYTES = 0x1e0


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def align16(size):
    return (size + 15) & ~15


def read_regular(path):
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > BANK_BYTES:
        raise ValueError(f'Expected a regular file no larger than one bank: {path}')
    return path.read_bytes()


def parse(data, *, allow_erased_padding=False):
    """Strict subset supported by the builder, not a device acceptance check."""
    if not HEADER_BYTES < len(data) <= BANK_BYTES or data[:16] != BANK_MAGIC:
        raise ValueError('Missing plain ZXIC image header or invalid size')
    header = data[:HEADER_BYTES]
    if (u32(header, 0x10) != 0 or u32(header, 0x18) != 0 or
            u32(header, 0x50) != 1 or header[0x148:0x14c] != b'133\0'):
        raise ValueError('Unsupported header: need the plain, single-version ZX279133 layout')
    if (u32(header, 0x64) or u32(header, 0x6c) or any(header[0xc8:0xf8]) or
            header[0x178:] != b'\xff' * (HEADER_BYTES - 0x178)):
        raise ValueError('Unsupported additional components or populated header trailer')
    if u32(header, 0x110) != zlib.crc32(header[0x14:0x110]):
        raise ValueError('Bad version-header CRC32')
    length, offset, expected_crc = struct.unpack_from('<III', header, 0x58)
    fit_end = offset + length
    end = align16(fit_end)
    if (offset != HEADER_BYTES or length < 40 or end > len(data) or
            u32(header, 0x54) != end or u32(header, 0x68) != end):
        raise ValueError('Inconsistent payload ranges')
    padding = data[fit_end:]
    if (len(data) != end and not allow_erased_padding) or padding.count(0xff) != len(padding):
        raise ValueError('Unexpected data after the FIT')
    fit = data[offset:fit_end]
    if fit[:4] != FDT or int.from_bytes(fit[4:8], 'big') != len(fit):
        raise ValueError('Bad FIT magic or size')
    if zlib.crc32(fit) != expected_crc:
        raise ValueError('Bad FIT CRC32')
    return header, fit


def verify_debug_payload(stock_header, stock, candidate, *, profile='debug'):
    nodes, old_ramdisk = stock_ramdisk(stock, stock_header)
    total, new_nodes = fdt_nodes(candidate)
    if len(candidate) != total or nodes.keys() != new_nodes.keys():
        raise ValueError('Candidate FIT layout differs from its stock base')
    for node, props in nodes.items():
        new_props = new_nodes[node]
        if props.keys() != new_props.keys() or any(
                val != new_props[name][1] for name, (_, val) in props.items()
                if (node, name) != (RAMDISK, 'data')):
            raise ValueError(f'Candidate changed properties outside ramdisk data: {node}')
    cpio = lzma.decompress(old_ramdisk[1], format=lzma.FORMAT_ALONE)
    debug = lzma.decompress(new_nodes[RAMDISK]['data'][1], format=lzma.FORMAT_ALONE)
    if profile == 'serial-shell':
        verify_serial(cpio, debug)
        return
    if profile == 'stock-busybox':
        verify_stock_busybox(cpio, debug)
        return
    trailer, _, names, _ = archive_layout(cpio)
    _, _, new_names, _ = archive_layout(debug)
    added = new_names - names
    if (cpio[:trailer] != debug[:trailer] or b'debug/bin/ont-info' not in added or
            any(path != b'debug' and not path.startswith(b'debug/') for path in added)):
        raise ValueError('Candidate initramfs must preserve stock records and only append /debug')


def wrap(header, fit):
    """Update only sizes, offsets and CRCs; preserve version and board metadata."""
    fit_end = HEADER_BYTES + len(fit)
    end = align16(fit_end)
    if end > BANK_BYTES:
        raise ValueError('Candidate exceeds nominal bank size')
    updated = bytearray(header)
    struct.pack_into('<II', updated, 0x54, end, len(fit))
    struct.pack_into('<I', updated, 0x60, zlib.crc32(fit))
    struct.pack_into('<I', updated, 0x68, end)
    struct.pack_into('<I', updated, 0x110, zlib.crc32(updated[0x14:0x110]))
    return bytes(updated) + fit + b'\xff' * (end - fit_end)


def inspect(data):
    header, fit = parse(data)
    nodes, _ = stock_ramdisk(fit, header)
    return dict(format='ZXIC ZX279133 plain single-FIT OTA', bytes=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
                firmware_version=header[0x24:0x50].split(b'\0', 1)[0].decode('ascii'),
                fit=dict(offset=HEADER_BYTES, bytes=len(fit), crc32=f'{u32(header, 0x60):08x}',
                         configurations=sum(node.startswith('/configurations/') for node in nodes)),
                header_crc32=f'{u32(header, 0x110):08x}',
                nominal_bank_slack=BANK_BYTES - len(data),
                validation='offline structure and CRCs only; device acceptance not verified')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    build = sub.add_parser('build', help='make an offline candidate from a verified clean bank')
    build.add_argument('stock_bank', type=Path, help='extracted/mtd_dtb/kernel1.bin')
    build.add_argument('debug_fit', type=Path, help='debug FIT built from the same stock bank')
    build.add_argument('output', type=Path, help='new file; must not already exist')
    kind = build.add_mutually_exclusive_group()
    kind.add_argument('--serial-shell', dest='profile', action='store_const', const='serial-shell',
                      help='allow the exact UART-shell profile')
    kind.add_argument('--stock-busybox', dest='profile', action='store_const', const='stock-busybox',
                      help='allow the stock system with only BusyBox and the root password replaced')
    build.set_defaults(profile='debug')
    check = sub.add_parser('inspect', help='check structure and CRCs without running the updater')
    check.add_argument('package', type=Path)
    args = parser.parse_args()
    try:
        if args.action == 'build':
            source = read_regular(args.stock_bank)
            header, fit = parse(source, allow_erased_padding=True)
            unchanged = wrap(header, fit)
            if unchanged != source[:len(unchanged)]:
                raise ValueError('Unmodified stock image does not round-trip')
            candidate = read_regular(args.debug_fit)
            verify_debug_payload(header, fit, candidate, profile=args.profile)
            data = wrap(header, candidate)
            report = inspect(data)
            if args.profile != 'debug':
                report['profile'] = args.profile
            with args.output.open('xb') as output:
                output.write(data)
        else:
            report = inspect(read_regular(args.package))
        print(json.dumps(report, indent=2))
    except (OSError, ValueError, KeyError, struct.error, lzma.LZMAError) as exc:
        parser.exit(1, f'error: {exc}\n')


if __name__ == '__main__':
    main()
