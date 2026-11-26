#!/usr/bin/env python3
"""Append manual diagnostics to a stock ZX279133 initramfs, entirely offline."""

import argparse
import gzip
import hashlib
import lzma
from pathlib import Path
import re
import stat
import struct
import tarfile
import zlib
from io import BytesIO

from extract_flash import BANK_MAGIC, align4, fdt_nodes, save_json

RAMDISK = '/images/initramfs@133'
BANK_BYTES = 32 * (1 << 20)
OVERLAY = Path(__file__).with_name('debug_overlay')


def archive_records(data):
    """Yield (normalized name, record start, payload start, record end, fields)."""
    pos, names = 0, set()
    while pos + 110 <= len(data):
        if data[pos:pos + 6] != b'070701':
            raise ValueError(f'Expected a newc record at {pos:#x}')
        fields = struct.unpack('>13I', bytes.fromhex(data[pos + 6:pos + 110].decode('ascii')))
        size, nlen = fields[6], fields[11]
        start = pos + 110
        end = start + nlen
        payload = align4(end)
        next_pos = align4(payload + size)
        if nlen < 2 or next_pos > len(data) or data[end - 1] != 0:
            raise ValueError(f'Truncated or invalid newc record at {pos:#x}')
        name = data[start:end - 1]
        if name == b'TRAILER!!!':
            if size or any(data[next_pos:]):
                raise ValueError('Unexpected data at or after the newc trailer')
            yield name, pos, payload, next_pos, fields
            return
        parts = name.split(b'/')
        if name.startswith(b'/') or b'..' in parts or b'\0' in name:
            raise ValueError(f'Unsafe archive path: {name!r}')
        normal = b'/'.join(part for part in parts if part not in (b'', b'.'))
        if normal in names:
            raise ValueError(f'Duplicate archive path: {name!r}')
        names.add(normal)
        yield normal, pos, payload, next_pos, fields
        pos = next_pos
    raise ValueError('Missing newc trailer')


def archive_layout(data):
    """Return the raw trailer span, existing names and the highest inode."""
    names, max_ino = set(), 0
    for name, start, _, end, fields in archive_records(data):
        if name == b'TRAILER!!!':
            return start, end, names, max_ino
        names.add(name)
        max_ino = max(fields[0], max_ino)


def newc_record(name, ino, mode, nlink, data):
    name = name.encode('ascii') + b'\0'
    fields = (ino, mode, 0, 0, nlink, 0, len(data), 0, 0, 0, 0, len(name), 0)
    if any(not 0 <= value <= 0xffffffff for value in fields):
        raise ValueError('Newc field overflow')
    header = b'070701' + ''.join(f'{value:08x}' for value in fields).encode('ascii') + name
    return header.ljust(align4(len(header)), b'\0') + data.ljust(align4(len(data)), b'\0')


def add_debug(original, files):
    start, end, stock_names, ino = archive_layout(original)
    if any(name == b'debug' or name.startswith(b'debug/') for name in stock_names):
        raise ValueError('Stock initramfs already has /debug')
    entries = [('debug', stat.S_IFDIR | 0o755, 3, b''),
               ('debug/bin', stat.S_IFDIR | 0o755, 2, b'')]
    entries.extend((f'debug/{name}', stat.S_IFREG | mode, 1, data)
                   for name, (mode, data) in files.items())
    result = (original[:start] + b''.join(newc_record(name, ino + i, mode, nlink, data)
                for i, (name, mode, nlink, data) in enumerate(entries, 1)) + original[start:end])
    return result.ljust((len(result) + 511) & ~511, b'\0')


def require_static_arm(data):
    """Reject the wrong ISA and ELFs dependent on a userland loader or libraries."""
    if data[:6] == b'\x7fELF\x01\x01':
        header, phdr, dyn = '<16sHHIIIIIHHHHHH', '<8I', '<II'
        machine = 40  # EM_ARM
    elif data[:6] == b'\x7fELF\x02\x01':
        header, phdr, dyn = '<16sHHIQQQIHHHHHH', '<II6Q', '<QQ'
        machine = 183  # EM_AARCH64
    else:
        raise ValueError('expected a little-endian ARM or AArch64 ELF')
    _, kind, arch, version, entry, phoff, _, flags, _, entsize, count, *_ = struct.unpack_from(header, data)
    if kind not in (2, 3) or arch != machine or version != 1 or not entry:
        raise ValueError('expected an ARM/AArch64 executable, not an object or shared library')
    if machine == 40 and flags >> 24 != 5:
        raise ValueError('expected ARM EABI5')
    if entsize != struct.calcsize(phdr) or not count or phoff + entsize * count > len(data):
        raise ValueError('invalid ELF program header table')
    load = False
    for i in range(count):
        values = struct.unpack_from(phdr, data, phoff + entsize * i)
        tag = values[0]
        if machine == 40:
            _, off, _, _, size, _, _, _ = values
        else:
            _, _, off, _, _, size, _, _ = values
        if off + size > len(data):
            raise ValueError('truncated ELF segment')
        if tag == 1:
            load = True
        elif tag == 3:  # PT_INTERP
            raise ValueError('dynamic ELF interpreter present; supply a static binary')
        elif tag == 2:  # PT_DYNAMIC (possible in a static PIE)
            if size % struct.calcsize(dyn):
                raise ValueError('invalid ELF dynamic segment')
            for key, _ in struct.iter_unpack(dyn, memoryview(data)[off:off + size]):
                if key == 0:  # DT_NULL
                    break
                if key == 1:  # DT_NEEDED
                    raise ValueError('shared library dependency present; supply a static binary')
            else:
                raise ValueError('unterminated ELF dynamic segment')
    if not load:
        raise ValueError('ELF has no load segment')


def debug_files(tools):
    files = {'README.txt': (0o644, (OVERLAY / 'README.txt').read_bytes()),
             'bin/ont-info': (0o755, (OVERLAY / 'ont-info').read_bytes())}
    for spec in tools:
        name, sep, path = spec.partition('=')
        key = f'bin/{name}'
        if not sep or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]*', name) or key in files:
            raise ValueError(f'Invalid or duplicate --tool NAME=PATH: {spec!r}')
        data = Path(path).read_bytes()
        try:
            require_static_arm(data)
        except (ValueError, struct.error) as exc:
            raise ValueError(f'{path}: {exc}') from exc
        files[key] = 0o755, data
    return files


def stock_ramdisk(fit, header):
    if header[:16] != BANK_MAGIC or len(header) != 0x1e0:
        raise ValueError('Expected a ZX279133 extracted bank header')
    size, offset, crc = struct.unpack_from('<III', header, 0x58)
    if (size, offset, crc) != (len(fit), len(header), zlib.crc32(fit)):
        raise ValueError('Stock FIT does not match its extracted bank header')
    total, nodes = fdt_nodes(fit)
    if total != len(fit) or any(node.count('/') > 2 for node in nodes):
        raise ValueError('Unsupported FIT layout (trailing data or nested nodes such as hashes/signatures)')
    for node, props in nodes.items():
        if node.startswith('/images/') and ('data' not in props or
                {'data-offset', 'data-position', 'data-size'} & props.keys()):
            raise ValueError(f'Expected inline FIT payload: {node}')
    ramdisk = nodes[RAMDISK]
    if (ramdisk['type'][1], ramdisk['compression'][1].lower()) != (b'ramdisk\0', b'lzma\0'):
        raise ValueError('Unexpected FIT ramdisk type or compression')
    return nodes, ramdisk['data']


def replace_ramdisk(fit, nodes, old_property, replacement):
    # Splice a single FDT property, keeping padding/alignment and all other contents.
    pos, original = old_property
    struct_off, strings_off = struct.unpack_from('>II', fit, 8)
    struct_size, = struct.unpack_from('>I', fit, 36)
    old_end = align4(pos + len(original))
    if not (struct_off + 12 <= pos <= old_end <= struct_off + struct_size <= strings_off):
        raise ValueError('Unexpected placement of FIT ramdisk data')
    if struct.unpack_from('>II', fit, pos - 12) != (3, len(original)):
        raise ValueError('Invalid FIT ramdisk property header')
    padding = align4(len(replacement)) - len(replacement)
    result = bytearray(fit[:pos] + replacement + bytes(padding) + fit[old_end:])
    delta = len(result) - len(fit)
    struct.pack_into('>I', result, pos - 8, len(replacement))
    struct.pack_into('>I', result, 4, len(result))
    struct.pack_into('>I', result, 12, strings_off + delta)
    struct.pack_into('>I', result, 36, struct_size + delta)
    result = bytes(result)
    total, changed = fdt_nodes(result)
    if total != len(result) or changed.keys() != nodes.keys():
        raise ValueError('Rebuilt FIT structure did not round-trip')
    for node, props in nodes.items():
        if {key: replacement if (node, key) == (RAMDISK, 'data') else val
                for key, (_, val) in props.items()} != {key: val for key, (_, val) in changed[node].items()}:
            raise ValueError(f'Unexpected property change under {node!r}')
    return result


def tools_tar(path, files):
    with path.open('wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0) as packed:
        with tarfile.open(fileobj=packed, mode='w') as tar:
            for name in ('debug', 'debug/bin'):
                info = tarfile.TarInfo(name)
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                tar.addfile(info)
            for name, (mode, data) in files.items():
                info = tarfile.TarInfo(f'debug/{name}')
                info.mode, info.size = mode, len(data)
                tar.addfile(info, BytesIO(data))


def build(base, output, tools, *, transform=None, overlay=True):
    if output.exists():
        raise ValueError(f'Output directory already exists: {output}')
    if not overlay and tools:
        raise ValueError('--tool requires the /debug overlay')
    files = debug_files(tools) if overlay else {}
    fit = (base / 'firmware.itb').read_bytes()
    header = (base / 'zte-header.bin').read_bytes()
    nodes, old_property = stock_ramdisk(fit, header)
    cpio = lzma.decompress(old_property[1], format=lzma.FORMAT_ALONE)
    patched = add_debug(cpio, files) if overlay else cpio
    profile = {}
    if transform is not None:
        patched, profile = transform(patched)
    # LZMA-Alone, matching the stock lc/lp/pb and using a smaller dictionary.
    packed = lzma.compress(patched, format=lzma.FORMAT_ALONE, preset=6)
    if lzma.decompress(packed, format=lzma.FORMAT_ALONE) != patched:
        raise ValueError('LZMA round-trip failed')
    candidate = replace_ramdisk(fit, nodes, old_property, packed)
    remaining = BANK_BYTES - len(header) - len(candidate)
    if remaining < 0:
        raise ValueError('FIT alone exceeds the available kernel bank capacity')
    output.mkdir(mode=0o700, parents=True)
    artifacts = {'debug-rootfs.cpio': patched, 'debug-initramfs.lzma': packed,
                 'debug-offline-test.itb': candidate}
    for name, data in artifacts.items():
        (output / name).write_bytes(data)
    report = {name: {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
              for name, data in artifacts.items()}
    if overlay:
        tools_tar(output / 'debug-tools.tar.gz', files)
        tar_data = (output / 'debug-tools.tar.gz').read_bytes()
        report['debug-tools.tar.gz'] = {'bytes': len(tar_data),
                                        'sha256': hashlib.sha256(tar_data).hexdigest()}
    added = ['/debug', '/debug/bin'] + [f'/debug/{name}' for name in files] if overlay else []
    save_json(output / 'manifest.json', dict(source=str(base), stock_fit_bytes=len(fit),
              stock_fit_sha256=hashlib.sha256(fit).hexdigest(), stock_cpio_bytes=len(cpio),
              added_paths=added,
              bytes_left_before_trailers_or_bad_blocks=remaining, vendor_upgrade_package=False,
              artifacts=report, **profile))
    print(f'{output}: wrote a debug initramfs and offline FIT ({len(candidate):,} bytes, '
          f'{len(candidate) - len(fit):+,} vs stock); NOT an updater package')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base', type=Path, help='extracted/kernel0 or extracted/kernel1')
    parser.add_argument('output', type=Path, help='new output directory')
    parser.add_argument('--tool', action='append', default=[], metavar='NAME=PATH',
                        help='add a trusted static ARM or AArch64 Linux executable to /debug/bin')
    args = parser.parse_args()
    try:
        build(args.base, args.output, args.tool)
    except (OSError, ValueError, KeyError, struct.error, lzma.LZMAError) as exc:
        parser.exit(1, f'error: {exc}\n')


if __name__ == '__main__':
    main()
