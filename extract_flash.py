#!/usr/bin/env python3
"""Offline extraction of this 256 MiB ZX279133 dump. Never writes to the source."""
import argparse
import hashlib
import json
import lzma
import mmap
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import zlib
from collections import defaultdict
from xml.etree import ElementTree

MiB = 1 << 20
BLOCK = 0x20000
LABELS = ('boot', 'parameter tags', 'kernel0', 'middleware', 'usercfg', 'kernel1',
          'others', 'wlan', 'phoneapp0', 'osgi0', 'plugin_data', 'osgi1',
          'phoneapp1', 'GN25L95_datas')
REPORTED = (0, 2, 6, 38, 42, 50, 82, 88, 92, 94, 139, 208, 253, 255, 256)
FLASH_SIZE = 256 * MiB
FDT = b'\xd0\x0d\xfe\xed'
BANK_MAGIC = bytes.fromhex('999999994444444455555555aaaaaaaa')


def save_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=True, indent=2) + '\n')


def integer(data):
    return int.from_bytes(data, 'big')


def align4(n):
    return (n + 3) & ~3


def safe_component(name):
    if not re.fullmatch(r'[A-Za-z0-9@_.+-]+', name) or name in {'.', '..'}:
        raise ValueError(f'Unexpected FIT component: {name!r}')
    return name


def fdt_nodes(data):
    if data[:4] != FDT:
        raise ValueError('Missing FDT magic')
    total, pos, strings, _, _, _, _, str_size, tree_size = struct.unpack_from('>9I', data, 4)
    limit = pos + tree_size
    if not (40 <= pos <= limit <= total <= len(data) and strings + str_size <= total):
        raise ValueError('Invalid FDT ranges')
    stack, nodes = [], {}
    while pos < limit:
        tag, = struct.unpack_from('>I', data, pos)
        pos += 4
        if tag == 1:
            end = data.index(b'\0', pos, limit)
            stack.append(data[pos:end].decode())
            nodes['/'.join(stack)] = {}
            pos = align4(end + 1)
        elif tag == 2:
            stack.pop()
        elif tag == 3:
            size, name = struct.unpack_from('>2I', data, pos)
            pos += 8
            end = data.index(b'\0', strings + name, strings + str_size)
            if pos + size > limit:
                raise ValueError('Truncated FDT property')
            nodes['/'.join(stack)][data[strings + name:end].decode()] = (pos, data[pos:pos + size])
            pos = align4(pos + size)
        elif tag == 9 and not stack:
            return total, nodes
        elif tag != 4:
            raise ValueError(f'Unexpected FDT token {tag}')
    raise ValueError('Missing FDT_END')


def fit_images(data, dest, flash_base=None):
    total, nodes = fdt_nodes(data)
    rows, blobs = [], {}
    for node, props in nodes.items():
        if not node.startswith('/images/') or node.count('/') != 2:
            continue
        p = {key: item[1] for key, item in props.items()}
        kind = p['type'].rstrip(b'\0').decode()
        compression = p['compression'].rstrip(b'\0').decode().lower()
        if 'data' in props:
            pos, blob = props['data']
        else:
            pos = (integer(p['data-position']) if 'data-position' in p else
                   align4(total) + integer(p['data-offset']))
            length = integer(p['data-size'])
            blob = data[pos:pos + length]
            if len(blob) != length:
                raise ValueError('Truncated FIT external payload')
        name = safe_component(node.rsplit('/', 1)[1])
        blobs[name] = blob
        if kind == 'flat_dt':
            target = dest / 'dtb' / (name + '.dtb')
            target.parent.mkdir(exist_ok=True)
            target.write_bytes(blob)
            if shutil.which('dtc'):
                with (dest / 'dtc.log').open('ab') as log:
                    subprocess.run(['dtc', '-I', 'dtb', '-O', 'dts', '-o',
                                    target.with_suffix('.dts'), target], stderr=log, check=True)
        else:
            target = dest / (name + {'gzip': '.gz', 'lzma': '.lzma'}.get(compression, '.bin'))
            target.write_bytes(blob)
        row = dict(node=node, type=kind, compression=compression, offset=hex(pos),
                   size=len(blob), sha256=hashlib.sha256(blob).hexdigest())
        if flash_base is not None:
            row['flash_offset'] = hex(flash_base + pos)
        for key in ('load', 'entry'):
            if key in p:
                row[key] = hex(integer(p[key]))
        rows.append(row)
    save_json(dest / 'fit_images.json', rows)
    save_json(dest / 'fit_configurations.json', {
        node: {key: (val.rstrip(b'\0').decode() if key in
                     ('default', 'description', 'fdt', 'kernel', 'ramdisk', 'boardtype') else val.hex())
               for key, (_, val) in props.items()}
        for node, props in nodes.items() if node.startswith('/configurations')})
    return blobs


def extract_cpio(data, dest):
    """Read newc; delay symlinks, suppress special nodes and ownership changes."""
    dest.mkdir()
    pos, entries, links, dirs, hard_data, hard_paths = 0, [], [], [], {}, []
    seen = set()
    while pos + 110 <= len(data):
        if data[pos:pos + 6] != b'070701':
            raise ValueError(f'Expected newc entry at {pos:#x}')
        fields = [int(data[i:i + 8], 16) for i in range(pos + 6, pos + 110, 8)]
        ino, mode, uid, gid, nlink, mtime, size, devmaj, devmin, rmaj, rmin, nlen, _ = fields
        start = pos + 110
        name = os.fsdecode(data[start:start + nlen - 1])
        if not nlen or data[start + nlen - 1:start + nlen] != b'\0':
            raise ValueError('Invalid CPIO filename')
        pos = align4(start + nlen)
        payload = data[pos:pos + size]
        if len(payload) != size:
            raise ValueError('Truncated CPIO payload')
        pos = align4(pos + size)
        if name == 'TRAILER!!!':
            if any(data[pos:]):
                raise ValueError('Nonzero data after CPIO trailer')
            break
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or relative in seen:
            raise ValueError(f'Unsafe or duplicate CPIO entry {name!r}')
        seen.add(relative)
        target = dest / relative
        entries.append(dict(path=name, mode=oct(mode), inode=ino, uid=uid, gid=gid,
                            nlink=nlink, mtime=mtime, size=size, rdev=[rmaj, rmin]))
        perms = mode & 0o777
        if stat.S_ISDIR(mode):
            target.mkdir(parents=True, exist_ok=True)
            dirs.append((target, perms))
        elif stat.S_ISLNK(mode):
            link = os.fsdecode(payload.rstrip(b'\0'))
            if not link or '\0' in link:
                raise ValueError(f'Invalid CPIO symlink target for {name!r}')
            entries[-1]['target'] = link
            links.append((target, link))
        elif stat.S_ISREG(mode):
            perms |= 0o400  # original permissions are in rootfs_entries.json
            target.parent.mkdir(parents=True, exist_ok=True)
            if nlink > 1:
                key = (devmaj, devmin, ino)
                hard_paths.append((key, target, perms))
                if size:
                    hard_data[key] = payload
            else:
                target.write_bytes(payload)
                target.chmod(perms)
        else:
            entries[-1]['metadata_only'] = True
    else:
        raise ValueError('No CPIO trailer')
    hard_copies = {}
    for key, target, perms in hard_paths:
        if key in hard_copies:
            os.link(hard_copies[key], target)
        else:
            target.write_bytes(hard_data.get(key, b''))
            target.chmod(perms)
            hard_copies[key] = target
    for target, _ in links:
        target.parent.mkdir(parents=True, exist_ok=True)
    for target, link in links:
        target.symlink_to(link)
    for target, perms in reversed(dirs):
        target.chmod(perms | 0o700)
    save_json(dest.parent / 'rootfs_entries.json', entries)
    return len(entries)


def elf64(raw, base, entry):
    size = len(raw)
    header = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01\x01', 2, 183, 1,
                         entry, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    segment = struct.pack('<IIQQQQQQ', 1, 5, 0x1000, base, base, size, size, 0x1000)
    return (header + segment).ljust(0x1000, b'\0') + raw


def extract_boot(flash, dest):
    dest.mkdir()
    firstboot = flash[:0x20000]
    (dest / 'firstboot.bin').write_bytes(firstboot)
    firstboot_size, = struct.unpack_from('<I', firstboot, 0x14)
    if firstboot_size != 0xa000 or any(firstboot[firstboot_size:]):
        raise ValueError('Unexpected firstboot payload or padding')
    (dest / 'firstboot.elf').write_bytes(elf64(firstboot[:firstboot_size], 0x200000, 0x200800))
    base, gz_offset = struct.unpack_from('<QQ', flash, 0x20008)
    if base != 0x88000000 or gz_offset != 0xa2c88:
        raise ValueError('Unexpected U-Boot header')
    start = 0x20000
    gz_start = start + gz_offset
    inflater = zlib.decompressobj(31)
    window = flash[gz_start:0x140000]
    fit = inflater.decompress(window)
    if not inflater.eof:
        raise ValueError('Truncated U-Boot device-tree gzip')
    gz_end = gz_start + len(window) - len(inflater.unused_data)
    (dest / 'uboot.bin').write_bytes(flash[start:gz_end])
    (dest / 'uboot-code.elf').write_bytes(elf64(flash[start:gz_start], base, base))
    (dest / 'uboot-dtbs.itb.gz').write_bytes(flash[gz_start:gz_end])
    (dest / 'uboot-dtbs.itb').write_bytes(fit)
    fit_images(fit, dest)
    trailer = flash[gz_end:0x140000].rstrip(b'\xff')
    (dest / 'uboot-trailer.bin').write_bytes(trailer)
    env = flash[0x180000:0x1a0000]
    (dest / 'uboot-env.bin').write_bytes(env)
    env_text = env[4:].split(b'\0\0', 1)[0].replace(b'\0', b'\n')
    (dest / 'uboot-env.txt').write_bytes(env_text + b'\n')
    save_json(dest / 'offsets.json', {'firstboot': ['0x0', '0x20000'],
              'firstboot_payload': ['0x0', hex(firstboot_size)],
              'uboot': [hex(start), hex(gz_end)], 'uboot_gzip': [hex(gz_start), hex(gz_end)],
              'uboot_trailer': [hex(gz_end), hex(gz_end + len(trailer))],
              'environment': ['0x180000', '0x1a0000']})
    save_json(dest / 'uboot-env.status.json', dict(stored_le=env[:4][::-1].hex(),
              crc32_of_bytes_after_header=f'{zlib.crc32(env[4:]):08x}',
              crc_verified=struct.unpack_from('<I', env)[0] == zlib.crc32(env[4:])))


def extract_bank(flash, offset, dest):
    dest.mkdir()
    if flash[offset:offset + 16] != BANK_MAGIC:
        raise ValueError(f'No firmware header at {offset:#x}')
    size, rel, crc = struct.unpack_from('<III', flash, offset + 0x58)
    start = offset + rel
    fit = flash[start:start + size]
    if fit[:4] != FDT or integer(fit[4:8]) != size or zlib.crc32(fit) != crc:
        raise ValueError(f'Invalid FIT length or CRC at {start:#x}')
    (dest / 'zte-header.bin').write_bytes(flash[offset:start])
    (dest / 'firmware.itb').write_bytes(fit)
    blobs = fit_images(fit, dest, start)
    kernel = zlib.decompress(blobs['kernel@133'], 31)
    if kernel[0x38:0x3c] != b'ARMd':
        raise ValueError('Invalid AArch64 Image')
    (dest / 'kernel.Image').write_bytes(kernel)
    _, nodes = fdt_nodes(fit)
    kernel_props = nodes['/images/kernel@133']
    (dest / 'kernel.elf').write_bytes(elf64(kernel, integer(kernel_props['load'][1]),
                                            integer(kernel_props['entry'][1])))
    cpio = lzma.decompress(blobs['initramfs@133'], format=lzma.FORMAT_ALONE)
    (dest / 'rootfs.cpio').write_bytes(cpio)
    count = extract_cpio(cpio, dest / 'rootfs')
    version = re.search(rb'Linux version [^\x00\n]+', kernel)
    save_json(dest / 'summary.json', dict(bank_start=hex(offset), fit_start=hex(start),
              fit_end=hex(start + size), fit_crc32=f'{crc:08x}', rootfs_entries=count,
              linux_version=version.group().decode() if version else None))
    return blobs['fdt@133'], start + size


def partition_files(flash, parts, dest):
    dest.mkdir()
    rows = []
    for name, offset, size in parts:
        data = flash[offset:offset + size]
        stem = name.replace(' ', '_')
        (dest / f'{stem}.bin').write_bytes(data)
        rows.append(dict(name=name, file=f'{stem}.bin', offset=hex(offset), size=size,
                         erased=data.count(b'\xff') == size,
                         sha256=hashlib.sha256(data).hexdigest()))
    save_json(dest / 'manifest.json', rows)


def jffs_crc(data):
    return zlib.crc32(data, -1) ^ 0xffffffff


def jffs_nodes(data, base, truncated):
    pos = 0
    while (pos := data.find(b'\x85\x19', pos)) >= 0:
        if pos + 12 > len(data):
            break
        nodetype, size, crc = struct.unpack_from('<HII', data, pos + 2)
        if pos % 4 or size < 12 or jffs_crc(data[pos:pos + 8]) != crc:
            pos += 2
            continue
        if pos + size > len(data):
            truncated.append(dict(flash_offset=hex(base + pos), size=size,
                                  available=len(data) - pos))
            break
        yield pos, nodetype, size
        pos += align4(size)


def scan_jffs(data, base):
    bad, donors, truncated = [], defaultdict(list), []
    for pos, nodetype, size in jffs_nodes(data, base, truncated):
        if nodetype == 0xe002 and size >= 68:
            ino, version = struct.unpack_from('<II', data, pos + 12)
            fragment, length, expanded = struct.unpack_from('<III', data, pos + 44)
            data_crc, node_crc = struct.unpack_from('<II', data, pos + 60)
            if size >= 68 + length and jffs_crc(data[pos:pos + 60]) == node_crc:
                key = (ino, fragment, length, expanded, data[pos + 56], data_crc)
                payload = data[pos + 68:pos + 68 + length]
                if data_crc == jffs_crc(payload):
                    donors[key].append(pos)
                else:
                    bad.append((key, pos, version))
    return bad, donors, truncated


def jffs_expand(blob, compression, size):
    if compression in (0, 4):  # none/copy
        expanded = blob
    elif compression == 1:  # zero
        expanded = bytes(size)
    elif compression == 2:  # rtime
        positions = [0] * 256
        output = bytearray()
        if len(blob) % 2:
            raise ValueError('Invalid JFFS2 rtime packet')
        for value, repeat in zip(blob[::2], blob[1::2]):
            back = positions[value]
            output.append(value)
            positions[value] = len(output)
            if len(output) + repeat > size:
                raise ValueError('Invalid JFFS2 rtime expansion')
            for i in range(repeat):
                output.append(output[back + i])
        expanded = output
    elif compression == 6:  # zlib
        expanded = zlib.decompress(blob)
    else:
        raise ValueError(f'Unsupported JFFS2 compression {compression}')
    if len(expanded) != size:
        raise ValueError('Wrong expanded JFFS2 length')
    return expanded


def materialize_jffs(data, dest, base, partial):
    """Extract the live tree, including deletion records and deferred symlinks."""
    inodes, dirents = defaultdict(dict), defaultdict(dict)
    for pos, kind, size in jffs_nodes(data, base, []):
        if kind == 0xe001 and size >= 40:
            parent, version, ino, mtime, namelen, dtype = struct.unpack_from('<IIIIBB', data, pos + 12)
            node_crc, name_crc = struct.unpack_from('<II', data, pos + 32)
            name = bytes(data[pos + 40:pos + 40 + namelen])
            if (namelen == 0 or size < 40 + namelen or node_crc != jffs_crc(data[pos:pos + 32])
                    or name_crc != jffs_crc(name)):
                continue
            name = os.fsdecode(name)
            if name in {'.', '..'} or '/' in name or '\0' in name:
                raise ValueError(f'Unsafe JFFS2 name {name!r}')
            current = dirents[parent].get(name)
            if current is None or version > current[0]:
                dirents[parent][name] = (version, ino, mtime, dtype)
            elif version == current[0] and ino != current[1]:
                raise ValueError(f'Conflicting JFFS2 directory entries at {base + pos:#x}')
        elif kind == 0xe002 and size >= 68:
            fields = struct.unpack_from('<IIIHH7IBBHII', data, pos + 12)
            ino, version, mode, uid, gid, isize, atime, mtime, ctime, off, csize, dsize, comp, _, _, data_crc, node_crc = fields
            if (size < 68 + csize or node_crc != jffs_crc(data[pos:pos + 60]) or
                    data_crc != jffs_crc(data[pos + 68:pos + 68 + csize])):
                continue
            key = (version, off)  # middleware has two disjoint extents at version 138
            if key in inodes[ino]:
                # GC copies may differ in timestamps, but must agree on extent data.
                prev = inodes[ino][key]
                if prev[1:] != (mode, uid, gid, isize, off, csize, dsize, comp, data_crc):
                    raise ValueError(f'Conflicting JFFS2 inode versions at {base + pos:#x}')
            inodes[ino][key] = (pos, mode, uid, gid, isize, off, csize, dsize, comp, data_crc)

    entries, links, directories, copies, missing = [], [], [], {}, []
    dest.mkdir()

    def populate(parent, directory, ancestors):
        for name, (_, ino, mtime, dtype) in sorted(dirents[parent].items()):
            if not ino:  # latest entry is a deletion
                continue
            target = directory / name
            relative = str(target.relative_to(dest))
            records = inodes.get(ino)
            if not records:
                missing.append(dict(path=relative, inode=ino, dirent_type=dtype))
                continue
            versions = [record for _, record in sorted(records.items())]
            _, mode, uid, gid, logical_size, *_ = versions[-1]
            row = dict(path=relative, inode=ino, mode=oct(mode), uid=uid, gid=gid,
                       size=logical_size, dirent_mtime=mtime)
            entries.append(row)
            if stat.S_ISDIR(mode):
                if ino in ancestors:
                    raise ValueError(f'JFFS2 directory cycle: {relative}')
                target.mkdir()
                populate(ino, target, ancestors | {ino})
                directories.append((target, (mode & 0o777) | 0o700))
            elif stat.S_ISREG(mode) or stat.S_ISLNK(mode):
                if ino in copies and stat.S_ISREG(mode):
                    os.link(copies[ino], target)
                    continue
                if logical_size > 256 * MiB:
                    raise ValueError(f'Unexpected JFFS2 file size: {relative}')
                payload = bytearray()
                last_size = 0
                for pos, _, _, _, isize, off, csize, dsize, comp, _ in versions:
                    if isize < last_size:
                        del payload[isize:]
                    last_size = isize
                    if dsize and off < isize:
                        blob = jffs_expand(data[pos + 68:pos + 68 + csize], comp, dsize)
                        end = min(isize, off + dsize)
                        if end > len(payload):
                            payload.extend(bytes(end - len(payload)))
                        payload[off:end] = blob[:end - off]
                if len(payload) < logical_size:
                    if partial:
                        row['extracted_size'] = len(payload)
                    else:
                        payload.extend(bytes(logical_size - len(payload)))
                if stat.S_ISLNK(mode):
                    link = os.fsdecode(bytes(payload).rstrip(b'\0'))
                    if not link or '\0' in link:
                        raise ValueError(f'Invalid JFFS2 symlink: {relative}')
                    row['target'] = link
                    links.append((target, link))
                else:
                    target.write_bytes(payload)
                    target.chmod((mode & 0o777) | 0o400)
                    copies[ino] = target
            else:
                row['metadata_only'] = True

    populate(1, dest, {1})
    for target, link in links:
        target.symlink_to(link)
    for target, perms in directories:
        target.chmod(perms)
    save_json(dest.parent / 'entries.json', entries)
    return missing


def extract_jffs(data, dest, base):
    dest.mkdir()
    raw = dest / 'filesystem.jffs2'
    raw.write_bytes(data)
    bad, donors, truncated = scan_jffs(data, base)
    patches, diagnostics = {}, []
    for key, pos, version in bad:
        ino, fragment, length, expanded, _, crc = key
        row = dict(flash_offset=hex(base + pos), inode=ino, version=version,
                   file_offset=fragment, stored=length, expanded=expanded,
                   expected_crc32=f'{crc:08x}')
        # Only accept byte-identical candidates from valid nodes of this inode and
        # fragment; permit differences only where the dump has erased bytes.
        original = data[pos + 68:pos + 68 + length]
        matches = defaultdict(list)
        for source in donors[key]:
            candidate = data[source + 68:source + 68 + length]
            if all(a == b or a == 0xff for a, b in zip(original, candidate)):
                matches[candidate].append(source)
        if len(matches) == 1:
            payload, sources = next(iter(matches.items()))
            patches[pos + 68] = payload
            row['recovered_from_node'] = hex(base + sources[0])
        diagnostics.append(row)
    if patches:
        repaired = bytearray(data)
        for offset, payload in patches.items():
            repaired[offset:offset + len(payload)] = payload
        if len(scan_jffs(repaired, base)[0]) != len(bad) - len(patches):
            raise ValueError('JFFS2 repair CRC verification failed')
        raw = dest / 'filesystem.repaired.jffs2'
        raw.write_bytes(repaired)
    if truncated:
        end = int(truncated[0]['flash_offset'], 16) - base
        raw = dest / 'filesystem.complete-nodes.jffs2'
        raw.write_bytes((repaired if patches else data)[:end])
    view = repaired if patches else data
    if truncated:
        view = view[:end]
    missing = materialize_jffs(view, dest / 'files', base, bool(truncated))
    status = dict(flash_start=hex(base), length=len(data), bad_data_crc=diagnostics,
                  truncated_nodes=truncated, extraction_input=raw.name, missing_inodes=missing)
    save_json(dest / 'status.json', status)
    if (dest / 'files/paramtag').is_file():
        param = (dest / 'files/paramtag').read_bytes()
        if param[:8] == b'TAGH0201':
            crc, size = struct.unpack_from('<II', param, 12)
            if len(param) == 16 + size and zlib.crc32(param[16:]) == crc:
                rows = []
                pos = 20
                while pos < len(param):
                    tag, length, repeat = struct.unpack_from('<HHH', param, pos)
                    if repeat != length or pos + 6 + length > len(param):
                        raise ValueError('Bad TAGH0201 record')
                    val = param[pos + 6:pos + 6 + length]
                    rows.append(dict(tag=f'0x{tag:04x}', hex=val.hex(),
                                     ascii=val.decode('ascii') if all(32 <= x < 127 for x in val) else None))
                    pos = align4(pos + 6 + length)
                save_json(dest / 'paramtag.decoded.json', rows)


def zte_zlib_config(data):
    magic, kind, size, _, block_size, body_crc, header_crc = struct.unpack_from('>7I', data)
    if magic != 0x01020304 or kind != 0 or zlib.crc32(data[:24]) != header_crc:
        raise ValueError('Invalid embedded configuration header')
    pos, crc, output = 60, 0, bytearray()
    while True:
        expanded, stored, next_ = struct.unpack_from('>3I', data, pos)
        if not (0 < expanded <= block_size and 0 < stored <= len(data) - pos - 12):
            raise ValueError('Invalid compressed configuration chunk')
        chunk = data[pos + 12:pos + 12 + stored]
        crc = zlib.crc32(chunk, crc)
        plain = zlib.decompress(chunk)
        if len(plain) != expanded:
            raise ValueError('Compressed configuration chunk length mismatch')
        output.extend(plain)
        pos += 12 + stored
        if not next_:
            break
    if len(output) != size or crc != body_crc or any(data[pos:]):
        raise ValueError('Embedded configuration size, padding or CRC mismatch')
    return bytes(output)


def decode_config(data, openssl):
    # This dump's cspd/dbCfg decoder uses a zero-initialized AES key buffer on
    # this configuration path. This is not the SR1010 firmware image format.
    mode, revision = data[28:30]
    if mode not in (1, 2) or revision != 1:
        raise ValueError(f'Unsupported ZTE configuration mode {mode:#x}/{revision:#x}')
    payload_size, body_end, block_size = struct.unpack_from('>3I', data, 8)
    if block_size != 0x10000 or not 60 < body_end <= len(data):
        raise ValueError('Unexpected ZTE configuration header lengths')
    encrypted, pos = bytearray(), 60
    while True:
        expanded, size, next_ = struct.unpack_from('>3I', data, pos)
        if not (expanded == size and 0 < size <= block_size and size % 16 == 0
                and pos + 12 + size <= body_end):
            raise ValueError('Invalid encrypted configuration chunk')
        encrypted.extend(data[pos + 12:pos + 12 + size])
        pos += 12 + size
        if not next_:
            break
    if len(encrypted) != payload_size or pos != body_end:
        raise ValueError('Encrypted configuration length mismatch')
    if not re.fullmatch(rb'\x01\x02\x03\x04[0-9a-f]{32}', data[pos:]):
        raise ValueError('Unexpected configuration footer')
    decrypted = subprocess.run([openssl, 'enc', '-d', '-aes-128-ecb', '-nosalt', '-nopad',
                                '-K', '0' * 32], input=encrypted, capture_output=True, check=True).stdout
    return (zte_zlib_config(decrypted) if mode == 2 else decrypted).rstrip(b'\0')


def extract_configs(source, dest, openssl):
    reports = {}
    for path in sorted(source.rglob('*.xml')):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open('rb') as f:
            if f.read(4) != b'\x01\x02\x03\x04':
                continue
            data = b'\x01\x02\x03\x04' + f.read()
        relative = path.relative_to(source)
        report = dict(length=len(data), sha256=hashlib.sha256(data).hexdigest(),
                      header_words_be=[f'0x{word:08x}' for word in struct.unpack_from('>15I', data)])
        reports[str(relative)] = report
        if not openssl:
            report['decode_error'] = 'openssl not found'
            continue
        try:
            plain = decode_config(data, openssl)
        except (ValueError, struct.error, zlib.error, subprocess.CalledProcessError) as error:
            report['decode_error'] = str(error)
            continue
        report['decoded_length'] = len(plain)
        report['decoded_sha256'] = hashlib.sha256(plain).hexdigest()
        try:
            report['xml_root'] = ElementTree.fromstring(plain).tag
        except ElementTree.ParseError as error:
            report['xml_parse_error'] = str(error)
        target = dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(plain)
    if reports:
        dest.mkdir(parents=True, exist_ok=True)
        save_json(dest / 'manifest.json', reports)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('image', type=Path)
    ap.add_argument('output', type=Path, help='new output directory')
    args = ap.parse_args()
    os.umask(0o077)
    with args.image.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as flash:
        if len(flash) != FLASH_SIZE:
            raise ValueError('Expected a 256 MiB main-area dump')
        args.output.mkdir(mode=0o700)
        out = args.output
        extract_boot(flash, out / 'boot')
        dtb, end0 = extract_bank(flash, 0x200000, out / 'kernel0')
        dtb1, end1 = extract_bank(flash, 0x2200000, out / 'kernel1')
        maps = []
        for device_tree in (dtb, dtb1):
            _, tree = fdt_nodes(device_tree)
            maps.append({props['label'][1].rstrip(b'\0').decode(): struct.unpack('>II', props['reg'][1])
                         for path, props in tree.items() if path.startswith('/part@256/partition@')})
        if maps[0] != maps[1] or maps[0].pop('whole') != (0, FLASH_SIZE):
            raise ValueError('Inconsistent 256 MiB DTB maps')
        dtb_parts = sorted(((name, *maps[0][name]) for name in LABELS), key=lambda part: part[1])
        for i, (name, off, size) in enumerate(dtb_parts):
            expected = dtb_parts[i + 1][1] if i + 1 < len(dtb_parts) else FLASH_SIZE
            if (i == 0 and off != 0) or off + size != expected:
                raise ValueError(f'Partition gap/overlap at {name}')
        save_json(out / 'source.json', dict(size=len(flash), sha256=hashlib.sha256(flash).hexdigest()))
        partition_files(flash, [(label, lo * MiB, (hi - lo) * MiB)
                               for label, lo, hi in zip(LABELS, REPORTED, REPORTED[1:])], out / 'mtd_user_order')
        partition_files(flash, dtb_parts, out / 'mtd_dtb')
        aux = out / 'auxiliary'
        aux.mkdir()
        for name, off, size in dtb_parts:
            if name in {'boot', 'kernel0', 'kernel1', 'others'}:
                continue
            start = next((i for i in range(off, off + size, BLOCK)
                          if flash[i:i + 2] == b'\x85\x19'), None)
            if start is not None:
                extract_jffs(flash[start:off + size], aux / name.replace(' ', '_'), start)
        for index, end in enumerate((end0, end1)):
            label = f'kernel{index}'
            bank_offset, bank_size = maps[0][label]
            gap = flash[align4(end):bank_offset + bank_size]
            tail = gap.rstrip(b'\xff')
            if tail:
                start = len(tail) - len(tail.lstrip(b'\xff'))
                if tail[start:start + 2] == b'\x85\x19':
                    extract_jffs(tail[start:], aux / f'bank{index}_appended_jffs2',
                                 align4(end) + start)
                else:
                    (aux / f'bank{index}_tail.bin').write_bytes(tail)
        fragment = aux / 'bank0_appended_jffs2' / 'files'
        reference = aux / 'phoneapp0' / 'files'
        if fragment.is_dir() and reference.is_dir():
            prefix = (fragment / 'phoneapp').read_bytes()
            full = (reference / 'phoneapp').read_bytes()
            save_json(fragment.parent / 'phoneapp_reference.json', dict(
                      observed_prefix_length=len(prefix), reference_length=len(full),
                      prefix_matches=full.startswith(prefix),
                      version_matches=(fragment / 'phapp_ver').read_bytes() ==
                                      (reference / 'phapp_ver').read_bytes(),
                      complete_copy='auxiliary/phoneapp0/files/phoneapp'))
        openssl = shutil.which('openssl')
        for label in ('kernel0', 'kernel1'):
            extract_configs(out / label / 'rootfs' / 'etc', out / label / 'decoded_etc', openssl)
        for label in ('usercfg', 'middleware'):
            extract_configs(aux / label / 'files', aux / label / 'decoded_config', openssl)
        others = aux / 'others'
        others.mkdir()
        bootstate = flash[0x4200000:0x4220000].split(b'\0', 1)[0].rstrip(b'\xff')
        (others / 'boot-state.txt').write_bytes(bootstate.rstrip() + b'\n')
        save_json(others / 'boot-state.json', dict(item.split('=', 1) for item in
                  bootstate.decode('ascii').strip().split(',') if '=' in item))
        vendor = flash[0x4600000:0x460000c]
        (others / 'board-id.bin').write_bytes(vendor)
        save_json(others / 'board-id.json', dict(magic=vendor[:7].decode(),
                  id_le=hex(struct.unpack_from('<I', vendor, 8)[0])))
        print(f'Wrote {out}.')


if __name__ == '__main__':
    main()
