import lzma
import stat
import struct
import unittest
import zlib

from build_debug_rootfs import (RAMDISK, add_debug, archive_layout, newc_record,
                                replace_ramdisk, require_static_arm, stock_ramdisk)
from extract_flash import BANK_MAGIC, FDT, align4, elf64, fdt_nodes


def example_fit(ramdisk, extra_child=False):
    # Minimal inline FDT fixture with deliberately odd-sized data properties.
    prop_names = b'data\0type\0compression\0'
    def node(name, content):
        name += b'\0'
        return struct.pack('>I', 1) + name.ljust(align4(len(name)), b'\0') + content + struct.pack('>I', 2)

    def prop(name, value):
        return (struct.pack('>3I', 3, len(value), prop_names.index(name + b'\0')) +
                value.ljust(align4(len(value)), b'\0'))

    ram = prop(b'data', ramdisk) + prop(b'type', b'ramdisk\0') + prop(b'compression', b'LZMA\0')
    if extra_child:
        ram += node(b'hash@1', b'')
    images = node(b'initramfs@133', ram) + node(b'kernel@133', prop(b'data', b'unchanged'))
    tree = node(b'', node(b'images', images) + node(b'configurations', b'')) + struct.pack('>I', 9)
    strings_off = 56 + len(tree)
    return (FDT + struct.pack('>9I', strings_off + len(prop_names), 56, strings_off, 40,
                              17, 16, 0, len(prop_names), len(tree)) + bytes(16) + tree + prop_names)


def bank_header(fit):
    data = bytearray(0x1e0)
    data[:16] = BANK_MAGIC
    struct.pack_into('<III', data, 0x58, len(fit), len(data), zlib.crc32(fit))
    return data


class ArchiveTests(unittest.TestCase):
    trailer = newc_record('TRAILER!!!', 0, 0, 1, b'')

    def test_append_preserves_raw_entries(self):
        init = newc_record('init', 5, stat.S_IFREG | 0o755, 1, b'test\n')
        original = init + self.trailer + bytes(4)
        changed = add_debug(original, {'bin/ont-info': (0o755, b'hello')})
        start, end, names, max_ino = archive_layout(changed)
        self.assertEqual(changed[:len(init)], init)
        self.assertEqual(changed[start:end], self.trailer)
        self.assertEqual(names, {b'init', b'debug', b'debug/bin', b'debug/bin/ont-info'})
        self.assertEqual(max_ino, 8)
        self.assertEqual(len(changed) % 512, 0)

    def test_conflict(self):
        entry = newc_record('./debug', 1, stat.S_IFLNK | 0o777, 1, b'/etc')
        with self.assertRaisesRegex(ValueError, 'already has /debug'):
            add_debug(entry + self.trailer, {})

    def test_truncated_and_concatenated(self):
        for malformed in (self.trailer[:-1], self.trailer * 2):
            with self.assertRaises(ValueError):
                archive_layout(malformed)


class FitTests(unittest.TestCase):
    def test_splice_only_ramdisk(self):
        for length in (3, 4, 5, 257):
            packed = lzma.compress(b'stock', format=lzma.FORMAT_ALONE)
            fit = example_fit(packed)
            nodes, old = stock_ramdisk(fit, bank_header(fit))
            self.assertEqual(old[1], packed)
            candidate = replace_ramdisk(fit, nodes, old, b'x' * length)
            total, props = fdt_nodes(candidate)
            self.assertEqual(total, len(candidate))
            self.assertEqual(props[RAMDISK]['data'][1], b'x' * length)
            self.assertEqual(props['/images/kernel@133']['data'][1], b'unchanged')

    def test_reject_hash_layout_and_bad_crc(self):
        hashed = example_fit(b'abc', extra_child=True)
        with self.assertRaisesRegex(ValueError, 'nested nodes'):
            stock_ramdisk(hashed, bank_header(hashed))
        fit = example_fit(b'abc')
        with self.assertRaisesRegex(ValueError, 'does not match'):
            stock_ramdisk(fit, bank_header(fit + b'x'))


class ElfTests(unittest.TestCase):
    def test_require_static_arm(self):
        good = elf64(b'\0' * 4, 0x1000, 0x1000)
        require_static_arm(good)
        for offset, value in ((18, 62), (64, 3)):  # x86-64 or PT_INTERP
            bad = bytearray(good)
            struct.pack_into('<H', bad, offset, value)
            with self.assertRaises(ValueError):
                require_static_arm(bad)


if __name__ == '__main__':
    unittest.main()
