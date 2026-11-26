from pathlib import Path
import lzma
import stat
import struct
import unittest

from build_debug_rootfs import add_debug, newc_record, replace_ramdisk, stock_ramdisk
from build_ota import HEADER_BYTES, inspect, parse, u32, verify_debug_payload, wrap
from extract_flash import BANK_MAGIC
from test_debug_rootfs import example_fit


def fixture():
    header = bytearray(HEADER_BYTES)
    header[:16] = BANK_MAGIC
    header[0x24:0x2e] = b'V32.AA1.04'
    struct.pack_into('<I', header, 0x50, 1)
    struct.pack_into('<I', header, 0x5c, HEADER_BYTES)
    header[0x148:0x14c] = b'133\0'
    header[0x178:] = b'\xff' * (HEADER_BYTES - 0x178)
    cpio = newc_record('init', 1, stat.S_IFREG | 0o755, 1, b'stock init')
    cpio += newc_record('TRAILER!!!', 0, 0, 1, b'')
    return header, cpio, example_fit(lzma.compress(cpio, format=lzma.FORMAT_ALONE))


class OtaTests(unittest.TestCase):
    def test_build_and_inspect(self):
        header, cpio, fit = fixture()
        header, _ = parse(wrap(header, fit))
        nodes, prop = stock_ramdisk(fit, header)
        new = add_debug(cpio, {'bin/ont-info': (0o755, b'diagnostics')})
        candidate = replace_ramdisk(fit, nodes, prop, lzma.compress(new, format=lzma.FORMAT_ALONE))
        verify_debug_payload(header, fit, candidate)
        data = wrap(header, candidate)
        self.assertEqual(inspect(data)['firmware_version'], 'V32.AA1.04')
        self.assertEqual(len(data) % 16, 0)
        self.assertEqual(u32(data, 0x54), len(data))
        self.assertEqual(u32(data, 0x68), len(data))
        self.assertEqual(parse(data)[1], candidate)

    def test_reject_corrupted_or_trailing_data(self):
        header, _, fit = fixture()
        data = wrap(header, fit)
        for off, reason in ((0x25, 'version-header CRC'), (HEADER_BYTES + 12, 'FIT CRC')):
            corrupted = bytearray(data)
            corrupted[off] ^= 1
            with self.assertRaisesRegex(ValueError, reason):
                parse(corrupted)
        with self.assertRaisesRegex(ValueError, 'Inconsistent payload ranges'):
            parse(data[:-1])
        with self.assertRaisesRegex(ValueError, 'Unexpected data'):
            parse(data + b'\xff')
        with self.assertRaisesRegex(ValueError, 'Unexpected data'):
            parse(data + b'\0', allow_erased_padding=True)

    def test_reject_additional_component(self):
        header, _, fit = fixture()
        struct.pack_into('<I', header, 0xe0, 0x40000)
        with self.assertRaisesRegex(ValueError, 'additional components'):
            parse(wrap(header, fit))

    def test_reject_unrelated_fit(self):
        header, _, fit = fixture()
        header, _ = parse(wrap(header, fit))
        with self.assertRaisesRegex(ValueError, 'preserve stock records'):
            verify_debug_payload(header, fit, fit)
        other = fit.replace(b'unchanged', b'modified!')
        with self.assertRaisesRegex(ValueError, 'outside ramdisk data'):
            verify_debug_payload(header, fit, other)

    @unittest.skipUnless(Path('extracted/mtd_dtb/kernel1.bin').is_file(), 'real dump not present')
    def test_stock_bank_round_trip(self):
        stock = Path('extracted/mtd_dtb/kernel1.bin').read_bytes()
        header, fit = parse(stock, allow_erased_padding=True)
        data = wrap(header, fit)
        self.assertEqual(data, stock[:0x183bb20])
        self.assertEqual(inspect(data)['fit']['configurations'], 40)


if __name__ == '__main__':
    unittest.main()
