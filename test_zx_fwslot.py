"""Host tests for zx_fwslot.c on fake NAND seeded from the real flash dump."""

import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
import zlib

HERE = Path(__file__).resolve().parent
DUMP = HERE / 'extracted/mtd_dtb'
STOCK_OTA = HERE / 'build/stock-busybox/stock-busybox-ota-candidate.bin'
SERIAL_OTA = HERE / 'build/serial-lan-ssh/serial-lan-ssh-ota-candidate.bin'
ARM_BINARY = HERE / 'build/zx-fwslot/zx-fwslot'
BLOCK, BANK = 0x20000, 0x2000000
MAGIC = bytes.fromhex('99999999444444445555555' '5aaaaaaaa')
# Indices as in the vendor mtdparts; fw_flashing hardcodes mtd3/mtd6/mtd7.
PARTS = [('whole', 0x10000000, 0), ('boot', 0x200000, 0), ('parameter tags', 0x400000, 0x4800000),
         ('kernel0', BANK, 0x200000), ('middleware', 0x400000, 0x5400000),
         ('usercfg', 0x800000, 0x4c00000), ('kernel1', BANK, 0x2200000),
         ('others', 0x600000, 0x4200000)]
K0, K1, OTHERS = 3, 6, 7
CMDLINE = ('console=ttyAMA0,115200n8 rdinit=/sbin/init U-Boot V32.AA1.04 20240906120040 '
           '0x2200000 0x1 0x82 0x82 UpModeInfo=0x00000040\n')
VERSIONSTATES = ('baseaddress    : 0x2200000\ncurrent        : 1\nversion1states : 0x82\n'
                 'version2states : 0x82\n')
# What fw_flashing leaves after writing the serial build into bank 1.
OTHERS_TEXT = (b'UpModeInfo=0x00000040,BootImageNum=0x00000001,DownloadState=0x00000003,'
               b'LastBooting=0x00000000,ReginoCode=0xffffeb30,Restore=0xffffffd0,'
               b'Image1Status=0xffffffff,')


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


class FakeBoard:
    template = None

    @classmethod
    def make_template(cls, where):
        root = Path(where)
        (root / 'dev').mkdir()
        k0 = (DUMP / 'kernel0.bin').read_bytes()
        serial = SERIAL_OTA.read_bytes()
        others = bytearray((DUMP / 'others.bin').read_bytes())
        dumped = OTHERS_TEXT[:-24].replace(b'BootImageNum=0x00000001', b'BootImageNum=0x00000000')
        assert others[:len(dumped)] == dumped and others[len(dumped)] == 0xff
        others[:0x1000] = OTHERS_TEXT.ljust(0x1000, b'\xff')
        (root / f'dev/mtd{K0}').write_bytes(k0)
        (root / f'dev/mtd{K1}').write_bytes(serial.ljust(BANK, b'\xff'))
        (root / f'dev/mtd{OTHERS}').write_bytes(bytes(others))
        (root / 'proc/zxic').mkdir(parents=True)
        (root / 'proc/mtd').write_text('dev:    size   erasesize  name\n' + ''.join(
            f'mtd{i}: {size:08x} {BLOCK:08x} "{name}"\n' for i, (name, size, _) in enumerate(PARTS)))
        (root / 'proc/cmdline').write_text(CMDLINE)
        (root / 'proc/zxic/versionstates').write_text(VERSIONSTATES)
        (root / 'proc/1').mkdir()
        (root / 'proc/1/comm').write_text('init\n')
        for i, (_, _, offset) in enumerate(PARTS):
            (root / f'sys/class/mtd/mtd{i}').mkdir(parents=True)
            (root / f'sys/class/mtd/mtd{i}/offset').write_text(f'{offset}\n')

    def __init__(self, test, workdir):
        self.root = Path(workdir) / 'board'
        shutil.copytree(self.template, self.root)
        self.test = test
        self.env = dict(os.environ, FAKE_ROOT=str(self.root), LD_PRELOAD=test.shim)

    def run(self, *args, **env):
        return subprocess.run([self.test.tool, *map(str, args)], env=dict(self.env, **env),
                              capture_output=True, text=True)

    def dev(self, index):
        return (self.root / f'dev/mtd{index}').read_bytes()

    def lines(self, name):
        path = self.root / name
        return path.read_text().splitlines() if path.exists() else []

    def bad(self, index, extra=''):
        listed = {int(x.split(':')[1], 16) // BLOCK for x in extra.split(',')
                  if x and int(x.split(':')[0]) == index}
        listed |= {int(o, 16) // BLOCK for d, o in (l.split() for l in self.lines('badlist'))
                   if int(d) == index}
        return listed

    def logical(self, index, length, extra_bad=''):
        data, bad, out, block = self.dev(index), self.bad(index, extra_bad), b'', 0
        while len(out) < length:
            if block not in bad:
                out += data[block * BLOCK:(block + 1) * BLOCK]
            block += 1
        return out[:length]

    def uboot_choice(self, extra_bad=''):
        """Independent model of zxboot: BootImageNum, then CRC checks, one fallback."""
        text = self.logical(OTHERS, 0x1000, extra_bad)
        at = text.find(b'BootImageNum=')
        first = int(text[at + 13:at + 23], 16) if at == 0 or (at > 0 and text[at - 1] == 0x2c) else 0
        first = first if first in (0, 1) else 0
        for bank in (first, first ^ 1):
            index = (K0, K1)[bank]
            data, bad = self.dev(index), self.bad(index, extra_bad)
            for block in range(BANK // BLOCK):
                if block in bad or data[block * BLOCK:block * BLOCK + 16] != MAGIC:
                    continue
                header = data[block * BLOCK:block * BLOCK + 0x1e0]
                if zlib.crc32(header[0x14:0x110]) != u32(header, 0x110):
                    break
                stream, b = b'', block
                while len(stream) < 0x1e0 + u32(header, 0x58):
                    if b not in bad:
                        stream += data[b * BLOCK:(b + 1) * BLOCK]
                    b += 1
                if zlib.crc32(stream[0x1e0:0x1e0 + u32(header, 0x58)]) == u32(header, 0x60):
                    return bank, header
                break
        return None, None


@unittest.skipUnless(shutil.which('gcc') and DUMP.is_dir() and STOCK_OTA.is_file()
                     and SERIAL_OTA.is_file(), 'host gcc, flash dump or OTA builds missing')
class ZxFwslotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        tmp = Path(cls.tmp.name)
        cls.tool, cls.shim = str(tmp / 'zx-fwslot'), str(tmp / 'fakemtd.so')
        subprocess.run(['gcc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', '-o', cls.tool,
                        str(HERE / 'zx_fwslot.c')], check=True)
        subprocess.run(['gcc', '-std=c11', '-O2', '-shared', '-fPIC', '-o', cls.shim,
                        str(HERE / 'tests/fakemtd_zx.c'), '-ldl'], check=True)
        FakeBoard.template = tmp / 'template'
        FakeBoard.make_template(FakeBoard.template.mkdir() or FakeBoard.template)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.board = FakeBoard(self, self.work.name)

    def tearDown(self):
        self.assertEqual(self.board.lines('violations'), [], 'NAND rule violated')
        self.work.cleanup()

    def assertOk(self, result):
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        return result.stdout

    def assertRefused(self, result, text):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(text, result.stderr)

    def touched(self):
        return {int(line.split()[1]) for line in self.board.lines('oplog')}

    def test_check_accepts_builds_and_rejects_damage(self):
        for package in (STOCK_OTA, SERIAL_OTA):
            self.assertIn('ok:', self.assertOk(self.board.run('check', package)))
        damaged = Path(self.work.name) / 'damaged.bin'
        data = bytearray(STOCK_OTA.read_bytes())
        data[0x1e0 + 0x100000] ^= 1
        damaged.write_bytes(data)
        self.assertRefused(self.board.run('check', damaged), 'FIT CRC mismatch')
        # A raw bank with an appended component is bootable but not a package.
        self.assertRefused(self.board.run('check', DUMP / 'kernel0.bin'), 'components')

    def test_info_reports_state(self):
        out = self.assertOk(self.board.run('info'))
        self.assertIn('running bank: 1', out)
        self.assertIn('BootImageNum: 1', out)
        self.assertRegex(out, r'bank 0: mtd3 version="V32\.AA1\.04" build="ZDFW2412095d005"')
        self.assertRegex(out, r'bank 1: mtd6 .*\[running\] \[next boot\]')
        self.assertEqual(self.touched(), set())

    def test_flash_writes_other_bank_like_fw_flashing(self):
        before_running, before_others = self.board.dev(K1), self.board.dev(OTHERS)
        out = self.assertOk(self.board.run('flash', STOCK_OTA))
        self.assertIn('bank 0 written and selected', out)
        package = STOCK_OTA.read_bytes()
        span = 0x1e0 + u32(package, 0x58)
        bank = self.board.dev(K0)
        self.assertEqual(bank[:span], package[:span])
        self.assertTrue(all(b == 0xff for b in bank[span:]), 'stale data left in bank 0')
        self.assertEqual(self.board.dev(K1), before_running)
        self.assertEqual(self.touched(), {K0, OTHERS})
        others = self.board.dev(OTHERS)
        expected = OTHERS_TEXT.replace(b'BootImageNum=0x00000001', b'BootImageNum=0x00000000')
        expected += b'Image0Status=0xffffffff,'
        self.assertEqual(others[:0x1000], expected.ljust(0x1000, b'\xff'))
        self.assertEqual(others[0x1000:], before_others[0x1000:])  # ZXICVID at 0x400000 kept
        erased = [l for l in self.board.lines('oplog') if l.startswith(f'erase {OTHERS} ')]
        self.assertEqual(len(erased), 4)
        choice, header = self.board.uboot_choice()
        self.assertEqual(choice, 0)
        self.assertEqual(header, package[:0x1e0])

    def test_dry_run_changes_nothing(self):
        self.assertIn('dry run', self.assertOk(self.board.run('flash', '-n', STOCK_OTA)))
        self.assertEqual(self.touched(), set())

    def test_select_back_to_stock_bank_with_component(self):
        before = {i: self.board.dev(i) for i in (K0, K1)}
        out = self.assertOk(self.board.run('switch'))
        self.assertIn('next boot uses bank 0', out)
        self.assertEqual({i: self.board.dev(i) for i in (K0, K1)}, before)
        self.assertEqual(self.touched(), {OTHERS})
        self.assertIn(b'BootImageNum=0x00000000,', self.board.dev(OTHERS)[:0x1000])
        self.assertNotIn(b'Image0Status', self.board.dev(OTHERS)[:0x1000])
        self.assertEqual(self.board.uboot_choice()[0], 0)
        # Selecting the running bank again restores the previous record.
        self.assertOk(self.board.run('select', 1))
        self.assertEqual(self.board.dev(OTHERS)[:0x1000], OTHERS_TEXT.ljust(0x1000, b'\xff'))

    def test_refuses_to_select_a_damaged_bank(self):
        path = self.board.root / f'dev/mtd{K0}'
        data = bytearray(path.read_bytes())
        data[0x1e0 + 0x200000] ^= 0xff
        path.write_bytes(data)
        self.assertRefused(self.board.run('switch'), 'FIT CRC mismatch')
        self.assertEqual(self.touched(), set())

    def test_bad_blocks_are_skipped_consistently(self):
        bad = f'{K0}:0x0,{K0}:0xa0000,{OTHERS}:0x0'
        self.assertOk(self.board.run('flash', STOCK_OTA, FAKE_BAD=bad))
        package = STOCK_OTA.read_bytes()
        span = 0x1e0 + u32(package, 0x58)
        self.assertEqual(self.board.logical(K0, span, bad), package[:span])
        self.assertEqual(self.board.dev(K0)[BLOCK:BLOCK + 16], MAGIC)
        self.assertEqual(self.board.uboot_choice(bad)[0], 0)
        self.assertIn('bank 0: mtd3 version=', self.assertOk(self.board.run('info', FAKE_BAD=bad)))

    def test_failed_write_marks_block_bad_and_continues(self):
        self.assertOk(self.board.run('flash', STOCK_OTA, FAKE_WRITE_FAIL=f'{K0}:0x60000'))
        self.assertIn(f'{K0} 60000', self.board.lines('badlist'))
        package = STOCK_OTA.read_bytes()
        span = 0x1e0 + u32(package, 0x58)
        self.assertEqual(self.board.logical(K0, span), package[:span])
        self.assertEqual(self.board.uboot_choice()[0], 0)

    def test_failed_erase_marks_block_bad(self):
        self.assertOk(self.board.run('flash', STOCK_OTA, FAKE_ERASE_FAIL=f'{K0}:0x20000'))
        self.assertIn(f'{K0} 20000', self.board.lines('badlist'))
        self.assertEqual(self.board.uboot_choice()[0], 0)

    def test_refuses_with_vendor_daemons_running(self):
        (self.board.root / 'proc/321').mkdir()
        (self.board.root / 'proc/321/comm').write_text('cspd\n')
        self.assertRefused(self.board.run('flash', STOCK_OTA), 'vendor process cspd')
        self.assertRefused(self.board.run('switch'), 'vendor process cspd')
        self.assertEqual(self.touched(), set())

    def test_refuses_inconsistent_running_bank(self):
        (self.board.root / 'proc/zxic/versionstates').write_text(
            VERSIONSTATES.replace('0x2200000', '0x200000').replace(': 1', ': 0'))
        self.assertRefused(self.board.run('flash', STOCK_OTA), 'disagree')
        (self.board.root / 'proc/cmdline').write_text('console=ttyAMA0\n')
        self.assertRefused(self.board.run('info'), 'no U-Boot bank record')
        self.assertEqual(self.touched(), set())

    def test_never_erases_bank_when_others_is_unexpected(self):
        path = self.board.root / f'dev/mtd{OTHERS}'
        data = bytearray(path.read_bytes())
        data[0x2000] = 0
        path.write_bytes(data)
        self.assertRefused(self.board.run('flash', STOCK_OTA), 'would be erased')
        self.assertEqual(self.touched(), set())

    def test_wrong_partition_geometry_is_refused(self):
        proc_mtd = self.board.root / 'proc/mtd'
        stock = proc_mtd.read_text()
        proc_mtd.write_text(stock.replace('"kernel0"', '"kernel0x"'))
        self.assertRefused(self.board.run('flash', STOCK_OTA), 'no MTD partition named kernel0')
        proc_mtd.write_text(stock)
        offset = self.board.root / f'sys/class/mtd/mtd{K0}/offset'
        offset.write_text('0\n')
        self.assertRefused(self.board.run('flash', STOCK_OTA), 'starts at 0, expected 0x200000')
        self.assertEqual(self.touched(), set())

    @unittest.skipUnless(ARM_BINARY.is_file() and shutil.which('qemu-arm'),
                         'ARM build (build_zx_fwslot.sh) or QEMU missing')
    def test_static_arm_build_runs_check(self):
        from build_debug_rootfs import require_static_arm
        data = ARM_BINARY.read_bytes()
        require_static_arm(data)
        self.assertTrue(data[4] == 1 and u32(data, 36) & 0x200, 'expected ARM32 soft-float')
        result = subprocess.run(['qemu-arm', str(ARM_BINARY), 'check', str(STOCK_OTA)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
