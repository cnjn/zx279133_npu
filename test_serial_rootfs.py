import shutil
import stat
import struct
import subprocess
import unittest
from pathlib import Path

from build_debug_rootfs import add_debug, archive_records, debug_files, newc_record
from serial_rootfs import (DROPBEAR_LINKS, INITTAB, LAN_SSH_BINARIES, LAN_SSH_SCRIPTS, REPLACED,
                           ROOT_HASH, apply_serial, replace_root_shadow, verify_serial)


def fixture():
    # A minimal static ARM32 EABI5 soft-float ELF for archive tests (not executed).
    code = bytes(4)
    elf = struct.pack('<16sHHIIIIIHHHHHH', b'\x7fELF\x01\x01\x01', 2, 40, 1, 0x1000,
                      52, 0, 0x5000200, 52, 32, 1, 0, 0, 0)
    elf += struct.pack('<8I', 1, 84, 0x1000, 0x1000, len(code), len(code), 5, 4) + code
    entries = (
        ('bin/busybox', stat.S_IFREG | 0o755, b'stock-busybox'),
        ('bin/sh', stat.S_IFLNK | 0o777, b'busybox\0'),
        ('sbin/init', stat.S_IFLNK | 0o777, b'../bin/busybox\0'),
        ('etc/passwd', stat.S_IFREG | 0o775, b'root:x:0:0:root:/root:/bin/sh\n'),
        ('etc/shadow', stat.S_IFREG | 0o775, b'root:old:0:0:99999:7:::\nother:!:::::::\n'),
        ('etc/inittab', stat.S_IFREG | 0o775, b'::sysinit:/etc/init.d/rcS\n'),
        ('etc/init.d/rcS', stat.S_IFREG | 0o775, b'vendor startup'),
        ('etc/mcode/mcode_133.bin', stat.S_IFREG | 0o644, b'vendor microcode'),
    )
    tty = newc_record('dev/ttyAMA0', 99, stat.S_IFCHR | 0o666, 1, b'')
    tty = tty[:78] + b'000000cc00000040' + tty[94:]
    stock = b''.join(newc_record(name, i, mode, 1, data)
                     for i, (name, mode, data) in enumerate(entries, 1))
    stock += tty + newc_record('TRAILER!!!', 0, 0, 1, b'')
    return stock, elf


def plain(data):
    return {name: (data[start:end], fields, data[payload:payload + fields[6]])
            for name, start, payload, end, fields in archive_records(data)}


class SerialTests(unittest.TestCase):
    def test_replacements_and_unchanged_records(self):
        stock, elf = fixture()
        patched, report = apply_serial(add_debug(stock, debug_files([])), elf)
        verify_serial(stock, patched)
        before, after = plain(stock), plain(patched)
        self.assertEqual(report['profile'], 'serial-shell')
        self.assertEqual({n for n in before if before[n][0] != after[n][0]}, set(REPLACED))
        self.assertEqual(after[b'bin/busybox'][2], elf)
        self.assertEqual(after[b'etc/inittab'][2], INITTAB)
        self.assertEqual(after[b'etc/passwd'][2], before[b'etc/passwd'][2])
        self.assertEqual(after[b'etc/shadow'][1][1:4], (stat.S_IFREG | 0o600, 0, 0))
        self.assertIn(b'other:!:::::::\n', after[b'etc/shadow'][2])
        self.assertIn(b'root:' + ROOT_HASH + b':1::::::\n', after[b'etc/shadow'][2])
        self.assertEqual(after[b'debug/applets/tree'][2], b'/bin/busybox')
        self.assertEqual(after[b'etc/inittab'][2].count(b'::respawn:'), 1)
        self.assertNotIn(b'/etc/init', after[b'etc/inittab'][2])

    def test_extra_static_tool_is_verified(self):
        stock, elf = fixture()
        files = debug_files([])
        files['bin/zx-fwslot'] = (0o755, elf)
        patched, _ = apply_serial(add_debug(stock, files), elf)
        verify_serial(stock, patched)
        self.assertEqual(plain(patched)[b'debug/bin/zx-fwslot'][2], elf)
        with self.assertRaisesRegex(ValueError, 'exact UART profile'):
            verify_serial(stock, patched.replace(b'vendor microcode', b'changed microcod'))

    def test_lan_ssh_bundle(self):
        stock, elf = fixture()
        bins = {name: elf + name.encode() for name in LAN_SSH_BINARIES}
        patched, report = apply_serial(add_debug(stock, debug_files([])), elf, bins)
        verify_serial(stock, patched)
        before, after = plain(stock), plain(patched)
        self.assertEqual({n for n in before if before[n][0] != after[n][0]}, set(REPLACED))
        for name in LAN_SSH_SCRIPTS:
            record = after[f'debug/bin/{name}'.encode()]
            self.assertEqual(record[2], Path('debug_overlay', name).read_bytes())
            self.assertEqual(record[1][1], stat.S_IFREG | 0o755)
        for name, path in LAN_SSH_BINARIES.items():
            self.assertEqual(after[path.encode()][2], bins[name])
        for name in DROPBEAR_LINKS:
            record = after[f'debug/bin/{name}'.encode()]
            self.assertTrue(stat.S_ISLNK(record[1][1]))
            self.assertEqual(record[2], b'dropbearmulti')
        self.assertEqual(set(report['lan_ssh_sha256']), set(LAN_SSH_BINARIES))
        inodes = [fields[0] for _, fields, _ in after.values() if fields[0]]
        self.assertEqual(len(inodes), len(set(inodes)))
        with self.assertRaisesRegex(ValueError, 'exact UART profile'):
            verify_serial(stock, patched.replace(b'siswitch -spen 4 0', b'siswitch -spen 4 9'))
        with self.assertRaisesRegex(ValueError, 'needs exactly'):
            apply_serial(add_debug(stock, debug_files([])), elf, {'dropbearmulti': elf})
        hard = bytearray(elf)
        struct.pack_into('<I', hard, 36, 0x5000400)
        with self.assertRaisesRegex(ValueError, 'sftp-server: must be ARM32 soft-float'):
            apply_serial(add_debug(stock, debug_files([])), elf, dict(bins, **{'sftp-server': bytes(hard)}))

    def test_verify_rejects_misc_edits(self):
        stock, elf = fixture()
        patched, _ = apply_serial(add_debug(stock, debug_files([])), elf)
        with self.assertRaisesRegex(ValueError, 'exact UART profile'):
            verify_serial(stock, patched.replace(b'vendor microcode', b'changed microcod'))

    def test_rejects_hardfloat_or_bad_shadow(self):
        stock, elf = fixture()
        hard = bytearray(elf)
        struct.pack_into('<I', hard, 36, 0x5000400)
        with self.assertRaisesRegex(ValueError, 'soft-float'):
            apply_serial(add_debug(stock, debug_files([])), hard)
        with self.assertRaisesRegex(ValueError, 'one conventional root'):
            replace_root_shadow(b'root:x\n')

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL not present')
    def test_root_password_hash(self):
        expected = subprocess.check_output(['openssl', 'passwd', '-6', '-salt', 'ontlab-133', '--', 'root'])
        self.assertEqual(ROOT_HASH, expected.strip())

    @unittest.skipUnless(shutil.which('qemu-arm') and Path('build/busybox/busybox-arm').is_file(),
                         'QEMU or compiled BusyBox not present')
    def test_compiled_binary(self):
        command = ['qemu-arm', 'build/busybox/busybox-arm']
        applets = subprocess.check_output(command + ['--list']).splitlines()
        self.assertGreaterEqual(len(applets), 400)
        self.assertTrue({b'init', b'ash', b'mount', b'mdev', b'lsblk', b'mkpasswd', b'vi'} <= set(applets))
        expected = subprocess.check_output(command + ['mkpasswd', '-m', 'sha512', '-S', 'ontlab-133', 'root'])
        self.assertEqual(ROOT_HASH, expected.strip())
        for script in ('serial-shell', 'ssh-up') + LAN_SSH_SCRIPTS:
            subprocess.run(command + ['ash', '-n', f'debug_overlay/{script}'], check=True)


if __name__ == '__main__':
    unittest.main()
