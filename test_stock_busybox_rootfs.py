import shutil
import subprocess
import struct
import unittest
from pathlib import Path

from serial_rootfs import ROOT_HASH
import stat

from serial_rootfs import DROPBEAR_LINKS
from stock_busybox_rootfs import (OSGID, OSGID_FORMAT, REPLACED, SSH_BINARIES, SSH_SCRIPTS, apply_stock_busybox,
                                  verify_stock_busybox)
from build_debug_rootfs import newc_record
from test_serial_rootfs import fixture as serial_fixture, plain


def fixture():
    # The serial fixture plus a stand-in /bin/osgid holding the vendor kill format.
    stock, elf = serial_fixture()
    at = stock.rindex(b'070701')
    offset, old, _ = OSGID_FORMAT
    osgid = bytes(offset) + old + b'tail'
    return stock[:at] + newc_record('bin/osgid', 50, stat.S_IFREG | 0o775, 1, osgid) + stock[at:], elf

ROOTFS = Path('extracted/kernel1/rootfs')
BUSYBOX = Path('build/busybox/busybox-arm')


class StockBusyboxTests(unittest.TestCase):
    def test_only_busybox_and_root_password_change(self):
        stock, elf = fixture()
        patched, report = apply_stock_busybox(stock, elf)
        verify_stock_busybox(stock, patched)
        before, after = plain(stock), plain(patched)
        self.assertEqual(report['profile'], 'stock-busybox')
        self.assertEqual(before.keys(), after.keys())
        self.assertEqual({n for n in before if before[n][0] != after[n][0]}, set(REPLACED) | {OSGID})
        self.assertEqual(after[b'bin/busybox'][2], elf)
        self.assertTrue(after[b'etc/shadow'][2].startswith(b'root:' + ROOT_HASH + b':'))
        self.assertIn(b'other:!:::::::\n', after[b'etc/shadow'][2])
        for name in REPLACED:
            # Inode, mode, owner, mtime etc. stay stock; only the size field may change.
            old, new = list(before[name][1]), list(after[name][1])
            old[6] = new[6] = 0
            self.assertEqual(old, new)
        self.assertEqual(after[b'etc/inittab'][2], b'::sysinit:/etc/init.d/rcS\n')
        offset, old, new = OSGID_FORMAT
        self.assertEqual(after[OSGID][2], before[OSGID][2].replace(old, new))
        self.assertEqual(after[OSGID][1], before[OSGID][1])

    def test_real_osgid_patch_is_one_byte(self):
        from stock_busybox_rootfs import patch_osgid
        stock = (ROOTFS / 'bin/osgid').read_bytes()
        patched = patch_osgid(stock)
        self.assertEqual(len(stock), len(patched))
        self.assertEqual([i for i in range(len(stock)) if stock[i] != patched[i]], [0xa360])
        with self.assertRaisesRegex(ValueError, 'Unexpected /bin/osgid'):
            patch_osgid(patched)

    def test_ssh_bundle(self):
        stock, elf = fixture()
        bins = {name: elf + name.encode() for name in SSH_BINARIES}
        patched, report = apply_stock_busybox(stock, elf, bins)
        verify_stock_busybox(stock, patched)
        before, after = plain(stock), plain(patched)
        self.assertEqual({n for n in before if before[n][0] != after[n][0]}, set(REPLACED) | {OSGID})
        added = set(after) - set(before)
        self.assertTrue(all(n.startswith(b'debug') for n in added))
        self.assertEqual(list(after)[-1], b'TRAILER!!!')
        for name in SSH_SCRIPTS:
            self.assertEqual(after[f'debug/bin/{name}'.encode()][2], Path('debug_overlay', name).read_bytes())
        for name, path in SSH_BINARIES.items():
            self.assertEqual(after[path.encode()][2], bins[name])
        for name in DROPBEAR_LINKS:
            record = after[f'debug/bin/{name}'.encode()]
            self.assertTrue(stat.S_ISLNK(record[1][1]))
            self.assertEqual(record[2], b'dropbearmulti')
        inodes = [fields[0] for _, fields, _ in after.values() if fields[0]]
        self.assertEqual(len(inodes), len(set(inodes)))
        self.assertEqual(set(report['ssh_sha256']), set(SSH_BINARIES))
        with self.assertRaisesRegex(ValueError, 'stock-busybox profile'):
            verify_stock_busybox(stock, patched.replace(b'exec lab-sshd', b'exec lab-sshX'))
        with self.assertRaisesRegex(ValueError, 'needs exactly'):
            apply_stock_busybox(stock, elf, {'dropbearmulti': elf})

    def test_verify_rejects_misc_edits(self):
        stock, elf = fixture()
        patched, _ = apply_stock_busybox(stock, elf)
        with self.assertRaisesRegex(ValueError, 'stock-busybox profile'):
            verify_stock_busybox(stock, patched.replace(b'vendor microcode', b'changed microcod'))

    def test_rejects_hardfloat_and_debug_overlay(self):
        stock, elf = fixture()
        hard = bytearray(elf)
        struct.pack_into('<I', hard, 36, 0x5000400)
        with self.assertRaisesRegex(ValueError, 'soft-float'):
            apply_stock_busybox(stock, bytes(hard))
        from build_debug_rootfs import add_debug, debug_files
        with self.assertRaisesRegex(ValueError, 'without /debug'):
            apply_stock_busybox(add_debug(stock, debug_files([])), elf)

    @unittest.skipUnless(shutil.which('qemu-arm') and BUSYBOX.is_file() and ROOTFS.is_dir(),
                         'QEMU, compiled BusyBox or extracted rootfs not present')
    def test_new_busybox_covers_stock_applets_and_scripts(self):
        stock = ['qemu-arm', '-L', str(ROOTFS), str(ROOTFS / 'bin/busybox')]
        new = ['qemu-arm', str(BUSYBOX)]
        missing = (set(subprocess.check_output(stock + ['--list']).split()) -
                   set(subprocess.check_output(new + ['--list']).split()))
        # nuke is disabled upstream by default; no stock script or binary invokes it.
        self.assertEqual(missing, {b'nuke'})
        # Stock root hashes are SHA-256 crypt; the stock login must still verify them.
        args = ['mkpasswd', '-m', 'sha256', '-S', 'abcdefgh', 'test123']
        self.assertEqual(subprocess.check_output(stock + args), subprocess.check_output(new + args))
        # Vendor scripts rely on sed's empty \1 and ash [[ ]] / == extensions.
        script = ("printf 'upmode: 64\\n' | sed -e 's/^upmode: /\\1/'; "
                  "x=64; if [[ $x -eq 64 ]] || [[ $x -eq 128 ]]; then echo ok; fi; "
                  "[ $x == 64 ] && echo ok")
        self.assertEqual(subprocess.check_output(stock + ['sh', '-c', script]),
                         subprocess.check_output(new + ['sh', '-c', script]))
        for path in ('etc/init.d/rcS', 'etc/rcS.d/S99modules', 'etc/default/S01userconfig'):
            subprocess.run(new + ['ash', '-n', str(ROOTFS / path)], check=True)

if __name__ == '__main__':
    unittest.main()
