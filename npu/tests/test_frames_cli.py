"""Frame building/decoding, configuration and command-line parsing (no lab access)."""
import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from npukit import acl, cli, config, frames  # noqa: E402


class Frames(unittest.TestCase):
    def test_udp4_round_trip(self):
        f = frames.udp4('10.1.1.2', '10.2.2.2', 40001, 7781, seq=7, smac='02:00:00:00:00:02', dmac='00:d0:d0:61:62:01')
        d = frames.decode(f)
        self.assertEqual((d['sip'], d['dip'], d['sport'], d['dport'], d['seq']), ('10.1.1.2', '10.2.2.2', 40001, 7781, 7))
        self.assertTrue(d['ip_csum_ok'] and d['udp_csum_ok'])
        self.assertEqual(d['smac'], '02:00:00:00:00:02')

    def test_udp6_round_trip(self):
        f = frames.udp6('2001:db8:1::2', '2001:db8:2::2', 40001, 7781, seq=3, smac='02:00:00:00:00:02',
                        dmac='00:d0:d0:61:62:01')
        d = frames.decode(f)
        self.assertEqual((d['sip'], d['nh'], d['seq']), ('2001:db8:1::2', 17, 3))
        self.assertTrue(d['udp_csum_ok'])

    def test_dslite_capture_decodes(self):
        # frame captured in exp101 (DS-Lite add on the board)
        h = ('00e041680d8600d0d061620186dd60000000003c044020010db800000000000000000000000120010db8000000000000'
             '0000000000024500003c12340000401151770a0101020a0202029c411e650028a05941434c5400000000000000000000'
             '000000000000000000000000000000000000')
        d = frames.decode(bytes.fromhex(h))
        self.assertEqual((d['nh'], d['plen'], d['sip'], d['dip']), (4, 60, '2001:db8::1', '2001:db8::2'))
        self.assertEqual((d['inner']['sip'], d['inner']['ttl']), ('10.1.1.2', 64))
        self.assertTrue(d['inner']['ip_csum_ok'] and d['inner']['udp_csum_ok'])

    def test_digest_modes(self):
        s, d = acl.v6digest('2001:db8:1::2', '2001:db8:2::2')
        self.assertEqual((s, d), (0xefa00008, 0x917fa934))           # board, mode 1
        self.assertEqual(acl.v6digest('2001:db8:1::2', '2001:db8:2::2', 0), (0x6231358f, 0x12da0936))


class Config(unittest.TestCase):
    def test_defaults_and_override(self):
        with tempfile.NamedTemporaryFile('w', suffix='.toml', delete=False) as f:
            f.write('[mac]\nhost = "h"\n[board]\nlan_port = 6\n')
        try:
            c = config.load(f.name)
            self.assertEqual((c.mac.host, c.board.lan_port, c.board.uplink_port), ('h', 6, 0))
            self.assertIn('mac.serial_dev', c.missing())
        finally:
            os.unlink(f.name)


class Cli(unittest.TestCase):
    def run_cli(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cli.main(list(argv))
        return buf.getvalue()

    def test_fast_add_dry_run(self):
        out = self.run_cli('fast', 'add', '--sip', '10.1.1.2', '--proto', 'udp', '--dport', '7781',
                           '--out-port', '5', '--set-dport', '0x2222', '--dry-run')
        self.assertIn('k_sip=a010102:ffffffff', out)
        self.assertIn('k_l4_dport=1e65:ffff', out)
        self.assertIn('r_l4_dport=2222', out)
        self.assertTrue(out.strip().endswith('> acl_debug/acl_hgu_table_set'))

    def test_wanlink_dry_run(self):
        out = self.run_cli('fast', 'wanlink', '4', '--pppoe', '0x1234', '--dry-run')
        self.assertIn('pppoe_add_flag=1 pppoe_session_id=1234', out)

    def test_digest_and_layout(self):
        self.assertIn('k_sip=efa00008  k_dip=917fa934', self.run_cli('fast', 'digest', '2001:db8:1::2', '2001:db8:2::2'))
        out = self.run_cli('fast', 'layout', 'wan_link')
        self.assertIn('pppoe_add_flag', out)
        self.assertIn('word 0 [30:30]', out)


if __name__ == '__main__':
    unittest.main()
