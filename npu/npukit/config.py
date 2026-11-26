"""Paths inside the repository and the lab configuration (npu/config.toml).

The lab has three machines: this analysis host, a "jump" Mac that owns the board's UART
and sits on the board's LAN, and the board.  Everything environment-specific lives in
npu/config.toml (copy config.example.toml); $NPU_CONFIG points at another file."""
import os
import tomllib
from pathlib import Path

KIT = Path(__file__).resolve().parent
NPU = KIT.parent
ROOT = NPU.parent
RE = ROOT / 'build/npu-re'              # offline microcode / driver tools
EXP = ROOT / 'build/npu-exp'            # historical experiment scripts and logs
STOCK = ROOT / 'extracted/kernel1/rootfs/etc/mcode/mcode_133.bin'
KO = ROOT / 'extracted/kernel1/rootfs/kmodule/np_133.ko'
STATE = NPU / 'state'                   # local run state (fast-path rule handles), not in git
MAC_FILES = NPU / 'mac'                 # scripts that run on the jump Mac

DEFAULTS = {
    'mac': {
        'host': '',                     # ssh destination of the jump Mac
        'ssh_options': ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10'],
        'workdir': 'npukit',            # helper directory on the Mac (relative = under $HOME)
        'serial_dev': '',               # UART device on the Mac
        'iface': '',                    # Mac interface cabled to the board's LAN port
        'addr': '',                     # MAC address of that interface
        'ip': '192.168.1.2',
    },
    'board': {
        'ip': '192.168.1.1',
        'addr': '',                     # board LAN MAC (eth0)
        'lan_port': 5,                  # NP port number of the cabled LAN port
        'uplink_port': 0,               # #34 entry 0 bits 31:26 (WAN / uplink)
        'push_port': 9178,              # TCP port used to push files to the board
        'stock_mcode': '/etc/mcode/mcode_133.bin',
    },
    'test': {
        'fake_sa': '02:00:00:00:00:02',  # source MAC of raw test frames, registered in #50
    },
}


class Config:
    def __init__(self, data, path):
        self.path = path
        for section, values in DEFAULTS.items():
            merged = dict(values)
            merged.update(data.get(section, {}))
            setattr(self, section, type(section, (), merged))
        self.raw = data

    def missing(self):
        """Settings that must be filled in before talking to the lab."""
        need = [('mac', 'host'), ('mac', 'serial_dev'), ('mac', 'iface'), ('mac', 'addr'), ('board', 'addr')]
        return [f'{s}.{k}' for s, k in need if not getattr(getattr(self, s), k)]


def load(path=None):
    p = Path(path or os.environ.get('NPU_CONFIG') or NPU / 'config.toml')
    data = tomllib.loads(p.read_text()) if p.exists() else {}
    return Config(data, p if p.exists() else None)


_cfg = None


def cfg():
    global _cfg
    if _cfg is None:
        _cfg = load()
    return _cfg


def mac_bytes(text):
    return bytes.fromhex(text.replace(':', '').replace('-', ''))
