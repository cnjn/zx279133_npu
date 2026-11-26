"""Symbolic names for npdis --names (reading aid). Only fields with evidence get a name;
see NPU_MCODE.md for each one. Names are emitted as .equ lines, so the output still
assembles byte-for-byte."""
import csv
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Operand / condition aliases per image (exact operand text -> name). Conditions read
# register bits (board exp70): rN.B in a condition, rN[B] as an operand.
ALIASES = {
    'zx133': {
        'r4[5:0]': 'in_port',        # descriptor h3+44; MAC-table port check, protocol-action index
        'r5[29:24]': 'out_port',     # output-port counters and h3+20 destination port
        'r14[25:24]': 'da_cast',     # descriptor h3+36; 0 unicast, 1 multicast, else broadcast
        'r8.26': 'ipv6',             # bmov from h3+40 bit 22 (PC 5009, exp73)
        'r8.27': 'ipv4',             # bmov from h3+40 bit 23
        'r12.30': 'skip_l4_csum_write',  # cset.eq UDP checksum == 0; PC 828/974 bypass the store
        'r32.31': 's0_miss',         # slot-0 result word bit 31 (miss) after lkup s0
    },
    'sr1010': {
        'r10.3': 'ipv6', 'r10.4': 'ipv4', 'r10.5': 'udp', 'r10.6': 'tcp',   # exp8b + UDP/TCP csum offsets
        'r10[0]': 'pkt_color',      # h3+28 bit 16 and SR1010 #26 policer dataflow
    },
}

# Lookup tables (ZX133 driver has no SDT names; these come from reading the code).
TABLES = {
    'zx133': {
        24: 'protocol action', 27: 'port isolation', 28: 'ingress VLAN check',
        47: 'up-PON MAC mux counters', 48: 'stat counters', 50: 'MAC table (MAC + 2 bytes)',
        53: 'hash, 8-byte key', 56: 'GEM port / VLAN map (6-byte MAC key)',
        111: 'VLAN tag values / modify mask', 116: 'encapsulation actions',
        164: 'fast-path hash', 165: 'SFU path hash',
    },
}

MUX_INDEX_NAMES = ('unicast', 'multicast', 'broadcast')

# Exact words only; inferred local effects are comments, not ISA definitions.
RAW_NOTES = {
    'zx133': {
    },
    'sr1010': {
    },
}


def stat_labels(tsv=HERE / 'debug-stat-reads-133.tsv'):
    """Table-48 index -> driver counter label (fixed indices only)."""
    out = {}
    if tsv.exists():
        with tsv.open() as f:
            for r in csv.DictReader(f, delimiter='\t'):
                if r.get('fixed_index'):
                    out[int(r['fixed_index'], 16)] = r['driver_label']
    return out


def which(blob_len_main):
    return 'zx133' if blob_len_main == 5214 else 'sr1010' if blob_len_main == 5272 else None
