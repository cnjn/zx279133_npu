"""npu: one command line for the ZX279133 NP work.  `npu -h`, `npu COMMAND -h`."""
import argparse
import json
import runpy
import sys

from . import acl, board, frames, link, selftest
from .config import EXP, RE, ROOT, STOCK, cfg


def _run_script(path, argv):
    sys.argv = [str(path)] + list(argv)
    sys.path.insert(0, str(path.parent))
    runpy.run_path(str(path), run_name='__main__')


def _print(out):
    sys.stdout.write(out if out.endswith('\n') else out + '\n')


# ------------------------------------------------------------------ offline
def c_dis(a):
    _run_script(RE / 'npdis.py', [a.image or str(STOCK)] + (['--names'] if a.names else []) + a.rest)


def c_asm(a):
    _run_script(RE / 'npasm.py', [a.src, '-o', a.out] + (['--fit-gap'] if a.fit_gap else []))


def c_flow(a):
    _run_script(RE / 'np_flow.py', [a.image or str(STOCK)])


def c_patch(a):
    _run_script(EXP / 'snippet.py', [a.src, str(a.hook), str(a.base), a.outdir, a.name])


def c_ko(a):
    _run_script(RE / 'ko_tool.py', a.args)


# ------------------------------------------------------------------ lab basics
def c_config(a):
    c = cfg()
    print('config file:', c.path or '(none: defaults only; copy npu/config.example.toml to npu/config.toml)')
    for s in ('mac', 'board', 'test'):
        for k, v in vars(getattr(c, s)).items():
            if not k.startswith('_'):
                print(f'  {s}.{k} = {v!r}')
    if c.missing():
        print('missing:', ', '.join(c.missing()))


def c_mac_sync(a):
    print('copied to the Mac:', ', '.join(link.mac_sync()))


def c_sh(a):
    _print(link.ser(' '.join(a.cmd), a.timeout))


def c_run(a):
    cmds = open(a.file).read().splitlines() if a.file else a.cmd
    cmds = [x for x in cmds if x.strip() and not x.lstrip().startswith('#')]
    _print(link.script(cmds, a.timeout, a.level))


def c_health(a):
    h = board.health()
    for k, v in h.items():
        print(f'{k:16} {v}')
    sys.exit(0 if h['ok'] else 1)


def c_stats(a):
    if a.diff:
        before = json.load(open(a.diff))
        now = board.stats()
        for k, v in board.stats_diff(before, now).items():
            print(f'{v:+8}  {k}')
    else:
        now = board.stats()
        for k, v in now.items():
            if v or a.all:
                print(f'{v:10}  {k}')
    if a.save:
        json.dump(now, open(a.save, 'w'), indent=1)


def c_load(a):
    _print(board.load(a.image))


def c_restore(a):
    _print(board.restore())


def c_reboot(a):
    _print(board.reboot(a.lan_only))


def c_inst(a):
    if a.word is not None:
        _print(board.inst_set(a.pc, int(a.word, 16)))
    words, out = board.inst_get(a.pc)
    for pc, w in sorted(words.items()):
        print(f'{pc:5}  {w:016x}')
    if not words:
        _print(out)


# ------------------------------------------------------------------ SE tables
def c_se(a):
    if a.op == 'sdt':
        for k, v in board.sdt(a.sdt).items():
            print(f'{k:24} {v}')
    elif a.op == 'read':
        for i in range(a.index, a.index + a.count):
            print(f'{a.sdt}[{i}] ' + ' '.join(f'{w:08x}' for w in board.se_read(a.sdt, i, a.words)))
    elif a.op == 'write':
        _print(board.se_write(a.sdt, a.index, [int(x, 16) for x in a.values], a.force))
    elif a.op == 'hash-add':
        _print(board.hash_op(a.sdt, a.key, a.rsp, 0))
    elif a.op == 'hash-del':
        _print(board.hash_op(a.sdt, a.key, None, 1))


def c_mac50(a):
    _print(board.mac50(a.mac, a.port if a.op == 'add' else 0, 0 if a.op == 'add' else 1))


# ------------------------------------------------------------------ fast path
def _boot_id():
    out = link.ser('cat /proc/sys/kernel/random/boot_id', 15)
    return out.splitlines()[0].strip()


def c_fast(a):
    op = a.fop
    if op == 'digest':
        s, d = acl.v6digest(a.src, a.dst, a.mode)
        print(f'k_sip={s:08x}  k_dip={d:08x}')
        return
    if op == 'layout':
        tabs = {'hgu_key': acl.HGU_KEY, 'hgu_result': acl.HGU_RESULT, **acl.TABLES}
        for name in ([a.table] if a.table else tabs):
            t = tabs[name]
            print(f'{t.name}  (#{t.sdt}, {t.width} bits){"  " + t.note if t.note else ""}')
            for f, (pos, n) in t.fields.items():
                reg, hi, lo = t.bits(f)
                print(f'  {f:34} bits {pos + n - 1:3}:{pos:<3}  = word {reg} [{hi}:{lo}]')
        return
    if op in ('add', 'wanlink'):
        if op == 'add':
            r = acl.Rule(sip=a.sip, dip=a.dip, proto=a.proto, sport=a.sport, dport=a.dport, in_port=a.in_port,
                         tos=a.tos, out_port=a.out_port, out_que=a.out_que, set_sip=a.set_sip, set_dip=a.set_dip,
                         set_smac=a.set_smac, set_dmac=a.set_dmac, set_sport=a.set_sport, set_dport=a.set_dport,
                         vlan_push=a.vlan_push, vlan_push2=a.vlan_push2, vlan_pop=a.vlan_pop, wan_link=a.wan_link,
                         drop=a.drop, pri=a.pri, extra=a.field or ())
            cmds, desc = [r.command()], ' '.join(sys.argv[2:])
        else:
            cmds = acl.wanlink_commands(a.index, pppoe=a.pppoe, dslite=a.dslite, hop_limit=a.hop_limit,
                                        del_pppoe=a.del_pppoe, del_dslite=a.del_dslite)
        if a.dry_run:
            print('\n'.join(cmds))
            return
        out = link.script(cmds, 120, name='npukit_fast')
        if op == 'wanlink':
            bad = [l for l in out.splitlines() if 'fail' in l.lower() or 'error' in l.lower()]
            print('wan link', a.index, 'written' if not bad else 'FAILED: ' + '; '.join(bad[:3]))
            return
        handle, errs = acl.parse_set_output(out)
        if not handle:
            print('rule NOT added:', '; '.join(errs[:5]) or out.strip()[-600:])
            sys.exit(1)
        st = acl.State()
        st.sync_boot(_boot_id())
        print('rule', st.add(handle, cmds[0], desc), 'added')
    elif op == 'del':
        st = acl.State()
        st.sync_boot(_boot_id())
        ids = [r['id'] for r in st.data['rules']] if a.all else a.ids
        for rid in ids:
            rule = next((r for r in st.data['rules'] if r['id'] == rid), None)
            if not rule:
                print('no rule', rid)
                continue
            out = link.script([f"echo {rule['handle']} > acl_debug/acl_hgu_table_del"], 60, name='npukit_fast_del')
            ok = 'success' in out
            print('rule', rid, 'deleted' if ok else 'delete FAILED')
            if ok:
                st.remove(rid)
    elif op == 'list':
        st = acl.State()
        dropped = st.sync_boot(_boot_id())
        if dropped:
            print(f'(board rebooted since; forgot {dropped} rules)')
        for r in st.data['rules']:
            print(f"{r['id']:3}  {r['time']}  {r['desc']}")
        out = link.script(['echo cnt > acl_debug/acl_hgu_table_show'], 60, name='npukit_fast_cnt')
        print('hardware:', ' '.join(l.strip() for l in out.splitlines() if 'items' in l))
    elif op == 'dump':
        t = acl.TABLES[a.table]
        for i in range(a.index, a.index + a.count):
            words = board.se_read(t.sdt, i, t.width // 32)
            v = t.value(words)
            print(f'{a.table}[{i}] ' + ' '.join(f'{w:08x}' for w in words))
            print('   ', ' '.join(acl.fmt_fields({k: x for k, x in t.unpack(v).items() if x})) or '(empty)')
    elif op == 'lastkey':
        key, rsp, out = board.key_last()
        print('key   ', key[:32].hex())
        for f in acl.fmt_fields(acl.decode_key(key)):
            print('   ', f)
        if len(rsp) >= 9:
            res = rsp[1:9]
            print('result', ' '.join(f'{w:08x}' for w in res), '(miss)' if res[0] >> 31 else '')
            if not res[0] >> 31:
                for f in acl.fmt_fields(acl.HGU_RESULT.unpack(acl.HGU_RESULT.value(res))):
                    print('   ', f)


def c_send(a):
    fs = [frames.udp(a.src, a.dst, a.sport, a.dport, seq=i) for i in range(a.count)]
    before = board.stats() if a.stats else None
    rx, out = frames.send(fs, a.gap, a.wait)
    print(out.strip().splitlines()[-1])
    for d in rx:
        print(json.dumps(d))
    if before is not None:
        for k, v in board.stats_diff(before, board.stats()).items():
            print(f'{v:+8}  {k}')


def c_selftest(a):
    sys.exit(0 if selftest.run(with_board=a.board, with_fast=a.fast) else 1)


def build():
    p = argparse.ArgumentParser(prog='npu', description=__doc__,
                                epilog='See npu/README.md (quick start) and npu/SAFETY.md before touching the board.')
    sub = p.add_subparsers(dest='cmd', required=True, metavar='COMMAND')

    def cmd(name, fn, help):
        s = sub.add_parser(name, help=help, description=help)
        s.set_defaults(fn=fn)
        return s

    s = cmd('dis', c_dis, 'disassemble a microcode image (default: stock ZX133)')
    s.add_argument('image', nargs='?')
    s.add_argument('--names', action='store_true', help='symbolic names and counter comments')
    s.add_argument('rest', nargs=argparse.REMAINDER)
    s = cmd('asm', c_asm, 'assemble source back into an image (byte-exact for unmodified listings)')
    s.add_argument('src')
    s.add_argument('-o', '--out', required=True)
    s.add_argument('--fit-gap', action='store_true')
    s = cmd('flow', c_flow, 'static reachability: entries -> exits')
    s.add_argument('image', nargs='?')
    s = cmd('patch', c_patch, 'assemble a labelled snippet at BASE and hook it at HOOK (writes apply/restore commands)')
    for x in ('src', 'hook', 'base', 'outdir', 'name'):
        s.add_argument(x, type=int if x in ('hook', 'base') else str)
    s = cmd('ko', c_ko, 'driver RE: ko dis | ko fn NAME [N] | ko str TEXT | ko var SYMBOL')
    s.add_argument('args', nargs=argparse.REMAINDER)

    cmd('config', c_config, 'show the lab configuration')
    cmd('mac-sync', c_mac_sync, 'copy npu/mac/* helpers to the jump Mac')
    s = cmd('sh', c_sh, 'run a short shell command on the board (UART)')
    s.add_argument('cmd', nargs='+')
    s.add_argument('-t', '--timeout', type=int, default=30)
    s = cmd('run', c_run, 'push and run a list of board commands, each followed by its dmesg')
    s.add_argument('cmd', nargs='*')
    s.add_argument('-f', '--file', help='file with one command per line')
    s.add_argument('-t', '--timeout', type=int, default=120)
    s.add_argument('-l', '--level', type=int, default=3, help='SE driver print_level while running (default 3)')
    cmd('health', c_health, 'NP stuck threads, ping, NP->CPU path counters')
    s = cmd('stats', c_stats, 'stat counters (#48) by name')
    s.add_argument('--all', action='store_true', help='also zero counters')
    s.add_argument('--save', help='write a JSON snapshot')
    s.add_argument('--diff', help='print changes since a saved snapshot')
    s = cmd('load', c_load, 'load a whole microcode image file (from this host)')
    s.add_argument('image')
    cmd('restore', c_restore, 'reload the stock microcode')
    s = cmd('reboot', c_reboot, 'reboot the board safely over the UART and bring LAN1 up')
    s.add_argument('--lan-only', action='store_true', help='no reboot: only run lan1-up (board already restarted)')
    s = cmd('inst', c_inst, 'read (or write) live instruction words: inst PC [WORD_HEX]')
    s.add_argument('pc', type=int)
    s.add_argument('word', nargs='?')

    s = cmd('se', c_se, 'SE tables: sdt N | read SDT IDX [-n COUNT] [-w WORDS] | write SDT IDX W.. | hash-add SDT KEY RSP | hash-del SDT KEY')
    ss = s.add_subparsers(dest='op', required=True)
    x = ss.add_parser('sdt')
    x.add_argument('sdt', type=int)
    x = ss.add_parser('read')
    x.add_argument('sdt', type=int)
    x.add_argument('index', type=int)
    x.add_argument('-n', '--count', type=int, default=1)
    x.add_argument('-w', '--words', type=int, default=4, help='entry width in 32-bit words (1, 2, 4)')
    x = ss.add_parser('write')
    x.add_argument('sdt', type=int)
    x.add_argument('index', type=int)
    x.add_argument('values', nargs='+', help='hex words, microcode order (as `se read` prints)')
    x.add_argument('--force', action='store_true', help='allow ACL tables #111-#122 (see SAFETY.md)')
    x = ss.add_parser('hash-add')
    x.add_argument('sdt', type=int)
    x.add_argument('key')
    x.add_argument('rsp')
    x = ss.add_parser('hash-del')
    x.add_argument('sdt', type=int)
    x.add_argument('key')
    s = cmd('mac50', c_mac50, 'MAC table #50: add MAC PORT | del MAC (needed to enter the fast path)')
    s.add_argument('op', choices=['add', 'del'])
    s.add_argument('mac')
    s.add_argument('port', type=int, nargs='?', default=0)

    s = cmd('fast', c_fast, 'HGU fast path (ACL tables): add | del | list | wanlink | dump | lastkey | digest | layout')
    fs = s.add_subparsers(dest='fop', required=True)
    x = fs.add_parser('add', help='add a rule (only the match fields you give are compared)')
    for o in ('sip', 'dip', 'proto', 'sport', 'dport', 'in-port', 'tos'):
        x.add_argument('--' + o, help='match')
    x.add_argument('--out-port', type=int)
    x.add_argument('--out-que', type=int, default=0)
    for o in ('set-sip', 'set-dip', 'set-smac', 'set-dmac', 'set-sport', 'set-dport'):
        x.add_argument('--' + o)
    x.add_argument('--vlan-push', metavar='TPID:PRI:VID')
    x.add_argument('--vlan-push2', metavar='OUTER,INNER')
    x.add_argument('--vlan-pop', type=int, metavar='N')
    x.add_argument('--wan-link', type=int, metavar='N', help='apply WAN link N (see `fast wanlink`)')
    x.add_argument('--drop', action='store_true')
    x.add_argument('--pri', type=int)
    x.add_argument('--field', action='append', metavar='NAME=VAL', help='raw driver field, e.g. k_tag_level=0:7')
    x.add_argument('--dry-run', action='store_true', help='print the sysfs command only')
    x = fs.add_parser('wanlink', help='prepare WAN link N: --pppoe SID and/or --dslite LOCAL6 REMOTE6')
    x.add_argument('index', type=int)
    x.add_argument('--pppoe', metavar='SESSION')
    x.add_argument('--dslite', nargs=2, metavar=('LOCAL6', 'REMOTE6'))
    x.add_argument('--hop-limit', type=int, default=64)
    x.add_argument('--del-pppoe', action='store_true', help='strip PPPoE (untested)')
    x.add_argument('--del-dslite', action='store_true', help='DS-Lite decapsulation (untested)')
    x.add_argument('--dry-run', action='store_true')
    x = fs.add_parser('del', help='delete rules added with `fast add`')
    x.add_argument('ids', type=int, nargs='*')
    x.add_argument('--all', action='store_true')
    fs.add_parser('list', help='rules added by this tool, and the hardware entry count')
    x = fs.add_parser('dump', help='read and decode ACL table entries (safe replacement for acl_*_table_get)')
    x.add_argument('table', choices=sorted(acl.TABLES))
    x.add_argument('index', type=int)
    x.add_argument('-n', '--count', type=int, default=1)
    fs.add_parser('lastkey', help='decode the last hash key/result the PPU used (after sending a frame)')
    x = fs.add_parser('digest', help='IPv6 key digests (k_sip, k_dip) of an address pair')
    x.add_argument('src')
    x.add_argument('dst')
    x.add_argument('--mode', type=int, default=1, help='SPA compress mode (this board: 1)')
    x = fs.add_parser('layout', help='bit layout of the HGU key/result and the ACL tables')
    x.add_argument('table', nargs='?')

    s = cmd('send', c_send, 'send raw UDP test frames from the fake source MAC and show what comes back')
    s.add_argument('src')
    s.add_argument('dst')
    s.add_argument('sport', type=int)
    s.add_argument('dport', type=int)
    s.add_argument('-n', '--count', type=int, default=3)
    s.add_argument('--gap', type=float, default=0.01)
    s.add_argument('--wait', type=float, default=1.0)
    s.add_argument('--stats', action='store_true', help='also print counter changes')
    s = cmd('selftest', c_selftest, 'offline tests; --board: lab and board checks; --fast: fast-path smoke test')
    s.add_argument('--board', action='store_true')
    s.add_argument('--fast', action='store_true', help='implies --board; adds and removes a test rule')
    return p


def main(argv=None):
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(line_buffering=True)
    p = build()
    a = p.parse_args(argv)
    for k in list(vars(a)):
        if '-' in k:
            setattr(a, k.replace('-', '_'), getattr(a, k))
    try:
        a.fn(a)
    except link.LinkError as e:
        sys.exit(f'npu: {e}')
    except ValueError as e:
        sys.exit(f'npu: {e}')
    except BrokenPipeError:                      # output piped into head etc.
        import os
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(1)
