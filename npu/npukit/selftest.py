"""Self tests: offline unit tests, lab connectivity / board health, and a fast-path smoke test.

The fast-path smoke test changes board state (two #50 entries, one HGU rule) and always
removes them again, also when it fails."""
import subprocess
import sys
import time

from . import acl, board, frames, link
from .config import NPU, RE, cfg

FLOW = dict(sip='10.1.1.2', dip='10.2.2.2', sport=40001, dport=7781)


def offline():
    ok = True
    for d in (RE, NPU / 'tests'):
        r = subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', str(d), '-p', 'test_*.py'],
                           capture_output=True, text=True)
        last = (r.stderr.strip().splitlines() or ['?'])[-1]
        print(f'  unit tests {d.relative_to(NPU.parent)}: {last}')
        ok &= r.returncode == 0
    return ok


def lab():
    c = cfg()
    miss = c.missing()
    if miss:
        print('  config incomplete:', ', '.join(miss))
        return False
    out = link.mac('echo mac-ok; ls ' + link.workdir(), 20)
    if 'mac-ok' not in out:
        print('  jump Mac unreachable:', out.strip()[-200:])
        return False
    need = {'ser.py', 'push.sh', 'board_reboot.py', 'rawtest.py'}
    have = set(out.split())
    if need - have:
        print('  Mac helpers missing, run `npu mac-sync`:', ', '.join(sorted(need - have)))
        return False
    u = link.ser('uptime', 15)
    if not link.ser_ok(u):
        print('  UART shell not answering:', u.strip()[-200:])
        return False
    print('  UART ok:', u.splitlines()[0].strip())
    h = board.health()
    print(f"  NP: stuck threads {h['stuck_threads']}, ping {h['ping_replies']}/3, "
          f"IDM->CPU {h['idm_dma_to_cpu']}, eth0 rx {h['eth0_rx']}")
    if not h['ok']:
        return False
    try:
        link.push(__file__, '/tmp/npukit_selftest.py')
        print('  LAN push ok')
    except link.LinkError as e:
        print('  LAN push failed:', e)
        return False
    return True


def fast():
    c = cfg()
    rule = acl.Rule(proto='udp', out_port=c.board.lan_port, set_sip='10.8.8.8', set_dip='10.9.9.9',
                    set_smac=c.board.addr, set_dmac=c.mac.addr, set_sport=0x1111, set_dport=0x2222, **FLOW)
    handle = None
    try:
        board.mac50(c.test.fake_sa, c.board.lan_port)
        board.mac50(c.board.addr, c.board.uplink_port)
        out = link.script([rule.command()], 120, name='npukit_fast')
        handle, errs = acl.parse_set_output(out)
        if not handle:
            print('  rule not accepted:', errs[:3])
            return False
        rx, _ = frames.send([frames.udp(FLOW['sip'], FLOW['dip'], FLOW['sport'], FLOW['dport'], seq=i) for i in range(3)] +
                            [frames.udp(FLOW['sip'], FLOW['dip'], FLOW['sport'] + 1, FLOW['dport'], seq=99)])
        want = {'dmac': c.mac.addr.lower(), 'smac': c.board.addr.lower(), 'sip': '10.8.8.8', 'dip': '10.9.9.9',
                'sport': 0x1111, 'dport': 0x2222, 'ip_csum_ok': True, 'udp_csum_ok': True}
        good = [d for d in rx if all(d.get(k) == v for k, v in want.items())]
        stray = [d for d in rx if d.get('seq') == 99]
        print(f'  fast path: {len(good)}/3 rewritten correctly, non-matching frame forwarded: {bool(stray)}')
        return len(good) == 3 and not stray
    finally:
        if handle:
            link.script([f'echo {handle} > acl_debug/acl_hgu_table_del'], 60, name='npukit_fast_del')
        board.mac50(c.test.fake_sa, 0, op=1)
        board.mac50(c.board.addr, 0, op=1)


def run(with_board=False, with_fast=False):
    t0 = time.time()
    results = {}
    print('offline:')
    results['offline'] = offline()
    if with_board or with_fast:
        print('lab:')
        results['lab'] = lab()
        if with_fast and results['lab']:
            print('fast path smoke test:')
            results['fast'] = fast()
            h = board.health()
            print(f"  after: stuck threads {h['stuck_threads']}, ping {h['ping_replies']}/3")
            results['after'] = h['ok']
    print('result:', ', '.join(f'{k} {"ok" if v else "FAIL"}' for k, v in results.items()),
          f'({time.time() - t0:.0f} s)')
    return all(results.values())
