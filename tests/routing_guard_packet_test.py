#!/usr/bin/env python3
"""Exercise generated output rules in a disposable network namespace only."""
import json
import os
import re
import shutil
import socket
import subprocess
import sys


def run(*args, **kwargs):
    return subprocess.check_output(args, **kwargs)


def inside(binary, host_namespace):
    assert os.readlink('/proc/self/ns/net') != host_namespace
    run('ip', 'link', 'add', 'uplink', 'type', 'dummy')
    run('ip', 'link', 'set', 'uplink', 'up')
    run('ip', 'addr', 'add', '192.0.2.1/24', 'dev', 'uplink')
    run('ip', 'route', 'add', 'default', 'via', '192.0.2.3')
    run('ip', 'route', 'add', 'table', '45000', '192.0.2.0/24', 'dev', 'uplink')
    run('ip', 'route', 'add', 'table', '45000', 'default', 'via', '192.0.2.2')
    rule = ('ip', 'rule', 'add', 'pref', '15000', 'fwmark', '0x530003e8', 'lookup', '45000')
    fallback = ('ip', 'rule', 'add', 'pref', '15001', 'fwmark', '0x530003e8', 'unreachable')
    run(*rule)
    run(*fallback)

    def install(active, replace=False):
        generated = run(binary, '--active' if active else '--blocked').decode()
        # Cgroup delegation is unavailable in an unprivileged netns. Substitute
        # only the selector; the production verdict/route checks stay unchanged.
        generated, count = re.subn(r'socket cgroupv2 level 5 "[^"]+"', 'meta skuid 0', generated)
        assert count == 1
        if replace:
            generated = 'delete table inet skewer_guard_1000\n' + generated
        run('nft', '-f', '-', input=generated.encode())

    def dropped():
        data = json.loads(run('nft', '-j', 'list', 'table', 'inet', 'skewer_guard_1000'))
        return sum(expr['counter']['packets'] for row in data['nftables']
                   for expr in row.get('rule', {}).get('expr', []) if 'counter' in expr)

    def probe(expect_drop, mark=True, destination='198.18.0.1', expect_unreachable=False):
        before = dropped()
        failed = False
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            if mark:
                client.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 0x530003e8)
            try:
                client.sendto(b'guard regression', (destination, 12345))
            except OSError:
                failed = True
        assert dropped() - before == int(expect_drop), (expect_drop, destination)
        assert failed == (expect_drop or expect_unreachable), (expect_drop, expect_unreachable, destination)

    install(False)
    probe(True)
    install(True, True)
    probe(False)
    probe(True, mark=False)
    probe(False, mark=False, destination='198.51.100.7')
    run('ip', 'rule', 'del', 'pref', '15000')
    probe(False, expect_unreachable=True)  # The adjacent rule blocks main-table fallback.
    run(*rule)
    run('ip', 'route', 'del', 'table', '45000', 'default')
    probe(False, expect_unreachable=True)
    install(False, True)
    probe(True, mark=False, destination='198.51.100.7')
    print('Fail-closed: active, unmarked, unreachable fallback, exemption and disable passed')


if __name__ == '__main__':
    if len(sys.argv) == 2:
        if any(not shutil.which(tool) for tool in ('unshare', 'ip', 'nft')):
            sys.exit(77)
        if subprocess.run(['unshare', '-Urn', 'true'], capture_output=True).returncode:
            sys.exit(77)
        sys.exit(subprocess.call(['unshare', '-Urn', sys.executable, __file__,
                                  '--inside', sys.argv[1], os.readlink('/proc/self/ns/net')]))
    assert len(sys.argv) == 4 and sys.argv[1] == '--inside'
    inside(sys.argv[2], sys.argv[3])
