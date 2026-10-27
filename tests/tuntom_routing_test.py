#!/usr/bin/env python3
"""Real kernel tunnel routing gate in disposable network/mount namespaces."""
import json
import os
import shutil
import socket
import subprocess
import sys
import time


def inside(helper, driver, uid, net, mount):
    assert os.readlink('/proc/self/ns/net') != net
    assert os.readlink('/proc/self/ns/mnt') != mount
    def run(*args):
        return subprocess.check_output(args, stderr=subprocess.STDOUT)
    run('mount', '-t', 'tmpfs', 'tmpfs', '/run')
    run('ip', 'link', 'add', 'skt1c', 'type', 'veth', 'peer', 'name', 'peer')
    run('ip', 'link', 'set', 'skt1c', 'up')
    run('ip', 'link', 'set', 'peer', 'up')
    run('ip', 'addr', 'add', '10.253.0.6/30', 'dev', 'skt1c')
    run('ip', 'link', 'set', 'lo', 'up')
    run('ip', 'addr', 'add', '192.0.2.1/32', 'dev', 'lo')
    peer = json.loads(run('ip', '-j', 'link', 'show', 'peer'))[0]['address']
    run('ip', 'neigh', 'replace', '10.253.0.5', 'lladdr', peer, 'nud', 'permanent', 'dev', 'skt1c')
    environment = dict(os.environ, SUDO_UID=uid)
    environment.pop('PKEXEC_UID', None)
    def gate(action):
        return subprocess.run([driver, action, uid, net, mount], capture_output=True)
    initial = gate('begin')
    if initial.returncode and b'cgroup does not exist' in initial.stderr:
        return 77
    assert initial.returncode == 0, initial.stderr
    table = str(45000 + int(uid) % 1000)
    def routed():
        result = subprocess.run(['ip', 'route', 'show', 'table', table], capture_output=True)
        return b'default via 10.253.0.5 ' in result.stdout
    def closed():
        rules = json.loads(run('nft', '-j', 'list', 'table', 'inet', 'skewer_guard_' + uid))
        # A closed guard never allows marked IPv4 out of its guarded chain.
        return not any('return' in expr for row in rules['nftables']
                       if row.get('rule', {}).get('chain') == 'guarded'
                       for expr in row['rule'].get('expr', []))
    worker = subprocess.Popen([helper, 'serve'], env=environment,
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        time.sleep(2.5)
        assert not routed() and closed(), 'generic watchdog reopened unverified tunnel'
        direct = subprocess.run([helper, 'up', '10.253.0.5'], env=environment, capture_output=True)
        assert direct.returncode != 0, 'direct up bypassed tunnel ownership'
        assert gate('verified').returncode == 0
        assert routed() and not closed()
        nat = run('nft', 'list', 'chain', 'inet', 'skewer_' + uid, 'tunnel_snat')
        assert b'snat ip to 10.253.0.6' in nat and b'oifname "skt1c"' in nat
        # Deliberately retain a source from the original host, as OUTPUT
        # rerouting may do. The wire must carry the tunnel's return address.
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as capture:
            capture.bind(('peer', 0))
            capture.settimeout(2)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 0x53000000 | int(uid))
                client.bind(('192.0.2.1', 0))
                client.sendto(b'tunnel return path', ('198.18.0.1', 12345))
            packet = capture.recv(2048)
            assert socket.inet_ntoa(packet[26:30]) == '10.253.0.6', packet.hex()
        assert gate('waiting').returncode == 0
        time.sleep(2.5)
        assert not routed() and closed(), 'watchdog bypassed lost tunnel verification'
        assert gate('verified').returncode == 0
        assert routed()
        for _ in range(3):
            assert gate('waiting').returncode == 0
            assert not routed() and closed(), 'lost tunnel must remain fail-closed'
            assert gate('verified').returncode == 0
            assert routed() and not closed(), 'verified tunnel must restore routing repeatedly'
        # The tunnel worker can repair route loss only after verification.
        run('ip', 'route', 'del', 'table', table, 'default')
        assert gate('verified').returncode == 0 and routed()
        subprocess.run([helper, 'down'], env=environment, capture_output=True, check=True)
        assert gate('verified').returncode != 0, 'stale worker ignored Disable'
        assert not routed() and closed()
        subprocess.run([helper, 'up', '10.253.0.5'], env=environment, capture_output=True, check=True)
        assert gate('waiting').returncode != 0
        assert routed() and not closed(), 'old tunnel worker disturbed new direct routing'
        subprocess.run([helper, 'down'], env=environment, capture_output=True, check=True)
        direct_host = subprocess.run([helper, 'up', '10.253.0.5', '--whole-host'], env=environment, capture_output=True)
        assert direct_host.returncode == 0, direct_host.stderr
        assert b'chain egress' in run('nft', 'list', 'table', 'inet', 'skewer_host')
        assert b'masquerade' in run('nft', 'list', 'table', 'inet', 'skewer_host')
        assert subprocess.run([helper, 'up', '10.253.0.5'], env=environment, capture_output=True).returncode != 0
        subprocess.run([helper, 'down'], env=environment, capture_output=True, check=True)
        assert closed(), 'release must restore selected-application protection'
        assert gate('begin-host').returncode == 0
        def host_ready():
            return subprocess.run(['nft', 'list', 'chain', 'inet', 'skewer_host', 'egress'], capture_output=True).returncode == 0
        assert not host_ready()
        assert gate('verified').returncode == 0 and host_ready()
        assert b'--whole-host' in open('/run/skewer-route-intent-' + uid + '.json', 'rb').read()
        # Host scope marks root/service sockets too, with the tunnel return source.
        run('ip', 'route', 'add', 'default', 'via', '10.253.0.5', 'dev', 'skt1c', 'onlink')
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as capture:
            capture.bind(('peer', 0)); capture.settimeout(2)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.bind(('192.0.2.1', 0))
                client.sendto(b'host through tunnel', ('198.18.0.9', 53))
            while True:
                packet = capture.recv(2048)
                if b'host through tunnel' in packet: break
            assert socket.inet_ntoa(packet[26:30]) == '10.253.0.6'
        for _ in range(2):
            assert gate('waiting').returncode == 0 and not host_ready()
            assert gate('verified').returncode == 0 and host_ready()
        subprocess.run([helper, 'down'], env=environment, capture_output=True, check=True)
        assert not host_ready() and closed()
        assert not os.path.exists('/run/skewer-host.json')
        assert gate('verified').returncode != 0
    finally:
        worker.stdin.close()
        worker.wait(timeout=5)
    return 0


if __name__ == '__main__':
    if len(sys.argv) == 3:
        if any(not shutil.which(tool) for tool in ('unshare', 'ip', 'nft', 'mount')):
            sys.exit(77)
        if subprocess.run(['unshare', '-Urnm', 'true'], capture_output=True).returncode:
            sys.exit(77)
        sys.exit(subprocess.call(['unshare', '-Urnm', sys.executable, __file__, '--inside',
            *sys.argv[1:], str(os.getuid()), os.readlink('/proc/self/ns/net'), os.readlink('/proc/self/ns/mnt')]))
    assert len(sys.argv) == 7 and sys.argv[1] == '--inside'
    sys.exit(inside(*sys.argv[2:]))
