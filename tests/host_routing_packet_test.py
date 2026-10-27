#!/usr/bin/env python3
"""Exercise host marking, DNS, NAT, exemptions, loss and release in private namespaces."""
import os
import json
import socket
import subprocess
import sys


def inside(driver, net, mount):
    assert os.readlink('/proc/self/ns/net') != net
    assert os.readlink('/proc/self/ns/mnt') != mount
    def run(*args, **kw):
        return subprocess.check_output(args, stderr=subprocess.STDOUT, **kw)
    run('mount', '-t', 'tmpfs', 'tmpfs', '/run')
    run('ip', 'link', 'set', 'lo', 'up')
    for dev, peer, address, gateway in [('skout', 'peer', '10.20.0.2/24', '10.20.0.1'),
                                         ('underlay', 'physical', '192.0.2.2/24', '192.0.2.1')]:
        run('ip', 'link', 'add', dev, 'type', 'veth', 'peer', 'name', peer)
        for link in (dev, peer): run('ip', 'link', 'set', link, 'up')
        run('ip', 'addr', 'add', address, 'dev', dev)
        mac = json.loads(run('ip', '-j', 'link', 'show', peer))[0]['address']
        run('ip', 'neigh', 'replace', gateway, 'lladdr', mac, 'nud', 'permanent', 'dev', dev)
    run('ip', 'route', 'add', 'default', 'via', '192.0.2.1', 'dev', 'underlay')
    run('ip', 'route', 'add', 'table', '45000', 'default', 'via', '10.20.0.1', 'dev', 'skout', 'onlink')
    run('ip', 'rule', 'add', 'pref', '15000', 'fwmark', '0x530003e8', 'table', '45000')
    run('ip', 'rule', 'add', 'pref', '15001', 'fwmark', '0x530003e8', 'unreachable')
    original = run('ip', 'route', 'show', 'table', 'main')
    def apply(ready, replace=False):
        rules = run(driver, 'ready' if ready else 'closed')
        if replace: rules = b'delete table inet skewer_host\n' + rules
        run('nft', '-f', '-', input=rules)
    def packet(destination, port, interface, expected=True, source=None):
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as wire:
            wire.bind((interface, 0)); wire.settimeout(.3)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                try: client.sendto(b'whole-host-egress', (destination, port))
                except PermissionError:
                    assert not expected
            found = None
            try:
                while True:
                    data = wire.recv(4096)
                    if b'whole-host-egress' in data: found = data; break
            except socket.timeout: pass
            assert bool(found) == expected, (destination, port, interface, expected)
            if source: assert socket.inet_ntoa(found[26:30]) == source
    run('ip', '-6', 'addr', 'add', 'fd00:1::2/64', 'dev', 'underlay', 'nodad')
    mac = json.loads(run('ip', '-j', 'link', 'show', 'physical'))[0]['address']
    run('ip', '-6', 'neigh', 'replace', 'fd00:1::1', 'lladdr', mac, 'nud', 'permanent', 'dev', 'underlay')
    run('ip', '-6', 'route', 'add', 'default', 'via', 'fd00:1::1', 'dev', 'underlay')
    apply(True)
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as client:
        try:
            client.sendto(b'ipv6 must be blocked', ('2001:db8::1', 443))
            raise AssertionError('IPv6 escaped the host guard')
        except PermissionError: pass
    packet('203.0.113.9', 443, 'peer', source='10.20.0.2')
    packet('203.0.113.53', 53, 'peer', source='10.20.0.2')
    packet('198.51.100.7', 443, 'physical', source='192.0.2.2')
    # A competing VPN rule wins policy lookup, but cannot leak host packets.
    run('ip', 'rule', 'add', 'pref', '100', 'lookup', 'main')
    packet('203.0.113.8', 443, 'physical', expected=False)
    run('ip', 'rule', 'del', 'pref', '100')
    apply(False, True)
    packet('203.0.113.8', 443, 'physical', expected=False)
    packet('198.51.100.7', 443, 'physical')
    apply(True, True)
    packet('203.0.113.9', 443, 'peer', source='10.20.0.2')
    run('nft', 'delete', 'table', 'inet', 'skewer_host')
    packet('203.0.113.8', 443, 'physical', source='192.0.2.2')
    assert run('ip', 'route', 'show', 'table', 'main') == original


if __name__ == '__main__':
    if len(sys.argv) == 2:
        if subprocess.run(['unshare', '-Urnm', 'true'], capture_output=True).returncode: sys.exit(77)
        sys.exit(subprocess.call(['unshare', '-Urnm', sys.executable, __file__, *sys.argv[1:],
            os.readlink('/proc/self/ns/net'), os.readlink('/proc/self/ns/mnt')]))
    inside(*sys.argv[1:])
