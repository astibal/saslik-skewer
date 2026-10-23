#!/usr/bin/env python3
"""Persistent real helper test, restricted to disposable net/mount namespaces."""
import json
import os
import select
import shutil
import subprocess
import sys
import time


def run(*args):
    return subprocess.check_output(args, stderr=subprocess.STDOUT)


def inside(binary, uid, host_net, host_mount):
    assert os.readlink('/proc/self/ns/net') != host_net
    assert os.readlink('/proc/self/ns/mnt') != host_mount
    run('mount', '-t', 'tmpfs', 'tmpfs', '/run')
    run('ip', 'link', 'add', 'uplink', 'type', 'dummy')
    run('ip', 'link', 'set', 'uplink', 'up')
    run('ip', 'addr', 'add', '192.0.2.1/24', 'dev', 'uplink')
    environment = dict(os.environ, SUDO_UID=uid)
    environment.pop('PKEXEC_UID', None)
    worker = subprocess.Popen([binary, 'serve'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=environment)

    def request(args):
        worker.stdin.write(json.dumps({'args': args}).encode() + b'\n')
        worker.stdin.flush()
        assert select.select([worker.stdout], [], [], 15)[0], 'helper response timed out'
        line = worker.stdout.readline()
        assert line, worker.stderr.read().decode()
        return json.loads(line)

    table = str(45000 + int(uid) % 1000)

    def restored():
        result = subprocess.run(['ip', '-4', 'route', 'show', 'table', table], capture_output=True)
        return result.returncode == 0 and b'default via 192.0.2.2 ' in result.stdout

    def wait_restore():
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if restored():
                return
            time.sleep(.1)
        raise AssertionError('worker did not restore desired routing')

    def guard_open():
        value = json.loads(run('nft', '-j', 'list', 'table', 'inet', 'skewer_guard_' + uid))
        for entry in value['nftables']:
            rule = entry.get('rule', {})
            expressions = rule.get('expr', [])
            if rule.get('chain') == 'guarded' and any('return' in item for item in expressions):
                for item in expressions:
                    match = item.get('match', {})
                    if (match.get('left', {}).get('meta', {}).get('key') == 'mark'
                            and match.get('right') == (0x53000000 | int(uid))):
                        return True
        return False

    try:
        assert not request(['serve'])['ok']
        assert not request(['/bin/sh', '-c', 'true'])['ok']
        assert not request(['up', 'invalid-address'])['ok']
        # The helper remains alive after invalid requests; the UID is fixed.
        result = request(['up', '192.0.2.2', '--local-control=127.0.0.1:8766'])
        if not result['ok'] and 'cgroup does not exist' in result['detail']:
            print('SKIP: no existing routed cgroup for live-kernel matcher test')
            return 77
        assert result['ok'], result
        pid = worker.pid
        assert restored()
        assert request(['exemptions', '198.51.100.0/24'])['ok']
        with open('/run/skewer-route-intent-' + uid + '.json') as saved:
            assert '--local-control=127.0.0.1:8766' in json.load(saved)['exemptions']
        receipt = '/run/skewer-guard-' + uid
        unchanged = os.stat(receipt).st_mtime_ns
        time.sleep(2.5)
        assert os.stat(receipt).st_mtime_ns == unchanged, run('nft', '-j', 'list', 'table', 'inet', 'skewer_guard_' + uid).decode()
        os.unlink(receipt)
        assert request(['guard'])['ok']
        deadline = time.monotonic() + 8
        while not guard_open():
            assert time.monotonic() < deadline, 'drop-only guard was not reopened for desired routing'
            time.sleep(.1)
        run('ip', 'route', 'del', 'table', table, 'default', 'via', '192.0.2.2')
        assert not restored()
        wait_restore()
        # Replacing the interface reproduces a lab restart, not just deletion
        # of one route. Both route and guard must be reinstalled without auth.
        run('ip', 'link', 'del', 'uplink')
        time.sleep(2.5)
        run('ip', 'link', 'add', 'uplink', 'type', 'dummy')
        run('ip', 'link', 'set', 'uplink', 'up')
        run('ip', 'addr', 'add', '192.0.2.1/24', 'dev', 'uplink')
        wait_restore()
        assert worker.pid == pid and worker.poll() is None
        assert request(['down'])['ok']
        time.sleep(2.5)
        assert not os.path.exists('/run/skewer-route-intent-' + uid + '.json')
        assert not restored()
        run('nft', 'list', 'table', 'inet', 'skewer_guard_' + uid)
        # A separate client can Disable too; this worker must not undo it.
        assert request(['up', '192.0.2.2'])['ok']
        subprocess.run([binary, 'down'], env=environment, capture_output=True, check=True)
        time.sleep(2.5)
        assert not restored()
        # Explicitly enabling again survives client closure, as before.
        assert request(['up', '192.0.2.2'])['ok']
        worker.stdin.close()
        assert worker.wait(timeout=5) == 0
        assert restored()
        # A new client resumes saved intent even before the lab returns.
        run('ip', 'link', 'del', 'uplink')
        worker = subprocess.Popen([binary, 'serve'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, env=environment)
        assert request(['resume'])['ok']
        time.sleep(2.5)
        assert not restored()
        run('ip', 'link', 'add', 'uplink', 'type', 'dummy')
        run('ip', 'link', 'set', 'uplink', 'up')
        run('ip', 'addr', 'add', '192.0.2.1/24', 'dev', 'uplink')
        wait_restore()
        assert request(['down'])['ok']
        assert not request(['resume'])['ok']
        time.sleep(2.5)
        assert not restored()
        print('Persistent helper: recovery, restart/resume, Disable, invalid IPC, EOF passed')
    finally:
        if not worker.stdin.closed:
            worker.stdin.close()
        worker.wait(timeout=5)
    return 0


if __name__ == '__main__':
    if len(sys.argv) == 2:
        if any(not shutil.which(tool) for tool in ('unshare', 'ip', 'nft', 'mount')):
            sys.exit(77)
        if subprocess.run(['unshare', '-Urnm', 'true'], capture_output=True).returncode:
            sys.exit(77)
        sys.exit(subprocess.call(['unshare', '-Urnm', sys.executable, __file__, '--inside',
            sys.argv[1], str(os.getuid()), os.readlink('/proc/self/ns/net'), os.readlink('/proc/self/ns/mnt')]))
    assert len(sys.argv) == 6 and sys.argv[1] == '--inside'
    sys.exit(inside(*sys.argv[2:]))
