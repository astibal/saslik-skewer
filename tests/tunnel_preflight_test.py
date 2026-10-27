"""A missing binary produces an actionable protocol failure, without authorization or network access."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    config = root / 'config' / 'Saslik'
    config.mkdir(parents=True)
    (config / 'Skewer.conf').write_text('[tunnel]\nbinary=/nonexistent-skewer-test/tuntom\n')
    env = dict(os.environ, XDG_CONFIG_HOME=str(root / 'config'), XDG_DATA_HOME=str(root / 'data'))
    result = subprocess.run([sys.argv[1], 'tunnel', 'skewer://127.0.0.1:8766/pair', '--gui-route'],
                            env=env, capture_output=True, timeout=5)
    assert result.returncode == 2, result.stderr
    status = json.loads(result.stdout)
    assert status['state'] == 'failed' and status['retryable'] is False
    assert 'Preferences > Tunnel' in status['error']
    assert result.stderr == b'', result.stderr
    logs = (root / 'data/skewer/logs/tunnel.log').read_text()
    assert 'preflight' in logs and 'Transport not found' in logs
    # Script mode keeps one useful error on stderr, with no stdout pollution.
    result = subprocess.run([sys.argv[1], 'tunnel', 'skewer://127.0.0.1:8766/pair'],
                            env=env, capture_output=True, timeout=5)
    assert result.returncode == 2 and result.stdout == b''
    assert b'Preferences > Tunnel' in result.stderr
