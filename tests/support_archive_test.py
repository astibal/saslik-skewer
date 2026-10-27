"""Verify exported archives with an independent ZIP reader, including CRCs."""
import json
import pathlib
import subprocess
import sys
import tempfile
import zipfile

with tempfile.TemporaryDirectory() as directory:
    archive = pathlib.Path(directory) / 'support.zip'
    subprocess.run([sys.argv[1], str(archive)], check=True)
    with zipfile.ZipFile(archive) as package:
        assert package.testzip() is None
        assert json.loads(package.read('manifest.json'))['version'] == 'test-version'
        assert json.loads(package.read('configuration.json'))['routing/scope'] == 'host'
        assert 'network/dns.txt' in package.namelist()
        for name in package.namelist():
            assert not name.startswith('/') and '..' not in pathlib.PurePosixPath(name).parts
            assert b'DO_NOT_EXPORT_THIS_VALUE' not in package.read(name)
