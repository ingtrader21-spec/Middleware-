"""Offline review harness; deny Internet socket connections before test imports."""
import os
from pathlib import Path
import runpy
import socket
import sys

ROOT = Path(__file__).resolve().parents[3]
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))
# Do not consume inherited provider credentials or a developer .env.
for key in tuple(os.environ):
    if key not in {'PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR', 'SYSTEMROOT'}:
        os.environ.pop(key, None)
os.environ.update(APP_ENV='test', ALLOW_IN_MEMORY_STORAGE='true', PYTHONDONTWRITEBYTECODE='1')
sys.dont_write_bytecode = True
original_connect = socket.socket.connect
original_connect_ex = socket.socket.connect_ex

def connect(self, address):
    if self.family in (socket.AF_INET, socket.AF_INET6):
        raise RuntimeError('review harness blocks network connections')
    return original_connect(self, address)

def connect_ex(self, address):
    if self.family in (socket.AF_INET, socket.AF_INET6):
        raise RuntimeError('review harness blocks network connections')
    return original_connect_ex(self, address)

socket.socket.connect = connect
socket.socket.connect_ex = connect_ex
if sys.argv[1] == 'pytest':
    import pytest
    raise SystemExit(pytest.main(['-p', 'no:cacheprovider', *sys.argv[2:]]))
script = sys.argv[1]
sys.argv = sys.argv[1:]
runpy.run_path(script, run_name='__main__')
