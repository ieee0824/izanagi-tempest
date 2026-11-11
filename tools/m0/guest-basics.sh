#!/bin/sh
# Disposable guest only. This is a transport probe, not a LWS authorization test.
set -eu
python3 - <<'PY'
import errno
import json
import os
import socket
import subprocess
import threading
import time
from pathlib import Path

result = {'kind': 'guest_basics', 'uid': os.getuid(), 'epoch_ns': time.time_ns()}
path = Path('/workspace/.tempest-m0-write-probe')
try:
    with path.open('x') as stream:
        stream.write('dummy')
    path.unlink()
    result['shared_write'] = {'blocked': False}
except OSError as error:
    result['shared_write'] = {'blocked': True, 'errno': error.errno,
                              'read_only_filesystem': error.errno == errno.EROFS}
result['privilege_tools'] = {}
for command in [['sudo', '-n', 'id'], ['doas', '-n', 'id']]:
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=5)
        result['privilege_tools'][command[0]] = {'returncode': process.returncode,
                                                'stdout': process.stdout, 'stderr': process.stderr}
    except OSError as error:
        result['privilege_tools'][command[0]] = {'error': str(error)}

with socket.socket() as server:
    server.bind(('127.0.0.1', 0))
    port = server.getsockname()[1]
    server.listen(1)
    server.settimeout(5)
    def reply():
        connection, _ = server.accept()
        with connection:
            connection.recv(1024)
            connection.sendall(b'HTTP/1.0 200 OK\r\nContent-Length: 16\r\n\r\ntempest-loopback')
    thread = threading.Thread(target=reply, daemon=True)
    thread.start()
    curl = subprocess.run(['curl', '--noproxy', '*', '--max-time', '5', '-sS',
                           f'http://127.0.0.1:{port}/tempest-m0-loopback'],
                          capture_output=True, text=True, timeout=7)
    thread.join(timeout=6)
    result['loopback_http'] = {'port': port, 'returncode': curl.returncode,
                              'stdout': curl.stdout, 'stderr': curl.stderr}
# Closing the bound socket gives a known unused port without touching a real service.
with socket.socket() as closed:
    closed.bind(('127.0.0.1', 0))
    refused_port = closed.getsockname()[1]
with socket.socket() as client:
    client.settimeout(3)
    result['loopback_refused'] = {'port': refused_port,
                                 'connect_errno': client.connect_ex(('127.0.0.1', refused_port))}
health = Path('/run/tempest-m0/backend-health.json')
if health.exists():
    listening = any(row.split()[1].split(':')[-1] == '11D7' and row.split()[3] == '0A'
                    for row in Path('/proc/net/tcp').read_text().splitlines()[1:])
    with socket.socket() as client:
        client.settimeout(3)
        error = client.connect_ex(('127.0.0.1', 4567))
    result['backend_rejection'] = {'port': 4567, 'root_health': json.loads(health.read_text()),
                                   'listening': listening, 'connect_errno': error}
    assert listening and error in (errno.ECONNREFUSED, errno.EACCES), result['backend_rejection']
print(json.dumps(result, sort_keys=True))
PY
