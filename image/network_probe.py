"""Public guest-only raw TCP controls for one VM-external host endpoint."""
import errno
import json
import os
from pathlib import Path
import re
import socket
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import proc_evidence as core

HOST_ADDRESS = '10.0.2.2'
MAX_FRAME = 256
CONTROL_PREFIX = 'TEMPEST-PUBLIC-NETWORK-'


def check_nonce(nonce):
    if not isinstance(nonce, str) or re.fullmatch('[0-9a-f]{32}', nonce) is None:
        raise ValueError('invalid public network nonce')


def local_control(nonce):
    check_nonce(nonce)
    payload = (CONTROL_PREFIX + nonce).encode('ascii')
    listener = socket.socket()
    thread = None
    started = False
    errors, received = [], []
    try:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(2)
        def serve():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(2)
                    data = b''
                    while len(data) < len(payload):
                        part = connection.recv(MAX_FRAME + 1 - len(data))
                        if not part:
                            break
                        data += part
                    if data != payload:
                        raise ValueError('local control bytes changed')
                    received.append(True)
                    connection.sendall(data)
            except (OSError, ValueError):
                errors.append('local_receiver_failed')
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        started = True
        with socket.create_connection(listener.getsockname(), timeout=2) as client:
            client.sendall(payload)
            reply = b''
            while len(reply) < len(payload):
                part = client.recv(MAX_FRAME)
                if not part:
                    break
                reply += part
            if reply != payload:
                raise RuntimeError('local TCP positive control failed')
        thread.join(3)
        if thread.is_alive() or errors or received != [True]:
            raise RuntimeError('local TCP receiver control failed')
        return {'passed': True, 'received': 1, 'bytes': len(payload), 'thread_joined': True}
    finally:
        listener.close()
        if thread is not None and started:
            thread.join(3)
            if thread.is_alive():
                raise RuntimeError('local receiver cleanup failed')


def probe_endpoint(port):
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError('invalid host fixture port')
    started = time.monotonic_ns()
    result = {'address': HOST_ADDRESS, 'port': port, 'connected': False, 'error_kind': None, 'errno': None}
    with socket.socket() as connection:
        connection.settimeout(2)
        try:
            connection.connect((HOST_ADDRESS, port))
            result['connected'] = True
        except TimeoutError as error:
            result.update(error_kind='timeout', errno=error.errno)
        except OSError as error:
            result.update(error_kind='os_error', errno=error.errno)
    result.update(started_monotonic_ns=started, ended_monotonic_ns=time.monotonic_ns())
    return result


def main():
    core.require_guest()  # Before opening any socket or reading guest identity.
    if len(sys.argv) != 3:
        raise ValueError('requires public nonce and fixed receiver port')
    nonce = sys.argv[1]
    check_nonce(nonce)
    port = int(sys.argv[2])
    control = local_control(nonce)
    result = {'schema_version': 1, 'nonce': nonce, 'actor_uid': os.getuid(),
              'guest_boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
              'local_control': control, 'endpoint': probe_endpoint(port),
              'scope': 'one host-alias endpoint only; raw TCP; not Internet-wide or production MCP egress'}
    print(json.dumps(result, separators=(',', ':')))


if __name__ == '__main__':
    main()
