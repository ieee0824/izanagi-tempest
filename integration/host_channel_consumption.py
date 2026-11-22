"""Check durable consumption and lost-response behavior with a real host ledger."""

import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import sys
import tempfile
import time
from unittest.mock import patch, Mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

TOOLS = Path(__file__).resolve().parents[1] / 'tools/host_ledger'
sys.path.insert(0, str(TOOLS))
import channel
from read_snapshot import read_management_snapshot
from write_transition import advance


def main(delay_commit=False):
    if os.geteuid() != 0:
        raise PermissionError('run as root for management ownership checks')
    with tempfile.TemporaryDirectory(prefix='tempest-channel-', dir='/var/lib') as temporary:
        root = Path(temporary)
        for name in ('host-login-authority', 'host-login-recovery',
                     'host-login-ledger-source', 'host-login-ledger'):
            (root / name).mkdir(mode=0o700)
        scope = dict(target_id='vm', permit_id='a' * 32, generation=1)
        record = dict(ledger_id='ledger', scope=scope, sequence=0, state='empty')
        checkpoint = dict(sequence=0, digest=hashlib.sha256(channel.canonical_json(record)).hexdigest())
        for name, value in [('host-login-authority/scope.json', scope),
                            ('host-login-authority/ledger-id.json', 'ledger'),
                            ('host-login-recovery/checkpoint.json', checkpoint)]:
            (root / name).write_bytes(channel.canonical_json(value))
            (root / name).chmod(0o600)
        (root / 'host-login-ledger/lock').touch(mode=0o600)
        database = root / 'host-login-ledger-source/ledger.sqlite3'
        with sqlite3.connect(database) as db:
            db.executescript((TOOLS / 'schema.sql').read_text())
        database.chmod(0o600)
        advance(root, 'issue')
        registration = dict(scope, boot_id='boot1', cid=231,
                            expires_unix_ms=time.time_ns() // 1_000_000 + 10000)
        approval = dict(registration, communication_expires_unix_ms=registration['expires_unix_ms'],
                        permit_expires_unix_ms=registration['expires_unix_ms'],
                        generation_expires_unix_ms=registration['expires_unix_ms'])
        path = root / 'host-login-authority/channel-approval.json'
        path.write_bytes(channel.canonical_json(approval))
        path.chmod(0o600)
        request = dict(scope, version=1, operation='consume', boot_id='boot1', challenge='b' * 64)
        signer = Mock(wraps=Ed25519PrivateKey.generate())
        with patch('channel.require_live_instance', side_effect=lambda *args: os.pidfd_open(os.getpid())):
            preflight = dict(request, operation='preflight')
            reader, writer = socket.socketpair()
            with reader, writer:
                writer.sendall(channel.canonical_json(preflight) + b'\n')
                channel.serve_query(reader, 231, registration, root, signer, time.monotonic() + 1)
                encoded = channel.read_frame(writer, channel.RESPONSE_LIMIT, time.monotonic() + 1)
                channel.verify_response(encoded, preflight, signer.public_key(), time.time_ns() // 1_000_000)
                assert read_management_snapshot(root, allowed_states=('issued',))['sequence'] == 1
            signer.reset_mock()
            reader, writer = socket.socketpair()
            import write_transition
            replace = write_transition.replace_checkpoint
            def delayed_checkpoint(path, value):
                replace(path, value)
                if delay_commit:
                    time.sleep(0.03)
            with reader, writer, patch('write_transition.replace_checkpoint', delayed_checkpoint):
                writer.sendall(channel.canonical_json(request) + b'\n')
                if not delay_commit:
                    writer.shutdown(socket.SHUT_RDWR)
                try:
                    channel.serve_query(reader, 231, registration, root, signer,
                                        time.monotonic() + (0.02 if delay_commit else 1))
                except (BrokenPipeError, TimeoutError):
                    pass
                else:
                    raise AssertionError('failed response was not observed')
                if delay_commit:
                    writer.settimeout(0.02)
                    try:
                        data = writer.recv(1)
                    except TimeoutError:
                        data = b''
                    assert not data
            if delay_commit:
                signer.sign.assert_not_called()
            assert read_management_snapshot(root)['state'] == 'consumed'
            reader, writer = socket.socketpair()
            with reader, writer:
                writer.sendall(channel.canonical_json(request) + b'\n')
                try:
                    channel.serve_query(reader, 231, registration, root, signer, time.monotonic() + 1)
                except ValueError:
                    pass
                else:
                    raise AssertionError('double consumption accepted')
            assert read_management_snapshot(root)['sequence'] == 2
        print('Lost response preserves consumed state; double consumption refused')


if __name__ == '__main__':
    main()
    main(delay_commit=True)
