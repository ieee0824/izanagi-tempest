"""Regressions for bounded management framing and boot identity checks."""

from pathlib import Path
import socket
import os
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import json
import sys
import time
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools/host_ledger'))
import channel


class ChannelTests(unittest.TestCase):
    def setUp(self):
        self.registration = dict(target_id='vm', boot_id='boot1', cid=231,
                                 permit_id='a' * 32, generation=1)
        self.request = {key: self.registration[key] for key in
                        ('target_id', 'boot_id', 'permit_id', 'generation')}
        self.request.update(version=1, operation='query', challenge='b' * 64)

    def test_actual_peer_and_all_registered_identities_must_match(self):
        payload = channel.canonical_json(self.request)
        self.assertEqual(channel.validate_request(payload, self.registration, 231), self.request)
        with self.assertRaises(ValueError):
            channel.validate_request(payload, self.registration, 232)
        for field, value in [('target_id', 'other'), ('boot_id', 'old'),
                             ('generation', True), ('permit_id', 'c' * 32)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                channel.validate_request(channel.canonical_json(dict(self.request, **{field: value})),
                                         self.registration, 231)

    def test_registration_cannot_outlive_any_approval(self):
        registration = dict(self.registration, expires_unix_ms=2000)
        approval = dict(self.registration, communication_expires_unix_ms=2000,
                        permit_expires_unix_ms=3000, generation_expires_unix_ms=4000)
        channel.validate_registration_deadline(registration, approval)
        for name in ('communication_expires_unix_ms', 'permit_expires_unix_ms',
                     'generation_expires_unix_ms'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                channel.validate_registration_deadline(registration, dict(approval, **{name: 1999}))

    def test_duplicate_fields_are_rejected(self):
        payload = channel.canonical_json(self.request)
        duplicate = payload[:-1] + b',"operation":"consume"}'
        with self.assertRaises(ValueError):
            channel.validate_request(duplicate, self.registration, 231)

    def test_signed_query_binds_request_and_short_expiry(self):
        reader, writer = socket.socketpair()
        signer = Ed25519PrivateKey.generate()
        commit = {"scope": {key: self.registration[key] for key in
                             ("target_id", "permit_id", "generation")},
                  "ledger_id": "ledger", "sequence": 2, "state": "consumed"}
        registration = dict(self.registration, expires_unix_ms=time.time_ns() // 1_000_000 + 250)
        with reader, writer, patch('channel.require_live_instance',
                                   side_effect=lambda *args: os.pidfd_open(os.getpid())), \
                patch('read_snapshot.read_management_snapshot', return_value=commit), \
                patch('read_snapshot.read_json', return_value=dict(registration,
                    communication_expires_unix_ms=registration['expires_unix_ms'],
                    permit_expires_unix_ms=registration['expires_unix_ms'],
                    generation_expires_unix_ms=registration['expires_unix_ms'])):
            writer.sendall(channel.canonical_json(self.request) + b'\n')
            channel.serve_query(reader, 231, registration, Path('/unused'), signer,
                                time.monotonic() + 1)
            reply = json.loads(channel.read_frame(writer, channel.RESPONSE_LIMIT,
                                                  time.monotonic() + 1))
        payload = reply['payload']
        signer.public_key().verify(bytes.fromhex(reply['signature']),
                                   channel.RECEIPT_DOMAIN + channel.canonical_json(payload))
        encoded = channel.canonical_json(reply)
        channel.verify_response(encoded, self.request, signer.public_key(), payload['issued_unix_ms'])
        with self.assertRaises(ValueError):
            channel.verify_response(encoded, self.request, signer.public_key(), payload['expires_unix_ms'])
        other = dict(self.request, challenge='c' * 64)
        with self.assertRaises(ValueError):
            channel.verify_response(encoded, other, signer.public_key(), payload['issued_unix_ms'])
        client, server = socket.socketpair()
        with client, server:
            server.sendall(encoded + b'\n')
            received = channel.exchange(client, self.request, signer.public_key(), time.monotonic() + 1)
            self.assertEqual(received, payload)
        client, server = socket.socketpair()
        with client, server:
            server.sendall(encoded + b'\n')
            with self.assertRaises(TimeoutError):
                channel.exchange(client, self.request, signer.public_key(), time.monotonic() - 1)
        self.assertEqual(payload['request'], self.request)
        self.assertEqual(payload['commit'], commit)
        self.assertLessEqual(payload['expires_unix_ms'] - payload['issued_unix_ms'], 2000)
        self.assertLessEqual(payload['expires_unix_ms'], registration['expires_unix_ms'])

    def test_qmp_peer_and_actual_device_cid_are_checked(self):
        stat = Path(f'/proc/{os.getpid()}/stat').read_text()
        ticks = int(stat[stat.rindex(')') + 2:].split()[19])
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'qmp.sock')
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            with listener:
                listener.bind(path)
                listener.listen(1)
                registration = dict(self.registration, qemu_pid=os.getpid(),
                                    qemu_start_ticks=ticks, qmp_socket=path,
                                    qemu_device_id='ledger')
                def qmp():
                    peer, _ = listener.accept()
                    with peer:
                        peer.sendall(b'{"QMP":{}}\n')
                        for response in ({}, {"status": "running"}, 232):
                            channel.read_frame(peer, 1024, time.monotonic() + 1)
                            channel.write_frame(peer, channel.canonical_json({"return": response}),
                                                4096, time.monotonic() + 1)
                server = threading.Thread(target=qmp)
                server.start()
                try:
                    with self.assertRaisesRegex(ValueError, 'CID assignment mismatch'):
                        channel.require_live_instance(registration, time.monotonic() + 1)
                finally:
                    server.join(timeout=2)
                self.assertFalse(server.is_alive())
                registration['qemu_start_ticks'] += 1
                with self.assertRaisesRegex(ValueError, 'lifetime mismatch'):
                    channel.require_live_instance(registration, time.monotonic() + 1)

    def test_frame_limit_and_disconnect(self):
        reader, writer = socket.socketpair()
        with reader, writer:
            writer.sendall(b'x' * (channel.REQUEST_LIMIT + 1) + b'\n')
            with self.assertRaises(ValueError):
                channel.read_frame(reader, channel.REQUEST_LIMIT, time.monotonic() + 1)
        reader, writer = socket.socketpair()
        with reader:
            writer.close()
            with self.assertRaises(ConnectionError):
                channel.read_frame(reader, channel.REQUEST_LIMIT, time.monotonic() + 1)

    def test_partial_frame_cannot_extend_absolute_deadline(self):
        reader, writer = socket.socketpair()
        with reader, writer:
            writer.sendall(b'partial')
            deadline = time.monotonic() + 0.02
            with self.assertRaises(TimeoutError):
                channel.read_frame(reader, channel.REQUEST_LIMIT, deadline)
            with self.assertRaises(TimeoutError):
                channel.write_frame(writer, b'retry', channel.RESPONSE_LIMIT, deadline)


if __name__ == '__main__':
    unittest.main()
