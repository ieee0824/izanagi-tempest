"""Dummy loopback only: challenge-bound ready handshake precedes opaque data."""
import copy
from dataclasses import replace
from pathlib import Path
import socket
import sys
import threading
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools/host_ledger'))
from channel import canonical_json, read_frame
from egress_authority import EgressPolicy, RunAuthorization, Scope, RECEIPT_DOMAIN
from egress_channel import validate_request, verify_ready, serve_connection


class EgressChannelTests(unittest.TestCase):
    def setUp(self):
        self.scope = dict(target_id='vm', permit_id='a'*32, generation=1)
        self.policy = EgressPolicy(Scope.parse(self.scope), 'boot', 'b'*64, 1,
                                  'platform.claude.com:443', '127.0.0.1', 443,
                                  time.time_ns() // 1_000_000 + 10000)
        self.registration = dict(self.scope, boot_id='boot', cid=231)
        self.request = dict(version=1, scope=self.scope, boot_id='boot',
                            manifest_sha256='b'*64, approved_ips_revision=1,
                            authority=self.policy.authority, challenge='c'*64)
        self.signer = Ed25519PrivateKey.generate()
        self.key = self.signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def signed(self, body):
        return canonical_json(dict(payload=body, signature=self.signer.sign(RECEIPT_DOMAIN+canonical_json(body)).hex()))

    def body(self):
        return dict(request=copy.deepcopy(self.request), peer=dict(address='127.0.0.1', port=443),
                    sequence=2, issued_unix_ms=10000, expires_unix_ms=12000)

    def test_actual_cid_and_every_request_binding(self):
        self.assertEqual(validate_request(canonical_json(self.request), 231, self.registration, self.policy), self.request)
        for name, value in [('version', True), ('scope', dict(self.scope, generation=2)), ('boot_id', 'old'),
                            ('manifest_sha256', 'd'*64), ('approved_ips_revision', True),
                            ('authority', 'other:443'), ('challenge', 'bad')]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_request(canonical_json(dict(self.request, **{name: value})), 231, self.registration, self.policy)
        with self.assertRaises(ValueError):
            validate_request(canonical_json(self.request), 232, self.registration, self.policy)

    def test_receipt_signature_challenge_peer_sequence_and_conservative_expiry(self):
        body = self.body()
        encoded = self.signed(body)
        self.assertEqual(verify_ready(encoded, self.request, self.policy, self.key, 2, 10, 11.9), body)
        for now in (12, float('nan')):
            with self.assertRaises(ValueError):
                verify_ready(encoded, self.request, self.policy, self.key, 2, 10, now)
        bad = []
        item = self.body(); item['request']['challenge'] = 'd'*64; bad.append(item)
        item = self.body(); item['peer']['address'] = '127.0.0.2'; bad.append(item)
        item = self.body(); item['sequence'] = 1; bad.append(item)
        item = self.body(); item['expires_unix_ms'] = 12001; bad.append(item)
        for item in bad:
            with self.subTest(item=item), self.assertRaises(ValueError):
                verify_ready(self.signed(item), self.request, self.policy, self.key, 2, 10, 10.1)
        changed = encoded.replace(b'127.0.0.1', b'127.0.0.2')
        with self.assertRaises(ValueError):
            verify_ready(changed, self.request, self.policy, self.key, 2, 10, 10.1)

    def state(self):
        state = RunAuthorization(self.policy.scope, 'boot', 'ledger', time.monotonic()+10)
        state.observe(dict(payload=dict(request=dict(self.scope, operation='query', boot_id='boot'),
                     commit=dict(scope=self.scope, state='consumed', sequence=2, ledger_id='ledger'),
                     issued_unix_ms=1, expires_unix_ms=2001)), time.monotonic())
        return state

    def test_real_handshake_then_data_and_revoke(self):
        state = self.state()
        caller, host = socket.socketpair()
        caller.settimeout(1)
        failures = []
        validations = []
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(1)
            policy = replace(self.policy, port=listener.getsockname()[1])
            def handle():
                try:
                    serve_connection(host, 231, self.registration, policy, state, self.signer,
                                     time.monotonic()+1, time.monotonic()+10,
                                     lambda deadline: validations.append(deadline))
                except TimeoutError:
                    pass
                except BaseException as error:
                    failures.append(error)
            worker = threading.Thread(target=handle)
            worker.start()
            try:
                started = time.monotonic()
                caller.sendall(canonical_json(self.request)+b'\n')
                peer, _ = listener.accept()
                with peer:
                    peer.settimeout(1)
                    ready = read_frame(caller, 4096, time.monotonic()+1)
                    verify_ready(ready, self.request, policy, self.key, 2, started, time.monotonic())
                    caller.sendall(b'\x00opaque TLS fixture')
                    self.assertEqual(peer.recv(100), b'\x00opaque TLS fixture')
                    peer.sendall(b'answer')
                    self.assertEqual(caller.recv(100), b'answer')
                    state.stop()
                    self.assertEqual(caller.recv(1), b'')
                    self.assertEqual(peer.recv(1), b'')
            finally:
                state.stop(); caller.close(); worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(failures, [])
            self.assertEqual(len(validations), 2)

    def test_rejected_request_cannot_dial(self):
        caller, host = socket.socketpair()
        with caller, patch('egress_channel.dial_peer') as dial:
            caller.sendall(canonical_json(dict(self.request, authority='other:443'))+b'\n')
            with self.assertRaises(ValueError):
                serve_connection(host, 231, self.registration, self.policy, self.state(), self.signer,
                                 time.monotonic()+1, time.monotonic()+10, lambda _: None)
            dial.assert_not_called()
