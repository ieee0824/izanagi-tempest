"""No-network checks for signed destination scope and irreversible egress freshness."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools/host_ledger'))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from channel import canonical_json
from egress_authority import POLICY_DOMAIN, RunAuthorization, Scope, parse_signed_policy


class EgressAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.scope = dict(target_id='vm', permit_id='a'*32, generation=1)
        self.registration = dict(self.scope, boot_id='boot1', expires_unix_ms=9000)
        self.approval = dict(self.registration, communication_expires_unix_ms=10000,
                             permit_expires_unix_ms=10000, generation_expires_unix_ms=10000)
        self.route = dict(manifest_sha256='b'*64, approved_ips_revision=1,
                          addresses=['127.0.0.1'], expires_unix_ms=8000)
        self.body = dict(version=1, scope=self.scope, boot_id='boot1', manifest_sha256='b'*64,
                         approved_ips_revision=1, authority='platform.claude.com:443',
                         peer=dict(address='127.0.0.1', port=443), expires_unix_ms=8000)
        self.signer = Ed25519PrivateKey.generate()
        self.key = self.signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.now = 0.0

    def signed(self, body):
        return canonical_json(dict(payload=body, signature=self.signer.sign(POLICY_DOMAIN+canonical_json(body)).hex()))

    def policy(self, encoded):
        return parse_signed_policy(encoded, self.key, self.registration, self.approval, self.route, 1000)

    def receipt(self, operation='query', sequence=2, lifetime=2000):
        return dict(payload=dict(request=dict(self.scope, boot_id='boot1', operation=operation),
                                 commit=dict(scope=self.scope, ledger_id='ledger1', sequence=sequence, state='consumed'),
                                 issued_unix_ms=1000, expires_unix_ms=1000+lifetime))

    def state(self):
        return RunAuthorization(Scope.parse(self.scope), 'boot1', 'ledger1', 10.0, lambda: self.now)

    def test_policy_signature_and_independent_peer_approval(self):
        valid = self.signed(self.body)
        self.assertEqual(self.policy(valid).address, '127.0.0.1')
        altered = json.loads(valid)
        altered['payload']['peer']['address'] = '192.0.2.1'
        with self.assertRaises(ValueError):
            self.policy(canonical_json(altered))
        for field, value in [('peer', dict(address='192.0.2.1', port=443)),
                             ('peer', dict(address='127.0.0.1', port=80)),
                             ('manifest_sha256', 'c'*64), ('approved_ips_revision', 2),
                             ('expires_unix_ms', 8001), ('expires_unix_ms', 1000),
                             ('version', True), ('boot_id', 'old-boot')]:
            with self.subTest(field=field, value=value):
                body = dict(self.body, **{field: value})
                with self.assertRaises(ValueError):
                    self.policy(self.signed(body))

    def test_control_receipt_is_required_and_preflight_does_not_renew(self):
        state = self.state()
        self.assertIsNone(state.current())
        self.assertFalse(state.observe(self.receipt('preflight'), 0.0))
        self.assertIsNone(state.current())
        self.assertTrue(state.observe(self.receipt('consume'), 0.0))
        self.now = 1.5
        self.assertFalse(state.observe(self.receipt('preflight'), 1.5))
        self.now = 2.0
        self.assertIsNone(state.current())

    def test_expiry_and_explicit_stop_never_resurrect(self):
        state = self.state()
        self.assertTrue(state.observe(self.receipt('consume'), 0.0))
        self.now = 2.0
        self.assertFalse(state.observe(self.receipt(), 2.0))
        self.assertIsNone(state.current())
        fresh = self.state()
        self.assertTrue(fresh.observe(self.receipt('consume'), 2.0))
        fresh.stop()
        self.assertFalse(fresh.observe(self.receipt(), 2.0))
        self.assertIsNone(fresh.current())

    def test_request_start_includes_processing_and_absolute_approval_cap(self):
        state = self.state()
        self.now = 1.8
        self.assertTrue(state.observe(self.receipt('consume'), 0.0))
        self.assertEqual(state.current().deadline, 2.0)
        self.now = 1.9
        self.assertTrue(state.observe(self.receipt(), 1.9))
        self.now = 3.8
        self.assertTrue(state.observe(self.receipt(), 3.8))
        self.now = 5.7
        self.assertTrue(state.observe(self.receipt(), 5.7))
        self.now = 7.6
        self.assertTrue(state.observe(self.receipt(), 7.6))
        self.now = 9.5
        self.assertTrue(state.observe(self.receipt(), 9.5))
        self.assertEqual(state.current().deadline, 10.0)
        self.now = 10.0
        self.assertIsNone(state.current())

    def test_wrong_ledger_scope_or_rollback_latches_stop(self):
        for kind in ('ledger', 'scope', 'rollback', 'malformed', 'overlong'):
            with self.subTest(kind=kind):
                state = self.state()
                self.assertTrue(state.observe(self.receipt('consume', sequence=3), 0.0))
                invalid = copy.deepcopy(self.receipt(sequence=3))
                if kind == 'ledger': invalid['payload']['commit']['ledger_id'] = 'other'
                if kind == 'scope': invalid['payload']['request']['target_id'] = 'other'
                if kind == 'rollback': invalid['payload']['commit']['sequence'] = 2
                if kind == 'malformed': invalid = {}
                if kind == 'overlong': invalid['payload']['expires_unix_ms'] = 3001
                self.assertFalse(state.observe(invalid, 0.0))
                self.assertFalse(state.observe(self.receipt(sequence=4), 0.0))
                self.assertIsNone(state.current())


if __name__ == '__main__':
    unittest.main()
