"""Host egress accepts only an independently approved existing login publication."""
import copy
import os
import tempfile
from hashlib import sha256
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools/host_ledger'))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from channel import canonical_json
from egress_generation import (AUTHORITY, CLI_SHA256, HANDOFF_DOMAIN, REVOCATION_DOMAIN,
                               verify_inputs, read_generation)


def digest(data):
    return sha256(data).hexdigest()


class GenerationTests(unittest.TestCase):
    def setUp(self):
        self.handoff_key = Ed25519PrivateKey.generate()
        self.revocation_key = Ed25519PrivateKey.generate()
        self.registration = dict(target_id='vm', permit_id='a'*32, generation=1)
        self.policy = dict(version=2, authority=AUTHORITY,
                           approved_ips=dict(revision=1, addresses=['127.0.0.1']),
                           permit=dict(target_hostname='guest', authority=AUTHORITY,
                                       approved_ips_revision=1, expires_unix_seconds=150))
        self.handoff = dict(self.registration, approval_pair_sha256='b'*64,
                            executable_sha256=CLI_SHA256, arguments=['auth', 'login'],
                            authority=AUTHORITY, approved_ips_revision=1, expires_unix_seconds=140)
        del self.handoff['generation']
        self.revocation = dict(self.registration, revocation_revision=2,
                               issued_unix_seconds=100, expires_unix_seconds=125, revoked=False)
        self.revocation['revision'] = self.revocation.pop('generation')
        self.target = dict(target_id='vm', target_hostname='guest')

    def public(self, key):
        return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def fixture(self):
        handoff = HANDOFF_DOMAIN + canonical_json(self.handoff)
        key = self.public(self.handoff_key)
        inputs = {'claude-manual-login.json': canonical_json(self.policy),
                  'claude-login-diagnostic-handoff': handoff,
                  'claude-login-diagnostic-signature': self.handoff_key.sign(handoff),
                  'claude-login-diagnostic-trust-key': key,
                  'claude-login-diagnostic-target-registration': canonical_json(self.target)}
        manifest = canonical_json({name: digest(data) for name, data in inputs.items()})
        approved = canonical_json(dict(revision=1, manifest_sha256=digest(manifest)))
        payload = REVOCATION_DOMAIN + canonical_json(dict(self.revocation, manifest_sha256=digest(manifest)))
        return [manifest, approved, inputs, key, self.registration, payload,
                self.revocation_key.sign(payload), self.public(self.revocation_key), 2,
                canonical_json(dict(revision=2, state_sha256=digest(payload))), 100000]

    def test_existing_formats_yield_only_manifest_bound_route_and_earliest_expiry(self):
        result = verify_inputs(*self.fixture())
        self.assertEqual(result.addresses, ('127.0.0.1',))
        self.assertEqual(result.approved_ips_revision, 1)
        self.assertEqual(result.expires_unix_ms, 125000)
        self.assertEqual(result.revocation_revision, 2)
        self.assertEqual(result.route()['manifest_sha256'], result.manifest_sha256)

    def test_hash_and_independent_trust_cannot_be_replaced_by_published_data(self):
        for index, value in [(0, b'{}'), (1, b'{"revision":2,"manifest_sha256":"bad"}'),
                             (3, self.public(self.revocation_key)), (6, b'x'*64), (8, 3),
                             (9, b'{"revision":1,"state_sha256":"bad"}'), (10, 125000)]:
            args = self.fixture(); args[index] = value
            with self.subTest(index=index), self.assertRaises(ValueError):
                verify_inputs(*args)
        args = self.fixture(); args[2] = dict(args[2]); args[2]['claude-manual-login.json'] += b' '
        with self.assertRaises(ValueError):
            verify_inputs(*args)

    def test_correct_signatures_do_not_override_scope_or_policy_constraints(self):
        cases = [('handoff', 'target_id', 'other'), ('handoff', 'permit_id', 'c'*32),
                 ('handoff', 'arguments', ['--version']), ('handoff', 'executable_sha256', 'd'*64),
                 ('handoff', 'approved_ips_revision', True), ('handoff', 'expires_unix_seconds', 100),
                 ('policy', 'version', 1), ('policy', 'authority', 'other:443'),
                 ('target', 'target_hostname', 'other'), ('revocation', 'revoked', True),
                 ('revocation', 'revision', 2), ('revocation', 'expires_unix_seconds', 131),
                 ('revocation', 'issued_unix_seconds', 101), ('revocation', 'revocation_revision', True)]
        for object_name, field, value in cases:
            source = getattr(self, object_name)
            original = copy.deepcopy(source)
            try:
                source[field] = value
                with self.subTest(object_name=object_name, field=field), self.assertRaises(ValueError):
                    verify_inputs(*self.fixture())
            finally:
                setattr(self, object_name, original)


    @unittest.skipUnless(os.geteuid() == 0, 'root-owned source metadata check')
    def test_root_original_reader_rejects_pending_and_untrusted_metadata(self):
        args = self.fixture()
        with tempfile.TemporaryDirectory(prefix='tempest-egress-source-', dir='/run') as directory:
            root = Path(directory)
            authority = root / 'claude-login-authority'
            publication = root / 'claude-login-publication'
            generation = publication / '1'
            for path in (authority, publication, generation):
                path.mkdir(mode=0o700)
            def write(path, data):
                path.write_bytes(data)
                path.chmod(0o600)
            write(publication / 'lock', b'')
            write(publication / 'current', b'1')
            write(authority / 'minimum', b'1')
            write(authority / 'trust-key', args[3])
            write(authority / 'approved-generation', args[1])
            write(authority / 'revocation-state', args[5])
            write(authority / 'revocation-signature', args[6])
            write(authority / 'revocation-key', args[7])
            write(authority / 'revocation-minimum', b'2')
            write(authority / 'revocation-committed', args[9])
            write(generation / 'manifest', args[0])
            for name, data in args[2].items():
                write(generation / name, data)
            self.assertEqual(read_generation(root, self.registration, 100000), verify_inputs(*args))
            for marker in (publication / 'pending', authority / 'revocation-pending'):
                write(marker, b'')
                with self.assertRaises(ValueError):
                    read_generation(root, self.registration, 100000)
                marker.unlink()
            key = authority / 'trust-key'
            key.chmod(0o644)
            with self.assertRaises(PermissionError):
                read_generation(root, self.registration, 100000)
            key.chmod(0o600)
            key.rename(authority / 'original-key')
            key.symlink_to('original-key')
            with self.assertRaises(PermissionError):
                read_generation(root, self.registration, 100000)
