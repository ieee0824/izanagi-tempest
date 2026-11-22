"""Signed refresh cannot change scope or operation cap, and failed switches quarantine."""
import fcntl
from dataclasses import replace
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools/host_ledger'))
import test_egress_generation as generation_fixture
from channel import canonical_json
from egress_generation import REVOCATION_DOMAIN, read_generation, verify_inputs
import refresh_revocation as refresh


class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.source = generation_fixture.GenerationTests()
        self.source.setUp()
        self.args = self.source.fixture()
        self.old = verify_inputs(*self.args)
        self.state = dict(self.source.revocation, manifest_sha256=self.old.manifest_sha256,
                          revocation_revision=3, issued_unix_seconds=110, expires_unix_seconds=140)

    def signed(self, state):
        payload = REVOCATION_DOMAIN + canonical_json(state)
        return refresh.Refresh(payload, self.source.revocation_key.sign(payload))

    def test_valid_signature_cannot_expand_operation_or_replace_scope(self):
        registration = self.source.registration
        key = self.args[7]
        self.assertEqual(refresh.validate_refresh(self.signed(self.state), key, registration, self.old, 110000), self.state)
        for name, value in [('revision', 2), ('manifest_sha256', 'c'*64), ('target_id', 'other'),
                            ('permit_id', 'd'*32), ('revoked', True), ('revocation_revision', 2),
                            ('issued_unix_seconds', 111), ('expires_unix_seconds', 141),
                            ('expires_unix_seconds', 110)]:
            invalid = dict(self.state, **{name: value})
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                refresh.validate_refresh(self.signed(invalid), key, registration, self.old, 110000)

    def driver(self, hard=40, delivery_error=None, delay=0):
        now = [0.0]
        current = [self.old]
        class Stop:
            def is_set(self): return False
            def wait(self, seconds): now[0] += seconds; return False
        def publish(*_args):
            source = current[0]
            current[0] = replace(source, revocation_revision=source.revocation_revision+1,
                revocation_state_sha256=f"{source.revocation_revision+1:064x}",
                revocation_expires_unix_ms=min(int((now[0]+130)*1000), source.operation_expires_unix_ms))
        def deliver(*_args):
            now[0] += delay
            if delivery_error: raise delivery_error
        deliver_mock = Mock(side_effect=deliver)
        with patch.object(refresh, 'read_generation', side_effect=lambda *_: current[0]), \
                patch.object(refresh, 'sign_refresh', return_value=self.signed(self.state)), \
                patch.object(refresh, 'publish', side_effect=publish), \
                patch.object(refresh, 'mark_uncertain') as uncertain, \
                patch.object(refresh.time, 'time_ns', side_effect=lambda: int((100+now[0])*1_000_000_000)):
            caught = None
            try:
                refresh.run_updater(Path('/unused'), self.source.registration, None,
                    deliver_mock, Stop(), hard, clock=lambda: now[0])
            except (OSError,ValueError) as error:
                caught = error
        return now[0], deliver_mock, uncertain, caught

    def test_updater_stops_at_immutable_operation_cap(self):
        for cap, expected_calls in ((40,4),(15,2)):
            now, delivered, uncertain, error = self.driver(cap)
            self.assertIsNone(error)
            self.assertEqual(now, cap)
            self.assertEqual(delivered.call_count, expected_calls)
            self.assertTrue(all(call.args[1] <= cap for call in delivered.call_args_list))
            uncertain.assert_not_called()

    def test_delivery_failure_or_deadline_overrun_quarantines_source(self):
        for kwargs in (dict(delivery_error=OSError('SSH failed')), dict(delay=11)):
            _, delivered, uncertain, error = self.driver(**kwargs)
            self.assertIsNotNone(error)
            self.assertEqual(delivered.call_count,1)
            uncertain.assert_called_once()

    def write_source(self, root):
        authority = root / 'claude-login-authority'
        publication = root / 'claude-login-publication'
        generation = publication / '1'
        for path in (authority, publication, generation): path.mkdir(mode=0o700)
        def write(path, data):
            path.write_bytes(data); path.chmod(0o600)
        files = {'lock': b'', 'current': b'1'}
        for name, data in files.items(): write(publication / name, data)
        files = {'minimum': b'1', 'trust-key': self.args[3], 'approved-generation': self.args[1],
                 'revocation-state': self.args[5], 'revocation-signature': self.args[6],
                 'revocation-key': self.args[7], 'revocation-minimum': b'2', 'revocation-committed': self.args[9]}
        for name, data in files.items(): write(authority / name, data)
        write(generation / 'manifest', self.args[0])
        for name, data in self.args[2].items(): write(generation / name, data)

    @unittest.skipUnless(os.geteuid() == 0, 'root-owned source transaction')
    def test_atomic_source_refresh_and_busy_reader_preserve_old_freshness(self):
        with tempfile.TemporaryDirectory(dir='/run', prefix='tempest-refresh-') as directory:
            root = Path(directory); self.write_source(root)
            lock = root / 'claude-login-publication/lock'
            with lock.open('rb') as held:
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertIsNone(read_generation(root, self.source.registration, 110000, defer_busy=True))
                with self.assertRaises(BlockingIOError):
                    read_generation(root, self.source.registration, 110000)
                marker = root / 'claude-login-authority/revocation-pending'
                marker.touch(mode=0o600)
                with self.assertRaises(ValueError):
                    read_generation(root, self.source.registration, 110000, defer_busy=True)
                marker.unlink()
            signed = refresh.sign_refresh(root, self.source.registration, self.source.revocation_key, now_unix_ms=110000)
            self.assertEqual(refresh.publish(root, self.source.registration, signed, now_unix_ms=110000), 3)
            result = read_generation(root, self.source.registration, 110000)
            self.assertEqual(result.revocation_revision, 3)
            self.assertEqual(result.revocation_expires_unix_ms, 140000)
            self.assertEqual(result.operation_expires_unix_ms, self.old.operation_expires_unix_ms)

    @unittest.skipUnless(os.geteuid() == 0, 'root-owned source transaction')
    def test_partial_commit_failure_leaves_uncertainty_marker(self):
        with tempfile.TemporaryDirectory(dir='/run', prefix='tempest-refresh-') as directory:
            root = Path(directory); self.write_source(root)
            original = refresh.os.replace
            count = 0
            def replace(source, destination):
                nonlocal count
                count += 1
                if count == 2: raise OSError('injected signature switch failure')
                return original(source, destination)
            with patch.object(refresh.os, 'replace', side_effect=replace), self.assertRaises(OSError):
                refresh.publish(root, self.source.registration, self.signed(self.state), now_unix_ms=110000)
            self.assertTrue((root / 'claude-login-authority/revocation-pending').is_file())
            with self.assertRaises(ValueError):
                read_generation(root, self.source.registration, 110000)

    @unittest.skipUnless(os.geteuid() == 0, 'root-owned source transaction')
    def test_expired_source_cannot_be_revived_by_a_new_signed_revision(self):
        with tempfile.TemporaryDirectory(dir='/run', prefix='tempest-refresh-') as directory:
            root = Path(directory); self.write_source(root)
            before = (root / 'claude-login-authority/revocation-state').read_bytes()
            with self.assertRaises(ValueError):
                refresh.publish(root, self.source.registration, self.signed(self.state), now_unix_ms=125000)
            self.assertEqual((root / 'claude-login-authority/revocation-state').read_bytes(), before)
