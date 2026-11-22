"""Host-original rechecks are read-only, scope-bound, and irreversibly fail closed."""
from dataclasses import replace
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools/host_ledger'))
from egress_authority import EgressPolicy, Scope
from egress_daemon import HostOriginals
from egress_generation import ApprovedGeneration


class OriginalsTests(unittest.TestCase):
    def setUp(self):
        self.scope = dict(target_id='vm', permit_id='a'*32, generation=1)
        self.registration = dict(self.scope, boot_id='boot', cid=231)
        self.policy = EgressPolicy(Scope.parse(self.scope), 'boot', 'b'*64, 1,
                                  'platform.claude.com:443', '127.0.0.1', 443, 9000)
        self.generation = ApprovedGeneration('b'*64, 1, ('127.0.0.1',), 9000, 2)
        self.state = Mock()
        self.state.current.return_value = object()
        self.commit = dict(scope=self.scope, ledger_id='ledger', sequence=2, state='consumed')
        self.originals = HostOriginals(Path('/unused'), self.registration, self.policy,
                                      self.generation, 'ledger', 2, b'k'*32, self.state)

    def check(self, generation=None, commit=None, policy=None, registration=None):
        # Real QMP/pidfd behavior is exercised in the existing channel/VM suite.
        with patch('egress_daemon.read_json', side_effect=lambda path:
                    (registration or self.registration) if path.name == 'channel-registration.json' else {}), \
                patch('egress_daemon.read_private', return_value=b'k'*32), \
                patch('egress_daemon.read_generation', return_value=generation or self.generation), \
                patch('egress_daemon.parse_signed_policy', return_value=policy or self.policy), \
                patch('egress_daemon.read_management_snapshot', return_value=commit or self.commit), \
                patch('egress_daemon.require_live_instance', return_value=77), \
                patch('egress_daemon.os.close') as close:
            self.originals.check(time.monotonic()+1)
            close.assert_called_once_with(77)

    def test_rechecks_can_advance_commits_but_never_renew_control(self):
        self.check(generation=replace(self.generation, revocation_revision=3),
                   commit=dict(self.commit, sequence=3))
        self.assertEqual(self.originals.sequence, 3)
        self.assertEqual(self.originals.revocation_revision, 3)
        self.state.observe.assert_not_called()
        self.state.stop.assert_not_called()
        with self.assertRaises(ValueError):
            self.check()
        self.state.stop.assert_called()

    def test_changed_generation_ledger_peer_or_instance_stops(self):
        cases = [dict(generation=replace(self.generation, manifest_sha256='c'*64)),
                 dict(generation=replace(self.generation, addresses=('127.0.0.2',))),
                 dict(generation=replace(self.generation, revocation_revision=1)),
                 dict(commit=dict(self.commit, ledger_id='other')),
                 dict(commit=dict(self.commit, state='issued')),
                 dict(policy=replace(self.policy, address='127.0.0.2')),
                 dict(registration=dict(self.registration, boot_id='new'))]
        for case in cases:
            self.state.reset_mock()
            with self.subTest(case=case), self.assertRaises(ValueError):
                self.check(**case)
            self.state.stop.assert_called()
            self.state.observe.assert_not_called()

    def test_expired_check_deadline_stops_without_reading(self):
        with patch('egress_daemon.read_json') as read, self.assertRaises(TimeoutError):
            self.originals.check(time.monotonic()-1)
        read.assert_not_called()
        self.state.stop.assert_called()
