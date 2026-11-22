"""Operation cap remains fixed while fresh signed revisions renew below it."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools/host_ledger'))
from freshness import FreshnessLatch


class FreshnessTests(unittest.TestCase):
    def setUp(self):
        self.now = 0.0
        self.state = FreshnessLatch(1, 'a'*64, 30, 300, lambda: self.now)

    def test_updates_live_beyond_initial_thirty_seconds_but_never_beyond_operation_cap(self):
        for revision in range(2, 32):
            self.now = (revision-1)*10
            if self.now >= 300:
                self.assertIsNone(self.state.deadline())
                self.assertFalse(self.state.observe(revision, 'b'*64, 330000, 300000, self.now))
                break
            self.assertTrue(self.state.observe(revision, 'b'*64,
                            int((self.now+30)*1000), int(self.now*1000), self.now))
            self.assertEqual(self.state.deadline(), min(self.now+30, 300))

    def test_same_revision_never_extends_even_after_wall_clock_change(self):
        self.now = 20
        self.assertTrue(self.state.observe(1, 'a'*64, 30000, 0, 20))
        self.assertEqual(self.state.deadline(), 30)
        self.now = 30
        self.assertIsNone(self.state.deadline())
        self.assertFalse(self.state.observe(2, 'b'*64, 60000, 30000, 30))

    def test_late_update_without_an_intermediate_poll_cannot_resurrect(self):
        self.now = 31
        self.assertFalse(self.state.observe(2, 'b'*64, 61000, 31000, 31))
        self.assertIsNone(self.state.deadline())

    def test_rollback_or_changed_same_revision_stops_irreversibly(self):
        for revision, digest in ((0, 'a'*64), (1, 'b'*64)):
            self.setUp()
            self.assertFalse(self.state.observe(revision, digest, 30000, 0, 0))
            self.assertFalse(self.state.observe(2, 'c'*64, 30000, 0, 0))

    def test_processing_time_is_charged_from_source_read_start(self):
        self.now = 20
        self.assertTrue(self.state.observe(2, 'b'*64, 30000, 0, 0))
        self.assertEqual(self.state.deadline(), 30)

    def test_control_updates_cannot_outlive_or_restore_signed_state_freshness(self):
        from egress_authority import RunAuthorization, Scope
        scope = dict(target_id='vm', permit_id='a'*32, generation=1)
        state = RunAuthorization(Scope.parse(scope), 'boot', 'ledger', 300,
                                 lambda: self.now, freshness=self.state)
        def receipt():
            return dict(payload=dict(request=dict(scope, boot_id='boot', operation='query'),
                        commit=dict(scope=scope, ledger_id='ledger', sequence=2, state='consumed'),
                        issued_unix_ms=1000, expires_unix_ms=3000))
        for second in range(30):
            self.now = second
            self.assertTrue(state.observe(receipt(), self.now))
        self.assertEqual(state.current().deadline, 30)
        self.now = 30
        self.assertIsNone(state.current())
        self.assertFalse(state.observe(receipt(), self.now))
        self.assertFalse(self.state.observe(2, 'b'*64, 60000, 30000, 30))
