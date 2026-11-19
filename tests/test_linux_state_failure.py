import copy
from pathlib import Path
import sys
import os
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'integration'))
from linux_state_home_smoke import valid_failure
from linux_state_trace import StateTrace


class FailureProjectionTests(unittest.TestCase):
    def test_close_releases_pinned_progress_and_process_descriptors(self):
        trace = StateTrace.__new__(StateTrace)
        trace.pidfd = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
        trace.progress_fd = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
        descriptors = (trace.pidfd, trace.progress_fd)
        trace.close()
        self.assertIsNone(trace.progress_fd)
        for fd in descriptors:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_architecture_is_rejected_before_process_or_register_access(self):
        with patch('linux_state_trace.platform.machine', return_value='aarch64'):
            with self.assertRaisesRegex(ValueError, '^unsupported_trace_architecture$'):
                StateTrace(None)

    def test_fixed_failure_projection_and_invalid_boundaries(self):
        value = dict(status='failed', stage='capture', exception='ValueError', captures=1,
                     captures_by_run={'state_run1':1,'state_run2':0}, host_reads=9,
                     stop_budget_exceeded=False, parent_terminal=True,
                     root_present=False, run_present=False, stderr_bytes=0,
                     audit_basename='tempest-state-home-failure-abcdefgh.json')
        self.assertTrue(valid_failure(value))
        for key, invalid in [('stage','arbitrary'), ('exception','raw error'),
                             ('captures',3), ('host_reads',18), ('stderr_bytes',65538),
                             ('audit_basename','/tmp/arbitrary'), ('parent_terminal',1)]:
            changed = copy.deepcopy(value)
            changed[key] = invalid
            self.assertFalse(valid_failure(changed))
        changed = copy.deepcopy(value)
        changed['captures_by_run']['state_run1'] = 2
        self.assertFalse(valid_failure(changed))
        changed = dict(value, raw_stderr='not allowed')
        self.assertFalse(valid_failure(changed))
