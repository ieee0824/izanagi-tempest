import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    'trace_evidence', Path(__file__).resolve().parents[1] / 'image/trace_evidence.py')
TRACE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRACE)


class TraceEvidenceTests(unittest.TestCase):
    def test_matches_open_in_rotated_log_without_publishing_raw_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'events.log.1'
            log.write_text('[2026-11-18 00:00:00.000] INFO pid=42 python3: openat("/tmp/tempest-trace-smoke-probe", 1) → 3\n')
            result = TRACE.trace_probe_evidence([log], 42, '/tmp/tempest-trace-smoke-probe')
            self.assertEqual(result['matched_open_events'], 1)
            self.assertNotIn('arguments', result)

    def test_other_pid_path_prefix_and_exec_argument_are_not_file_open_evidence(self):
        lines = [
            'pid=420 python3: openat("/tmp/tempest-trace-smoke-probe", 1)',
            'pid=42 python3: openat("/tmp/tempest-trace-smoke-probe-other", 1)',
            'pid=42 python3: execve("python3", "/tmp/tempest-trace-smoke-probe")',
        ]
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'events.log'
            log.write_text(''.join('[2026-11-18 00:00:00.000] INFO ' + line + ' → 3\n' for line in lines))
            with self.assertRaisesRegex(RuntimeError, 'no file-open trace'):
                TRACE.trace_probe_evidence([log], 42, '/tmp/tempest-trace-smoke-probe')

    def test_missing_logs_are_not_positive_evidence(self):
        with self.assertRaises(RuntimeError):
            TRACE.trace_probe_evidence([], 42, '/tmp/tempest-trace-smoke-probe')


if __name__ == '__main__':
    unittest.main()
