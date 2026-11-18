import ast
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('exec_evidence',
    Path(__file__).resolve().parents[1] / 'image/exec_evidence.py')
E = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(E)


class ExecEvidenceTests(unittest.TestCase):
    def test_marker_across_blocks_and_empty_marker_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stream'
            path.write_bytes(b'abcSECRETxyz')
            self.assertTrue(E.contains_marker(path, ['SECRET'], chunk_bytes=2))
            self.assertFalse(E.contains_marker(path, ['absent'], chunk_bytes=2))
            with self.assertRaises(ValueError):
                E.contains_marker(path, [''])

    def test_success_and_error_outputs_are_private_and_public_summary_is_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = E.ExecEvidence(Path(directory) / 'evidence')
            previous = os.umask(0o077)
            try:
                result = evidence.capture(lambda: subprocess.CompletedProcess([], 1, 'unavailable', 'denied'),
                                          ['PRIVATE-MARKER'], {'operation': 'seed', 'expected_error': True})
            finally:
                os.umask(previous)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(stat.S_IMODE(evidence.directory.stat().st_mode), 0o700)
            self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in evidence.directory.iterdir()))
            summary = evidence.summary(['PRIVATE-MARKER'])
            self.assertTrue(summary['passed'])
            self.assertEqual(summary['operations'], {'seed': 1})
            self.assertEqual(summary['expected_error_reads'], 1)
            self.assertNotIn('PRIVATE-MARKER', json.dumps(summary))
            self.assertNotIn('denied', json.dumps(summary))

    def test_stderr_leak_is_retained_and_rejected_before_return(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = E.ExecEvidence(Path(directory) / 'evidence')
            with self.assertRaises(E.MarkerLeak) as raised:
                evidence.capture(lambda: subprocess.CompletedProcess([], 0, 'ok', 'HIDDEN-VALUE'), ['HIDDEN-VALUE'])
            self.assertNotIn('HIDDEN-VALUE', str(raised.exception))
            self.assertEqual((evidence.directory / 'exec-000001.stderr').read_text(), 'HIDDEN-VALUE')
            summary = evidence.summary(['HIDDEN-VALUE'])
            self.assertFalse(summary['passed'])
            self.assertEqual(summary['leaked_streams'], ['exec-000001.stderr'])

    def test_timeout_partial_bytes_are_retained_then_original_timeout_propagates(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = E.ExecEvidence(Path(directory) / 'evidence')
            error = subprocess.TimeoutExpired(['dummy'], 1, output=b'partial\xff', stderr=b'diagnostic')
            def timeout():
                raise error
            with self.assertRaises(subprocess.TimeoutExpired) as raised:
                evidence.capture(timeout, ['absent'])
            self.assertIs(raised.exception, error)
            self.assertEqual((evidence.directory / 'exec-000001.stdout').read_bytes(), b'partial\xff')
            self.assertEqual(evidence.summary(['absent'])['timed_out'], 1)

    def test_final_scan_checks_markers_discovered_after_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = E.ExecEvidence(Path(directory) / 'evidence')
            evidence.capture(lambda: subprocess.CompletedProcess([], 0, 'LATER-MARKER', ''), ['other'])
            self.assertFalse(evidence.summary(['other', 'LATER-MARKER'])['passed'])

    def test_existing_or_symlink_stream_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = E.ExecEvidence(Path(directory) / 'evidence')
            target = Path(directory) / 'original'
            target.write_text('keep')
            (evidence.directory / 'exec-000001.stdout').symlink_to(target)
            with self.assertRaises(FileExistsError):
                evidence.capture(lambda: subprocess.CompletedProcess([], 0, 'replace', ''), [])
            self.assertEqual(target.read_text(), 'keep')
            self.assertFalse(evidence.summary([])['passed'])


class SmokeWiringTests(unittest.TestCase):
    def test_actual_execute_wrapper_scans_before_return_and_records_safe_failure(self):
        source = Path(__file__).resolve().parents[1] / 'integration/image_smoke.py'
        tree = ast.parse(source.read_text())
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        execute = next(node for node in main.body if isinstance(node, ast.FunctionDef) and node.name == 'execute')
        with tempfile.TemporaryDirectory() as directory:
            evidence = E.ExecEvidence(Path(directory) / 'evidence')
            report = {'checks': {}}
            saved = []
            class Process:
                TimeoutExpired = subprocess.TimeoutExpired
                @staticmethod
                def run(argv, **kwargs):
                    self.assertEqual(argv, ['pinned', 'exec', '--', 'doas'])
                    self.assertEqual(kwargs['errors'], 'surrogateescape')
                    return subprocess.CompletedProcess(argv, 1, '', 'PRIVATE-DUMMY')
            namespace = {'subprocess': Process, 'base': ['pinned'], 'box': type('Box', (), {'workspace': directory})(),
                         'environment': {}, 'exec_evidence': evidence, 'secret_markers': ['PRIVATE-DUMMY'],
                         'MarkerLeak': E.MarkerLeak, 'report': report, 'save': lambda: saved.append(True)}
            exec(compile(ast.Module(body=[execute], type_ignores=[]), str(source), 'exec'), namespace)
            with self.assertRaises(E.MarkerLeak):
                namespace['execute']('doas', evidence_context={'operation': 'probe', 'expected_error': True})
            self.assertTrue(saved)
            self.assertFalse(report['checks']['exec_private_markers']['passed'])
            self.assertNotIn('PRIVATE-DUMMY', json.dumps(report))
