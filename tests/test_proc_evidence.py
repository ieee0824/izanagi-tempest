import copy
import errno
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('proc_evidence',
    Path(__file__).resolve().parents[1] / 'image/proc_evidence.py')
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


def process(root, pid, command, environment):
    path = root / str(pid)
    path.mkdir()
    (path / 'cmdline').write_bytes(command)
    (path / 'environ').write_bytes(environment)
    (path / 'fd').mkdir()
    (path / 'stat').write_text(str(pid) + ' (process name) ' + ' '.join(['S', '1'] + ['0'] * 17 + ['123']))


class ProcEvidenceTests(unittest.TestCase):
    def fixture(self, root):
        process(root, 10, P.CONTROL_VALUE.encode() + b'\0',
                (P.CONTROL_KEY + '=' + P.CONTROL_VALUE).encode() + b'\0')
        process(root, 20, b'parent secret-looking-value\0', b'PUBLIC=1\0')
        value = P.snapshot(root, own_pid=10)
        value['actor_uid'] = 1000
        return value

    def test_positive_controls_and_redacted_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            value = self.fixture(Path(directory))
            summary = P.summarize(value)
            self.assertTrue(summary['passed'])
            self.assertEqual(summary['positive_controls'], {'cmdline': True, 'environ': True, 'fd_list': True})
            self.assertNotIn('secret-looking-value', json.dumps(summary))
            self.assertEqual(summary['stable_identities'], 2)

    def test_denied_vanished_and_unknown_reads_are_distinct(self):
        self.assertEqual(P.failure(PermissionError(errno.EACCES, 'x'))['status'], 'denied')
        self.assertEqual(P.failure(FileNotFoundError(errno.ENOENT, 'x'))['status'], 'vanished')
        self.assertEqual(P.failure(OSError(errno.EIO, 'x'))['status'], 'error')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            real_open = P.os.open
            def denied(path, *args):
                if path == root / '20/environ':
                    raise PermissionError(errno.EACCES, 'x')
                return real_open(path, *args)
            with patch.object(P.os, 'open', side_effect=denied):
                value = P.snapshot(root, own_pid=10)
            value['actor_uid'] = 1000
            self.assertTrue(P.summarize(value)['passed'])
            self.assertEqual(P.summarize(value)['environ_status'], {'read': 1, 'denied': 1})

    def test_truncation_missing_control_and_privileged_actor_do_not_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            value = self.fixture(Path(directory))
            for change in ('uid', 'control', 'pid_limit', 'stream_limit', 'identity', 'fd_control'):
                invalid = copy.deepcopy(value)
                if change == 'uid':
                    invalid['actor_uid'] = 0
                elif change == 'control':
                    invalid['records'][0]['environ']['text'] = ''
                elif change == 'pid_limit':
                    invalid['pid_set_truncated'] = True
                elif change == 'stream_limit':
                    invalid['records'][1]['cmdline']['truncated'] = True
                elif change == 'identity':
                    invalid['records'][0]['identity_stable'] = False
                else:
                    invalid['records'][0]['fd'] = {'status': 'denied', 'errno': errno.EACCES}
                with self.subTest(change=change):
                    self.assertFalse(P.summarize(invalid)['passed'])

    def test_bounded_reader_and_output_budget_never_silently_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            (root / '20/cmdline').write_bytes(b'X' * (P.MAX_BLOB + 1))
            result = P.read_blob(root / '20/cmdline')
            self.assertTrue(result['truncated'])
            self.assertEqual(len(result['text']), P.MAX_BLOB)
            with patch.object(P, 'MAX_OUTPUT', 1), self.assertRaises(RuntimeError):
                P.snapshot(root, own_pid=10)

    def test_pid_cap_keeps_own_positive_control_and_records_incompleteness(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            with patch.object(P, 'MAX_PIDS', 1):
                value = P.snapshot(root, own_pid=20)
            self.assertEqual([row['pid'] for row in value['records']], [20])
            self.assertTrue(value['pid_set_truncated'])
