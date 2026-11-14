import base64
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import contextlib
import io
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'image' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dispatcher = load('dispatcher')
transport = load('transport')


class MailboxTests(unittest.TestCase):
    def test_host_companion_authenticates_one_reply_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as parent:
            workspace = Path(parent) / 'workspace'
            process = subprocess.Popen(
                [sys.executable, '-B', '-I', str(ROOT / 'image' / 'host_bridge.py'), str(workspace)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True,
            )
            ready = json.loads(process.stdout.readline())
            self.assertTrue(ready['result']['ready'])
            process.stdin.write(json.dumps({'command': 'prepare', 'operation': 'claim', 'fields': {}}) + '\n')
            process.stdin.flush()
            prepared = json.loads(process.stdout.readline())
            request = workspace / prepared['result']['guest_path'].removeprefix('/workspace/')
            request_id, payload = dispatcher.read_request(request, request.parent, os.getuid())
            frame = dispatcher.encrypt_reply(request_id, payload, {'ok': True, 'result': {'token': 'pipe-only'}})
            frame['id'] = 'f' * 32
            process.stdin.write(json.dumps({'command': 'decode', 'frame': json.dumps(frame)}) + '\n')
            process.stdin.flush()
            failure = process.stdout.readline()
            self.assertEqual(json.loads(failure), {'ok': False, 'error': 'mailbox_companion_failed'})
            self.assertNotIn(request_id, failure)
            self.assertNotIn('pipe-only', failure)
            self.assertEqual(process.wait(timeout=5), 1)
            process.stdin.close()
            process.stdout.close()
            process.stderr.close()
            self.assertFalse(request.exists())
            self.assertFalse((workspace / '.tempest-readonly-probe').exists())

    def test_export_requires_barrier_and_finalizes_while_frozen(self):
        for mode in ['success', 'native_failure', 'barrier_failure', 'missing_identity']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as parent:
                calls = []
                frozen = False
                def daemon(operation, expected=None):
                    nonlocal frozen
                    calls.append(operation)
                    if operation == 'quiesce':
                        if mode == 'barrier_failure':
                            raise dispatcher.Rejected('barrier_failed')
                        frozen = True
                        return {'descendants_empty': True, 'service_frozen': True, 'frozen_monotonic_ns': 100}
                    self.assertEqual(operation, 'thaw')
                    frozen = False
                    return {'thawed': True, 'thawed_monotonic_ns': 175, 'thawed_guest_ns': 1000}
                def native(command, **kwargs):
                    calls.append('native_export')
                    self.assertTrue(frozen, 'native export ran outside frozen boundary')
                    self.assertIn('export', command)
                    self.assertEqual(kwargs['env']['TEMPEST_AUDIT_ID'], 'a' * 32)
                    self.assertNotIn('dummy', kwargs['env'].values())
                    if mode == 'native_failure':
                        raise subprocess.TimeoutExpired(command, 240)
                    Path(command[-1]).mkdir()
                    return subprocess.CompletedProcess(command, 0, b'{"complete":true,"manifest":{}}', b'')
                payload = {'operation': 'export', 'authorization': 'dummy', 'audit_id': 'a' * 32}
                if mode != 'missing_identity':
                    payload['daemon_identity'] = {'pid': 123}
                with mock.patch.object(dispatcher, 'STATE', Path(parent)), \
                     mock.patch.object(dispatcher, 'authenticate'), \
                     mock.patch.object(dispatcher, 'consume'), \
                     mock.patch.object(dispatcher, 'private_directory', side_effect=lambda path, **kwargs: path.mkdir(mode=0o700, parents=True, exist_ok=True)), \
                     mock.patch.object(dispatcher, 'daemon_control', side_effect=daemon), \
                     mock.patch.object(dispatcher.subprocess, 'run', side_effect=native):
                    if mode == 'success':
                        result = dispatcher.dispatch('d' * 32, payload)
                        self.assertTrue(result['quiesce']['descendants_empty'])
                        self.assertEqual(result['quiesce']['frozen_duration_ns'], 75)
                        self.assertEqual(result['quiesce']['thawed_guest_ns'], 1000)
                    else:
                        with self.assertRaises((dispatcher.Rejected, subprocess.TimeoutExpired)):
                            dispatcher.dispatch('d' * 32, payload)
                self.assertFalse(frozen)
                self.assertEqual(calls, {'success': ['quiesce', 'native_export', 'thaw'],
                                         'native_failure': ['quiesce', 'native_export', 'thaw'],
                                         'barrier_failure': ['quiesce'], 'missing_identity': []}[mode])

    def test_mapping_private_input_and_response_confidentiality(self):
        with tempfile.TemporaryDirectory() as parent:
            box = transport.Mailbox(Path(parent) / 'workspace')
            request = box.prepare('claim')
            self.assertEqual(request.path.stat().st_mode & 0o777, 0o600)
            request_id, payload = dispatcher.read_request(request.path, box.inbox, os.getuid())
            value = {'ok': True, 'result': {'token': 'dummy-secret-canary'}}
            frame = dispatcher.encrypt_reply(request_id, payload, value)
            raw = json.dumps(frame)
            self.assertNotIn('dummy-secret-canary', raw)
            self.assertEqual(request.decode(raw), value)
            other = box.prepare('claim')
            with self.assertRaises(ValueError):
                other.decode(raw)
            frame['ciphertext'] = base64.b64encode(bytes(65552)).decode()
            with self.assertRaises(Exception):
                request.decode(json.dumps(frame))
            request.path.chmod(0o644)
            with self.assertRaises(dispatcher.Rejected):
                dispatcher.read_request(request.path, box.inbox, os.getuid())

    def test_delegated_entry_reads_only_ciphertext(self):
        with tempfile.TemporaryDirectory() as parent:
            state = Path(parent)
            replies = state / 'replies'
            replies.mkdir(mode=0o700)
            request_id = 'b' * 32
            frame = b'{"ciphertext":"public-opaque-frame"}'
            (replies / (request_id + '.json')).write_bytes(frame)
            output = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
            with mock.patch.object(dispatcher, 'STATE', state), \
                 mock.patch.object(dispatcher.os, 'geteuid', return_value=0), \
                 mock.patch.object(dispatcher, 'private_directory'), \
                 mock.patch.object(dispatcher, 'read_request') as read, \
                 mock.patch.object(dispatcher, 'dispatch') as dispatch, \
                 mock.patch.object(dispatcher.sys, 'argv', ['tempest-guest', 'deliver', '/workspace/.tempest-control/' + request_id + '.json']), \
                 contextlib.redirect_stdout(output):
                self.assertEqual(dispatcher.main(), 0)
                self.assertEqual(dispatcher.main(), 0)
                read.assert_not_called()
                dispatch.assert_not_called()
            self.assertEqual(output.buffer.getvalue(), (frame + b'\n') * 2)

    def test_delegated_entry_cannot_start_consumer(self):
        with mock.patch.object(dispatcher.os, 'geteuid', return_value=0), \
             mock.patch.object(dispatcher.sys, 'argv', ['tempest-guest', '--watch']), \
             mock.patch.object(dispatcher, 'watch') as watch, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(dispatcher.main(), 1)
            watch.assert_not_called()

    def test_publication_never_stages_plaintext_in_public_parent(self):
        with tempfile.TemporaryDirectory() as parent:
            box = transport.Mailbox(Path(parent) / 'workspace')
            original = transport.os.rename
            def inspect(source, destination):
                self.assertEqual(source.parent, box.inbox)
                self.assertEqual(destination.parent, box.inbox)
                self.assertEqual(source.parent.stat().st_mode & 0o777, 0o700)
                self.assertTrue(source.read_bytes())
                original(source, destination)
            with mock.patch.object(transport.os, 'rename', side_effect=inspect):
                request = box.prepare('claim')
            self.assertEqual(list(box.workspace.glob('*.tmp')), [])
            request.remove()

    def test_consumption_survives_response_loss(self):
        with tempfile.TemporaryDirectory() as parent:
            directory = Path(parent) / 'consumed'
            dispatcher.consume(directory, 'a' * 32, os.getuid())
            with self.assertRaises(dispatcher.Rejected):
                dispatcher.consume(directory, 'a' * 32, os.getuid())

    def test_duplicate_json_and_symlink_denied(self):
        with tempfile.TemporaryDirectory() as parent:
            box = transport.Mailbox(Path(parent) / 'workspace')
            request = box.prepare('ping')
            request.path.write_text('{"version":1,"version":1}')
            with self.assertRaises(dispatcher.Rejected):
                dispatcher.read_request(request.path, box.inbox, os.getuid())
            request.remove()
            request.path.symlink_to('/etc/passwd')
            with self.assertRaises(OSError):
                dispatcher.read_request(request.path, box.inbox, os.getuid())

    def test_oversize_reply_is_explicitly_uncertain(self):
        with tempfile.TemporaryDirectory() as parent:
            box = transport.Mailbox(Path(parent) / 'workspace')
            request = box.prepare('export')
            _, payload = dispatcher.read_request(request.path, box.inbox, os.getuid())
            frame = dispatcher.encrypt_reply(request.id, payload, {'result': 'x' * 70000})
            self.assertEqual(request.decode(json.dumps(frame))['error'], 'reply_too_large_operation_uncertain')


if __name__ == '__main__':
    unittest.main()
