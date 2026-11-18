import ast
import copy
import errno
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'image'))
import network_evidence as E
import network_probe as P

NONCE = 'a' * 32


def sample():
    identity = {'schema_version': 1, 'nonce': NONCE, 'host_pid': 321,
                'address': '127.0.0.1', 'port': 40001, 'socket_inode': 999}
    def snapshot(count, phases, timestamp):
        return {'identity': dict(identity), 'accepts': count, 'phases': phases,
                'errors': [], 'thread_alive': True, 'host_monotonic_ns': timestamp}
    return {'identity': identity, 'before_guest': snapshot(1, ['before'], 10),
            'after_guest': snapshot(1, ['before'], 50), 'after_control': snapshot(2, ['before', 'after'], 60),
            'call_started_host_ns': 20, 'call_ended_host_ns': 40, 'receiver_closed': True,
            'observer_ack': {**identity, 'host_pid_starttime_ticks': 1234, 'invocation_id': 'b' * 32},
            'guest': {'schema_version': 1, 'nonce': NONCE, 'actor_uid': 1000, 'guest_boot_id': 'guest-boot',
                      'local_control': {'passed': True, 'received': 1, 'bytes': 55, 'thread_joined': True},
                      'endpoint': {'address': '10.0.2.2', 'port': 40001, 'connected': False,
                                   'error_kind': 'os_error', 'errno': errno.ECONNREFUSED,
                                   'started_monotonic_ns': 1000, 'ended_monotonic_ns': 2000}}}


class ValidationTests(unittest.TestCase):
    def test_endpoint_only_success_with_independent_clock_domains(self):
        result = E.validate(sample())
        self.assertTrue(result['passed'])
        self.assertEqual(result['host_accepts_during_guest'], 0)
        self.assertIn('no Internet-wide', result['scope'])

    def test_failed_controls_or_extra_arrival_refused(self):
        for key, field, bad in [('before_guest', 'accepts', 0), ('after_guest', 'accepts', 2),
                                ('after_control', 'accepts', 3), ('after_control', 'phases', ['after', 'before']),
                                ('after_guest', 'thread_alive', False), ('after_guest', 'errors', ['unexpected'])]:
            value = sample()
            value[key][field] = bad
            with self.assertRaises(ValueError):
                E.validate(value)

    def test_receiver_identity_ack_and_cleanup_required(self):
        for alter in ('socket', 'ack_nonce', 'ack_start', 'ack_invocation', 'cleanup', 'host_time'):
            value = sample()
            if alter == 'socket': value['after_guest']['identity']['socket_inode'] += 1
            elif alter == 'ack_nonce': value['observer_ack']['nonce'] = 'c' * 32
            elif alter == 'ack_start': value['observer_ack']['host_pid_starttime_ticks'] = 0
            elif alter == 'ack_invocation': value['observer_ack']['invocation_id'] = 'unknown'
            elif alter == 'cleanup': value['receiver_closed'] = False
            else: value['call_started_host_ns'] = 100
            with self.assertRaises(ValueError):
                E.validate(value)

    def test_connected_wrong_target_or_unexpected_errno_refused(self):
        for field, bad in [('connected', True), ('address', '1.1.1.1'), ('port', 4566), ('errno', errno.EINVAL)]:
            value = sample()
            value['guest']['endpoint'][field] = bad
            with self.assertRaises(ValueError):
                E.validate(value)
        value = sample()
        value['guest']['endpoint'].update(error_kind='timeout', errno=None)
        self.assertTrue(E.validate(value)['passed'])

    def test_unchanged_restrict_configuration_required(self):
        text = (ROOT / 'tools/m0/izanagi.example.toml').read_text()
        E.require_config(text)
        for changed in (text.replace('restrict_network = true', 'restrict_network = false'),
                        text.replace('read_only = true', 'read_only = false'),
                        text + '\n[behavior]\nenabled = true\n'):
            with self.assertRaises(ValueError):
                E.require_config(changed)

    def test_guest_guard_before_network_and_boot_read(self):
        with patch.object(P.core, 'require_guest', side_effect=RuntimeError('not guest')), \
                patch.object(P, 'local_control') as local, patch.object(P, 'probe_endpoint') as external:
            with self.assertRaisesRegex(RuntimeError, 'not guest'):
                P.main()
            local.assert_not_called()
            external.assert_not_called()


class HostFixtureTests(unittest.TestCase):
    def test_actual_host_controls_same_binding_and_close(self):
        receiver = E.EndpointReceiver(NONCE)
        try:
            receiver.control('before')
            before = receiver.snapshot()
            receiver.control('after')
            after = receiver.snapshot()
            self.assertEqual(before['identity'], after['identity'])
            self.assertEqual(after['accepts'], 2)
            self.assertEqual(after['phases'], ['before', 'after'])
            self.assertEqual(after['errors'], [])
        finally:
            receiver.close()
        self.assertFalse(receiver.thread.is_alive())
        with socket.socket() as check:
            check.settimeout(.5)
            self.assertNotEqual(check.connect_ex(('127.0.0.1', receiver.identity['port'])), 0)

    def test_accept_is_counted_even_without_payload(self):
        receiver = E.EndpointReceiver(NONCE)
        try:
            with socket.create_connection(('127.0.0.1', receiver.identity['port']), timeout=1):
                pass
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and not receiver.snapshot()['errors']:
                time.sleep(.01)
            result = receiver.snapshot()
            self.assertEqual(result['accepts'], 1)
            self.assertEqual(result['phases'], [])
            self.assertTrue(result['errors'])
        finally:
            receiver.close()

    def test_actual_guest_loopback_function_only(self):
        # Internal loopback function is tested without guest main or host /proc.
        result = P.local_control(NONCE)
        self.assertEqual(result, {'passed': True, 'received': 1, 'bytes': 55, 'thread_joined': True})

    def test_private_publish_and_root_ack_identity_validation(self):
        class Receiver:
            def snapshot(self): return {'thread_alive': True, 'errors': []}
        value = sample()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ack.json'
            E.publish(path, value['observer_ack'])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(ValueError):
                E.wait_observer(path, value['identity'], Receiver())
            metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o440, st_uid=0, st_gid=988, st_nlink=1, st_dev=1, st_ino=123)
            with patch.object(E.os, 'fstat', return_value=metadata):
                self.assertEqual(E.wait_observer(path, value['identity'], Receiver()), value['observer_ack'])
            pending = copy.copy(metadata)
            pending.st_nlink = 2
            with patch.object(E.os, 'fstat', side_effect=[pending, metadata]):
                self.assertEqual(E.wait_observer(path, value['identity'], Receiver()), value['observer_ack'])
            changed = copy.copy(metadata)
            changed.st_ino += 1
            with patch.object(E.os, 'fstat', side_effect=[pending, changed]):
                with self.assertRaisesRegex(ValueError, 'inode changed'):
                    E.wait_observer(path, value['identity'], Receiver())
            with self.assertRaises(FileExistsError):
                E.publish(path, {})
            with self.assertRaises(TimeoutError):
                E.wait_observer(Path(directory) / 'absent', value['identity'], Receiver(), timeout=0)


class RunnerTests(unittest.TestCase):
    def main(self):
        source = ROOT / 'integration/image_smoke.py'
        tree = ast.parse(source.read_text())
        return source, next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')

    def test_network_branch_uses_only_fixed_driver(self):
        source, main = self.main()
        trial = next(n for n in main.body if isinstance(n, ast.Try) and n.finalbody)
        branch = next(n for n in trial.body if isinstance(n, ast.If) and
                      isinstance(n.test, ast.Attribute) and n.test.attr == 'sidecar_evidence')
        calls = []
        execute = object()
        output = Path('/synthetic-output')
        def run(fn, directory):
            calls.append((fn, directory))
            return {'passed': True, 'scope': 'synthetic driver only'}
        ns = {'args': SimpleNamespace(sidecar_evidence=False, network_evidence=True),
              'network_evidence': SimpleNamespace(run=run), 'execute': execute,
              'output': output, 'report': {'checks': {}}, 'save': lambda: None}
        exec(compile(ast.Module(body=[branch], type_ignores=[]), str(source), 'exec'), ns)
        self.assertEqual(calls, [(execute, output)])
        self.assertTrue(ns['report']['checks']['network_endpoint']['passed'])

    def test_public_copy_is_only_guard_and_network_probe(self):
        source, main = self.main()
        setup = next(n for n in main.body if isinstance(n, ast.If) and
                     isinstance(n.test, ast.Attribute) and n.test.attr == 'network_evidence'
                     and any(isinstance(child, ast.For) for child in n.body))
        mapped = []
        def metadata(path, mode):
            self.assertTrue(path.stat().st_mode & stat.S_IWUSR)
            mapped.append((path.name, mode))
        with tempfile.TemporaryDirectory() as directory:
            public = Path(directory)
            ns = {'args': SimpleNamespace(network_evidence=True), 'ROOT': ROOT, 'public': public,
                  'stat': stat, 'mapped_metadata': metadata}
            exec(compile(ast.Module(body=[setup], type_ignores=[]), str(source), 'exec'), ns)
            self.assertEqual({p.name for p in public.iterdir()}, {'proc_evidence.py', 'network-probe.py'})
            self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o444 for p in public.iterdir()))
            self.assertEqual(len(mapped), 2)
