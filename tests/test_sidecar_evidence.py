import ast
import copy
import stat
import tempfile
import subprocess
import importlib.util
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'image' / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

E = module('sidecar_evidence')
P = module('sidecar_probe')
NONCE = 'a' * 32
SESSION = 'test-session'
BOOT = 'test-boot'
SOURCE = 'http-' + 'b' * 32


def sample():
    cases = {name: {'status': 200 if name in ('control', 'allowed') else 502,
                    'client': f'127.0.0.1:{30000 + n}', 'body_bytes': 80}
             for n, name in enumerate(('control', *E.CASES))}
    probe = {'schema_version': 1, 'nonce': NONCE, 'actor_uid': 1000,
             'receiver_counts': [1, 1], 'receiver_threads_joined': True,
             'sidecar': {'pid': 42, 'ppid': 1, 'uid': 0, 'starttime_ticks': 10},
             'guest_boot_id': BOOT, 'started_monotonic_ns': 100, 'ended_monotonic_ns': 10000,
             'cases': cases}
    records = []
    for name, (policy, outcome, status) in E.CASES.items():
        request_id = 'request-' + name
        payloads = [
            {'HttpRequest': {'request_id': request_id, 'connection_id': 'connection-' + name,
                             'tuple': {'client': cases[name]['client'], 'local': '127.0.0.1:18080', 'net_namespace': 1},
                             'method': 'post', 'policy': policy, 'declared_content_length': 80, 'raw_host': None}},
            {'HttpOutcome': {'request_id': request_id, 'outcome': outcome, 'status': status,
                             'client_bytes_received': 200, 'upstream_bytes_written': 200 if name == 'allowed' else 0,
                             'response_bytes_received': 100 if name == 'allowed' else 0}}]
        for payload in payloads:
            seq = len(records) + 1
            event = {'schema_version': 1, 'session_id': SESSION, 'guest_boot_id': BOOT,
                     'clock_domain': 'linux-monotonic:' + BOOT, 'source_instance_id': SOURCE,
                     'source_seq': seq, 'event_id': f'{SESSION}:{SOURCE}:{seq}',
                     'observed_monotonic_ns': 100 + seq, 'quality': {'issues': []}, 'payload': payload}
            records.append({'storage_gap': False, 'payload': {'Event': event}})
    return probe, records


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.probe, self.records = sample()

    def test_positive_and_distinct_rejections(self):
        result = E.validate_records(self.records, self.probe, NONCE, SESSION)
        self.assertTrue(result['passed'])
        self.assertEqual(result['private_port_failed'], 1)
        self.assertEqual(result['host_rejected'], 1)
        self.assertNotIn('raw_host', json.dumps(result))

    def test_wrong_identity_gap_privacy_or_duplicate_refused(self):
        for field, value in [('session_id', 'other'), ('guest_boot_id', 'other'),
                             ('event_id', 'other'), ('quality', {'issues': ['event_loss']})]:
            records = copy.deepcopy(self.records)
            records[0]['payload']['Event'][field] = value
            with self.assertRaises(ValueError):
                E.validate_records(records, self.probe, NONCE, SESSION)
        for records in (self.records[:-1], self.records + [self.records[0]]):
            with self.assertRaises(ValueError):
                E.validate_records(records, self.probe, NONCE, SESSION)
        records = copy.deepcopy(self.records)
        records[0]['storage_gap'] = True
        with self.assertRaises(ValueError):
            E.validate_records(records, self.probe, NONCE, SESSION)

    def test_rejected_port_must_not_be_called_policy_denied(self):
        records = copy.deepcopy(self.records)
        records[2]['payload']['Event']['payload']['HttpRequest']['policy'] = 'denied'
        with self.assertRaises(ValueError):
            E.validate_records(records, self.probe, NONCE, SESSION)
        records = copy.deepcopy(self.records)
        records[3]['payload']['Event']['payload']['HttpOutcome']['upstream_bytes_written'] = 1
        with self.assertRaises(ValueError):
            E.validate_records(records, self.probe, NONCE, SESSION)

    def test_probe_positive_control_cleanup_and_time_required(self):
        for field, value in [('receiver_counts', [1, 2]), ('receiver_threads_joined', False),
                             ('actor_uid', 0), ('nonce', 'wrong'), ('ended_monotonic_ns', 31_000_000_000)]:
            probe = copy.deepcopy(self.probe)
            probe[field] = value
            with self.assertRaises(ValueError):
                E.validate_probe(probe, NONCE)

    def test_restricted_config_and_mock_classifier(self):
        text = (ROOT / 'tools/m0/izanagi.example.toml').read_text()
        config = E.tomllib.loads(E.configure(text))
        self.assertTrue(config['sandbox']['qemu']['restrict_network'])
        self.assertTrue(config['share']['read_only'])
        self.assertEqual(config['behavior']['classifier'], {'provider': 'mock', 'allow_export': False})
        with self.assertRaises(ValueError):
            E.configure(text.replace('restrict_network = true', 'restrict_network = false'))

    def test_guest_guard_precedes_proc_and_network(self):
        with patch.object(P.core, 'require_guest', side_effect=RuntimeError('not guest')), \
                patch.object(P, 'sidecar_identity') as proc, patch.object(P, 'exercise') as network:
            with self.assertRaisesRegex(RuntimeError, 'not guest'):
                P.main()
            proc.assert_not_called()
            network.assert_not_called()


class LoopbackFixtureTests(unittest.TestCase):
    def test_actual_receiver_and_client_with_synthetic_loopback_proxy(self):
        # This proxy tests the fixture's real sockets only, not the Izanagi sidecar.
        reserved = [socket.socket(), socket.socket()]
        try:
            for sock in reserved:
                sock.bind(('127.0.0.1', 0))
            allowed, other = [sock.getsockname()[1] for sock in reserved]
        finally:
            for sock in reserved:
                sock.close()
        class Proxy(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                body = self.rfile.read(int(self.headers['Content-Length']))
                if self.path == f'http://127.0.0.1:{allowed}/fixture':
                    value = P.request(allowed, '127.0.0.1', allowed, body, proxy=False)
                    status, reply = value['status'], value['reply'].encode()
                else:
                    status, reply = 502, b''
                self.send_response(status)
                self.send_header('Content-Length', str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)
        server = HTTPServer(('127.0.0.1', 0), Proxy)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
        thread.start()
        try:
            result = P.exercise(NONCE, server.server_port, allowed, other)
            self.assertEqual(result['receiver_counts'], [1, 1])
            self.assertEqual(result['cases']['private_port']['status'], 502)
            self.assertEqual(result['cases']['denied_host']['status'], 502)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(4)
        self.assertFalse(thread.is_alive())
        # The fixture must release both bound receiver ports after completion.
        for port in (allowed, other):
            with socket.socket() as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('127.0.0.1', port))


class RunnerTests(unittest.TestCase):
    def main_nodes(self):
        source = ROOT / 'integration/image_smoke.py'
        tree = ast.parse(source.read_text())
        return source, next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')

    def test_dedicated_branch_runs_only_bounded_public_probe(self):
        source, main = self.main_nodes()
        trial = next(n for n in main.body if isinstance(n, ast.Try) and n.finalbody)
        branch = next(n for n in trial.body if isinstance(n, ast.If) and
                      isinstance(n.test, ast.Attribute) and n.test.attr == 'sidecar_evidence')
        probe, _ = sample()
        calls = []
        def execute(*argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, json.dumps(probe), '')
        namespace = {'args': type('Args', (), {'sidecar_evidence': True})(),
                     'secrets': type('Secrets', (), {'token_hex': staticmethod(lambda _: NONCE)})(),
                     'execute': execute, 'CONTROL_KEY': P.core.CONTROL_KEY,
                     'CONTROL_VALUE': P.core.CONTROL_VALUE, 'sidecar_evidence': E,
                     'json': json, 'report': {}, 'save': lambda: None}
        exec(compile(ast.Module(body=[branch], type_ignores=[]), str(source), 'exec'), namespace)
        self.assertEqual(len(calls), 1)
        self.assertIn('/workspace/readonly-check/sidecar-probe.py', calls[0][0])
        self.assertEqual(calls[0][1], {'timeout': 45})
        self.assertEqual(namespace['report']['sidecar_fixture']['nonce'], NONCE)

    def test_public_copy_uses_only_two_sources_and_writable_xattr_order(self):
        source, main = self.main_nodes()
        setup = next(n for n in main.body if isinstance(n, ast.If) and
                     isinstance(n.test, ast.Attribute) and n.test.attr == 'sidecar_evidence')
        # Select the setup, not the config transform, by its loop body.
        setup = next(n for n in main.body if isinstance(n, ast.If) and
                     isinstance(n.test, ast.Attribute) and n.test.attr == 'sidecar_evidence'
                     and any(isinstance(child, ast.For) for child in n.body))
        mapped = []
        def metadata(path, mode):
            self.assertTrue(path.stat().st_mode & stat.S_IWUSR)
            mapped.append((path.name, mode))
        with tempfile.TemporaryDirectory() as directory:
            public = Path(directory)
            ns = {'args': type('Args', (), {'sidecar_evidence': True})(), 'public': public,
                  'ROOT': ROOT, 'stat': stat, 'mapped_metadata': metadata}
            exec(compile(ast.Module(body=[setup], type_ignores=[]), str(source), 'exec'), ns)
            self.assertEqual({p.name for p in public.iterdir()}, {'proc_evidence.py', 'sidecar-probe.py'})
            self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o444 for p in public.iterdir()))
            self.assertEqual(len(mapped), 2)
