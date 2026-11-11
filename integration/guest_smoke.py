#!/usr/bin/env python3
"""Real pinned LWS + AWS CLI + tcpdump integration, no AWS network access.

Run as a non-root host user with loopback capture permission. All data/keys are
local dummy values. Production root/service-uid boundaries need a guest VM.
"""
import argparse
import concurrent.futures
import contextlib
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import signal
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
OPTIONS = None


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def private_json(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


def request_http(endpoint, method='GET', path='/', key=None, body=None, headers=None,
         chunked=False):
    headers = dict(headers or {})
    if key is not None:
        headers['Authorization'] = (
            f'AWS4-HMAC-SHA256 Credential={key}/local/us-east-1/s3/aws4_request, '
            'SignedHeaders=host, Signature=DO-NOT-STORE-SIGNATURE')
    connection = http.client.HTTPConnection('127.0.0.1', endpoint, timeout=15)
    try:
        connection.request(method, path, body, headers, encode_chunked=chunked)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


class Guest:
    def __init__(self, capture_failure=False, seed_failure=False):
        self.temp = tempfile.TemporaryDirectory(prefix='tempest-m2-', dir='/private/tmp' if sys.platform == 'darwin' else '/tmp')
        self.root = Path(self.temp.name)
        self.proxy_port, self.backend_port = port(), port()
        while self.proxy_port == self.backend_port:
            self.backend_port = port()
        self.admin_keys = []
        self.lws_pids = []
        # Independent test observer: keys stay in RAM, never a regular file.
        self.audit = socket.socket(socket.AF_UNIX)
        audit_path = self.root / 'admin.sock'
        self.audit.bind(str(audit_path))
        self.audit.listen(4)
        self.audit.settimeout(0.2)
        self.audit_stop = threading.Event()
        def observe():
            while not self.audit_stop.is_set():
                try:
                    conn, _ = self.audit.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                with conn:
                    value = bytearray()
                    while chunk := conn.recv(256):
                        value.extend(chunk)
                        assert len(value) <= 1024
                    report = json.loads(value)
                    self.admin_keys.append(report['key'])
                    self.lws_pids.append(report['pid'])
        self.audit_thread = threading.Thread(target=observe, daemon=True)
        self.audit_thread.start()
        wrapper = self.root / 'lws-observer'
        wrapper.write_text(f'#!{sys.executable}\nimport os,socket,json\ns=socket.socket(socket.AF_UNIX)\ns.connect({str(audit_path)!r})\ns.sendall(json.dumps({{"key":os.environ["LWS_ROOT_ACCESS_KEY_ID"],"pid":os.getpid()}}).encode())\ns.close()\nos.execv({str(OPTIONS.lws)!r}, [{str(OPTIONS.lws)!r}])\n')
        wrapper.chmod(0o700)
        self.config = private_json(self.root / 'guest.json', {
            'state_dir': str(self.root / 'state'),
            'data_dir': str(self.root / 'data'),
            'evidence_dir': str(self.root / 'evidence'),
            'listen': f'127.0.0.1:{self.proxy_port}',
            'upstream': f'127.0.0.1:{self.backend_port}',
            'lws': str(wrapper), 'aws': '/bin/false' if seed_failure else str(OPTIONS.aws),
            'tcpdump': '/bin/false' if capture_failure else str(OPTIONS.tcpdump),
            'capture_interface': 'lo0' if sys.platform == 'darwin' else 'lo',
            'service_uid': os.getuid(), 'service_gid': os.getgid(),
            'development': True, 'timeout_seconds': 5,
        })
        self.process = self.start()
        self.token = None
        self.bundle = {
            'users': [{'name': 'worker', 'policy': {'Version': '2012-10-17', 'Statement': [
                {'Effect': 'Allow', 'Action': ['s3:GetObject', 's3:PutObject'], 'Resource': 'arn:aws:s3:::public-data/*'},
                {'Effect': 'Allow', 'Action': ['sqs:GetQueueUrl', 'sqs:ReceiveMessage'], 'Resource': 'arn:aws:sqs:us-east-1:000000000000:jobs'},
                {'Effect': 'Allow', 'Action': ['sqs:ListQueues', 'ses:ListIdentities'], 'Resource': '*'},
            ]}}],
            'buckets': [
                {'name': 'public-data', 'objects': [{'key': 'readme.txt', 'body': 'PUBLIC-DUMMY'}, {'key': 'large.bin', 'body': 'initial'}]},
                {'name': 'private-data', 'objects': [{'key': 'secret.txt', 'body': 'PRIVATE-DUMMY'}]},
            ], 'queues': [{'name': 'jobs'}],
        }
        self.bundle_path = private_json(self.root / 'seed.json', self.bundle)

    def start(self):
        process = subprocess.Popen([str(OPTIONS.guest), '--config', str(self.config), 'recorder'],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError('supervisor startup failed: ' + process.stderr.read().decode())
            if (self.root / 'state/control.sock').exists():
                return process
            time.sleep(0.025)
        process.kill()
        process.wait()
        raise AssertionError('supervisor startup timeout')

    def call(self, command, *args, token=True, failure=False):
        argv = [str(OPTIONS.guest), '--config', str(self.config), command]
        credential = self.token if token is True else token if isinstance(token, str) else None
        if credential is not None:
            argv += ['--token-stdin']
        result = subprocess.run(argv + list(map(str, args)), input=(credential + '\n').encode() if credential else None,
                                capture_output=True, timeout=90)
        if failure:
            if result.returncode == 0:
                raise AssertionError(f'{command} unexpectedly succeeded')
            assert not self.token or self.token.encode() not in result.stderr
            return result
        if result.returncode:
            details = result.stderr.decode()
            if not details:
                with contextlib.suppress(ValueError):
                    details = json.dumps(json.loads(result.stdout).get('manifest', {}))
            raise AssertionError(f'{command} failed: {details}')
        return json.loads(result.stdout)

    def claim(self):
        self.token = self.call('claim', token=False)['token']

    def seed(self):
        return self.call('seed', self.bundle_path)['access_keys']['worker']

    def probe(self, key, api, resource):
        path = private_json(self.root / 'probe.json', {'access_key_id': key, 'api': api, 'resource': resource})
        return self.call('probe', path)

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.process.stdout.close()
        self.process.stderr.close()
        self.audit_stop.set()
        self.audit.close()
        self.audit_thread.join(timeout=2)
        self.temp.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class GuestIntegration(unittest.TestCase):
    def test_seed_probe_record_export_and_rotation(self):
        with Guest() as g:
            # Parallel claims serialize at the same persistent control state.
            def claim(_):
                return subprocess.run([str(OPTIONS.guest), '--config', str(g.config), 'claim'], capture_output=True, timeout=10)
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                claims = list(pool.map(claim, range(4)))
            self.assertEqual(sum(c.returncode == 0 for c in claims), 1)
            g.token = json.loads(next(c.stdout for c in claims if c.returncode == 0))['token']
            g.call('claim', token=False, failure=True)
            for args in [('seed', g.bundle_path), ('probe', g.bundle_path), ('seal',), ('export', g.root / 'bad-export')]:
                g.call(*args, token=False, failure=True)
                g.call(*args, token='0' * 64, failure=True)
            self.assertTrue(g.bundle_path.exists())
            worker = g.seed()
            self.assertFalse(g.bundle_path.exists())
            self.assertEqual(len(g.admin_keys), 2)
            self.assertNotEqual(g.admin_keys[0], g.admin_keys[1])
            for key, status in [(g.admin_keys[0], 403), (g.admin_keys[1], 200)]:
                actual, _ = request_http(g.backend_port, 'POST', '/', key, b'Action=ListUsers', {'Content-Type': 'application/x-www-form-urlencoded'})
                self.assertEqual(actual, status)
            for api, resource, outcome, status in [
                ('s3:GetObject', 'arn:aws:s3:::public-data/readme.txt', 'allow', 200),
                ('s3:GetObject', 'arn:aws:s3:::private-data/secret.txt', 'deny', 403),
                ('s3:PutBucketNotification', 'arn:aws:s3:::public-data', 'unsupported', 501),
            ]:
                result = g.probe(worker, api, resource)
                self.assertEqual((result['outcome'], result['status'], result['complete']), (outcome, status, True))
            unknown = g.probe('UNKNOWN-LOCAL-KEY', 's3:GetObject', 'arn:aws:s3:::public-data/readme.txt')
            self.assertEqual((unknown['outcome'], unknown['status'], unknown['credential_known']), ('error', 403, False))
            self.assertFalse((g.root / 'evidence/api.jsonl').exists())
            self.assertFalse((g.root / 'evidence/capture.pcap').exists())
            with socket.socket() as sock:
                self.assertNotEqual(sock.connect_ex(('127.0.0.1', g.proxy_port)), 0)
            for credential in [False, '0' * 64]:
                g.call('probe', g.root / 'probe.json', token=credential, failure=True)
                g.call('seal', token=credential, failure=True)
            g.call('seal')
            for i, credential in enumerate([False, '0' * 64]):
                target = g.root / f'unauthorized-export-{i}'
                g.call('export', target, token=credential, failure=True)
                self.assertFalse(target.exists())
            g.call('seal', failure=True)
            g.call('probe', g.root / 'probe.json', failure=True)
            g.call('seed', g.bundle_path, failure=True)
            calls = [
                ('GET', '/public-data/readme.txt', worker, None, {}, 200),
                ('GET', '/private-data/secret.txt', worker, None, {}, 403),
                ('GET', '/public-data/readme.txt', None, None, {}, 403),
                ('GET', '/public-data?notification', worker, None, {}, 501),
                ('GET', '/public-data?notification', None, None, {}, 501),
                ('GET', f'/public-data/readme.txt?X-Amz-Credential={worker}%2Flocal%2Fregion%2Fs3%2Faws4_request', None, None, {}, 200),
                ('POST', '/', worker, b'Action=ListQueues', {'Content-Type': 'application/x-www-form-urlencoded'}, 200),
                ('POST', '/', worker, b'Action=GetQueueUrl&QueueName=jobs', {'Content-Type': 'application/x-www-form-urlencoded'}, 200),
                ('POST', '/', worker, b'{"QueueUrl":"http://127.0.0.1:4566/000000000000/jobs"}', {'Content-Type': 'application/x-amz-json-1.0', 'X-Amz-Target': 'AmazonSQS.ReceiveMessage'}, 200),
                ('POST', '/', worker, b'Action=ListIdentities', {'Content-Type': 'application/x-www-form-urlencoded'}, 200),
                ('POST', '/v2/email/outbound-emails', worker, b'{"FromEmailAddress":"sender@example.invalid"}', {'Content-Type': 'application/json'}, 403),
            ]
            for method, path, key, body, headers, status in calls:
                actual, _ = request_http(g.proxy_port, method, path, key, body, headers)
                self.assertEqual(actual, status)
            payload = b'LARGE-TEMPEST-BODY-' * 131072
            chunks = (payload[i:i + 8192] for i in range(0, len(payload), 8192))
            status, _ = request_http(g.proxy_port, 'PUT', '/public-data/large.bin', worker, chunks, chunked=True)
            self.assertEqual(status, 200)
            status, received = request_http(g.proxy_port, path='/public-data/large.bin', key=worker)
            self.assertEqual(status, 200)
            self.assertEqual(received, payload)
            exported = g.call('export', g.root / 'export')
            self.assertTrue(exported['complete'], exported['manifest'])
            evidence = g.root / 'export'
            text = (evidence / 'api.jsonl').read_text()
            records = [json.loads(line) for line in text.splitlines()]
            self.assertEqual(len(records), len(calls) + 2)
            self.assertEqual([r['seq'] for r in records], list(range(1, len(records) + 1)))
            for marker in ['PUBLIC-DUMMY', 'PRIVATE-DUMMY', 'LARGE-TEMPEST-BODY', 'Credential=', 'DO-NOT-STORE-SIGNATURE', g.token, *g.admin_keys]:
                self.assertNotIn(marker, text)
            unsupported = [r for r in records if r['status'] == 501]
            self.assertEqual([r['access_key_id'] for r in unsupported], [worker, None])
            self.assertEqual(sum(r['status'] == 403 and r['access_key_id'] is None for r in records), 1)
            self.assertTrue(all(r['error_code'] == 'AccessDenied' for r in records if r['status'] == 403))
            self.assertTrue(all('?' not in r['path'] for r in records))
            self.assertTrue(all(r['error_code'] == 'NotImplemented' and r['action'] is None for r in unsupported))
            denied = next(r for r in records if r['path'] == '/private-data/secret.txt')
            self.assertEqual((denied['action'], denied['resource'], denied['error_code']),
                             ('s3:GetObject', 'arn:aws:s3:::private-data/secret.txt', 'AccessDenied'))
            self.assertTrue(any(r['action'] == 'sqs:ReceiveMessage' for r in records))
            self.assertTrue(any(r['action'] == 'ses:ListIdentities' for r in records))
            self.assertTrue(any(r['action'] == 'ses:SendEmail' and r['resource'].endswith('identity/sender@example.invalid') for r in records))
            large = [r for r in records if r['path'] == '/public-data/large.bin']
            digest = hashlib.sha256(payload).hexdigest()
            self.assertEqual((large[0]['req_bytes'], large[0]['req_sha256']), (len(payload), digest))
            self.assertEqual((large[1]['resp_bytes'], large[1]['resp_sha256']), (len(payload), digest))
            self.assertTrue(all(r['request_complete'] and r['response_complete'] for r in records))
            capture = (evidence / 'capture.pcap').read_bytes()
            self.assertGreater(len(capture), 24)
            parsed = subprocess.run([str(OPTIONS.tcpdump), '-n', '-r', str(evidence / 'capture.pcap'), '-c', '1'], capture_output=True)
            self.assertEqual(parsed.returncode, 0)
            self.assertTrue(parsed.stdout)
            state = (g.root / 'state/state.json').read_text()
            self.assertNotIn(g.token, state)
            for path in [g.root / 'state/state.json', evidence / 'api.jsonl', evidence / 'capture.pcap']:
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            g.call('export', g.root / 'export', failure=True)  # never overwrite
            g.call('probe', g.root / 'probe.json', failure=True)
            # Helper restart cannot recover a consumed claim or a live run.
            g.process.terminate()
            g.process.wait(timeout=15)
            g.process.stdout.close()
            g.process.stderr.close()
            g.process = g.start()
            g.call('claim', token=False, failure=True)
            g.call('seal', failure=True)

    def test_claim_response_loss_and_restart_cannot_reissue(self):
        with Guest() as g:
            with socket.socket(socket.AF_UNIX) as sock:
                sock.connect(str(g.root / 'state/control.sock'))
                sock.sendall(json.dumps({'token': None, 'operation': {'command': 'claim'}}).encode())
                sock.shutdown(socket.SHUT_WR)
                # Deliberately discard the response after persistent issuance.
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if json.loads((g.root / 'state/state.json').read_text())['phase'] == 'claimed':
                    break
                time.sleep(0.02)
            else:
                self.fail('claim was not persisted')
            g.call('claim', token=False, failure=True)
            g.process.terminate()
            g.process.wait(timeout=15)
            g.process.stdout.close()
            g.process.stderr.close()
            g.process = g.start()
            g.call('claim', token=False, failure=True)

    def test_partial_upload_exports_incomplete_evidence(self):
        with Guest() as g:
            g.claim()
            worker = g.seed()
            g.call('seal')
            with socket.create_connection(('127.0.0.1', g.proxy_port), timeout=5) as sock:
                head = ('PUT /public-data/large.bin HTTP/1.1\r\nHost: localhost\r\n'
                        f'Authorization: AWS4-HMAC-SHA256 Credential={worker}/d/r/s3/aws4_request\r\n'
                        'Content-Length: 1000000\r\n\r\n')
                sock.sendall(head.encode() + b'PARTIAL-DUMMY')
                time.sleep(0.1)
            time.sleep(0.1)
            result = g.call('export', g.root / 'partial-export', failure=True)
            report = json.loads(result.stdout)
            self.assertFalse(report['complete'])
            rows = [json.loads(line) for line in (g.root / 'partial-export/api.jsonl').read_text().splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertFalse(rows[0]['request_complete'])
            self.assertIsNotNone(rows[0]['transport_error'])
            self.assertNotIn('PARTIAL-DUMMY', (g.root / 'partial-export/api.jsonl').read_text())

    def test_export_drain_deadline_is_not_complete(self):
        with Guest() as g:
            g.claim()
            worker = g.seed()
            g.call('seal')
            with socket.create_connection(('127.0.0.1', g.proxy_port), timeout=5) as sock:
                head = ('PUT /public-data/large.bin HTTP/1.1\r\nHost: localhost\r\n'
                        f'Authorization: AWS4-HMAC-SHA256 Credential={worker}/d/r/s3/aws4_request\r\n'
                        'Content-Length: 1000000\r\n\r\n')
                sock.sendall(head.encode() + b'STALLED-DUMMY')
                time.sleep(0.1)
                result = g.call('export', g.root / 'drain-export', failure=True)
            report = json.loads(result.stdout)
            self.assertFalse(report['complete'])
            self.assertTrue(any(reason in report['manifest']['failures'] for reason in ['recorder drain/flush failed', 'incomplete HTTP observations']))
            rows = [json.loads(line) for line in (g.root / 'drain-export/api.jsonl').read_text().splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertFalse(rows[0]['request_complete'])
            with socket.socket() as sock:
                self.assertNotEqual(sock.connect_ex(('127.0.0.1', g.proxy_port)), 0)

    def test_upstream_failure_is_recorded_and_export_is_incomplete(self):
        with Guest() as g:
            g.claim()
            worker = g.seed()
            g.call('seal')
            os.kill(g.lws_pids[-1], signal.SIGKILL)
            time.sleep(0.05)
            status, _ = request_http(g.proxy_port, path='/public-data/readme.txt', key=worker)
            self.assertEqual(status, 502)
            result = g.call('export', g.root / 'upstream-export', failure=True)
            report = json.loads(result.stdout)
            self.assertFalse(report['complete'])
            rows = [json.loads(line) for line in (g.root / 'upstream-export/api.jsonl').read_text().splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['status'], 502)
            self.assertIsNotNone(rows[0]['transport_error'])

    def test_seal_waits_for_seed_and_cannot_capture_admin_requests(self):
        with Guest() as g:
            g.claim()
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                seeding = pool.submit(g.seed)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if json.loads((g.root / 'state/state.json').read_text())['phase'] == 'seeding':
                        break
                    time.sleep(0.01)
                else:
                    self.fail('seed did not start')
                g.call('seal')
                seeding.result(timeout=30)
            report = g.call('export', g.root / 'serialized-export')
            self.assertTrue(report['complete'], report['manifest'])
            self.assertEqual((g.root / 'serialized-export/api.jsonl').read_text(), '')
            self.assertEqual(report['manifest']['capture_statistics']['dropped'], 0)

    def test_proxy_body_drain_has_a_finite_deadline(self):
        with Guest() as g:
            ready = threading.Event()
            release = threading.Event()
            def slow_upstream():
                with socket.socket() as server:
                    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    server.bind(('127.0.0.1', g.backend_port))
                    server.listen(1)
                    ready.set()
                    conn, _ = server.accept()
                    with conn:
                        conn.recv(16384)
                        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\nx')
                        release.wait(15)
            thread = threading.Thread(target=slow_upstream, daemon=True)
            thread.start()
            self.assertTrue(ready.wait(5))
            proxy = subprocess.Popen([str(OPTIONS.guest), '__proxy'], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                proxy.stdin.write(g.config.read_bytes())
                proxy.stdin.close()
                self.assertTrue(select.select([proxy.stdout], [], [], 5)[0])
                self.assertEqual(proxy.stdout.readline(), b'{"ready":true}\n')
                with socket.create_connection(('127.0.0.1', g.proxy_port), timeout=5) as sock:
                    sock.sendall(b'GET /public-data/readme.txt HTTP/1.1\r\nHost: localhost\r\n\r\n')
                    self.assertIn(b'200 OK', sock.recv(16384))
                    started = time.monotonic()
                    proxy.terminate()
                    proxy.wait(timeout=8)
                    elapsed = time.monotonic() - started
                self.assertLess(elapsed, 8)
                self.assertNotEqual(proxy.returncode, 0)
                rows = [json.loads(line) for line in (g.root / 'evidence/api.jsonl').read_text().splitlines()]
                self.assertEqual(len(rows), 1)
                self.assertFalse(rows[0]['response_complete'])
                self.assertIsNotNone(rows[0]['transport_error'])
            finally:
                release.set()
                thread.join(timeout=2)
                if proxy.poll() is None:
                    proxy.kill()
                    proxy.wait()
                proxy.stdout.close()
                proxy.stderr.close()

    def test_seed_failure_is_terminal_and_removes_bundle(self):
        with Guest(seed_failure=True) as g:
            g.claim()
            g.call('seed', g.bundle_path, failure=True)
            self.assertFalse(g.bundle_path.exists())
            g.call('seal', failure=True)
            g.call('seed', g.bundle_path, failure=True)
            self.assertEqual(json.loads((g.root / 'state/state.json').read_text())['phase'], 'failed')

    def test_capture_failure_does_not_open_recorder(self):
        with Guest(capture_failure=True) as g:
            g.claim()
            g.seed()
            g.call('seal', failure=True)
            g.call('export', g.root / 'export', failure=True)
            with socket.socket() as sock:
                self.assertNotEqual(sock.connect_ex(('127.0.0.1', g.proxy_port)), 0)
            self.assertFalse((g.root / 'evidence/api.jsonl').exists())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lws', type=Path, required=True, help='native binary from pinned LWS commit')
    parser.add_argument('--guest', type=Path, default=ROOT / 'target/debug/tempest-guest')
    parser.add_argument('--aws', type=Path, default=Path(shutil.which('aws') or '/usr/bin/aws'))
    parser.add_argument('--tcpdump', type=Path, default=Path(shutil.which('tcpdump') or '/usr/sbin/tcpdump'))
    OPTIONS, remaining = parser.parse_known_args()
    for key in ['lws', 'guest', 'aws', 'tcpdump']:
        setattr(OPTIONS, key, getattr(OPTIONS, key).resolve())
        if not getattr(OPTIONS, key).is_file():
            parser.error(f'{key} executable missing')
    if os.geteuid() == 0:
        parser.error('development integration must run as a non-root host user')
    unittest.main(argv=[sys.argv[0], *remaining], verbosity=2)
