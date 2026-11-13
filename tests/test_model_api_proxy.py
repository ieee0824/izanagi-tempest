import http.server
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.request


MODULE_PATH = Path(__file__).parents[1] / 'tools/model_api_proxy.py'
SPEC = importlib.util.spec_from_file_location('model_api_proxy', MODULE_PATH)
proxy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(proxy)


class Upstream(http.server.ThreadingHTTPServer):
    def __init__(self):
        super().__init__(('127.0.0.1', 0), UpstreamHandler)
        self.requests = []


class UpstreamHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        self.server.requests.append((self.path, body, dict(self.headers)))
        response = b'{"accepted":true}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)


class ModelApiProxyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.upstream = Upstream()
        self.upstream_thread = threading.Thread(
            target=self.upstream.serve_forever, daemon=True)
        self.upstream_thread.start()
        upstream_url = f'http://127.0.0.1:{self.upstream.server_address[1]}'
        self.audit = self.root / 'audit.jsonl'
        self.allowed = {'type': 'function', 'name': 'mcp__tempest__sandbox_status',
                        'description': 'fixed', 'input_schema': {'type': 'object'}}
        self.policy = {
            'schema_version': 1,
            'paths': ['/v1/messages'],
            'models': ['model-1'],
            'top_level_fields': ['model', 'prompt', 'tools'],
            'tools': [self.allowed],
        }
        self.relay = proxy.Server(
            ('127.0.0.1', 0), upstream_url, 'x' * 32,
            self.policy, self.audit, 5, 'Authorization', 'fixture-value')
        self.relay_thread = threading.Thread(target=self.relay.serve_forever, daemon=True)
        self.relay_thread.start()
        self.url = f'http://127.0.0.1:{self.relay.server_address[1]}/' + 'x' * 32 + '/v1/messages'

    def tearDown(self):
        self.relay.shutdown()
        self.relay.server_close()
        self.upstream.shutdown()
        self.upstream.server_close()
        self.temporary.cleanup()

    def post(self, value):
        return self.post_raw(json.dumps(value).encode())

    def post_raw(self, body, headers=None):
        request_headers = {'Content-Type': 'application/json'}
        request_headers.update(headers or {})
        request = urllib.request.Request(
            self.url, data=body,
            headers=request_headers, method='POST')
        return urllib.request.urlopen(request, timeout=5)

    def test_exact_catalog_is_forwarded_and_audited_without_body(self):
        value = {'model': 'model-1', 'prompt': 'secret', 'tools': [self.allowed]}
        with self.post_raw(
                json.dumps(value).encode(),
                {'Authorization': 'agent-placeholder',
                 'X-Api-Key': 'agent-placeholder'}) as response:
            self.assertEqual(json.loads(response.read()), {'accepted': True})
        self.assertEqual(len(self.upstream.requests), 1)
        forwarded_headers = {
            name.lower(): child for name, child in self.upstream.requests[0][2].items()}
        self.assertEqual(forwarded_headers['authorization'], 'fixture-value')
        self.assertNotIn('x-api-key', forwarded_headers)
        event = json.loads(self.audit.read_text())
        self.assertTrue(event['forwarded'])
        self.assertEqual(event['tools'], ['function:mcp__tempest__sandbox_status'])
        self.assertNotIn('secret', self.audit.read_text())

    def test_added_missing_duplicate_and_unknown_tools_never_reach_upstream(self):
        invalid = [
            {'tools': []},
            {'tools': [self.allowed,
                       {'type': 'function', 'name': 'Bash'}]},
            {'tools': [self.allowed, self.allowed]},
            {'tools': [{**self.allowed, 'description': 'changed'}]},
            {'tools': [{'type': 'future-shape'}]},
            {'prompt': 'catalog omitted'},
            {'model': 'other-model', 'tools': [self.allowed]},
            {'model': 'model-1', 'tools': [self.allowed], 'previous_response_id': 'old'},
            {'model': 'model-1', 'tools': [self.allowed],
             'prompt': {'image_url': 'https://example.invalid/image'}},
        ]
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    self.post(value)
                self.assertEqual(raised.exception.code, 409)
                raised.exception.read()
                raised.exception.close()
        self.assertEqual(self.upstream.requests, [])
        events = [json.loads(line) for line in self.audit.read_text().splitlines()]
        self.assertEqual(len(events), len(invalid))
        self.assertTrue(all(not event['forwarded'] for event in events))

    def test_duplicate_json_keys_are_rejected_before_forwarding(self):
        body = (b'{"model":"model-1","tools":[{"type":"function","name":"Bash"}],'
                b'"tools":[' + json.dumps(self.allowed).encode() + b']}')
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self.post_raw(body)
        self.assertEqual(raised.exception.code, 409)
        raised.exception.read()
        raised.exception.close()
        self.assertEqual(self.upstream.requests, [])

    def test_unknown_path_capability_cannot_use_the_relay(self):
        url = f'http://127.0.0.1:{self.relay.server_address[1]}/' + 'y' * 32 + '/v1/messages'
        body = json.dumps({
            'model': 'model-1', 'tools': [self.allowed]}).encode()
        request = urllib.request.Request(url, data=body, method='POST')
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(raised.exception.code, 404)
        raised.exception.read()
        raised.exception.close()
        self.assertEqual(self.upstream.requests, [])

    def test_redirect_cannot_change_upstream_authority(self):
        class Sink(http.server.BaseHTTPRequestHandler):
            requests = 0

            def log_message(self, _format, *_args):
                return

            def do_GET(self):
                type(self).requests += 1
                self.send_response(200)
                self.end_headers()

        sink = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Sink)
        sink_thread = threading.Thread(target=sink.serve_forever, daemon=True)
        sink_thread.start()

        class Redirect(http.server.BaseHTTPRequestHandler):
            def log_message(self, _format, *_args):
                return

            def do_POST(self):
                self.send_response(302)
                self.send_header(
                    'Location', f'http://127.0.0.1:{sink.server_address[1]}/stolen')
                self.end_headers()

        redirect = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Redirect)
        thread = threading.Thread(target=redirect.serve_forever, daemon=True)
        thread.start()
        old_relay = self.relay
        old_relay.shutdown()
        old_relay.server_close()
        self.relay = proxy.Server(
            ('127.0.0.1', 0), f'http://127.0.0.1:{redirect.server_address[1]}',
            'x' * 32, self.policy, self.audit, 5, 'Authorization', 'fixture-value')
        self.relay_thread = threading.Thread(target=self.relay.serve_forever, daemon=True)
        self.relay_thread.start()
        self.url = f'http://127.0.0.1:{self.relay.server_address[1]}/' + 'x' * 32 + '/v1/messages'
        try:
            with self.assertRaises(urllib.error.HTTPError) as raised:
                self.post({'model': 'model-1', 'tools': [self.allowed]})
            self.assertEqual(raised.exception.code, 502)
            raised.exception.read()
            raised.exception.close()
            self.assertEqual(Sink.requests, 0)
        finally:
            redirect.shutdown()
            redirect.server_close()
            sink.shutdown()
            sink.server_close()


if __name__ == '__main__':
    unittest.main()
