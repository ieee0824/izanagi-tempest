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
        self.server.requests.append((self.path, body))
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
        self.relay = proxy.Server(
            ('127.0.0.1', 0), upstream_url, 'x' * 32,
            [self.allowed], self.audit, 5)
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
        request = urllib.request.Request(
            self.url, data=json.dumps(value).encode(),
            headers={'Content-Type': 'application/json'}, method='POST')
        return urllib.request.urlopen(request, timeout=5)

    def test_exact_catalog_is_forwarded_and_audited_without_body(self):
        with self.post({'prompt': 'secret', 'tools': [
                self.allowed]}) as response:
            self.assertEqual(json.loads(response.read()), {'accepted': True})
        self.assertEqual(len(self.upstream.requests), 1)
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

    def test_redirect_cannot_change_upstream_authority(self):
        class Redirect(http.server.BaseHTTPRequestHandler):
            def log_message(self, _format, *_args):
                return

            def do_POST(self):
                self.send_response(307)
                self.send_header('Location', 'http://example.invalid/stolen')
                self.end_headers()

        redirect = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Redirect)
        thread = threading.Thread(target=redirect.serve_forever, daemon=True)
        thread.start()
        old_relay = self.relay
        old_relay.shutdown()
        old_relay.server_close()
        self.relay = proxy.Server(
            ('127.0.0.1', 0), f'http://127.0.0.1:{redirect.server_address[1]}',
            'x' * 32, [self.allowed], self.audit, 5)
        self.relay_thread = threading.Thread(target=self.relay.serve_forever, daemon=True)
        self.relay_thread.start()
        self.url = f'http://127.0.0.1:{self.relay.server_address[1]}/' + 'x' * 32 + '/v1/messages'
        try:
            with self.assertRaises(urllib.error.HTTPError) as raised:
                self.post({'tools': [self.allowed]})
            self.assertEqual(raised.exception.code, 307)
            raised.exception.read()
            raised.exception.close()
        finally:
            redirect.shutdown()
            redirect.server_close()


if __name__ == '__main__':
    unittest.main()
