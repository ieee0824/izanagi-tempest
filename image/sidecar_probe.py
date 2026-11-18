"""Public, guest-only bounded loopback fixture for the fixed behavior sidecar."""
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import proc_evidence as core

PROXY = 18080
ALLOWED = 19090
OTHER = 19091
BINARY = '/usr/local/bin/izanagi-http-capture'
MAX_BODY = 1024
MAX_REPLY = 4096


def sidecar_identity(proc=Path('/proc')):
    found, count = [], 0
    for path in proc.iterdir():
        if not path.name.isdecimal():
            continue
        count += 1
        if count > 4096:
            raise RuntimeError('sidecar identity PID budget exceeded')
        before = core.identity(path)
        command = core.read_blob(path / 'cmdline')
        if command.get('status') != 'read' or command.get('truncated'):
            continue
        if command['text'].split('\0')[0] != BINARY:
            continue
        observed_status = core.read_blob(path / 'status')
        if observed_status.get('status') != 'read' or observed_status['truncated']:
            raise RuntimeError('sidecar UID status unavailable')
        status = observed_status['text']
        uid = next(line.split()[1:] for line in status.splitlines() if line.startswith('Uid:'))
        after = core.identity(path)
        if before != after or 'starttime_ticks' not in before or uid != ['0'] * 4:
            raise RuntimeError('sidecar process identity unstable or not root')
        found.append({'pid': int(path.name), 'starttime_ticks': before['starttime_ticks'],
                      'ppid': before['ppid'], 'uid': 0})
    if len(found) != 1:
        raise RuntimeError('expected exactly one fixed sidecar process')
    return found[0]


class Receiver(HTTPServer):
    allow_reuse_address = False

    def __init__(self, port):
        self.received = []
        super().__init__(('127.0.0.1', port), Handler)


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def setup(self):
        super().setup()
        self.connection.settimeout(3)

    def log_message(self, *args):
        pass

    def do_POST(self):
        try:
            length = int(self.headers.get('Content-Length', '-1'))
            if not 0 <= length <= MAX_BODY or len(self.server.received) >= 4:
                raise ValueError('fixture request budget')
            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError('incomplete fixture request')
            digest = hashlib.sha256(body).hexdigest()
            self.server.received.append({'bytes': length, 'sha256': digest})
            reply = digest.encode('ascii')
            self.send_response(200)
            self.send_header('Content-Length', str(len(reply)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(reply)
        finally:
            self.close_connection = True


def request(connect_port, target_host, target_port, body, proxy=True):
    connection = http.client.HTTPConnection('127.0.0.1', connect_port, timeout=3)
    target = f'http://{target_host}:{target_port}/fixture' if proxy else '/fixture'
    try:
        connection.request('POST', target, body,
                           {'Host': f'{target_host}:{target_port}', 'Connection': 'close'})
        client = '%s:%s' % connection.sock.getsockname()
        response = connection.getresponse()
        reply = response.read(MAX_REPLY + 1)
        if len(reply) > MAX_REPLY:
            raise RuntimeError('fixture response budget')
        return {'status': response.status, 'reply': reply.decode('ascii'), 'client': client,
                'body_bytes': len(body)}
    finally:
        connection.close()


def exercise(nonce, proxy_port=PROXY, allowed_port=ALLOWED, other_port=OTHER):
    """Internal test seam; guest main supplies only fixed loopback ports."""
    if not isinstance(nonce, str) or re.fullmatch('[0-9a-f]{32}', nonce) is None:
        raise ValueError('invalid public fixture nonce')
    servers, threads, running = [], [], []
    results = {}
    bodies = {name: ('TEMPEST-SIDECAR-PUBLIC-' + nonce + '-' + name).encode('ascii')
              for name in ('control', 'allowed', 'private_port', 'denied_host')}
    try:
        for port in (allowed_port, other_port):
            server = Receiver(port)
            servers.append(server)
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
            thread.start()
            threads.append(thread)
            running.append(server)
        results['control'] = request(other_port, '127.0.0.1', other_port, bodies['control'], proxy=False)
        results['allowed'] = request(proxy_port, '127.0.0.1', allowed_port, bodies['allowed'])
        results['private_port'] = request(proxy_port, '127.0.0.1', other_port, bodies['private_port'])
        results['denied_host'] = request(proxy_port, '127.0.0.2', other_port, bodies['denied_host'])
        for name in ('control', 'allowed'):
            if results[name]['status'] != 200 or results[name]['reply'] != hashlib.sha256(bodies[name]).hexdigest():
                raise RuntimeError('loopback fixture positive control failed')
        for name in ('private_port', 'denied_host'):
            if results[name]['status'] != 502 or results[name]['reply'] != '':
                raise RuntimeError('loopback fixture rejection failed')
        for server, name in zip(servers, ('allowed', 'control'), strict=True):
            expected = [{'bytes': len(bodies[name]), 'sha256': hashlib.sha256(bodies[name]).hexdigest()}]
            if server.received != expected:
                raise RuntimeError('receiver arrival control mismatch')
        # Body/reply hashes are public dummy controls, never real credentials.
        for item in results.values():
            item.pop('reply')
        return {'cases': results, 'receiver_counts': [len(s.received) for s in servers]}
    finally:
        for server in running:
            server.shutdown()
        for server in servers:
            server.server_close()
        for thread in threads:
            thread.join(timeout=4)
        if any(thread.is_alive() for thread in threads):
            raise RuntimeError('fixture receiver thread cleanup failed')


def main():
    core.require_guest()  # Must precede all sockets and /proc enumeration.
    if any(os.environ.get(key) != 'http://127.0.0.1:18080' for key in ('http_proxy', 'HTTP_PROXY')):
        raise RuntimeError('fixed sidecar proxy environment missing')
    if any(os.environ.get(key) != '' for key in ('no_proxy', 'NO_PROXY')):
        raise RuntimeError('proxy bypass environment changed')
    nonce = sys.argv[1] if len(sys.argv) == 2 else ''
    started = time.monotonic_ns()
    before = sidecar_identity()
    result = exercise(nonce)
    if sidecar_identity() != before:
        raise RuntimeError('sidecar process changed during fixture')
    result.update(schema_version=1, nonce=nonce, actor_uid=os.getuid(), sidecar=before,
                  guest_boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                  started_monotonic_ns=started, ended_monotonic_ns=time.monotonic_ns(),
                  receiver_threads_joined=True, scope='fixed guest loopback only; not external egress or writer attribution')
    encoded = json.dumps(result, separators=(',', ':'))
    if len(encoded.encode()) > 16384:
        raise RuntimeError('fixture summary budget')
    print(encoded)


if __name__ == '__main__':
    main()
