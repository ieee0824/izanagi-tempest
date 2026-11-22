"""Local sockets prove opaque relay forwarding and prompt fail-closed recovery."""
from pathlib import Path
import socket
import sys
import threading
import time
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools/host_ledger'))
from egress_authority import RunAuthorization, Scope
from egress_relay import dial_peer, relay_opaque


class RelayTests(unittest.TestCase):
    def state(self):
        scope = Scope('vm', 'a' * 32, 1)
        state = RunAuthorization(scope, 'boot', 'ledger', time.monotonic() + 10)
        body = dict(request=dict(target_id='vm', permit_id='a' * 32, generation=1, boot_id='boot', operation='query'),
                    commit=dict(scope=dict(target_id='vm', permit_id='a' * 32, generation=1), ledger_id='ledger', sequence=1, state='consumed'),
                    issued_unix_ms=1, expires_unix_ms=2001)
        self.assertTrue(state.observe({'payload': body}, time.monotonic()))
        return state

    def test_numeric_dial_is_local_and_checks_authorization(self):
        state = self.state()
        with socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            server.listen(1)
            policy = SimpleNamespace(address='127.0.0.1', port=server.getsockname()[1])
            # A dummy fixture policy is used only here; production policy parser fixes 443.
            with dial_peer(policy, state, time.monotonic() + 1) as client:
                peer, _ = server.accept()
                with peer:
                    self.assertEqual(client.getpeername(), server.getsockname())
            state.stop()
            with self.assertRaises(TimeoutError):
                dial_peer(policy, state, time.monotonic() + 1)

    def run_relay(self):
        state = self.state()
        client, left = socket.socketpair()
        right, server = socket.socketpair()
        client.settimeout(1)
        server.settimeout(1)
        failures = []

        def run():
            try:
                relay_opaque(left, right, state, time.monotonic() + 10)
            except TimeoutError:
                pass
            except BaseException as error:
                failures.append(error)
        worker = threading.Thread(target=run)
        worker.start()
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        self.addCleanup(lambda: worker.join(2))
        self.addCleanup(state.stop)
        return state, client, server, worker, failures

    def test_binary_both_directions_and_revoke_closes_both(self):
        state, client, server, worker, failures = self.run_relay()
        payload = bytes(range(256)) * 100
        client.sendall(payload)
        received = bytearray()
        while len(received) < len(payload):
            received.extend(server.recv(len(payload) - len(received)))
        self.assertEqual(received, payload)
        server.sendall(b'\x00\xffTLS-opaque')
        self.assertEqual(client.recv(100), b'\x00\xffTLS-opaque')
        began = time.monotonic()
        state.stop()
        self.assertEqual(client.recv(1), b'')
        self.assertEqual(server.recv(1), b'')
        worker.join(1)
        self.assertFalse(worker.is_alive())
        self.assertLess(time.monotonic() - began, 0.5)
        self.assertEqual(failures, [])

    def test_half_close_closes_other_direction(self):
        _, client, server, worker, failures = self.run_relay()
        client.shutdown(socket.SHUT_WR)
        self.assertEqual(server.recv(1), b'')
        self.assertEqual(client.recv(1), b'')
        worker.join(1)
        self.assertFalse(worker.is_alive())
        self.assertEqual(failures, [])

    def test_backpressure_does_not_prevent_revoke(self):
        state, client, server, worker, failures = self.run_relay()
        client.setblocking(False)
        for _ in range(100):
            try:
                client.send(b'x' * 65536)
            except BlockingIOError:
                break
        state.stop()
        worker.join(1)
        self.assertFalse(worker.is_alive())
        self.assertEqual(failures, [])
