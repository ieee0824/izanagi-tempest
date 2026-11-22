"""Data saturation cannot occupy the control pool; watchdogs cannot renew leases."""
from pathlib import Path
import socket
import sys
import threading
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools/host_ledger'))
from egress_service import serve_both, watch_originals


class Listener:
    def __init__(self):
        self.socket = socket.socket()
        self.socket.bind(('127.0.0.1', 0))
        self.socket.listen(10)

    def accept(self):
        connection, _ = self.socket.accept()
        return connection, (231, 12345)

    def settimeout(self, timeout):
        self.socket.settimeout(timeout)


class ServiceTests(unittest.TestCase):
    def test_watchdog_failure_stops_without_renewal(self):
        stop = threading.Event()
        state = Mock()
        check = Mock(side_effect=ValueError('revoked'))
        watch_originals(state, check, stop)
        self.assertTrue(stop.is_set())
        state.stop.assert_called()
        state.observe.assert_not_called()

    def test_four_held_data_slots_leave_control_usable_and_reject_fifth(self):
        stop = threading.Event()
        state = Mock()
        control, data = Listener(), Listener()
        clients = []
        held = 0
        all_held = threading.Event()
        lock = threading.Lock()
        failures = []

        def data_connection(*args):
            nonlocal held
            with lock:
                held += 1
                if held == 4:
                    all_held.set()
            stop.wait(2)

        def query(*args):
            return {'successful': 'signed control response'}

        def run():
            try:
                serve_both(control, data, {}, Path('/unused'), None, state, None,
                           time.monotonic()+10, lambda _: None, stop)
            except BaseException as error:
                failures.append(error)

        with patch('egress_service.serve_connection', side_effect=data_connection), \
                patch('broker.serve_query', side_effect=query):
            worker = threading.Thread(target=run)
            worker.start()
            try:
                for _ in range(4):
                    clients.append(socket.create_connection(data.socket.getsockname(), timeout=1))
                self.assertTrue(all_held.wait(1))
                with socket.create_connection(data.socket.getsockname(), timeout=1) as excess:
                    self.assertEqual(excess.recv(1), b'')
                with socket.create_connection(control.socket.getsockname(), timeout=1):
                    # The receipt callback is the observable completion of control.
                    until = time.monotonic()+1
                    while not state.observe.called and time.monotonic() < until:
                        threading.Event().wait(0.005)
                    state.observe.assert_called_once()
                self.assertEqual(held, 4)
            finally:
                stop.set()
                worker.join(2)
                for client in clients:
                    client.close()
                control.socket.close()
                data.socket.close()
            self.assertFalse(worker.is_alive())
            self.assertEqual(failures, [])
            state.stop.assert_called()
