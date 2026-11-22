"""Control success/failure drives the same-process egress stop latch."""
from pathlib import Path
import socket
import sys
import threading
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools/host_ledger'))
import broker


class ControlBridgeTests(unittest.TestCase):
    def run_bridge(self, failure=None):
        stop = threading.Event()
        authorization = Mock()
        response = {'payload': {'example': 'successful signed receipt'}}
        accepted = []

        class Listener:
            def __init__(self, listener):
                self.listener = listener

            def accept(self):
                connection, _ = self.listener.accept()
                accepted.append(time.monotonic())
                return connection, (231, 12345)

        def query(*args):
            stop.set()
            if failure:
                raise failure
            return response

        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            listener.settimeout(0.02)
            with socket.create_connection(listener.getsockname()), patch('broker.serve_query', side_effect=query):
                broker.serve(Listener(listener), {}, Path('/unused'), None, stop, authorization)
        return authorization, response, accepted[0]

    def test_only_successful_response_renews_using_acceptance_time(self):
        authorization, response, accepted = self.run_bridge()
        authorization.observe.assert_called_once()
        signed, started = authorization.observe.call_args.args
        self.assertEqual(signed, response)
        self.assertGreaterEqual(started, accepted)
        self.assertLess(started - accepted, 0.1)
        authorization.stop.assert_not_called()

    def test_rejection_or_failed_send_stops_instead_of_renewing(self):
        for failure in (ValueError('refused'), BrokenPipeError('failed send'), TimeoutError('late')):
            with self.subTest(failure=failure):
                authorization, _, _ = self.run_bridge(failure)
                authorization.observe.assert_not_called()
                authorization.stop.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
