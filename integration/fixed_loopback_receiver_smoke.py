#!/usr/bin/env python3
"""Measure fixed loopback dummy receipts and listener cleanup without a VM."""
from contextlib import ExitStack
import errno
import json
import os
import secrets
import select
import socket
import sys

LOOPBACK = '127.0.0.1'
TIMEOUT = 2
REQUEST = b'tempest dummy request\n'
RESPONSE = b'tempest dummy response\n'


class Receiver:
    def __init__(self, stack):
        self.listener = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        self.listener.bind((LOOPBACK, 0))
        self.listener.listen(1)
        self.listener.settimeout(TIMEOUT)
        self.endpoint = self.listener.getsockname()
        self.inode = os.fstat(self.listener.fileno()).st_ino
        self.accepted = 0
        self.matched = 0

    def snapshot(self):
        if select.select([self.listener], [], [], 0)[0]:
            raise RuntimeError('unexpected queued connection')
        return {'accepted': self.accepted, 'matched': self.matched}

    def receive(self):
        peer, _ = self.listener.accept()
        self.accepted += 1
        with peer:
            peer.settimeout(TIMEOUT)
            with peer.makefile('rb') as stream:
                request = stream.read(len(REQUEST) + 1)
            if request != REQUEST:
                raise RuntimeError('unexpected dummy request')
            self.matched += 1
            peer.sendall(RESPONSE)


def exchange(receiver):
    with socket.create_connection(receiver.endpoint, timeout=TIMEOUT) as client:
        client.sendall(REQUEST)
        client.shutdown(socket.SHUT_WR)
        receiver.receive()
        with client.makefile('rb') as stream:
            if stream.read(len(RESPONSE) + 1) != RESPONSE:
                raise RuntimeError('unexpected dummy response')


def listener_absent(receiver):
    if receiver.listener.fileno() != -1:
        return False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(TIMEOUT)
        return client.connect_ex(receiver.endpoint) == errno.ECONNREFUSED


def main():
    report = {
        'scope': 'fixed_loopback_receivers',
        'run': secrets.token_hex(16),
        'phases': {},
        'passed': False,
    }
    receivers = {}
    try:
        with ExitStack() as stack:
            for name in ('same_run_dummy', 'other_dummy'):
                receivers[name] = Receiver(stack)
            report['receivers'] = {
                name: {'port': receiver.endpoint[1], 'inode': receiver.inode}
                for name, receiver in receivers.items()
            }
            for target, receiver in receivers.items():
                before = {name: item.snapshot() for name, item in receivers.items()}
                phase = {'before': before}
                report['phases'][target] = phase
                try:
                    exchange(receiver)
                finally:
                    after = {name: item.snapshot() for name, item in receivers.items()}
                    phase['after'] = after
                    phase['delta'] = {
                        name: {key: count - before[name][key] for key, count in counts.items()}
                        for name, counts in after.items()
                    }
                for name, counts in phase['delta'].items():
                    expected = int(name == target)
                    if counts != {'accepted': expected, 'matched': expected}:
                        raise RuntimeError('unexpected receiver count')
    except (OSError, RuntimeError) as error:
        report['error'] = str(error)
    cleanup = {name: listener_absent(item) for name, item in receivers.items()}
    report['listener_absent'] = cleanup
    report['passed'] = 'error' not in report and len(cleanup) == 2 and all(cleanup.values())
    print(json.dumps(report, sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    if len(sys.argv) != 1:
        sys.exit('This fixture takes no arguments.')
    sys.exit(main())
