"""Test-only host controller for the isolated VM's real remote TLS exercise.

The control port mutates only a temporary dummy ledger; never run it as a service.
The authorization port runs the production broker with the real accepted peer CID.
"""
import errno
import json
import os
from pathlib import Path
import socket
import sqlite3
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools/host_ledger'))
import broker
from channel import canonical_json, read_frame, serve_query, write_frame
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from hashlib import sha256
from write_transition import advance


def control_request(value):
    """Guest-only test RPC; no private key or real login data is transferred."""
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect((socket.VMADDR_CID_HOST, 23102))
        deadline = time.monotonic() + 5
        write_frame(connection, canonical_json(value), 1024, deadline)
        reply = json.loads(read_frame(connection, 4096, deadline))
        if 'error' in reply:
            raise RuntimeError(reply['error'])
        return reply


class HostController:
    def __init__(self, root, qmp):
        self.root = root
        self.qmp = qmp
        self.signer = Ed25519PrivateKey.generate()
        self.registration = {}
        self.drop_responses = False
        self.counts = {}
        self.stopping = threading.Event()
        self.errors = []
        self.lock = threading.Lock()
        self.listeners = []
        self.threads = []
        root.mkdir(mode=0o700)
        for name in ('host-login-authority', 'host-login-recovery', 'host-login-ledger-source', 'host-login-ledger'):
            (root / name).mkdir(mode=0o700)
        (root / 'host-login-ledger/lock').touch(mode=0o600)

    def write(self, name, value):
        path = self.root / name
        path.write_bytes(canonical_json(value))
        path.chmod(0o600)

    def prepare(self, value):
        scope = value['scope']
        expires = value['expires_unix_ms']
        if set(scope) != {'target_id', 'permit_id', 'generation'} or not time.time_ns()//1_000_000 < expires < time.time_ns()//1_000_000 + getattr(self, "maximum_window_ms", 60000):
            raise ValueError('invalid dummy scope or lifetime')
        stat = Path(f'/proc/{self.vm.pid}/stat').read_text()
        ticks = int(stat[stat.rindex(')')+2:].split()[19])
        self.registration.clear()
        self.registration.update(scope, boot_id='tls-boot', cid=234, qemu_pid=self.vm.pid,
            qemu_start_ticks=ticks, qmp_socket=str(self.qmp), qemu_device_id='ledger', expires_unix_ms=expires)
        self.write('host-login-authority/scope.json', scope)
        self.write('host-login-authority/ledger-id.json', 'tls-fixture')
        record = dict(ledger_id='tls-fixture', scope=scope, sequence=0, state='empty')
        self.write('host-login-recovery/checkpoint.json', dict(sequence=0, digest=sha256(canonical_json(record)).hexdigest()))
        database = self.root / 'host-login-ledger-source/ledger.sqlite3'
        if database.exists():
            database.unlink()
        with sqlite3.connect(database) as db:
            db.executescript((Path(__file__).resolve().parents[1] / 'tools/host_ledger/schema.sql').read_text())
        database.chmod(0o600)
        self.write('host-login-authority/channel-approval.json', dict(self.registration,
            communication_expires_unix_ms=expires, permit_expires_unix_ms=expires, generation_expires_unix_ms=expires))
        advance(self.root, 'issue')
        self.drop_responses = False
        self.counts = {}
        print('REMOTE_TLS_HOST_ISSUED', scope['permit_id'], flush=True)
        return dict(registration=dict(scope, boot_id='tls-boot', ledger_id='tls-fixture', minimum_sequence=1),
            key=self.signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())

    def control_loop(self, listener):
        while not self.stopping.is_set():
            try:
                connection, peer = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if self.stopping.is_set():
                    return
                raise
            with connection:
                try:
                    if peer[0] != 234:
                        raise ValueError('unexpected control VM')
                    value = json.loads(read_frame(connection, 1024, time.monotonic()+5))
                    operation = value['operation']
                    with self.lock:
                        if operation == 'prepare':
                            reply = self.prepare(value)
                        elif operation == 'revoke':
                            advance(self.root, 'revoke')
                            print('REMOTE_TLS_HOST_REVOKED', self.counts, flush=True)
                            reply = dict(counts=self.counts)
                        elif operation == 'lose-response':
                            self.drop_responses = True
                            print('REMOTE_TLS_HOST_RESPONSE_LOSS', self.counts, flush=True)
                            reply = dict(counts=self.counts)
                        elif operation == 'stats':
                            reply = dict(counts=self.counts)
                        elif hasattr(self, 'extra_control'):
                            reply = self.extra_control(value)
                        else:
                            raise ValueError('unknown dummy operation')
                    write_frame(connection, canonical_json(reply), 4096, time.monotonic()+5)
                except Exception as error:
                    self.errors.append(str(error))
                    write_frame(connection, canonical_json(dict(error=str(error))), 4096, time.monotonic()+1)

    def start(self, vm):
        self.vm = vm
        original_handler = broker.serve_query
        controller = self

        class ObservedConnection:
            def __init__(self, connection):
                self.connection = connection
                self.request = bytearray()
            def __getattr__(self, name):
                return getattr(self.connection, name)
            def recv(self, length):
                data = self.connection.recv(length)
                self.request.extend(data)
                return data

        def observed(connection, cid, registration, management, signer, deadline):
            if controller.drop_responses:
                return
            observed_connection = ObservedConnection(connection)
            original_handler(observed_connection, cid, registration, management, signer, deadline)
            request = json.loads(observed_connection.request)
            operation = request['operation']
            with controller.lock:
                controller.counts[operation] = controller.counts.get(operation, 0) + 1
            print('REMOTE_TLS_HOST_ACCEPTED', operation, flush=True)

        broker.serve_query = observed
        self.original_handler = original_handler
        for port, target in ((23102, self.control_loop), (23100, lambda listener: broker.serve(listener, self.registration, self.root, self.signer, self.stopping))):
            listener = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            listener.bind((socket.VMADDR_CID_HOST, port))
            listener.listen(8)
            listener.settimeout(0.5)
            self.listeners.append(listener)
            def run(listener=listener, target=target):
                try:
                    target(listener)
                except OSError as error:
                    if not self.stopping.is_set():
                        self.errors.append(str(error))
            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            self.threads.append(thread)

    def close(self):
        self.stopping.set()
        for listener in self.listeners:
            try:
                listener.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            listener.close()
        for thread in self.threads:
            thread.join(timeout=3)
            if thread.is_alive():
                self.errors.append('test host thread did not stop')
        broker.serve_query = self.original_handler
        if self.errors:
            raise RuntimeError(self.errors)
