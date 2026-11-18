"""Finite host TCP receiver, root observer handshake and endpoint-only validation."""
import errno
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import threading
import time
import tomllib

from network_probe import check_nonce, HOST_ADDRESS, MAX_FRAME, CONTROL_PREFIX


class EndpointReceiver:
    def __init__(self, nonce):
        check_nonce(nonce)
        self.nonce = nonce
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.accepts = 0
        self.messages = []
        self.errors = []
        self.deadline = time.monotonic() + 60
        self.socket = socket.socket()
        self.thread = None
        self.started = False
        try:
            self.socket.bind(('127.0.0.1', 0))
            self.socket.listen(4)
            self.socket.settimeout(.1)
            self.identity = {'schema_version': 1, 'nonce': nonce, 'host_pid': os.getpid(),
                             'address': '127.0.0.1', 'port': self.socket.getsockname()[1],
                             'socket_inode': os.fstat(self.socket.fileno()).st_ino}
            self.thread = threading.Thread(target=self.serve, daemon=True)
            self.thread.start()
            self.started = True
        except BaseException:
            self.socket.close()
            raise

    def serve(self):
        while not self.stop.is_set():
            if time.monotonic() >= self.deadline:
                self.errors.append('receiver_deadline')
                return
            try:
                connection, _ = self.socket.accept()
            except TimeoutError:
                continue
            except OSError:
                if not self.stop.is_set():
                    self.errors.append('accept_failed')
                return
            with self.lock:
                self.accepts += 1
                over_budget = self.accepts > 4
            with connection:
                try:
                    if over_budget:
                        with self.lock:
                            self.errors.append('receiver_accept_budget')
                        return
                    connection.settimeout(2)
                    data = b''
                    while b'\n' not in data and len(data) <= MAX_FRAME:
                        remaining = self.deadline - time.monotonic()
                        if self.stop.is_set() or remaining <= 0:
                            raise TimeoutError('receiver stopped or expired')
                        connection.settimeout(min(2, remaining))
                        part = connection.recv(MAX_FRAME + 1 - len(data))
                        if not part:
                            break
                        data += part
                    if len(data) > MAX_FRAME or not data.endswith(b'\n'):
                        raise ValueError('receiver frame budget')
                    value = json.loads(data)
                    if set(value) != {'nonce', 'phase'} or value['nonce'] != self.nonce or value['phase'] not in ('before', 'after'):
                        raise ValueError('receiver control binding')
                    with self.lock:
                        self.messages.append(value['phase'])
                    connection.sendall(data)
                except (OSError, ValueError):
                    with self.lock:
                        self.errors.append('receiver_protocol_failed')

    def snapshot(self):
        if self.socket.getsockname() != ('127.0.0.1', self.identity['port']) \
                or os.fstat(self.socket.fileno()).st_ino != self.identity['socket_inode']:
            raise RuntimeError('host receiver bind changed')
        return self.counters()

    def counters(self):
        with self.lock:
            return {'identity': dict(self.identity), 'accepts': self.accepts,
                    'phases': list(self.messages), 'errors': list(self.errors),
                    'thread_alive': self.thread.is_alive(), 'host_monotonic_ns': time.monotonic_ns()}

    def control(self, phase):
        data = (json.dumps({'nonce': self.nonce, 'phase': phase}, separators=(',', ':')) + '\n').encode()
        with socket.create_connection(('127.0.0.1', self.identity['port']), timeout=2) as connection:
            connection.sendall(data)
            received = b''
            deadline = time.monotonic() + 3
            while len(received) < len(data):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('host control deadline')
                connection.settimeout(min(2, remaining))
                part = connection.recv(MAX_FRAME + 1)
                if not part:
                    break
                received += part
                if len(received) > MAX_FRAME:
                    raise RuntimeError('host control reply budget')
        if received != data:
            raise RuntimeError('host endpoint positive control failed')

    def close(self):
        self.stop.set()
        self.socket.close()
        if self.thread is not None and self.started:
            self.thread.join(3)
            if self.thread.is_alive():
                raise RuntimeError('host receiver thread cleanup failed')


def publish(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.tmp')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write((json.dumps(value, separators=(',', ':')) + '\n').encode())
        stream.flush()
        os.fsync(stream.fileno())
    # link is exclusive: a concurrent existing result is never overwritten.
    os.link(temporary, path, follow_symlinks=False)
    temporary.unlink()
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def wait_observer(path, identity, receiver, timeout=10):
    deadline = time.monotonic() + timeout
    observed_inode = None
    while time.monotonic() < deadline:
        snapshot = receiver.snapshot()
        if not snapshot['thread_alive'] or snapshot['errors']:
            raise RuntimeError('host receiver unavailable before observer ack')
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            if observed_inode is not None:
                raise ValueError('network observer ack disappeared during publication')
            time.sleep(.05)
            continue
        with os.fdopen(descriptor, 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink not in (1, 2) \
                    or (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) != (0, 988, 0o440):
                raise ValueError('network observer ack owner or mode mismatch')
            inode = (metadata.st_dev, metadata.st_ino)
            if observed_inode is not None and observed_inode != inode:
                raise ValueError('network observer ack inode changed during publication')
            observed_inode = inode
            # Exclusive link publication briefly has pending+final names. Only
            # consume after the same inode becomes single-link; never accept 2.
            if metadata.st_nlink == 2:
                time.sleep(.01)
                continue
            data = stream.read(4097)
        if len(data) > 4096:
            raise ValueError('network observer ack budget')
        ack = json.loads(data)
        validate_ack(ack, identity)
        return ack
    raise TimeoutError('network receiver was not acknowledged by fixed observer')


def validate_ack(ack, identity):
    if set(ack) != set(identity) | {'host_pid_starttime_ticks', 'invocation_id'} \
            or any(ack.get(key) != value for key, value in identity.items()) \
            or type(ack.get('host_pid_starttime_ticks')) is not int or ack['host_pid_starttime_ticks'] <= 0 \
            or re.fullmatch('[0-9a-f]{32}', ack.get('invocation_id', '')) is None:
        raise ValueError('network observer ack identity mismatch')


def validate(value):
    identity = value['identity']
    check_nonce(identity['nonce'])
    if identity['schema_version'] != 1 or identity['address'] != '127.0.0.1' \
            or not 1024 <= identity['port'] <= 65535 or identity['host_pid'] <= 0 or identity['socket_inode'] <= 0:
        raise ValueError('invalid host receiver identity')
    before, after, final = (value[key] for key in ('before_guest', 'after_guest', 'after_control'))
    for item in (before, after, final):
        if item['identity'] != identity or not item['thread_alive'] or item['errors']:
            raise ValueError('host receiver changed or failed during trial')
    if before['accepts'] != 1 or after['accepts'] != 1 or final['accepts'] != 2 \
            or before['phases'] != ['before'] or after['phases'] != ['before'] or final['phases'] != ['before', 'after']:
        raise ValueError('unexpected connection reached the host endpoint')
    closed = value['closed_state']
    if closed['identity'] != identity or closed['accepts'] != 2 or closed['phases'] != ['before', 'after'] \
            or closed['errors'] or closed['thread_alive'] is not False \
            or closed['host_monotonic_ns'] < final['host_monotonic_ns']:
        raise ValueError('host receiver final arrivals or cleanup mismatch')
    if not before['host_monotonic_ns'] <= value['call_started_host_ns'] \
            <= value['call_ended_host_ns'] <= after['host_monotonic_ns'] <= final['host_monotonic_ns']:
        raise ValueError('host interval binding failed')
    ack = value['observer_ack']
    validate_ack(ack, identity)
    guest = value['guest']
    if guest['schema_version'] != 1 or guest['actor_uid'] != 1000 or guest['nonce'] != identity['nonce'] \
            or not guest['guest_boot_id'] or guest['local_control'] != {'passed': True, 'received': 1, 'bytes': len(CONTROL_PREFIX) + len(identity['nonce']), 'thread_joined': True}:
        raise ValueError('guest raw loopback control failed')
    endpoint = guest['endpoint']
    if endpoint['address'] != HOST_ADDRESS or endpoint['port'] != identity['port'] or endpoint['connected'] is not False:
        raise ValueError('guest reached or changed the VM-external endpoint')
    if endpoint['error_kind'] == 'timeout':
        if endpoint['errno'] not in (None, errno.ETIMEDOUT):
            raise ValueError('unknown timeout diagnostic')
    elif endpoint['error_kind'] != 'os_error' or endpoint['errno'] not in (errno.ECONNREFUSED, errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EACCES, errno.EPERM):
        raise ValueError('unexpected guest connect failure')
    if not 0 < endpoint['started_monotonic_ns'] <= endpoint['ended_monotonic_ns'] \
            or endpoint['ended_monotonic_ns'] - endpoint['started_monotonic_ns'] > 5_000_000_000 \
            or value['receiver_closed'] is not True:
        raise ValueError('network fixture interval or cleanup failed')
    return {'passed': True, 'host_positive_controls': 2, 'guest_loopback_control': True,
            'guest_endpoint': endpoint, 'guest_boot_id': guest['guest_boot_id'],
            'host_receiver': identity, 'observer_ack': ack,
            'guest_interval_host_ns': [value['call_started_host_ns'], value['call_ended_host_ns']],
            'host_accepts_during_guest': 0, 'receiver_thread_joined': True,
            'scope': 'one VM-external host-alias endpoint; no Internet-wide or production MCP egress claim'}


def run(execute, output):
    output = Path(output)
    nonce = secrets.token_hex(16)
    receiver = EndpointReceiver(nonce)
    value = {'identity': receiver.identity}
    try:
        publish(output / 'network-receiver.ready.json', receiver.identity)
        value['observer_ack'] = wait_observer(output.parent / 'evidence/network-receiver-observed.json', receiver.identity, receiver)
        receiver.control('before')
        value['before_guest'] = receiver.snapshot()
        value['call_started_host_ns'] = time.monotonic_ns()
        try:
            result = execute('/usr/bin/env', 'TEMPEST_PROC_PUBLIC_CONTROL=TEMPEST-PUBLIC-PROC-CONTROL',
                             '/usr/bin/python3', '-I', '-B', '/workspace/readonly-check/network-probe.py',
                             nonce, str(receiver.identity['port']), timeout=10)
        finally:
            value['call_ended_host_ns'] = time.monotonic_ns()
            value['after_guest'] = receiver.snapshot()
        if result.returncode != 0 or len(result.stdout.encode('utf-8', 'surrogateescape')) > 16384:
            raise RuntimeError('guest network probe failed; private exec output retained')
        value['guest'] = json.loads(result.stdout)
        receiver.control('after')
        value['after_control'] = receiver.snapshot()
    finally:
        try:
            receiver.close()
        finally:
            value['closed_state'] = receiver.counters()
            value['receiver_closed'] = receiver.socket.fileno() == -1 and not value['closed_state']['thread_alive']
            publish(output / 'network-receiver.closed.json',
                    {'schema_version': 1, 'identity': receiver.identity,
                     'receiver_closed': value['receiver_closed'], 'host_monotonic_ns': time.monotonic_ns()})
            publish(output / 'network-host.private.json', value)
    return validate(value)


def require_config(text):
    config = tomllib.loads(text)
    if config['sandbox']['qemu']['restrict_network'] is not True or config['share']['read_only'] is not True \
            or config['detect']['allowed_hosts'] != [] or any(key in config for key in ('behavior', 'http_capture', 'dns_proxy')):
        raise ValueError('network fixture requires unchanged restricted baseline configuration')
