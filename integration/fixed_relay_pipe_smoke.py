#!/usr/bin/env python3
"""Exercise the fixed relay's pipe ownership, deadline, and child reaping locally."""
import json
import math
import os
import select
import signal
import socket
import time

REQUEST = b'tempest relay request\n'
RESPONSE = b'tempest relay response\n'


def transfer(source, target, expected, deadline):
    received = bytearray()
    while len(received) < len(expected):
        wait_ready(source, select.POLLIN, deadline)
        try:
            chunk = os.read(source, len(expected) - len(received))
        except BlockingIOError:
            continue
        if not chunk:
            raise EOFError('short fixed frame')
        received.extend(chunk)
    if received != expected:
        raise ValueError('unexpected fixed frame')
    pending = memoryview(received)
    while pending:
        wait_ready(target, select.POLLOUT, deadline)
        try:
            count = os.write(target, pending)
        except BlockingIOError:
            continue
        if count == 0:
            raise EOFError('short fixed write')
        pending = pending[count:]


def wait_ready(fd, events, deadline):
    poller = select.poll()
    poller.register(fd, events)
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not poller.poll(math.ceil(remaining * 1000)) or time.monotonic() >= deadline:
        raise TimeoutError('fixed relay deadline')


def relay(request_fd, response_fd, peer_fd, timeout):
    deadline = time.monotonic() + timeout
    try:
        os.set_blocking(request_fd, False)
        os.set_blocking(response_fd, False)
        transfer(request_fd, peer_fd, REQUEST, deadline)
        transfer(peer_fd, response_fd, RESPONSE, deadline)
        return 0
    except TimeoutError:
        return 1
    except (EOFError, BrokenPipeError):
        return 2
    except (OSError, ValueError):
        return 3


def exercise(case):
    request_read, request_write = os.pipe2(os.O_CLOEXEC)
    response_read, response_write = os.pipe2(os.O_CLOEXEC)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(2)
    endpoint = listener.getsockname()
    pid = os.fork()
    if pid == 0:
        listener.close()
        os.close(request_write)
        os.close(response_read)
        try:
            with socket.create_connection(endpoint, timeout=2) as peer:
                peer.setblocking(False)
                status = relay(request_read, response_write, peer.fileno(), 0.25 if case == 'timeout' else 2)
        except OSError:
            status = 4
        os._exit(status)

    os.close(request_read)
    os.close(response_write)
    pidfd = None
    with listener, os.fdopen(request_write, 'wb', buffering=0) as request, \
            os.fdopen(response_read, 'rb', buffering=0) as response:
        try:
            pidfd = os.pidfd_open(pid)
            if case != 'timeout':
                request.write(REQUEST[:1] if case == 'short_request' else REQUEST)
                request.close()
            if case in ('complete', 'peer_eof'):
                local, _ = listener.accept()
                with local:
                    local.settimeout(2)
                    with local.makefile('rb') as reader:
                        if reader.readline(len(REQUEST) + 1) != REQUEST:
                            raise RuntimeError('dummy peer did not receive fixed request')
                    if case == 'peer_eof':
                        local.shutdown(socket.SHUT_WR)
                    else:
                        local.sendall(RESPONSE)
                        wait_ready(response.fileno(), select.POLLIN, time.monotonic() + 2)
                        if response.read(len(RESPONSE) + 1) != RESPONSE:
                            raise RuntimeError('parent did not receive fixed response')
            wait_ready(pidfd, select.POLLIN, time.monotonic() + 2)
        except BaseException:
            try:
                if pidfd is None:
                    # This parent is the sole reaper of the direct child.
                    os.kill(pid, signal.SIGKILL)
                else:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            raise
        finally:
            if pidfd is not None:
                os.close(pidfd)
            waited, status = os.waitpid(pid, 0)
            if waited != pid:
                raise RuntimeError('fixed relay child was not reaped')

    expected = {'complete': 0, 'timeout': 1, 'short_request': 2, 'peer_eof': 2}[case]
    if os.waitstatus_to_exitcode(status) != expected:
        raise RuntimeError('unexpected fixed relay exit')
    return {'case': case, 'exit': expected, 'reaped': True}


if __name__ == '__main__':
    print(json.dumps([exercise(case) for case in ('complete', 'timeout', 'short_request', 'peer_eof')]))
