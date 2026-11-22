"""Numeric-peer dialing and bounded opaque relay; no TLS or credential parsing."""
import errno
import ipaddress
import selectors
import socket
import time

BUFFER_LIMIT = 64 * 1024
POLL_SECONDS = 0.02


def require_authorization(authorization, deadline, clock=time.monotonic):
    now = clock()
    fresh = authorization.current()
    if fresh is None or now >= min(deadline, fresh.deadline):
        raise TimeoutError('egress authorization ended')
    return min(deadline, fresh.deadline)


def dial_peer(policy, authorization, deadline):
    """Dial a verified policy's numeric address only, checking actual TCP peer."""
    address = ipaddress.ip_address(policy.address)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    peer = (str(address), policy.port, 0, 0) if address.version == 6 else (str(address), policy.port)
    connection = socket.socket(family, socket.SOCK_STREAM)
    connection.setblocking(False)
    try:
        require_authorization(authorization, deadline)
        status = connection.connect_ex(peer)
        if status not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY):
            raise OSError(status, 'egress connection refused')
        with selectors.DefaultSelector() as selector:
            selector.register(connection, selectors.EVENT_WRITE)
            while status != 0:
                expires = require_authorization(authorization, deadline)
                if selector.select(min(POLL_SECONDS, max(0, expires - time.monotonic()))):
                    status = connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    if status:
                        raise OSError(status, 'egress connection failed')
        require_authorization(authorization, deadline)
        actual = connection.getpeername()
        if ipaddress.ip_address(actual[0]) != address or actual[1] != policy.port:
            raise ValueError('actual egress TCP peer mismatch')
        return connection
    except BaseException:
        connection.close()
        raise


def relay_opaque(left, right, authorization, absolute_deadline):
    """Relay at most 64 KiB per direction; EOF or lease loss closes both peers.

    This owns both connected sockets. No cleanup grace authorizes further I/O.
    """
    buffers = {left: bytearray(), right: bytearray()}
    peers = {left: right, right: left}
    try:
        left.setblocking(False)
        right.setblocking(False)
        with selectors.DefaultSelector() as selector:
            while True:
                expires = require_authorization(authorization, absolute_deadline)
                for connection in (left, right):
                    events = 0
                    if len(buffers[peers[connection]]) < BUFFER_LIMIT:
                        events |= selectors.EVENT_READ
                    if buffers[connection]:
                        events |= selectors.EVENT_WRITE
                    try:
                        selector.unregister(connection)
                    except KeyError:
                        pass
                    if events:
                        selector.register(connection, events)
                ready = selector.select(min(POLL_SECONDS, max(0, expires - time.monotonic())))
                for key, events in ready:
                    connection = key.fileobj
                    if events & selectors.EVENT_READ:
                        require_authorization(authorization, absolute_deadline)
                        pending = buffers[peers[connection]]
                        try:
                            chunk = connection.recv(BUFFER_LIMIT - len(pending))
                        except BlockingIOError:
                            continue
                        if not chunk:
                            return
                        pending.extend(chunk)
                    if events & selectors.EVENT_WRITE:
                        require_authorization(authorization, absolute_deadline)
                        pending = buffers[connection]
                        try:
                            count = connection.send(pending)
                        except BlockingIOError:
                            continue
                        if count <= 0:
                            raise ConnectionError('egress write disconnected')
                        del pending[:count]
    finally:
        for connection in (left, right):
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
