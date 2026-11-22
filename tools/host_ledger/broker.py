"""Serve bounded permit queries and consumption on the dedicated host vsock port."""

from concurrent.futures import ThreadPoolExecutor
import os
import socket
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from channel import REQUEST_SECONDS, serve_query
from read_snapshot import MANAGEMENT, check_directory, check_file, read_json

PORT = 23100
CONNECTION_LIMIT = 8


def serve(listener, registration, management, signer, stop_event=None, authorization=None):
    slots = threading.BoundedSemaphore(CONNECTION_LIMIT)
    active = set()
    lock = threading.Lock()

    def handle(connection, peer, deadline):
        cid = peer[0]
        claimed = False
        try:
            with connection:
                with lock:
                    if cid in active:
                        return
                    active.add(cid)
                    claimed = True
                signed = serve_query(connection, cid, registration, management, signer, deadline)
                if authorization is not None:
                    authorization.observe(signed, deadline - REQUEST_SECONDS)
        except (OSError, ValueError, KeyError):
            # A rejected request gets no signed authorization.
            if authorization is not None and claimed:
                authorization.stop()
        finally:
            if claimed:
                with lock:
                    active.remove(cid)
            slots.release()

    with ThreadPoolExecutor(max_workers=CONNECTION_LIMIT) as workers:
        while stop_event is None or not stop_event.is_set():
            try:
                connection, peer = listener.accept()
            except TimeoutError:
                # Polling a shutdown event must not recreate worker/CID state.
                continue
            except OSError:
                if stop_event is not None and stop_event.is_set():
                    break
                raise
            if stop_event is not None and stop_event.is_set():
                connection.close()
                break
            deadline = time.monotonic() + REQUEST_SECONDS
            if not slots.acquire(blocking=False):
                connection.close()
                continue
            try:
                workers.submit(handle, connection, peer, deadline)
            except BaseException:
                connection.close()
                slots.release()
                raise


def main():
    if os.geteuid() != 0:
        raise PermissionError("management broker requires root")
    for parent in reversed(MANAGEMENT.parents):
        check_directory(parent)
    check_directory(MANAGEMENT, 0o700)
    authority = MANAGEMENT / 'host-login-authority'
    signer_directory = MANAGEMENT / 'host-login-signer'
    check_directory(authority, 0o700)
    check_directory(signer_directory, 0o700)
    registration = read_json(authority / 'channel-registration.json')
    seed = signer_directory / 'signing-seed'
    check_file(seed)
    signer = Ed25519PrivateKey.from_private_bytes(seed.read_bytes())
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as listener:
        listener.bind((socket.VMADDR_CID_HOST, PORT))
        listener.listen(CONNECTION_LIMIT)
        serve(listener, registration, MANAGEMENT, signer)


if __name__ == '__main__':
    main()
