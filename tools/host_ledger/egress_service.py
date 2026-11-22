"""Independent egress pool and host-original watchdog in the control daemon."""
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import threading
import time

from channel import REQUEST_SECONDS
from egress_authority import CONNECTION_LIMIT
from egress_channel import serve_connection

CHECK_SECONDS = 0.25
REJECTIONS = (OSError, ValueError, KeyError, TypeError, sqlite3.Error)


def watch_originals(authorization, validate_current, stop_event):
    """Only host originals are checked here; this never renews control freshness."""
    try:
        while not stop_event.is_set():
            validate_current(time.monotonic() + CHECK_SECONDS)
            # Evaluation itself makes an elapsed control lease irreversible.
            authorization.current()
            stop_event.wait(CHECK_SECONDS)
    except REJECTIONS:
        authorization.stop()
        stop_event.set()
    finally:
        authorization.stop()


def serve_data(listener, registration, policy, authorization, signer,
               absolute_deadline, validate_current, stop_event):
    """The four data slots are unrelated to the control daemon's eight slots."""
    slots = threading.BoundedSemaphore(CONNECTION_LIMIT)

    def handle(connection, peer, deadline):
        try:
            with connection:
                serve_connection(connection, peer[0], registration, policy, authorization,
                                 signer, deadline, absolute_deadline, validate_current)
        except REJECTIONS:
            # Invalid guest requests never get a ready receipt or data mode.
            pass
        finally:
            slots.release()

    try:
        with ThreadPoolExecutor(max_workers=CONNECTION_LIMIT) as workers:
            try:
                while not stop_event.is_set():
                    try:
                        connection, peer = listener.accept()
                    except TimeoutError:
                        continue
                    except OSError:
                        if stop_event.is_set():
                            break
                        raise
                    if stop_event.is_set() or not slots.acquire(blocking=False):
                        connection.close()
                        continue
                    deadline = time.monotonic() + REQUEST_SECONDS
                    try:
                        workers.submit(handle, connection, peer, deadline)
                    except BaseException:
                        connection.close()
                        slots.release()
                        raise
            finally:
                # Stop before the pool joins, including listener failure.
                authorization.stop()
    finally:
        authorization.stop()
        stop_event.set()


def serve_both(control_listener, data_listener, registration, management, policy,
               authorization, signer, absolute_deadline, validate_current, stop_event):
    """Run listeners and original checks in one process with shared run state."""
    import broker

    def run_data():
        try:
            serve_data(data_listener, registration, policy, authorization, signer,
                       absolute_deadline, validate_current, stop_event)
        finally:
            authorization.stop()
            stop_event.set()

    monitor = threading.Thread(target=watch_originals,
                               args=(authorization, validate_current, stop_event))
    data = threading.Thread(target=run_data)
    # All listener accept calls must periodically observe daemon shutdown.
    control_listener.settimeout(CHECK_SECONDS)
    data_listener.settimeout(CHECK_SECONDS)
    monitor.start()
    data.start()
    try:
        broker.serve(control_listener, registration, management, signer, stop_event,
                     authorization=authorization)
    finally:
        authorization.stop()
        stop_event.set()
        monitor.join()
        data.join()
