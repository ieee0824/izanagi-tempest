"""Unprivileged check of pidfd handoff and subreaper wait ownership."""
import ctypes
import errno
import os
import select
import signal
import socket

libc = ctypes.CDLL(None, use_errno=True)
PR_SET_CHILD_SUBREAPER = 36


def run_case(handoff, released=False):
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "set subreaper")
    upper, lower = socket.socketpair(type=socket.SOCK_SEQPACKET)
    upper.settimeout(2)
    supervisor = os.fork()
    if supervisor == 0:
        upper.close()
        gate_read, gate_write = os.pipe()
        receipt_read, receipt_write = os.pipe()
        worker = os.fork()
        if worker == 0:
            lower.close()
            os.close(gate_write)
            os.close(receipt_read)
            gate_byte = os.read(gate_read, 1)
            if released and gate_byte == b"R":
                os.write(receipt_write, b"R")
                signal.pause()
                os._exit(4)
            os._exit(0 if gate_byte == b"" else 1)
        os.close(gate_read)
        os.close(receipt_write)
        if handoff:
            with_pidfd = os.pidfd_open(worker)
            socket.send_fds(lower, [str(worker).encode()], [with_pidfd])
        else:
            lower.send(str(worker).encode())
        if lower.recv(1) != b"A":
            os._exit(2)
        if released:
            os.write(gate_write, b"R")
            if os.read(receipt_read, 1) != b"R":
                os._exit(5)
            lower.send(b"R")
        signal.pause()
        os._exit(3)

    lower.close()
    supervisor_fd = os.pidfd_open(supervisor)
    payload, fds, flags, _ = socket.recv_fds(upper, 32, 1)
    assert len(fds) == int(handoff) and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
    worker = int(payload)
    worker_fd = fds[0] if handoff else None
    if handoff:
        try:
            os.waitid(os.P_PIDFD, worker_fd, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError as exc:
            assert exc.errno == errno.ECHILD
        else:
            raise AssertionError("worker already waitable before supervisor exit")
    upper.send(b"A")
    if released:
        assert upper.recv(1) == b"R"
    signal.pidfd_send_signal(supervisor_fd, signal.SIGKILL)
    assert select.select([supervisor_fd], [], [], 2)[0]
    supervisor_status = os.waitid(os.P_PIDFD, supervisor_fd, os.WEXITED)
    assert supervisor_status.si_code == os.CLD_KILLED
    assert supervisor_status.si_status == signal.SIGKILL
    if released:
        assert os.waitid(os.P_PIDFD, worker_fd,
                         os.WEXITED | os.WNOHANG | os.WNOWAIT) is None
        signal.pidfd_send_signal(worker_fd, signal.SIGKILL)
    if handoff:
        assert select.select([worker_fd], [], [], 2)[0]
        worker_status = os.waitid(os.P_PIDFD, worker_fd, os.WEXITED)
        os.close(worker_fd)
    else:
        worker_status = os.waitid(os.P_PID, worker, os.WEXITED)
    assert worker_status.si_pid == worker
    if released:
        assert worker_status.si_code == os.CLD_KILLED
        assert worker_status.si_status == signal.SIGKILL
    else:
        assert worker_status.si_code == os.CLD_EXITED and worker_status.si_status == 0
    os.close(supervisor_fd)
    upper.close()
    print(f"handoff={handoff} supervisor=killed worker=adopted-and-reaped released={released}")


if __name__ == "__main__":
    run_case(False)
    run_case(True)
    run_case(True, released=True)
