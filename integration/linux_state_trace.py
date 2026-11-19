"""x86_64 tracing of an already stopped, owned dummy supervisor only."""
import ctypes
import json
import os
from pathlib import Path
import select
import signal
import stat
import time
import platform

from linux_state_observer import DIRECTORY_FLAGS, observe_home

LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
LIBC.ptrace.restype = ctypes.c_long
RUN = Path('/run/tempest-linux-isolation-probe')


def ptrace(request, pid, address=0, data=0):
    result = LIBC.ptrace(request, pid, ctypes.c_void_p(address), ctypes.c_void_p(data))
    if result == -1:
        raise OSError(ctypes.get_errno(), 'fixed_trace_operation')
    return result


def lineage(pid):
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return int(fields[1]), int(fields[19])


class StateTrace:
    def __init__(self, process):
        if platform.machine() != 'x86_64':
            raise ValueError('unsupported_trace_architecture')
        self.process = process
        self.birth = lineage(process.pid)
        if self.birth[0] != os.getpid():
            raise ValueError('tracee_not_owned')
        self.pidfd = os.pidfd_open(process.pid)
        self.captures = []
        self.previous = None
        self.nonces = {}
        self.progress_fd = None

    def bound(self):
        if (lineage(self.process.pid) != self.birth
                or select.select([self.pidfd], [], [], 0)[0]):
            raise ValueError('tracee_identity')

    def stop(self, until):
        while time.monotonic() < until:
            waited, status = os.waitpid(self.process.pid, os.WNOHANG | 0x40000000)
            if waited:
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    self.process.returncode = os.waitstatus_to_exitcode(status)
                    raise ValueError('tracee_terminal_before_capture')
                if not os.WIFSTOPPED(status):
                    raise ValueError('tracee_stop_invalid')
                return os.WSTOPSIG(status)
            time.sleep(0.0001)
        raise ValueError('trace_deadline')

    def capture(self):
        self.bound()
        ptrace(0x4200, self.process.pid, data=1)  # SETOPTIONS/TRACESYSGOOD only
        until = time.monotonic() + 20
        pending = None
        deliver = 0
        while len(self.captures) < 2:
            ptrace(24, self.process.pid, data=deliver)
            stopped = self.stop(until)
            deliver = 0
            if stopped != signal.SIGTRAP | 0x80:
                deliver = 0 if stopped == signal.SIGTRAP else stopped
                continue
            registers = (ctypes.c_ulonglong * 27)()
            ptrace(12, self.process.pid, data=ctypes.addressof(registers))
            if registers[15] != 1:  # orig_rax != SYS_write
                continue
            if registers[10] == 2**64 - 38:  # entry rax=-ENOSYS
                pending = None
                size = registers[12]  # rdx
                if not 1 <= size <= 4096:
                    continue
                with open(f'/proc/{self.process.pid}/mem', 'rb', buffering=0) as memory:
                    memory.seek(registers[13])  # rsi
                    raw = memory.read(size)
                try:
                    value = json.loads(raw)
                except (ValueError, UnicodeError):
                    continue
                if not isinstance(value, dict):
                    continue
                run = value.get('scenario')
                if run not in ['state_run1', 'state_run2']:
                    continue
                if set(value) == {'scenario', 'role', 'nonce', 'supervisor', 'peers'}:
                    nonce = value['nonce']
                    if (not isinstance(nonce, list) or len(nonce) != 16
                            or any(type(n) is not int or not 0 <= n <= 255 for n in nonce)
                            or value['supervisor'] != self.process.pid):
                        raise ValueError('manifest_binding')
                    if run in self.nonces and self.nonces[run] != nonce:
                        raise ValueError('manifest_nonce_mismatch')
                    self.nonces[run] = nonce
                if value != {'scenario': run, 'phase': 'barrier'}:
                    continue
                if size > 128 or run != ['state_run1', 'state_run2'][len(self.captures)]:
                    raise ValueError('capture_order')
                fd_path = Path(f'/proc/{self.process.pid}/fd/{registers[14]}')
                self.progress_fd = os.open(fd_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
                metadata = os.fstat(self.progress_fd)
                named = (RUN / 'progress').lstat()
                if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                        or stat.S_IMODE(metadata.st_mode) != 0o600
                        or (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)):
                    raise ValueError('progress_identity')
                pending = run, size, (metadata.st_dev, metadata.st_ino)
            elif pending is not None:
                started = time.monotonic()
                run, size, progress_identity = pending
                pending = None
                if registers[10] != size or run not in self.nonces:
                    raise ValueError('progress_write_failed')
                after = os.fstat(self.progress_fd)
                named = (RUN / 'progress').lstat()
                raw = os.pread(self.progress_fd, 129, 0)
                if ((after.st_dev, after.st_ino) != progress_identity
                        or (named.st_dev, named.st_ino) != progress_identity
                        or len(raw) > 128
                        or json.loads(raw) != {'scenario':run, 'phase':'barrier'}):
                    raise ValueError('progress_changed')
                os.close(self.progress_fd)
                self.progress_fd = None
                self.bound()
                fd = os.open(RUN, DIRECTORY_FLAGS)
                try:
                    self.previous = observe_home(fd, self.previous)
                finally:
                    os.close(fd)
                self.captures.append({'scenario': run, 'nonce': self.nonces[run],
                                      'host': self.previous})
                if time.monotonic() - started > 0.1:
                    raise ValueError('capture_stop_budget')
        ptrace(17, self.process.pid)  # DETACH, resume normal supervision
        return self.captures

    def close(self):
        if self.progress_fd is not None:
            os.close(self.progress_fd)
            self.progress_fd = None
        os.close(self.pidfd)
