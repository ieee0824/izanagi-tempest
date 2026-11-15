#!/usr/bin/env python3
"""Root-only fork-stop test: guardian cannot outlive a successful startup failure."""
from linux_existing_cgroup_smoke import run_fixture

FIXTURE = r'''
import ctypes, json, os, pathlib, select, signal, subprocess, sys, time
root = pathlib.Path('/sys/fs/cgroup/tempest-linux-isolation-probe')
run = pathlib.Path('/run/tempest-linux-isolation-probe')
assert not root.exists() and not run.exists()
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_long
process = subprocess.Popen([sys.argv[1], 'linux-isolation-probe'], env={},
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
guardian = None
guardian_handle = None
stage = 'seize'
report = None
output = b''
errors = b''
try:
    # Trace only our own root dummy process. No ptrace/sysctl setting changes.
    assert libc.ptrace(0x4206, process.pid, None, ctypes.c_void_p(2 | (1 << 20))) == 0
    stage = 'fork_event'
    until = time.monotonic() + 8
    while time.monotonic() < until:
        waited, status = os.waitpid(process.pid, os.WNOHANG | 0x40000000)
        if waited:
            assert os.WIFSTOPPED(status) and status >> 16 == 1
            message = ctypes.c_ulong()
            assert libc.ptrace(0x4201, process.pid, None, ctypes.byref(message)) == 0
            guardian = message.value
            break
        time.sleep(0.001)
    assert guardian is not None
    guardian_handle = os.pidfd_open(guardian)
    stage = 'freeze_guardian'
    _, stopped = os.waitpid(guardian, 0x40000000)
    assert os.WIFSTOPPED(stopped)
    assert not root.exists()
    # The child is stopped before its first post-fork instruction. Detach it
    # into SIGSTOP, then resume only the owner to run its real ACK timeout.
    # The inherited PTRACE_EVENT stop is not a signal-delivery stop: detach
    # cannot inject SIGSTOP there. Queue it, resume to its delivery stop, and
    # only then detach while delivering the actual signal.
    signal.pidfd_send_signal(guardian_handle, signal.SIGSTOP)
    assert libc.ptrace(7, guardian, None, None) == 0
    _, stopped = os.waitpid(guardian, 0x40000000)
    assert os.WIFSTOPPED(stopped) and os.WSTOPSIG(stopped) == signal.SIGSTOP
    assert not root.exists()
    assert libc.ptrace(17, guardian, None, ctypes.c_void_p(signal.SIGSTOP)) == 0
    assert libc.ptrace(17, process.pid, None, None) == 0
    stage = 'timeout_reap'
    output, errors = process.communicate(timeout=15)
    report = json.loads(output)
    stage = 'startup_result'
    assert process.returncode != 0 and report['reason'] == 'watchdog_startup_failed'
    assert report['resources_removed'] is True
    assert select.select([guardian_handle], [], [], 0)[0]
    assert not root.exists() and not run.exists()
    stage = 'next_generation'
    follow = subprocess.Popen([sys.argv[1], 'linux-isolation-probe'], env={},
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        until = time.monotonic() + 10
        admitted = False
        while time.monotonic() < until:
            assert follow.poll() is None
            try:
                if (root / 'a' / 'cgroup.procs').read_text().split():
                    admitted = True
                    break
            except FileNotFoundError:
                pass
            time.sleep(0.002)
        assert admitted
    finally:
        follow.kill()
        follow.wait(timeout=5)
    until = time.monotonic() + 10
    while time.monotonic() < until and (root.exists() or run.exists()):
        time.sleep(0.02)
    assert not root.exists() and not run.exists()
    print(json.dumps({'status': 'passed', 'guardian_stopped_before_create': True,
                      'guardian_reaped_before_removed': True, 'next_generation_admitted': True,
                      'resources_removed': True}))
except BaseException as error:
    reason = report.get('reason') if isinstance(report, dict) else 'other'
    allowed = {'watchdog_startup_failed', 'watchdog_guardian_unconfirmed', 'run_cleanup', 'identity', 'kernel', 'other'}
    print(json.dumps({'status': 'failed', 'scenario': 'guardian_before_create', 'fixture_stage': stage,
                      'probe_reason': reason if reason in allowed else 'other',
                      'probe_removed': bool(report.get('resources_removed')) if isinstance(report, dict) else False,
                      'failure_kind': 'timeout' if isinstance(error, subprocess.TimeoutExpired) else 'parse' if isinstance(error, ValueError) else 'assertion',
                      'exit_code': process.returncode, 'stdout_bytes': len(output), 'stderr_bytes': len(errors)}))
    raise
finally:
    if process.poll() is None:
        process.kill()
        process.wait(timeout=5)
    if guardian_handle is not None:
        try: signal.pidfd_send_signal(guardian_handle, signal.SIGKILL)
        except ProcessLookupError: pass
        os.close(guardian_handle)
'''

if __name__ == '__main__':
    raise SystemExit(run_fixture(FIXTURE, 'guardian_startup_recovery_fixture', timeout=45))
