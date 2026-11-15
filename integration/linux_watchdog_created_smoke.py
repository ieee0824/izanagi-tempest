#!/usr/bin/env python3
"""Stop our own guardian after creation or at the ACK write syscall entry."""
from linux_existing_cgroup_smoke import run_fixture

FIXTURE = r'''
import ctypes, json, os, pathlib, platform, select, signal, stat, subprocess, sys, time
assert platform.machine() == 'x86_64'
root = pathlib.Path('/sys/fs/cgroup/tempest-linux-isolation-probe')
run = pathlib.Path('/run/tempest-linux-isolation-probe')
assert not root.exists() and not run.exists()
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_long
results = []
for scenario in ['guardian_after_create', 'guardian_before_ack', 'guardian_after_ack']:
    process = subprocess.Popen([sys.argv[1], 'linux-isolation-probe'], env={},
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    guardian_handle = directory = None
    stage = 'seize'
    try:
        assert libc.ptrace(0x4206, process.pid, None, ctypes.c_void_p(2 | (1 << 20))) == 0
        stage = 'fork_event'
        until = time.monotonic() + 8
        guardian = None
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
        _, status = os.waitpid(guardian, 0x40000000)
        assert os.WIFSTOPPED(status) and not root.exists()
        # x86_64 syscall stops only; no EXIT trace-stop can delay SIGKILL exit.
        assert libc.ptrace(0x4200, guardian, None, ctypes.c_void_p(1 | (1 << 20))) == 0
        stage = 'freeze_guardian'
        until = time.monotonic() + 8
        while True:
            assert time.monotonic() < until
            assert libc.ptrace(24, guardian, None, None) == 0
            _, status = os.waitpid(guardian, 0x40000000)
            assert os.WIFSTOPPED(status) and os.WSTOPSIG(status) == (signal.SIGTRAP | 0x80)
            registers = (ctypes.c_ulonglong * 27)()
            assert libc.ptrace(12, guardian, None, ctypes.byref(registers)) == 0
            # orig_rax=write, rdx=20, rax=-ENOSYS identifies ACK syscall entry.
            ack_entry = (registers[15] == 1 and registers[12] == 20
                         and registers[10] == (2**64 - 38))
            selected = root.exists() if scenario == 'guardian_after_create' else ack_entry
            if selected:
                assert root.exists()
                if scenario != 'guardian_after_create':
                    assert all((root / role).is_dir() for role in ['a', 'b', 'guard'])
                    endpoint = pathlib.Path(f'/proc/{guardian}/fd/{registers[14]}').stat()
                    assert stat.S_ISFIFO(endpoint.st_mode)
                    readers = []
                    for fd in pathlib.Path(f'/proc/{process.pid}/fd').iterdir():
                        metadata = fd.stat()
                        if (metadata.st_dev, metadata.st_ino) == (endpoint.st_dev, endpoint.st_ino):
                            flags = pathlib.Path(f'/proc/{process.pid}/fdinfo/{fd.name}').read_text()
                            access = int(next(line.split()[1] for line in flags.splitlines() if line.startswith('flags:')), 8) & os.O_ACCMODE
                            if access == os.O_RDONLY:
                                readers.append(int(fd.name))
                    # The owner is still at its fork event and can also retain
                    # the write end it will close on resumption.
                    assert len(readers) == 1
                else:
                    assert registers[15] in [83, 258] and registers[10] == 0
                directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                pinned = os.fstat(directory)
                identity = (pinned.st_dev, pinned.st_ino)
                break
        ack_written = scenario == 'guardian_after_ack'
        if ack_written:
            assert libc.ptrace(24, guardian, None, None) == 0
            _, status = os.waitpid(guardian, 0x40000000)
            assert os.WIFSTOPPED(status) and os.WSTOPSIG(status) == (signal.SIGTRAP | 0x80)
            assert libc.ptrace(12, guardian, None, ctypes.byref(registers)) == 0
            assert registers[15] == 1 and registers[10] == 20
            signal.pidfd_send_signal(guardian_handle, signal.SIGKILL)
        else:
            assert libc.ptrace(17, process.pid, None, None) == 0
        # Leave the guardian in its exact syscall stop. SIGKILL bypasses that
        # stop; drain the tracer's exit notification so its real parent can reap.
        stage = 'timeout_reap'
        until = time.monotonic() + 10
        while True:
            assert time.monotonic() < until
            waited, status = os.waitpid(guardian, os.WNOHANG | 0x40000000)
            if waited:
                assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
                break
            time.sleep(0.002)
        if ack_written:
            assert select.select([guardian_handle], [], [], 0)[0]
            assert libc.ptrace(17, process.pid, None, None) == 0
        output, _ = process.communicate(timeout=5)
        report = json.loads(output)
        stage = 'startup_result'
        assert process.returncode != 0 and report['reason'] == 'watchdog_startup_failed'
        assert report['phase'] == 'watchdog' and report['watchdog_status'] is None
        assert report['formal_eligible'] is False and report['model_launched'] is False
        assert report['resources_removed'] is False
        assert select.select([guardian_handle], [], [], 0)[0]
        assert not run.exists() and (root.stat().st_dev, root.stat().st_ino) == identity
        def snapshot():
            return [(str(path.relative_to(root)), path.read_text()) for path in sorted(root.rglob('*'))
                    if path.name in ['cgroup.procs', 'memory.max', 'pids.max', 'cpu.max', 'cgroup.subtree_control']]
        before = snapshot()
        stage = 'next_generation'
        rejected = subprocess.run([sys.argv[1], 'linux-isolation-probe'], env={}, capture_output=True, timeout=12)
        rejected_report = json.loads(rejected.stdout)
        assert rejected.returncode != 0 and rejected_report['resources_removed'] is False
        assert rejected_report['phase'] == 'watchdog' and snapshot() == before and not run.exists()
        # Explicit fixture cleanup only: the inode was pinned at our trace-stop,
        # both owner and guardian are dead, and no task may occupy any subgroup.
        assert (root.stat().st_dev, root.stat().st_ino) == identity
        assert not (root / 'cgroup.procs').read_text().split()
        for role in ['a', 'b', 'guard']:
            if (root / role).exists():
                assert not (root / role / 'cgroup.procs').read_text().split()
                os.rmdir(role, dir_fd=directory)
        root.rmdir()
        results.append({'scenario': scenario, 'guardian_reaped': True,
                        'guardian_signal': 'sigkill', 'reason': report['reason'],
                        'phase': report['phase'], 'probe_exit_code': process.returncode,
                        'ack_write_completed': ack_written, 'ownership_confirmed': False,
                        'unproved_group_preserved': True,
                        'resources_removed': report['resources_removed'],
                        'next_generation_rejected_without_mutation': True,
                        'fixture_owned_cleanup': True})
    except BaseException:
        print(json.dumps({'status': 'failed', 'scenario': scenario, 'fixture_stage': stage}))
        raise
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if guardian_handle is not None:
            try: signal.pidfd_send_signal(guardian_handle, signal.SIGKILL)
            except ProcessLookupError: pass
            os.close(guardian_handle)
        if directory is not None: os.close(directory)
print(json.dumps({'status': 'passed', 'cases': results}))
'''

if __name__ == '__main__':
    raise SystemExit(run_fixture(FIXTURE, 'guardian_created_recovery_fixture', timeout=45))
