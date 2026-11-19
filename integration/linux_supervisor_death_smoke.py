#!/usr/bin/env python3
"""Explicit root integration: SIGKILL after admission or detached grandchild observation."""
from linux_existing_cgroup_smoke import run_fixture

FIXTURE = r'''
import json, os, pathlib, signal, subprocess, sys, time
root = pathlib.Path('/sys/fs/cgroup/tempest-linux-isolation-probe')
run = pathlib.Path('/run/tempest-linux-isolation-probe')
if root.exists() or run.exists():
    raise SystemExit(2)
results = []
for scenario in ['initial_admission', 'detached_grandchild', 'lease_stopped']:
    process = subprocess.Popen([sys.argv[1], 'linux-isolation-probe'], env={},
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    stage = 'select_target'
    handles = []
    status_reader = None
    watchdog_handle = None
    try:
        until = time.monotonic() + 20
        while time.monotonic() < until:
            if process.poll() is not None:
                raise RuntimeError('supervisor_exited_before_injection')
            try:
                # Select real kernel processes, never a readiness marker file.
                pids = [int(pid) for pid in (root / 'a' / 'cgroup.procs').read_text().split()]
                selected = bool(pids) and scenario == 'initial_admission'
                if scenario in ['detached_grandchild', 'lease_stopped'] and len(pids) == 2:
                    states = {}
                    for pid in pids:
                        tail = pathlib.Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
                        states[pid] = tuple(int(value) for value in tail[1:4])
                    for pid, (parent, group_id, session) in states.items():
                        if parent in states and group_id == session and group_id > 0 and group_id != pid:
                            if session != states[parent][2] and group_id != states[parent][1]:
                                selected = True
                if selected:
                    # Stop the supervisor before pinning: it cannot normally
                    # clean up or advance to another case during our checks.
                    os.kill(process.pid, signal.SIGSTOP)
                    _, status = os.waitpid(process.pid, os.WUNTRACED)
                    assert os.WIFSTOPPED(status)
                    assert set(pids) == set(int(pid) for pid in (root / 'a' / 'cgroup.procs').read_text().split())
                    try:
                        for pid in pids:
                            handles.append(os.pidfd_open(pid))
                    except BaseException:
                        for handle in handles:
                            os.close(handle)
                        handles = []
                        raise
                    if scenario in ['detached_grandchild', 'lease_stopped']:
                        for pid in pids:
                            tail = pathlib.Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
                            assert tuple(int(value) for value in tail[1:4]) == states[pid]
                    break
            except (FileNotFoundError, ProcessLookupError):
                pass
            time.sleep(0.0005)
        assert handles
        # Duplicate only the private, typed guardian status pipe. Prove it is
        # the same FIFO inode as the guardian's write end, never an arbitrary fd.
        stage = 'status_metadata'
        metadata = json.loads((run / 'watchdog.channel').read_bytes())
        assert set(metadata) == {'watchdog_pid', 'status_fd'}
        watcher = int(metadata['watchdog_pid'])
        status_fd = int(metadata['status_fd'])
        assert pathlib.Path(f'/proc/{watcher}/stat').read_text().rsplit(')', 1)[1].split()[1] == str(process.pid)
        source = pathlib.Path(f'/proc/{process.pid}/fd/{status_fd}')
        target_stat = source.stat()
        import stat
        assert stat.S_ISFIFO(target_stat.st_mode)
        matches = []
        for candidate in pathlib.Path(f'/proc/{watcher}/fd').iterdir():
            m = candidate.stat()
            if (m.st_dev, m.st_ino) == (target_stat.st_dev, target_stat.st_ino):
                flags = pathlib.Path(f'/proc/{watcher}/fdinfo/{candidate.name}').read_text()
                access = int(next(line.split()[1] for line in flags.splitlines() if line.startswith('flags:')), 8) & os.O_ACCMODE
                matches.append(access == os.O_WRONLY)
        assert matches == [True]
        stage = 'open_status_channel'
        status_reader = os.open(source, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        watchdog_handle = os.pidfd_open(watcher)
        stage = 'owner_stop'
        if scenario != 'lease_stopped':
            os.kill(process.pid, signal.SIGKILL)
        # lease_stopped stays SIGSTOP'ed: the guardian must kill the owner
        # itself before acquiring cleanup ownership.
        assert process.wait(timeout=12) == -signal.SIGKILL
        stage = 'recovery_paths'
        until = time.monotonic() + 10
        while time.monotonic() < until and (root.exists() or run.exists()):
            time.sleep(0.02)
        assert not root.exists() and not run.exists()
        import select
        assert all(select.select([handle], [], [], 0)[0] for handle in handles)
        assert select.select([watchdog_handle], [], [], 5)[0]
        stage = 'decode_status'
        data = bytearray()
        while True:
            try:
                chunk = os.read(status_reader, 512)
            except BlockingIOError:
                break
            if not chunk:
                break
            data.extend(chunk)
            assert len(data) <= 2048
        statuses = [json.loads(line) for line in data.splitlines()]
        reason = 'lease_expired' if scenario == 'lease_stopped' else 'owner_dead'
        expected = ['owner_stopping', 'watchdog_owned', 'recovered'] if scenario == 'lease_stopped' else ['watchdog_owned', 'recovered']
        stage = 'validate_status'
        assert [value['transition'] for value in statuses] == expected
        assert all(value['reason'] == reason and value['trigger'] == reason for value in statuses)
        assert all(value['owner_dead'] for value in statuses if value['transition'] != 'owner_stopping')
        assert all(0 <= value['elapsed_ms'] <= 3600000 for value in statuses)
        results.append({'scenario': scenario, 'owner_signal': 'sigkill',
                        'admitted_payloads_dead': True, 'resources_removed': True,
                        'watchdog_status': statuses})
    except BaseException:
        print(json.dumps({'status': 'failed', 'scenario': scenario, 'fixture_stage': stage}))
        raise
    finally:
        for handle in handles:
            os.close(handle)
        if status_reader is not None: os.close(status_reader)
        if watchdog_handle is not None: os.close(watchdog_handle)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        # Never adopt or delete leftovers; preserve evidence on any failure.
print(json.dumps({'status': 'passed', 'cases': results}))
'''

if __name__ == '__main__':
    raise SystemExit(run_fixture(FIXTURE, 'supervisor_death_recovery_fixture', timeout=90))
