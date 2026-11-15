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
for scenario in ['initial_admission', 'detached_grandchild']:
    process = subprocess.Popen([sys.argv[1], 'linux-isolation-probe'], env={},
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    handles = []
    try:
        until = time.monotonic() + 20
        while time.monotonic() < until:
            if process.poll() is not None:
                raise RuntimeError('supervisor_exited_before_injection')
            try:
                # Select real kernel processes, never a readiness marker file.
                pids = [int(pid) for pid in (root / 'a' / 'cgroup.procs').read_text().split()]
                selected = bool(pids) and scenario == 'initial_admission'
                if scenario == 'detached_grandchild' and len(pids) == 2:
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
                    if scenario == 'detached_grandchild':
                        for pid in pids:
                            tail = pathlib.Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
                            assert tuple(int(value) for value in tail[1:4]) == states[pid]
                    break
            except (FileNotFoundError, ProcessLookupError):
                pass
            time.sleep(0.0005)
        assert handles
        os.kill(process.pid, signal.SIGKILL)
        assert process.wait(timeout=5) == -signal.SIGKILL
        until = time.monotonic() + 10
        while time.monotonic() < until and (root.exists() or run.exists()):
            time.sleep(0.02)
        assert not root.exists() and not run.exists()
        import select
        assert all(select.select([handle], [], [], 0)[0] for handle in handles)
        results.append({'scenario': scenario, 'supervisor_sigkill': True,
                        'admitted_payloads_dead': True, 'resources_removed': True})
    finally:
        for handle in handles:
            os.close(handle)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        # Never adopt or delete leftovers; preserve evidence on any failure.
print(json.dumps({'status': 'passed', 'cases': results}))
'''

if __name__ == '__main__':
    raise SystemExit(run_fixture(FIXTURE, 'supervisor_death_recovery_fixture', timeout=60))
