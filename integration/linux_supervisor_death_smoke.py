#!/usr/bin/env python3
"""Explicit root integration: SIGKILL of supervisor after payload admission."""
from linux_existing_cgroup_smoke import run_fixture

FIXTURE = r'''
import json, os, pathlib, signal, subprocess, sys, time
root = pathlib.Path('/sys/fs/cgroup/tempest-linux-isolation-probe')
run = pathlib.Path('/run/tempest-linux-isolation-probe')
if root.exists() or run.exists():
    raise SystemExit(2)
process = subprocess.Popen([sys.argv[1], 'linux-isolation-probe'], env={},
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
admitted = False
try:
    until = time.monotonic() + 10
    while time.monotonic() < until:
        if process.poll() is not None:
            raise RuntimeError('supervisor_exited_before_injection')
        try:
            # Select a real kernel-observed admitted payload, not a state file.
            pids = (root / 'a' / 'cgroup.procs').read_text().split()
            if pids:
                payloads = [int(p) for p in pids]
                # Bind each observed PID to a pidfd before killing supervisor.
                handles = [os.pidfd_open(pid) for pid in payloads]
                admitted = True
                break
        except FileNotFoundError:
            pass
        time.sleep(0.002)
    assert admitted
    os.kill(process.pid, signal.SIGKILL)
    assert process.wait(timeout=5) == -signal.SIGKILL
    until = time.monotonic() + 10
    while time.monotonic() < until and (root.exists() or run.exists()):
        time.sleep(0.02)
    assert not root.exists() and not run.exists()
    import select
    for handle in handles:
        assert select.select([handle], [], [], 0)[0]
        os.close(handle)
    print(json.dumps({'status': 'passed', 'supervisor_sigkill': True,
                      'admitted_payloads_dead': True, 'resources_removed': True}))
finally:
    if process.poll() is None:
        process.kill()
        process.wait(timeout=5)
    # Never adopt or delete leftovers; a failure must preserve evidence and
    # cause a subsequent probe to refuse to run.
'''

if __name__ == '__main__':
    raise SystemExit(run_fixture(FIXTURE, 'supervisor_death_recovery_fixture'))
