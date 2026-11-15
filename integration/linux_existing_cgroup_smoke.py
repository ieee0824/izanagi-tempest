#!/usr/bin/env python3
"""Explicit root fixture: a rejected new probe must preserve an existing group.

Run as the normal dedicated-VM user. Uses only a dummy sleep process and the
fixed repository binary. No credentials, model, network or persistent changes.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

from linux_isolation_smoke import privileged

FIXTURE = r'''
import json, os, pathlib, subprocess, sys
root = pathlib.Path('/sys/fs/cgroup/tempest-linux-isolation-probe')
run = pathlib.Path('/run/tempest-linux-isolation-probe')
if root.exists() or run.exists():
    raise SystemExit(2)
root.mkdir()
identity = (root.stat().st_dev, root.stat().st_ino)
child = None
try:
    (root / 'memory.max').write_text('67108864')
    (root / 'pids.max').write_text('4')
    child = subprocess.Popen(['/usr/bin/sleep', '30'], stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (root / 'cgroup.procs').write_text(str(child.pid))
    def snapshot():
        stat = root.stat()
        return ((stat.st_dev, stat.st_ino), sorted(p.name for p in root.iterdir()),
                [(n, (root / n).read_text()) for n in
                 ['memory.max', 'pids.max', 'cpu.max', 'cgroup.subtree_control', 'cgroup.procs']])
    before = snapshot()
    result = subprocess.run([sys.argv[1], 'linux-isolation-probe'], env={},
                            capture_output=True, timeout=12)
    report = json.loads(result.stdout)
    assert result.returncode != 0 and report['status'] == 'failed'
    assert report['phase'] == 'watchdog'
    assert before == snapshot() and child.poll() is None
    # The failed probe owns only this empty run lock, not the existing cgroup.
    # Never recursively delete unexpected entries from a failed probe.
    if run.exists():
        assert not list(run.iterdir())
        run.rmdir()
    print(json.dumps({'status': 'passed', 'existing_group_unchanged': True,
                      'existing_process_alive': True}))
finally:
    if child is not None:
        child.kill()
        child.wait(timeout=5)
    if root.exists() and (root.stat().st_dev, root.stat().st_ino) == identity:
        root.rmdir()
'''


def main():
    if len(sys.argv) != 1 or sys.platform != 'linux' or os.geteuid() == 0:
        print(json.dumps({'status': 'rejected', 'reason': 'nonroot_dedicated_vm_entry_required'}))
        return 2
    source = Path(__file__).resolve().parent.parent / 'target/debug/tempest'
    root = Path('/var/lib') / ('tempest-probe-install-' + uuid.uuid4().hex)
    installed = root / 'tempest'
    created = False
    try:
        if privileged('/usr/bin/mkdir', '-m', '0700', '--', str(root)).returncode:
            raise RuntimeError
        created = True
        if privileged('/usr/bin/install', '-o', 'root', '-g', 'root', '-m', '0700', '--', str(source), str(installed)).returncode:
            raise RuntimeError
        result = privileged('/usr/bin/python3', '-c', FIXTURE, str(installed), timeout=25)
        if result.returncode != 0:
            raise RuntimeError
        report = json.loads(result.stdout)
        print(json.dumps(report))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        print(json.dumps({'status': 'failed', 'reason': 'existing_group_preservation_fixture'}))
        return 1
    finally:
        if created:
            privileged('/usr/bin/rm', '-f', '--', str(installed))
            privileged('/usr/bin/rmdir', '--', str(root))


if __name__ == '__main__':
    raise SystemExit(main())
