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
    for attempt in range(2):
        result = subprocess.run([sys.argv[1], 'linux-isolation-probe'], env={},
                                capture_output=True, timeout=12)
        report = json.loads(result.stdout)
        assert result.returncode != 0 and report['status'] == 'failed'
        assert report['phase'] == 'watchdog'
        assert before == snapshot() and child.poll() is None
        assert not run.exists()
    # No external cleanup occurs between the two rejected invocations above.
    # Freeze only AFTER a real directory FD pins RUN. This prevents a path
    # mutation from occurring before the supervisor acquires its own identity.
    for mutation in ['entry', 'replacement']:
        proc = subprocess.Popen([sys.argv[1], 'linux-isolation-probe'], env={},
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stopped = False
        try:
            import time, signal, stat
            until = time.monotonic() + 5
            while time.monotonic() < until and proc.poll() is None:
                try:
                    original = run.stat()
                    for fd in pathlib.Path(f'/proc/{proc.pid}/fd').iterdir():
                        m = fd.stat()
                        if stat.S_ISDIR(m.st_mode) and (m.st_dev, m.st_ino) == (original.st_dev, original.st_ino):
                            os.kill(proc.pid, signal.SIGSTOP)
                            _, status = os.waitpid(proc.pid, os.WUNTRACED)
                            assert os.WIFSTOPPED(status)
                            stopped = True
                            break
                except FileNotFoundError:
                    pass
                if stopped:
                    break
                time.sleep(0.0001)
            assert stopped
            current = run.stat()
            original_identity = (original.st_dev, original.st_ino)
            assert (current.st_dev, current.st_ino) == original_identity
            alternate = run.with_name('tempest-linux-isolation-probe-negative-original')
            assert not alternate.exists()
            if mutation == 'entry':
                marker = run / 'unexpected-fixed-marker'
                marker.touch(exist_ok=False)
            else:
                run.rename(alternate)
                run.mkdir(mode=0o700)
                replacement_identity = (run.stat().st_dev, run.stat().st_ino)
            os.kill(proc.pid, signal.SIGCONT)
            stopped = False
            output, _ = proc.communicate(timeout=12)
            report = json.loads(output)
            assert proc.returncode != 0 and report['reason'] == 'run_cleanup'
            assert report['resources_removed'] is False
            assert before == snapshot() and child.poll() is None
            if mutation == 'entry':
                assert (run.stat().st_dev, run.stat().st_ino) == original_identity
                assert marker.exists()
                marker.unlink()
                run.rmdir()
            else:
                assert (run.stat().st_dev, run.stat().st_ino) == replacement_identity
                assert (alternate.stat().st_dev, alternate.stat().st_ino) == original_identity
                run.rmdir()
                alternate.rmdir()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
    print(json.dumps({'status': 'passed', 'existing_group_unchanged': True,
                      'existing_process_alive': True, 'rejected_twice_without_cleanup': True, 'run_entry_retained': True, 'run_replacement_retained': True}))
finally:
    if child is not None:
        child.kill()
        child.wait(timeout=5)
    if root.exists() and (root.stat().st_dev, root.stat().st_ino) == identity:
        root.rmdir()
'''


def run_fixture(fixture, failure_reason, timeout=25):
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
        result = privileged('/usr/bin/python3', '-c', fixture, str(installed), timeout=timeout)
        if result.returncode != 0:
            try:
                diagnostic = json.loads(result.stdout)
                if isinstance(diagnostic, dict) and {'status', 'scenario', 'fixture_stage'} <= set(diagnostic) <= {'status', 'scenario', 'fixture_stage', 'probe_reason', 'probe_removed', 'failure_kind', 'exit_code', 'stdout_bytes', 'stderr_bytes', 'completed_cases'}:
                    scenarios = {'initial_admission', 'detached_grandchild', 'lease_stopped', 'guardian_before_create', 'guardian_after_create', 'guardian_before_ack', 'guardian_after_ack', 'guardian_ack_timeout', 'guardian_admission', 'guardian_payload', 'guardian_collector', 'guardian_stopped', 'primary_eof_guardian_death', 'primary_output_cleanup_eio'}
                    stages = {'select_target', 'status_metadata', 'open_status_channel', 'owner_stop', 'recovery_paths', 'decode_status', 'validate_status', 'seize', 'fork_event', 'freeze_guardian', 'timeout_reap', 'next_generation', 'startup_result', 'ack_timeout_parent', 'guardian_stop', 'cleanup_entry', 'pin_roles', 'inject_secondary'}
                    if (diagnostic['status'] == 'failed' and diagnostic['scenario'] in scenarios and diagnostic['fixture_stage'] in stages
                            and diagnostic.get('probe_reason', 'other') in {'watchdog_startup_failed', 'watchdog_guardian_unconfirmed', 'run_cleanup', 'identity', 'kernel', 'other', 'child_exit', 'child_signal', 'watchdog_guardian_died', 'watchdog_lease_unavailable'}
                            and type(diagnostic.get('probe_removed', False)) is bool
                            and diagnostic.get('failure_kind', 'assertion') in {'timeout', 'parse', 'assertion'}
                            and type(diagnostic.get('completed_cases',0)) is int and 0 <= diagnostic.get('completed_cases',0) <= 4
                            and (diagnostic.get('exit_code') is None or type(diagnostic['exit_code']) is int and -128 <= diagnostic['exit_code'] <= 255)
                            and all(type(diagnostic.get(key, 0)) is int and 0 <= diagnostic.get(key, 0) <= 65536 for key in ['stdout_bytes', 'stderr_bytes'])):
                        print(json.dumps(diagnostic))
                        return 1
            except (ValueError, TypeError):
                pass
            raise RuntimeError
        report = json.loads(result.stdout)
        print(json.dumps(report))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        print(json.dumps({'status': 'failed', 'reason': failure_reason}))
        return 1
    finally:
        if created:
            privileged('/usr/bin/rm', '-f', '--', str(installed))
            privileged('/usr/bin/rmdir', '--', str(root))


if __name__ == '__main__':
    raise SystemExit(run_fixture(FIXTURE, 'existing_group_preservation_fixture'))
