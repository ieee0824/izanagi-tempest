#!/usr/bin/env python3
"""Explicit root fixture: a rejected new probe must preserve an existing group.

Run as the normal dedicated-VM user. Uses only a dummy sleep process and the
fixed repository binary. No credentials, model, network or persistent changes.
"""
import json
import os
import re
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


def valid_follow_details(diagnostic):
    stages = {None, 'admission', 'metadata', 'lineage', 'writer', 'kill_reap', 'guardian_terminal', 'paths_absent'}
    exceptions = {'AssertionError', 'FileNotFoundError', 'ProcessLookupError', 'PermissionError',
                  'ChildProcessError', 'OSError', 'TimeoutExpired', 'TimeoutError', 'ValueError',
                  'JSONDecodeError', 'KeyError', 'TypeError', 'RuntimeError', 'Other'}
    scenarios = {'baseline', 'foreign_ready', 'fd_file_a', 'fd_file_b', 'fd_directory_a', 'fd_directory_b',
                 'fd_socket_a', 'fd_socket_b', 'control_truncation', 'unexpected_control', 'frame_oversize',
                 'frame_malformed', 'library_late_write', 'library_hardlink', 'library_symlink',
                 'library_replacement', 'pids_limit', 'tmpfs_full', 'detached_grandchild', 'report_timeout',
                 'report_eof', 'cgroup_kill_noop', 'memory_oom', 'stdout_flood', 'stderr_flood',
                 'peer_stdout_flood', 'continuous_stdout', 'other'}
    progress = diagnostic.get('follow_last_progress')
    return (diagnostic.get('follow_stage') in stages
            and diagnostic.get('exception_type', 'Other') in exceptions
            and type(diagnostic.get('fixture_line', 0)) is int and 0 <= diagnostic.get('fixture_line', 0) <= 10000
            and (diagnostic.get('follow_exit_code') is None or type(diagnostic['follow_exit_code']) is int and -128 <= diagnostic['follow_exit_code'] <= 255)
            and all(type(diagnostic.get(key, False)) is bool for key in ['follow_root_exists', 'follow_run_exists'])
            and (progress is None or isinstance(progress, dict) and set(progress) == {'scenario', 'phase'}
                 and progress['scenario'] in scenarios and progress['phase'] in {'barrier', 'payload', 'collector', 'other'}))


def valid_audit_basename(diagnostic):
    basename = diagnostic.get('audit_basename')
    scenario = diagnostic.get('scenario')
    if scenario == 'snapshot_exit_race':
        pattern = r'tempest-snapshot-race-audit-[a-z0-9_]{8}\.json'
    elif scenario in {'primary_eof_guardian_death', 'primary_output_cleanup_eio'}:
        pattern = r'tempest-primary-fault-audit-[a-z0-9_]{8}\.json'
    else:
        return basename is None
    return basename is None or isinstance(basename, str) and re.fullmatch(pattern, basename) is not None


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
                snapshot_state = diagnostic.get('cleanup_state') if isinstance(diagnostic, dict) else None
                snapshot_projection = diagnostic.get('early_report') if isinstance(diagnostic, dict) else None
                valid_snapshot_details = (not isinstance(diagnostic, dict) or diagnostic.get('scenario') != 'snapshot_exit_race' or
                    all(type(diagnostic.get(key, 0)) is int and 0 <= diagnostic.get(key, 0) <= 16
                        for key in ['guardian_poll_hits', 'snapshot_read_hits', 'snapshot_bind_hits', 'listed_count', 'role_pidfds_dead', 'prestop_live_owned', 'stopped_live_owned'])
                    and diagnostic.get('cleanup_disposition') in {'not_attempted', 'already_absent', 'preserved', 'removed'}
                    and (snapshot_state is None or isinstance(snapshot_state, dict)
                         and set(snapshot_state) == {'parent_terminal', 'root_present', 'run_present', 'identity_matches', 'roles_empty', 'populated_zero', 'role_pidfds_dead', 'guardian_dead'}
                         and all(type(value) is bool for value in snapshot_state.values()))
                    and diagnostic.get('early_read_status') in {'not_attempted', 'complete', 'oversize', 'timeout'}
                    and (snapshot_projection is None or isinstance(snapshot_projection, dict)
                         and set(snapshot_projection) == {'reason', 'parent_recovery_status', 'guardian_alive', 'resources_removed'}
                         and (snapshot_projection['reason'] is None or isinstance(snapshot_projection['reason'], str) and len(snapshot_projection['reason']) <= 64)
                         and type(snapshot_projection['guardian_alive']) in {bool, type(None)}
                         and type(snapshot_projection['resources_removed']) in {bool, type(None)}
                         and isinstance(snapshot_projection['parent_recovery_status'], dict)
                         and set(snapshot_projection['parent_recovery_status']) == {'transition', 'guardian_reaped', 'guardian_signal'}
                         and (snapshot_projection['parent_recovery_status']['transition'] is None or
                              isinstance(snapshot_projection['parent_recovery_status']['transition'], str)
                              and len(snapshot_projection['parent_recovery_status']['transition']) <= 32)
                         and type(snapshot_projection['parent_recovery_status']['guardian_reaped']) in {bool, type(None)}
                         and (snapshot_projection['parent_recovery_status']['guardian_signal'] is None or
                              type(snapshot_projection['parent_recovery_status']['guardian_signal']) is int
                              and 0 <= snapshot_projection['parent_recovery_status']['guardian_signal'] <= 64)))
                if isinstance(diagnostic, dict) and {'status', 'scenario', 'fixture_stage'} <= set(diagnostic) <= {'status', 'scenario', 'fixture_stage', 'probe_reason', 'probe_removed', 'failure_kind', 'exit_code', 'stdout_bytes', 'stderr_bytes', 'completed_cases', 'follow_stage', 'follow_exit_code', 'follow_last_progress', 'follow_root_exists', 'follow_run_exists', 'exception_type', 'fixture_line', 'audit_basename', 'guardian_poll_hits', 'snapshot_read_hits', 'snapshot_bind_hits', 'listed_count', 'role_pidfds_dead', 'prestop_live_owned', 'stopped_live_owned', 'early_read_status', 'early_report', 'cleanup_disposition', 'cleanup_state'}:
                    scenarios = {'initial_admission', 'detached_grandchild', 'lease_stopped', 'guardian_before_create', 'guardian_after_create', 'guardian_before_ack', 'guardian_after_ack', 'guardian_ack_timeout', 'guardian_admission', 'guardian_payload', 'guardian_collector', 'guardian_stopped', 'primary_eof_guardian_death', 'primary_output_cleanup_eio', 'snapshot_exit_race'}
                    stages = {'select_target', 'status_metadata', 'open_status_channel', 'owner_stop', 'recovery_paths', 'decode_status', 'validate_status', 'seize', 'fork_event', 'freeze_guardian', 'timeout_reap', 'next_generation', 'startup_result', 'ack_timeout_parent', 'guardian_stop', 'cleanup_entry', 'pin_roles', 'inject_secondary', 'guardian_poll', 'snapshot_bind', 'fixture_cleanup'}
                    if (diagnostic['status'] == 'failed' and diagnostic['scenario'] in scenarios and diagnostic['fixture_stage'] in stages
                            and diagnostic.get('probe_reason', 'other') in {'watchdog_startup_failed', 'watchdog_guardian_unconfirmed', 'run_cleanup', 'identity', 'kernel', 'other', 'child_exit', 'child_signal', 'watchdog_guardian_died', 'watchdog_lease_unavailable', 'exited_after_listing'}
                            and type(diagnostic.get('probe_removed', False)) is bool
                            and diagnostic.get('failure_kind', 'assertion') in {'timeout', 'parse', 'assertion'}
                            and type(diagnostic.get('completed_cases',0)) is int and 0 <= diagnostic.get('completed_cases',0) <= 4
                            and valid_audit_basename(diagnostic)
                            and valid_follow_details(diagnostic)
                            and valid_snapshot_details
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
