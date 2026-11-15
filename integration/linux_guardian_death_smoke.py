#!/usr/bin/env python3
"""Fixed dummy guardian death at admission, detached payload, and collector."""
from linux_existing_cgroup_smoke import run_fixture

FIXTURE = r'''
import json, os, pathlib, select, signal, subprocess, sys, time
root = pathlib.Path('/sys/fs/cgroup/tempest-linux-isolation-probe')
run = pathlib.Path('/run/tempest-linux-isolation-probe')
assert not root.exists() and not run.exists()
results = []
for scenario in ['guardian_admission', 'guardian_payload', 'guardian_collector', 'guardian_stopped']:
    process = subprocess.Popen([sys.argv[1], 'linux-isolation-probe'], env={},
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    handles = []
    guardian_handle = None
    stage = 'select_target'
    try:
        until = time.monotonic() + 45
        while time.monotonic() < until:
            assert process.poll() is None
            try:
                pids = [int(pid) for pid in (root / 'a' / 'cgroup.procs').read_text().split()]
                selected = bool(pids) and scenario in ['guardian_admission', 'guardian_stopped']
                if scenario not in ['guardian_admission', 'guardian_stopped']:
                    progress = json.loads((run / 'progress').read_bytes())
                    if scenario == 'guardian_payload':
                        selected = progress['scenario'] == 'detached_grandchild' and len(pids) == 2
                        if selected:
                            states = {pid: tuple(int(v) for v in pathlib.Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[1:4]) for pid in pids}
                            selected = any(parent in states and group == session and group != pid
                                           and group != states[parent][1] and session != states[parent][2]
                                           for pid, (parent, group, session) in states.items())
                    else:
                        selected = progress == {'scenario':'report_timeout', 'phase':'collector'}
                if selected:
                    os.kill(process.pid, signal.SIGSTOP)
                    _, stopped = os.waitpid(process.pid, os.WUNTRACED)
                    assert os.WIFSTOPPED(stopped)
                    assert set(pids) == set(int(pid) for pid in (root / 'a' / 'cgroup.procs').read_text().split())
                    for role in ['a', 'b', 'guard']:
                        for pid in (root / role / 'cgroup.procs').read_text().split():
                            handles.append(os.pidfd_open(int(pid)))
                    break
            except (FileNotFoundError, ProcessLookupError, ValueError):
                pass
            time.sleep(0.0005)
        assert handles
        stage = 'status_metadata'
        metadata = json.loads((run / 'watchdog.channel').read_bytes())
        guardian = metadata['watchdog_pid']
        assert pathlib.Path(f'/proc/{guardian}/stat').read_text().rsplit(')', 1)[1].split()[1] == str(process.pid)
        guardian_handle = os.pidfd_open(guardian)
        stage = 'guardian_stop'
        stopped_without_takeover = False
        if scenario == 'guardian_stopped':
            # Hold the already admitted dummy role at the early stable point;
            # it cannot complete normally during the guardian SIGSTOP test.
            for handle in handles: signal.pidfd_send_signal(handle, signal.SIGSTOP)
            signal.pidfd_send_signal(guardian_handle, signal.SIGSTOP)
            until = time.monotonic() + 2
            while time.monotonic() < until:
                if pathlib.Path(f'/proc/{guardian}/stat').read_text().rsplit(')',1)[1].split()[0] == 'T': break
                time.sleep(0.001)
            else: raise AssertionError
            root_identity = (root.stat().st_dev, root.stat().st_ino)
            os.kill(process.pid, signal.SIGCONT)
            # The owner must remain live, with no result and no exclusive
            # takeover while the guardian is stopped but still alive.
            time.sleep(0.5)
            assert process.poll() is None and not select.select([process.stdout],[],[],0)[0]
            assert not select.select([guardian_handle],[],[],0)[0]
            assert all(not select.select([handle],[],[],0)[0] for handle in handles)
            assert (root.stat().st_dev,root.stat().st_ino) == root_identity
            stopped_without_takeover = True
        resumed = time.monotonic()
        signal.pidfd_send_signal(guardian_handle, signal.SIGKILL)
        # Do not wait for guardian death here: the parent must handle pipe
        # closure and pidfd notification in their actual kernel order.
        os.kill(process.pid, signal.SIGCONT)
        output, _ = process.communicate(timeout=10)
        total_ms = (time.monotonic() - resumed) * 1000
        stage = 'validate_status'
        report = json.loads(output)
        assert process.returncode == 1 and report['reason'] == 'watchdog_guardian_died'
        assert report['status'] == 'failed' and report['formal_eligible'] is False and report['model_launched'] is False
        assert report['resources_removed'] is True and report['guardian_alive'] is False
        assert select.select([guardian_handle],[],[],0)[0]
        statuses = report['parent_recovery_status']
        assert [value['transition'] for value in statuses] == ['guardian_dead','parent_owned','recovered']
        assert all(value['guardian_dead'] and value['guardian_reaped'] and value['guardian_signal'] == signal.SIGKILL for value in statuses)
        counts = statuses[-1]['counts']
        assert counts['direct'] >= 1 and counts['direct'] == counts['reaped']
        assert counts['dead_pidfds'] == counts['direct'] + counts['descendants']
        assert counts['registry_total'] == counts['dead_pidfds']
        assert counts['reap_unconfirmed'] == 0 and counts['unconfirmed_reason'] is None
        assert counts['cgroup_populated'] is False
        assert all(isinstance(value['counts'], dict) for value in statuses)
        if scenario == 'guardian_payload': assert counts['descendants'] >= 1
        assert all(select.select([handle], [], [], 0)[0] for handle in handles)
        assert not root.exists() and not run.exists()
        # Includes scheduling/report overhead, so this is a conservative bound
        # on resume-to-first-parent-status, rather than a pure detection sample.
        detection_upper_ms = max(0, total_ms - (statuses[-1]['elapsed_ms'] - statuses[0]['elapsed_ms']))
        assert detection_upper_ms <= 250
        stage = 'next_generation'
        full_follow = scenario == 'guardian_stopped'
        follow_checks = None
        follow = subprocess.Popen([sys.argv[1], 'linux-isolation-probe'], env={},
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE if full_follow else subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        try:
            until = time.monotonic() + 10
            admitted = False
            while time.monotonic() < until:
                assert follow.poll() is None
                try:
                    if (root / 'a' / 'cgroup.procs').read_text().split(): admitted = True; break
                except FileNotFoundError: pass
                time.sleep(0.002)
            assert admitted
            if full_follow:
                follow_output, _ = follow.communicate(timeout=115)
                follow_report = json.loads(follow_output)
                assert follow.returncode == 1 and follow_report['status'] == 'incomplete'
                assert follow_report['resources_removed'] is True
                assert follow_report['formal_eligible'] is False and follow_report['model_launched'] is False
                follow_checks = len(follow_report['checks'])
                assert follow_checks == 137 and all(check['passed'] for check in follow_report['checks'])
                assert follow_report['parent_recovery_status'][-1]['transition'] == 'verified'
        finally:
            if follow.poll() is None: follow.kill()
            follow.wait(timeout=5)
        until = time.monotonic() + 10
        while time.monotonic() < until and (root.exists() or run.exists()): time.sleep(0.02)
        assert not root.exists() and not run.exists()
        results.append({'scenario':scenario,'status':'passed','parent_recovery_status':statuses,
                        'external_payload_pidfds_dead':True,'resources_removed':True,
                        'guardian_stopped_without_takeover':stopped_without_takeover,
                        'external_guardian_readiness_wait':False,
                        'next_generation_full_checks':follow_checks,
                        'next_generation_admitted':True,'detection_upper_ms':round(detection_upper_ms,3)})
    except BaseException as error:
        reason = 'other'
        exited = process.poll() is not None
        if exited:
            try:
                failed_output, _ = process.communicate(timeout=2)
                failed_report = json.loads(failed_output)
                candidate = failed_report.get('reason') if isinstance(failed_report, dict) else None
                if candidate in {'identity','kernel','child_exit','child_signal','watchdog_guardian_died','watchdog_startup_failed','watchdog_guardian_unconfirmed','run_cleanup','watchdog_lease_unavailable'}:
                    reason = candidate
            except (ValueError, subprocess.TimeoutExpired): pass
        print(json.dumps({'status':'failed','scenario':scenario,'fixture_stage':stage,
                          'probe_reason':reason,'exit_code':process.returncode,
                          'failure_kind':'timeout' if isinstance(error, (subprocess.TimeoutExpired, TimeoutError)) else 'parse' if isinstance(error, ValueError) else 'assertion',
                          'completed_cases':len(results)}))
        raise
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        for handle in handles: os.close(handle)
        if guardian_handle is not None: os.close(guardian_handle)
print(json.dumps({'status':'passed','cases':results}))
'''

if __name__ == '__main__':
    raise SystemExit(run_fixture(FIXTURE, 'guardian_death_recovery_fixture', timeout=240))
