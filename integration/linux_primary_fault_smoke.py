#!/usr/bin/env python3
"""Preserve a collector fault across guardian death or one cleanup write failure."""
from linux_existing_cgroup_smoke import run_fixture

FIXTURE = r'''
import ctypes, errno, json, os, pathlib, platform, select, signal, stat, subprocess, sys, tempfile, time
assert platform.machine() == 'x86_64'
root = pathlib.Path('/sys/fs/cgroup/tempest-linux-isolation-probe')
run = pathlib.Path('/run/tempest-linux-isolation-probe')
assert not root.exists() and not run.exists()
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_long
WALL = 0x40000000
NEG_ENOSYS = 2**64 - errno.ENOSYS

def ptrace(request, pid, address=None, data=None):
    assert libc.ptrace(request, pid, address, data) == 0

def registers(pid):
    result = (ctypes.c_ulonglong * 27)()
    ptrace(12, pid, None, ctypes.byref(result))
    return result

def wait_stop(process, until):
    while time.monotonic() < until:
        waited, status = os.waitpid(process.pid, os.WNOHANG | WALL)
        if waited:
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                process.returncode = os.waitstatus_to_exitcode(status)
                raise AssertionError('tracee_exited')
            assert os.WIFSTOPPED(status)
            return status
        time.sleep(0.0001)
    raise AssertionError('trace_stop_timeout')

def next_syscall(process, until):
    deliver = 0
    while True:
        ptrace(24, process.pid, None, ctypes.c_void_p(deliver))
        status = wait_stop(process, until)
        stopped = os.WSTOPSIG(status)
        if stopped == (signal.SIGTRAP | 0x80): return registers(process.pid)
        # No TRACEFORK/TRACEEXIT: only our own supervisor is traced. Preserve
        # ordinary signal delivery rather than confusing it with a syscall.
        assert status >> 16 == 0
        deliver = stopped

def kill_reap(process):
    if process.returncode is not None: return
    # Popen.kill() polls first and could consume a ptrace stop as though it
    # were terminal. This unreaped direct child cannot have its PID reused.
    try: os.kill(process.pid, signal.SIGKILL)
    except ProcessLookupError: pass
    until = time.monotonic() + 5
    while time.monotonic() < until:
        waited, status = os.waitpid(process.pid, os.WNOHANG | WALL)
        if waited and (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
            process.returncode = os.waitstatus_to_exitcode(status)
            return
        time.sleep(0.0001)
    raise AssertionError('tracee_reap_timeout')

def lineage(pid):
    values = pathlib.Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return int(values[1]), int(values[19])

def bind_live_child(pid, parent):
    before = lineage(pid)
    assert before[0] == parent
    handle = os.pidfd_open(pid)
    try:
        assert lineage(pid) == before and not select.select([handle], [], [], 0)[0]
        return handle
    except BaseException:
        os.close(handle)
        raise

def main_guardian(process, diagnostic_step=None):
    if diagnostic_step is not None: diagnostic_step('metadata')
    metadata = json.loads((run / 'watchdog.channel').read_bytes())
    assert set(metadata) == {'watchdog_pid', 'status_fd'}
    guardian = metadata['watchdog_pid']
    if diagnostic_step is not None: diagnostic_step('lineage')
    handle = bind_live_child(guardian, process.pid)
    try:
        if diagnostic_step is not None: diagnostic_step('writer')
        endpoint = pathlib.Path(f'/proc/{process.pid}/fd/{metadata["status_fd"]}').stat()
        assert stat.S_ISFIFO(endpoint.st_mode)
        writers = []
        for fd in pathlib.Path(f'/proc/{guardian}/fd').iterdir():
            value = fd.stat()
            if (value.st_dev, value.st_ino) == (endpoint.st_dev, endpoint.st_ino):
                info = pathlib.Path(f'/proc/{guardian}/fdinfo/{fd.name}').read_text()
                flags = int(next(line.split()[1] for line in info.splitlines() if line.startswith('flags:')), 8)
                if flags & os.O_ACCMODE == os.O_WRONLY: writers.append(int(fd.name))
        assert len(writers) == 1
        return handle
    except BaseException:
        os.close(handle)
        raise

def next_generation(binary):
    global follow_diagnostic
    follow_diagnostic = {'follow_stage':'admission', 'follow_exit_code':None,
                         'follow_last_progress':None, 'follow_root_exists':False,
                         'follow_run_exists':False}
    follow = subprocess.Popen([binary, 'linux-isolation-probe'], env={}, stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    guardian = None
    scenarios = {'baseline', 'foreign_ready', 'fd_file_a', 'fd_file_b', 'fd_directory_a',
                 'fd_directory_b', 'fd_socket_a', 'fd_socket_b', 'control_truncation',
                 'unexpected_control', 'frame_oversize', 'frame_malformed', 'library_late_write',
                 'library_hardlink', 'library_symlink', 'library_replacement', 'pids_limit',
                 'tmpfs_full', 'detached_grandchild', 'report_timeout', 'report_eof',
                 'cgroup_kill_noop', 'memory_oom', 'stdout_flood', 'stderr_flood',
                 'peer_stdout_flood', 'continuous_stdout'}

    def snapshot():
        # Diagnostics never poll/reap the child or replace a failure. Retain
        # the last complete progress record after RUN disappears during cleanup.
        follow_diagnostic['follow_exit_code'] = follow.returncode
        for key, path in [('follow_root_exists', root), ('follow_run_exists', run)]:
            try: follow_diagnostic[key] = path.exists()
            except OSError: pass
        try:
            with (run / 'progress').open('rb') as stream:
                value = json.loads(stream.read(513))
            if isinstance(value, dict) and set(value) == {'scenario', 'phase'}:
                scenario = value['scenario']
                phase = value['phase']
                follow_diagnostic['follow_last_progress'] = {
                    'scenario':scenario if isinstance(scenario, str) and scenario in scenarios else 'other',
                    'phase':phase if isinstance(phase, str) and phase in {'barrier', 'payload', 'collector'} else 'other'}
        except (OSError, ValueError): pass

    def step(value):
        follow_diagnostic['follow_stage'] = value
        snapshot()

    try:
        try:
            until = time.monotonic() + 10
            admitted = False
            while time.monotonic() < until:
                assert follow.poll() is None
                try:
                    admitted = bool((root / 'a' / 'cgroup.procs').read_text().split())
                except FileNotFoundError: pass
                snapshot()
                if admitted:
                    guardian = main_guardian(follow, step)
                    break
                time.sleep(0.002)
            assert admitted
        finally:
            failed_stage = follow_diagnostic['follow_stage'] if sys.exc_info()[0] is not None else None
            step('kill_reap')
            kill_reap(follow)
            if failed_stage is not None: follow_diagnostic['follow_stage'] = failed_stage
        step('guardian_terminal')
        assert guardian is not None and select.select([guardian], [], [], 10)[0]
        step('paths_absent')
        assert not root.exists() and not run.exists()
    finally:
        snapshot()
        if guardian is not None: os.close(guardian)

def exception_diagnostic(error):
    allowed = {'AssertionError', 'FileNotFoundError', 'ProcessLookupError', 'PermissionError',
               'ChildProcessError', 'OSError', 'TimeoutExpired', 'TimeoutError', 'ValueError',
               'JSONDecodeError', 'KeyError', 'TypeError', 'RuntimeError'}
    name = type(error).__name__
    line = 0
    trace = error.__traceback__
    while trace is not None:
        if trace.tb_frame.f_code.co_filename == '<string>': line = trace.tb_lineno
        trace = trace.tb_next
    return {'exception_type':name if name in allowed else 'Other',
            'fixture_line':line if 0 <= line <= 10000 else 0}

results = []
for scenario, target, primary in [
        ('primary_eof_guardian_death', 'report_eof', 'report_eof'),
        ('primary_output_cleanup_eio', 'stdout_flood', 'output_limit')]:
    assert not root.exists() and not run.exists()
    process = subprocess.Popen([sys.argv[1], 'linux-isolation-probe'], env={}, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    handles = []
    guardian_handle = directory = None
    stage = 'select_target'
    follow_diagnostic = None
    report = None
    output = errors = b''
    audit_basename = None
    try:
        # ReportTimeout precedes both targets and provides a stable 30-second
        # window to attach. No helper argv, production timeout or test hook changes.
        until = time.monotonic() + 90
        while time.monotonic() < until:
            assert process.poll() is None
            try:
                if json.loads((run / 'progress').read_bytes()) == {'scenario':'report_timeout', 'phase':'collector'}:
                    break
            except (FileNotFoundError, ValueError): pass
            time.sleep(0.002)
        else: raise AssertionError('collector_window_missing')
        stage = 'seize'
        ptrace(0x4206, process.pid, None, ctypes.c_void_p(1 | (1 << 20)))
        ptrace(0x4207, process.pid)
        wait_stop(process, until)
        guardian_handle = main_guardian(process)
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        pinned = os.fstat(directory)
        identity = (pinned.st_dev, pinned.st_ino)
        kill_identity = (root / 'cgroup.kill').stat()
        kill_identity = (kill_identity.st_dev, kill_identity.st_ino)
        stage = 'cleanup_entry'
        while True:
            values = next_syscall(process, until)
            # x86_64 write entry: orig_rax, rax, rdx. Resolve only the owned
            # tracee FD and compare its inode with this run's cgroup.kill.
            if values[15] != 1 or values[10] != NEG_ENOSYS or values[12] != 1: continue
            endpoint = pathlib.Path(f'/proc/{process.pid}/fd/{values[14]}').stat()
            if (endpoint.st_dev, endpoint.st_ino) != kill_identity: continue
            progress = json.loads((run / 'progress').read_bytes())
            if progress != {'scenario':target, 'phase':'collector'}: continue
            ctypes.set_errno(0)
            word = libc.ptrace(2, process.pid, ctypes.c_void_p(values[13]), None)
            assert ctypes.get_errno() == 0 and word & 255 == ord('1')
            assert (root.stat().st_dev, root.stat().st_ino) == identity
            break
        # This first target cgroup.kill follows collector error recording and
        # its kernel state checks; all three live direct roles are still pinned.
        stage = 'pin_roles'
        for role in ['a', 'b', 'guard']:
            pids = (root / role / 'cgroup.procs').read_text().split()
            assert len(pids) == 1
            pid = int(pids[0])
            handle = bind_live_child(pid, process.pid)
            handles.append(handle)
            assert f'0::/tempest-linux-isolation-probe/{role}' in pathlib.Path(f'/proc/{pid}/cgroup').read_text().splitlines()
            assert not select.select([handle], [], [], 0)[0]
        assert not select.select([guardian_handle], [], [], 0)[0]
        stage = 'inject_secondary'
        if scenario == 'primary_eof_guardian_death':
            signal.pidfd_send_signal(guardian_handle, signal.SIGKILL)
            assert select.select([guardian_handle], [], [], 2)[0]
        else:
            # Skip exactly this syscall, then provide EIO at its exit stop.
            # The real kernel operation never runs and later writes are unchanged.
            values[15] = 2**64 - 1
            ptrace(13, process.pid, None, ctypes.byref(values))
            values = next_syscall(process, until)
            assert values[15] == 2**64 - 1 and values[10] == NEG_ENOSYS
            values[10] = 2**64 - errno.EIO
            ptrace(13, process.pid, None, ctypes.byref(values))
        ptrace(17, process.pid)
        output, errors = process.communicate(timeout=15)
        stage = 'validate_status'
        for marker in [b'dummy-argv-marker', b'dummy-stderr-marker', b'synthetic-canary-only', b'dummy-output-marker']:
            assert marker not in output and marker not in errors
        report = json.loads(output)
        # Retain the complete public audit before assertions can discard the
        # recovery counts and failure evidence. mkstemp creates a private file
        # without following an existing path; raw stderr is never persisted.
        audit_fd, audit_path = tempfile.mkstemp(prefix='tempest-primary-fault-audit-', suffix='.json')
        with os.fdopen(audit_fd, 'w') as audit:
            json.dump({'scenario': scenario, 'report': report}, audit)
            audit.write('\n')
        audit_basename = pathlib.Path(audit_path).name
        assert process.returncode == 1 and report['status'] == 'failed'
        assert report['first_fault'] == primary and report['active_scenario'] == target
        assert report['formal_eligible'] is False and report['model_launched'] is False
        assert report['resources_removed'] is True and report['guardian_alive'] is False
        statuses = report['parent_recovery_status']
        assert all(value['guardian_dead'] and value['guardian_reaped'] for value in statuses)
        final = statuses[-1]
        counts = final['counts']
        assert counts['reap_unconfirmed'] == 0 and counts['unconfirmed_reason'] is None
        assert counts['cgroup_populated'] is False
        if scenario == 'primary_eof_guardian_death':
            assert report['reason'] == 'watchdog_guardian_died'
            assert [value['transition'] for value in statuses] == ['guardian_dead','parent_owned','recovered']
            assert final['guardian_signal'] == signal.SIGKILL
            assert counts['registry_total'] == counts['direct'] == counts['dead_pidfds'] == counts['reaped'] == 3
        else:
            assert report['reason'] == 'kernel' and report['errno'] == errno.EIO
            assert [value['transition'] for value in statuses] == ['guardian_dead','verified']
            assert final['guardian_exit'] == 0 and final['guardian_signal'] is None
            # The normal reaper already removed its direct records. Verified
            # requires registry.finish(); zero here is not a new three-child reap.
            assert counts['registry_total'] == counts['direct'] == counts['dead_pidfds'] == counts['reaped'] == 0
        assert counts['descendants'] == 0 and counts['unattached'] == 0
        assert all(select.select([handle], [], [], 0)[0] for handle in handles)
        assert select.select([guardian_handle], [], [], 0)[0]
        assert not root.exists() and not run.exists()
        stage = 'next_generation'
        next_generation(sys.argv[1])
        results.append({'scenario':scenario,'status':'passed','first_fault':report['first_fault'],
                        'reason':report['reason'],'errno':report['errno'],'parent_recovery_status':statuses,
                        'external_role_pidfds_dead':len(handles),'resources_removed':True,
                        'next_generation_admitted':True})
    except BaseException as error:
        reason = report.get('reason') if isinstance(report, dict) else 'other'
        allowed = {'watchdog_guardian_died', 'watchdog_guardian_unconfirmed', 'watchdog_startup_failed',
                   'watchdog_lease_unavailable', 'run_cleanup', 'identity', 'kernel', 'child_exit', 'child_signal', 'exited_after_listing'}
        print(json.dumps({'status':'failed','scenario':scenario,'fixture_stage':stage,
                          'probe_reason':reason if reason in allowed else 'other',
                          'probe_removed':bool(report.get('resources_removed')) if isinstance(report, dict) else False,
                          'failure_kind':'timeout' if isinstance(error, subprocess.TimeoutExpired) else 'parse' if isinstance(error, ValueError) else 'assertion',
                          'exit_code':process.returncode,'stdout_bytes':len(output),'stderr_bytes':len(errors),
                          'completed_cases':len(results), 'audit_basename':audit_basename, **(follow_diagnostic or {}),
                          **exception_diagnostic(error)}))
        raise
    finally:
        # This Popen child is either still ours/unreaped or already recorded
        # terminal. SIGKILL bypasses ptrace stops; TRACEEXIT is never enabled.
        try:
            kill_reap(process)
        finally:
            for handle in handles: os.close(handle)
            if guardian_handle is not None: os.close(guardian_handle)
            if directory is not None: os.close(directory)
        # Failure leaves resource evidence intact; never adopt or delete it.
print(json.dumps({'status':'passed','cases':results}))
'''

if __name__ == '__main__':
    raise SystemExit(run_fixture(FIXTURE, 'primary_fault_preservation_fixture', timeout=240))
