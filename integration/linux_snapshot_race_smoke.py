#!/usr/bin/env python3
"""Exit an owned role between recovery listing and PIDFD bind."""
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


import socket
process = subprocess.Popen([sys.argv[1], 'linux-isolation-probe'], env={}, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
handles = {}; directories = {}; guardian_handle = None
stage = 'select_target'
audit_basename = None
guardian_poll_hits = snapshot_bind_hits = 0
try:
    until = time.monotonic() + 90
    while time.monotonic() < until:
        assert process.poll() is None
        try:
            if json.loads((run/'progress').read_bytes()) == {'scenario':'report_timeout','phase':'collector'}: break
        except (FileNotFoundError, ValueError): pass
        time.sleep(0.002)
    else: raise AssertionError
    stage = 'seize'
    ptrace(0x4206, process.pid, None, ctypes.c_void_p(1 | (1 << 20)))
    ptrace(0x4207, process.pid); wait_stop(process, until)
    guardian = json.loads((run/'watchdog.channel').read_bytes())['watchdog_pid']
    guardian_handle = main_guardian(process)
    for key,path in [('root',root),('run',run)]:
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        directories[key]=fd
    identities={key:(os.fstat(fd).st_dev,os.fstat(fd).st_ino) for key,fd in directories.items()}
    for role in ['a','b','guard']:
        pids=(root/role/'cgroup.procs').read_text().split(); assert len(pids)==1
        pid=int(pids[0]);handles[pid]=bind_live_child(pid,process.pid)
    stage = 'guardian_poll'
    while True:
        values=next_syscall(process,until)
        if values[15]!=7 or values[10]!=NEG_ENOSYS or values[13]!=1 or values[12]!=0: continue
        ctypes.set_errno(0)
        word=libc.ptrace(2,process.pid,ctypes.c_void_p(values[14]),None)
        assert ctypes.get_errno()==0
        fd=word & 0xffffffff
        if fd >= 2**31: continue
        info=pathlib.Path(f'/proc/{process.pid}/fdinfo/{fd}').read_text()
        if f'Pid:\t{guardian}' not in info.splitlines(): continue
        guardian_poll_hits += 1
        break
    assert guardian_poll_hits == 1
    assert all(not select.select([h],[],[],0)[0] for h in handles.values())
    signal.pidfd_send_signal(guardian_handle,signal.SIGKILL)
    assert select.select([guardian_handle],[],[],2)[0]
    stage = 'snapshot_bind'
    listed = set()
    member_files = {(p.stat().st_dev,p.stat().st_ino) for p in
                    [root/role/'cgroup.procs' for role in ['a','b','guard']]}
    def trace_bytes(address, length):
        assert 0 <= length <= 1024
        value=bytearray()
        for offset in range(0,length,8):
            ctypes.set_errno(0)
            word=libc.ptrace(2,process.pid,ctypes.c_void_p(address+offset),None)
            assert ctypes.get_errno()==0
            value.extend((word & (2**64-1)).to_bytes(8,'little'))
        return bytes(value[:length])
    while True:
        values=next_syscall(process,until)
        if values[15]==0 and 0 < values[10] <= 1024:
            endpoint=pathlib.Path(f'/proc/{process.pid}/fd/{values[14]}').stat()
            if (endpoint.st_dev,endpoint.st_ino) in member_files:
                listed.update(int(pid) for pid in trace_bytes(values[13],values[10]).split())
        if values[15]==434 and values[10]==NEG_ENOSYS and values[14] in handles:
            target=values[14];snapshot_bind_hits += 1;break
    assert snapshot_bind_hits == 1
    assert target in listed
    assert not select.select([handles[target]],[],[],0)[0]
    # The parent is inside its snapshot bind, after listing the live target.
    assert any(str(target) in (root/role/'cgroup.procs').read_text().split() for role in ['a','b','guard'])
    signal.pidfd_send_signal(handles[target],signal.SIGKILL)
    assert select.select([handles[target]],[],[],2)[0]
    ptrace(17,process.pid)
    output,errors=process.communicate(timeout=15)
    report=json.loads(output)
    audit_fd,audit_path=tempfile.mkstemp(prefix='tempest-primary-fault-audit-',suffix='.json')
    with os.fdopen(audit_fd,'w') as audit:json.dump(report,audit)
    audit_basename=pathlib.Path(audit_path).name
    stage='validate_status'
    assert process.returncode==1 and report['resources_removed'] is False
    final=report['parent_recovery_status'][-1];counts=final['counts']
    assert final['transition']=='failed' and final['guardian_reaped']
    assert final['guardian_signal']==signal.SIGKILL and report['formal_eligible'] is False
    assert report['model_launched'] is False
    assert counts['snapshot_stage']=='bind' and counts['snapshot_reason']=='exited_after_listing'
    assert counts['direct']==counts['dead_pidfds']==counts['reaped']==3
    assert counts['reap_unconfirmed']==0 and counts['cgroup_populated'] is False
    assert all(select.select([h],[],[],0)[0] for h in handles.values())
    stage='fixture_cleanup'
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as lock:
        lock.bind('\0tempest-linux-isolation-probe-lock')
        for key,path in [('root',root),('run',run)]:
            st=path.lstat();assert (st.st_dev,st.st_ino)==identities[key]
            st=os.fstat(directories[key]);assert (st.st_dev,st.st_ino)==identities[key]
        for role in ['', 'a','b','guard']:
            assert not (root/role/'cgroup.procs').read_text().split()
            assert 'populated 0' in (root/role/'cgroup.events').read_text().splitlines()
        for role in ['a','b','guard']:os.rmdir(role,dir_fd=directories['root'])
        assert (root.lstat().st_dev,root.lstat().st_ino)==identities['root']
        root.rmdir()
        # Preserve RUN rather than delete diagnostic evidence.
        hold=pathlib.Path(tempfile.mkdtemp(prefix='tempest-snapshot-race-evidence-',dir='/run'))
        assert (run.lstat().st_dev,run.lstat().st_ino)==identities['run']
        run.rename(hold/'original-run')
        assert not root.exists() and not run.exists()
    stage='next_generation'
    next_generation(sys.argv[1])
    print(json.dumps({'status':'passed','snapshot_counts':counts,'audit_basename':pathlib.Path(audit_path).name,
                      'resources_removed_by_probe':False,'fixture_owned_cleanup':True,'next_generation_admitted':True}))
except BaseException as error:
    print(json.dumps({'status':'failed','scenario':'snapshot_exit_race','fixture_stage':stage,
                      'audit_basename':audit_basename,**exception_diagnostic(error)}))
    raise
finally:
    kill_reap(process)
    for fd in [*handles.values(),*directories.values()]:os.close(fd)
    if guardian_handle is not None:os.close(guardian_handle)
'''

if __name__ == '__main__':
    raise SystemExit(run_fixture(FIXTURE, 'snapshot_exit_race_fixture', timeout=150))
