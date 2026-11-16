#!/usr/bin/env python3
"""Independent fixed ptrace/dirfd HOME evidence on the dedicated Linux VM."""
from pathlib import Path
import re
from linux_existing_cgroup_smoke import run_fixture


def valid_failure(value):
    keys = {'status', 'stage', 'exception', 'captures', 'host_reads',
            'stop_budget_exceeded', 'parent_terminal', 'root_present', 'run_present',
            'stderr_bytes', 'audit_basename', 'captures_by_run'}
    return (isinstance(value, dict) and set(value) == keys
            and value['status'] == 'failed'
            and value['stage'] in {'spawn', 'initial_stop', 'capture', 'wait', 'validate', 'save', 'cleanup'}
            and value['exception'] in {'ValueError', 'AssertionError', 'OSError', 'TimeoutExpired', 'Other'}
            and type(value['captures']) is int and 0 <= value['captures'] <= 2
            and type(value['host_reads']) is int and value['host_reads'] == value['captures'] * 9
            and isinstance(value['captures_by_run'], dict)
            and set(value['captures_by_run']) == {'state_run1', 'state_run2'}
            and all(type(count) is int and count in (0, 1) for count in value['captures_by_run'].values())
            and sum(value['captures_by_run'].values()) == value['captures']
            and all(type(value[key]) is bool for key in ['stop_budget_exceeded',
                'parent_terminal', 'root_present', 'run_present'])
            and type(value['stderr_bytes']) is int and 0 <= value['stderr_bytes'] <= 65537
            and isinstance(value['audit_basename'], str)
            and re.fullmatch(r'tempest-state-home-failure-[a-z0-9_]{8}\.json', value['audit_basename']) is not None)

# Embed reviewed fixed sources, rather than importing writable modules as root.
BASE = Path(__file__).resolve().parent
FIXTURE = (BASE / 'linux_state_observer.py').read_text()
FIXTURE += '\n' + (BASE / 'linux_state_evidence.py').read_text()
FIXTURE += '\n' + (BASE / 'linux_state_trace.py').read_text().replace(
    'from linux_state_observer import DIRECTORY_FLAGS, observe_home', '')
FIXTURE += r'''
import hashlib, subprocess, sys, tempfile
root = Path('/sys/fs/cgroup/tempest-linux-isolation-probe')
assert not root.exists() and not RUN.exists()
digest = hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest()
process = None
trace = None
output = tempfile.TemporaryFile()
error = tempfile.TemporaryFile()
stage = 'spawn'
failure = None
try:
    def traced_exec():
        ptrace(0, 0)  # TRACEME: exec generates the initial stop.
    process = subprocess.Popen([sys.argv[1], 'linux-isolation-probe'], env={},
        stdin=subprocess.DEVNULL, stdout=output, stderr=error, preexec_fn=traced_exec)
    trace = StateTrace(process)
    stage = 'initial_stop'
    stopped = trace.stop(time.monotonic() + 5)
    assert stopped == signal.SIGTRAP
    stage = 'capture'
    captures = trace.capture()
    assert [item['scenario'] for item in captures] == ['state_run1', 'state_run2']
    assert captures[0]['nonce'] != captures[1]['nonce']
    stage = 'wait'
    process.wait(timeout=120)
    stage = 'validate'
    output.seek(0)
    raw = output.read(65537)
    assert len(raw) <= 65536
    report = json.loads(raw)
    projection = validate_probe(report)
    assert projection['binary_sha256'] == digest
    assert process.returncode == 1  # Fixed investigation remains incomplete.
    assert not root.exists() and not RUN.exists()
    stage = 'save'
    fd, audit = tempfile.mkstemp(prefix='tempest-state-home-independent-', suffix='.json')
    with os.fdopen(fd, 'w') as saved:
        json.dump({'binary_sha256':digest, 'captures':captures, 'probe':report}, saved,
                  sort_keys=True)
    success = {'status':'passed', 'scope':'dummy_independent_home_only',
        'production_authorized':False, 'binary_sha256':digest,
        'captures':len(captures), 'host_reads':18, 'checks_per_run':21,
        'probe_status':report['status'], 'audit_basename':Path(audit).name}
except BaseException as exception:
    failure = exception
finally:
    try:
        if process is not None and process.returncode is None:
            try:
                if trace is not None:
                    signal.pidfd_send_signal(trace.pidfd, signal.SIGKILL)
                else:
                    os.kill(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            # A trace stop is not terminal; continue until real exit and reap.
            until = time.monotonic() + 5
            while time.monotonic() < until:
                waited, status = os.waitpid(process.pid, os.WNOHANG | 0x40000000)
                if waited:
                    if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                        process.returncode = os.waitstatus_to_exitcode(status)
                        break
                    if os.WIFSTOPPED(status):
                        ptrace(7, process.pid, data=signal.SIGKILL)
                time.sleep(0.001)
            assert process.returncode is not None
    except BaseException as cleanup_error:
        if failure is None:
            failure, stage = cleanup_error, 'cleanup'
    finally:
        if trace is not None:
            trace.close()
    error.seek(0)
    stderr_bytes = len(error.read(65537))
    output.close()
    error.close()
    until = time.monotonic() + 15
    while (root.exists() or RUN.exists()) and time.monotonic() < until:
        time.sleep(0.01)
    if failure is None and (root.exists() or RUN.exists()):
        failure, stage = ValueError('resources_remain'), 'cleanup'
    if failure is not None:
        kind = type(failure).__name__
        diagnostic = {'status':'failed', 'stage':stage,
            'exception':kind if kind in ['ValueError','AssertionError','OSError','TimeoutExpired'] else 'Other',
            'captures':len(trace.captures) if trace else 0,
            'captures_by_run':{run:sum(item['scenario']==run for item in trace.captures) if trace else 0
                               for run in ['state_run1','state_run2']},
            'host_reads':9 * len(trace.captures) if trace else 0,
            'stop_budget_exceeded':str(failure) == 'capture_stop_budget',
            'parent_terminal':process is not None and process.returncode is not None,
            'root_present':root.exists(), 'run_present':RUN.exists(),
            'stderr_bytes':stderr_bytes, 'audit_basename':None}
        fd, audit = tempfile.mkstemp(prefix='tempest-state-home-failure-', suffix='.json')
        with os.fdopen(fd, 'w') as saved:
            json.dump(diagnostic, saved, sort_keys=True)
        diagnostic['audit_basename'] = Path(audit).name
        print(json.dumps(diagnostic))
        raise SystemExit(1)
    print(json.dumps(success))
'''

if __name__ == '__main__':
    raise SystemExit(run_fixture(FIXTURE, 'independent_state_home_fixture', timeout=150,
                                failure_validator=valid_failure))
