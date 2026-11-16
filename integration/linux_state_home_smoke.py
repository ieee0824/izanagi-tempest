#!/usr/bin/env python3
"""Independent fixed ptrace/dirfd HOME evidence on the dedicated Linux VM."""
from pathlib import Path
from linux_existing_cgroup_smoke import run_fixture

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
try:
    def traced_exec():
        ptrace(0, 0)  # TRACEME: exec generates the initial stop.
    process = subprocess.Popen([sys.argv[1], 'linux-isolation-probe'], env={},
        stdin=subprocess.DEVNULL, stdout=output, stderr=error, preexec_fn=traced_exec)
    trace = StateTrace(process)
    stopped = trace.stop(time.monotonic() + 5)
    assert stopped == signal.SIGTRAP
    captures = trace.capture()
    assert [item['scenario'] for item in captures] == ['state_run1', 'state_run2']
    assert captures[0]['nonce'] != captures[1]['nonce']
    process.wait(timeout=120)
    output.seek(0)
    raw = output.read(65537)
    assert len(raw) <= 65536
    report = json.loads(raw)
    projection = validate_probe(report)
    assert projection['binary_sha256'] == digest
    assert process.returncode == 1  # Fixed investigation remains incomplete.
    assert not root.exists() and not RUN.exists()
    fd, audit = tempfile.mkstemp(prefix='tempest-state-home-independent-', suffix='.json')
    with os.fdopen(fd, 'w') as saved:
        json.dump({'binary_sha256':digest, 'captures':captures, 'probe':report}, saved,
                  sort_keys=True)
    print(json.dumps({'status':'passed', 'scope':'dummy_independent_home_only',
        'production_authorized':False, 'binary_sha256':digest,
        'captures':len(captures), 'host_reads':18, 'checks_per_run':21,
        'probe_status':report['status'], 'audit_basename':Path(audit).name}))
finally:
    if process is not None and process.returncode is None:
        if trace is not None:
            signal.pidfd_send_signal(trace.pidfd, signal.SIGKILL)
        else:
            os.kill(process.pid, signal.SIGKILL)
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
    if trace is not None:
        trace.close()
    output.close()
    error.close()
    until = time.monotonic() + 15
    while (root.exists() or RUN.exists()) and time.monotonic() < until:
        time.sleep(0.01)
    assert not root.exists() and not RUN.exists()
'''

if __name__ == '__main__':
    raise SystemExit(run_fixture(FIXTURE, 'independent_state_home_fixture', timeout=150))
