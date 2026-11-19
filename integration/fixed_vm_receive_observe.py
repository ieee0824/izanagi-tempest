"""Validate fixed guest acknowledgements and private export on the host."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

PHASES = ('control_before', 'allow_same_run', 'deny_other', 'control_after')
FIELDS = {'schema_version', 'run_nonce', 'boot_id'}
COUNT_FIELDS = ('received', 'matched')
FIXED_IMAGE_SHA256 = '8e6ad453eea6a270fcee63e3dae5e79f90a4d25e70420c07f9fde52d2f51c3f4'
FIXED_GUEST_SHA256 = '3bc9fd0a15aa2f1e0e14f8a33731d0051242ae48ca991e937ad8506ae30d4284'
RECEIVER_PATH = Path('readonly-check/fixed-vm-receive.py')
RECEIVER_SOURCE = Path(__file__).resolve().parents[1] / 'image/fixed_vm_receive.py'


def stage_receiver(workspace, mapped_metadata):
    """Publish the fixed script into the harness's mapped read-only share."""
    destination = workspace / RECEIVER_PATH
    with destination.open('xb') as stream:
        stream.write(RECEIVER_SOURCE.read_bytes())
    mapped_metadata(destination, stat.S_IFREG | 0o444)
    destination.chmod(0o444)



def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate guest record field')
        result[key] = value
    return result


def parse_record(raw, limit, extra_fields, run_nonce, boot_id):
    if (
        re.fullmatch(r'[0-9a-f]{32}', run_nonce) is None
        or str(uuid.UUID(boot_id)) != boot_id
        or not 0 < len(raw) <= limit
    ):
        raise ValueError('invalid guest record binding or size')
    record = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object)
    if not isinstance(record, dict) or set(record) != FIELDS | extra_fields:
        raise ValueError('invalid guest record schema')
    if type(record['schema_version']) is not int or record['schema_version'] != 1:
        raise ValueError('invalid guest record version')
    if (record['run_nonce'], record['boot_id']) != (run_nonce, boot_id):
        raise ValueError('guest record binding mismatch')
    return record


def require_counts(counts, expected):
    if not isinstance(counts, dict) or set(counts) != set(COUNT_FIELDS):
        raise ValueError('invalid guest count schema')
    if any(type(counts[key]) is not int or counts[key] != expected for key in COUNT_FIELDS):
        raise ValueError('unexpected guest count')


def validate_guest_ack(stdout, *, run_nonce, boot_id, phase, operation):
    """Require the exact cumulative count at a fixed phase operation."""
    index = PHASES.index(phase)
    if operation not in ('start', 'request', 'end') or (phase == 'deny_other' and operation == 'request'):
        raise ValueError('invalid expected guest operation')
    if stdout.count(b'\n') != 1 or not stdout.endswith(b'\n'):
        raise ValueError('invalid guest acknowledgement framing')
    ack = parse_record(stdout, 512, {'phase', 'operation', 'counts', 'matched'}, run_nonce, boot_id)
    if (ack['phase'], ack['operation']) != (phase, operation) or ack['matched'] is not True:
        raise ValueError('unexpected guest acknowledgement')
    total = index - int(index > 2)
    require_counts(ack['counts'], total + int(phase != 'deny_other' and operation != 'start'))
    return ack


def validate_guest_export(raw, *, run_nonce, boot_id):
    """Require all closed phases, including independently measured denial."""
    report = parse_record(raw, 4096, {'counts', 'phases', 'complete'}, run_nonce, boot_id)
    if report['complete'] is not True or not isinstance(report['phases'], list) or len(report['phases']) != len(PHASES):
        raise ValueError('incomplete guest report')
    total = 0
    for phase, row in zip(PHASES, report['phases'], strict=True):
        if not isinstance(row, dict) or set(row) != {'phase', 'start', 'end', 'delta'} or row['phase'] != phase:
            raise ValueError('invalid guest phase record')
        delta = int(phase != 'deny_other')
        require_counts(row['start'], total)
        require_counts(row['delta'], delta)
        total += delta
        require_counts(row['end'], total)
    require_counts(report['counts'], total)
    return report


def observe_guest(execute, *, run_nonce, boot_id, phase, operation):
    """Invoke the fixed receiver through the harness's private session executor."""
    if re.fullmatch(r'[0-9a-f]{32}', run_nonce) is None or str(uuid.UUID(boot_id)) != boot_id:
        raise ValueError('invalid expected guest binding')
    if phase not in PHASES or operation not in ('start', 'request', 'end', 'report'):
        raise ValueError('invalid expected guest operation')
    if (operation == 'report' and phase != PHASES[-1]) or (operation == 'request' and phase == 'deny_other'):
        raise ValueError('invalid operation for guest phase')
    argv = ['/usr/bin/python3', '-I', '-B', str(Path('/workspace') / RECEIVER_PATH),
            operation, run_nonce, phase]
    if operation == 'request':
        argv.append(f'tempest-dummy-v1:{run_nonce}:{phase}')
    result = execute(*argv, timeout=10)
    if result.returncode != 0:
        raise RuntimeError('fixed guest receiver failed')
    stdout = result.stdout.encode('utf-8', 'surrogateescape')
    if operation == 'report':
        if stdout.count(b'\n') != 1 or not stdout.endswith(b'\n'):
            raise ValueError('invalid guest report framing')
        return validate_guest_export(stdout[:-1], run_nonce=run_nonce, boot_id=boot_id)
    return validate_guest_ack(stdout, run_nonce=run_nonce, boot_id=boot_id, phase=phase, operation=operation)


def preflight_guest(execute, build_inputs):
    """Check the dedicated image and capture boot identity before the first phase."""
    if build_inputs.get('fixed_vm_receiver_fixture') is not True:
        raise ValueError('fixed receiver fixture image required')
    if build_inputs.get('input_sha256', {}).get('guest') != FIXED_GUEST_SHA256:
        raise ValueError('fixed receiver guest input digest mismatch')
    code = """import hashlib, json, os, pwd, stat, uuid
from pathlib import Path
path = Path('/run/tempest-fixed-vm-receiver')
info = path.lstat()
owner = pwd.getpwnam('izanagi')
if (owner.pw_uid == 0 or os.geteuid() != owner.pw_uid or os.getegid() != owner.pw_gid
    or (info.st_uid, info.st_gid) != (owner.pw_uid, owner.pw_gid)
    or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
    or next(path.iterdir(), None) is not None):
    raise SystemExit('invalid fixed receiver record directory')
guest = '/usr/local/libexec/tempest-guest-native'
manifest = json.loads(Path('/etc/tempest/image.json').read_bytes())
with Path(guest).open('rb') as binary:
    actual = hashlib.file_digest(binary, 'sha256').hexdigest()
if (manifest.get('fixed_vm_receiver_fixture') is not True
    or manifest['input_sha256']['guest'] != actual or manifest['installed_sha256'][guest] != actual):
    raise SystemExit('invalid fixed receiver guest manifest')
boot = uuid.UUID(Path('/proc/sys/kernel/random/boot_id').read_text().strip())
print(json.dumps({'boot_id': str(boot), 'uid': info.st_uid, 'gid': info.st_gid, 'guest_sha256': actual}))
"""
    result = execute('/usr/bin/python3', '-I', '-B', '-c', code, timeout=10)
    if result.returncode != 0:
        raise RuntimeError('fixed guest receiver preflight failed')
    stdout = result.stdout
    if len(stdout) > 256 or stdout.count('\n') != 1 or not stdout.endswith('\n'):
        raise ValueError('invalid guest preflight framing')
    record = json.loads(stdout, object_pairs_hook=unique_object)
    if not isinstance(record, dict) or set(record) != {'boot_id', 'uid', 'gid', 'guest_sha256'}:
        raise ValueError('invalid guest preflight schema')
    boot_id = record['boot_id']
    if not isinstance(boot_id, str) or str(uuid.UUID(boot_id)) != boot_id:
        raise ValueError('invalid guest preflight boot ID')
    if any(type(record[key]) is not int or record[key] <= 0 for key in ('uid', 'gid')):
        raise ValueError('invalid guest preflight ownership')
    if record['guest_sha256'] != FIXED_GUEST_SHA256:
        raise ValueError('guest executable digest mismatch')
    return record


def validate_trial_counts(guest_export, host_phases, *, run_nonce, boot_id):
    """Require the same ordered intervals in guest and alternate-host counters."""
    guest = validate_guest_export(guest_export, run_nonce=run_nonce, boot_id=boot_id)
    if not isinstance(host_phases, list) or len(host_phases) != len(PHASES):
        raise ValueError('incomplete host phase records')
    total = 0
    for phase, host in zip(PHASES, host_phases, strict=True):
        if (
            not isinstance(host, dict)
            or set(host) != {'run_nonce', 'boot_id', 'phase', 'start', 'end', 'delta'}
            or (host['run_nonce'], host['boot_id'], host['phase']) != (run_nonce, boot_id, phase)
        ):
            raise ValueError('host phase binding mismatch')
        delta = int(phase in ('control_before', 'control_after'))
        for field, expected in (('start', total), ('end', total + delta), ('delta', delta)):
            counts = host[field]
            if not isinstance(counts, dict) or set(counts) != {'accepted', 'matched'}:
                raise ValueError('invalid host counter schema')
            if any(type(count) is not int or count != expected for count in counts.values()):
                raise ValueError('unexpected alternate host listener count')
        total += delta
    return guest

def session_binding(workspace, home, *, owner_uid, supervisor_pid, forward):
    """Check the private QEMU session against the parent and the observed forward."""
    instance = hashlib.sha256(os.fsencode(workspace)).hexdigest()
    path = home / '.izanagi' / 'instances' / instance / 'session.json'
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != owner_uid or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1 or not 0 < before.st_size <= 4096
        ):
            raise ValueError('invalid private session file')
        data = stream.read(4097)
        after = os.fstat(stream.fileno())
        current = path.lstat()
    identity = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if len(data) != before.st_size or any(
        getattr(before, key) != getattr(item, key) for item in (after, current) for key in identity
    ):
        raise ValueError('private session file changed during observation')
    session = json.loads(data, object_pairs_hook=unique_object)
    if not isinstance(session, dict) or set(session) != {'backend', 'pid', 'started_at'}:
        raise ValueError('invalid QEMU session schema')
    backend = session['backend']
    if (
        not isinstance(backend, dict) or backend.get('type') != 'qemu'
        or type(backend.get('host_port')) is not int or backend['host_port'] != forward['port']
        or type(session['pid']) is not int or session['pid'] != supervisor_pid
        or type(session['started_at']) is not int or session['started_at'] <= 0
    ):
        raise ValueError('private QEMU session does not match observed forward')
    return hashlib.sha256(data).digest()


class TrialBoundaries:
    """Require a live forward, session and guest binding at each phase boundary."""

    def __init__(self, *, run_nonce, boot_id, forward, session_fingerprint):
        if re.fullmatch(r'[0-9a-f]{32}', run_nonce) is None or str(uuid.UUID(boot_id)) != boot_id:
            raise ValueError('invalid fixed trial binding')
        if not isinstance(session_fingerprint, bytes) or len(session_fingerprint) != 32:
            raise ValueError('missing private session fingerprint')
        self._identity = (run_nonce, boot_id, dict(forward), session_fingerprint)
        self._boundaries = iter((phase, edge) for phase in PHASES for edge in ('start', 'end'))
        self._next = next(self._boundaries, None)

    def observe(self, phase, edge, *, guest_ack, forward, session_fingerprint):
        if (phase, edge) != self._next:
            raise ValueError('missing or out-of-order trial boundary')
        if (guest_ack['phase'], guest_ack['operation']) != (phase, edge):
            raise ValueError('guest acknowledgement is for a different boundary')
        bound = (guest_ack['run_nonce'], guest_ack['boot_id'], forward, session_fingerprint)
        if bound != self._identity:
            raise ValueError('fixed VM identity changed at trial boundary')
        self._next = next(self._boundaries, None)

    def require_complete(self):
        if self._next is not None:
            raise ValueError('incomplete trial boundary observations')


def collect_trial(execute, observe_route, snapshot_host, run_phase, *, run_nonce, boot_id):
    """Collect the fixed phase evidence around a harness-owned connection runner."""
    binding = {'run_nonce': run_nonce, 'boot_id': boot_id}
    forward, fingerprint = observe_route()
    boundaries = TrialBoundaries(**binding, forward=forward, session_fingerprint=fingerprint)

    def observe_boundary(phase, edge):
        ack = observe_guest(execute, **binding, phase=phase, operation=edge)
        current_forward, current_fingerprint = observe_route()
        boundaries.observe(phase, edge, guest_ack=ack, forward=current_forward,
                           session_fingerprint=current_fingerprint)

    host_phases = []
    for phase in PHASES:
        observe_boundary(phase, 'start')
        before = dict(snapshot_host())
        run_phase(phase)
        after = dict(snapshot_host())
        observe_boundary(phase, 'end')
        host_phases.append({
            **binding, 'phase': phase, 'start': before, 'end': after,
            'delta': {key: after[key] - before[key] for key in ('accepted', 'matched')},
        })

    boundaries.require_complete()
    guest = observe_guest(execute, **binding, phase=PHASES[-1], operation='report')
    if observe_route() != (forward, fingerprint):
        raise ValueError('fixed VM identity changed during final report')
    validate_trial_counts(json.dumps(guest).encode(), host_phases, **binding)
    return {'guest': guest, 'host_phases': host_phases, 'forward': forward}
