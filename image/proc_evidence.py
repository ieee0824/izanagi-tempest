"""Bounded, read-only actor proc snapshots; raw records stay in private exec evidence."""
from collections import Counter
import errno
import json
import os
from pathlib import Path
import stat
import time

CONTROL_KEY = 'TEMPEST_PROC_PUBLIC_CONTROL'
CONTROL_VALUE = 'TEMPEST-PUBLIC-PROC-CONTROL'
MAX_PIDS = 128
MAX_BLOB = 8192
MAX_OUTPUT = 131072



def require_guest(manifest=Path('/etc/tempest/image.json')):
    if os.getuid() != 1000 or os.environ.get(CONTROL_KEY) != CONTROL_VALUE:
        raise RuntimeError('requires guest actor and public environment control')
    metadata = manifest.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise RuntimeError('requires root-owned nonwritable guest image manifest')
    image = json.loads(manifest.read_text())
    if image.get('izanagi_commit') != '16d0b55947006a166cfa29dcb8bfe71f65f8c36a' \
            or image.get('lws_commit') != '2c0ea463f334f10a562e54f1cdc7ba8a474029e2':
        raise RuntimeError('requires the pinned dummy guest image')


def failure(error):
    status = {errno.EACCES: 'denied', errno.EPERM: 'denied', errno.ENOENT: 'vanished',
              errno.ESRCH: 'vanished'}.get(error.errno, 'error')
    return {'status': status, 'errno': error.errno}


def read_blob(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            value = stream.read(MAX_BLOB + 1)
    except OSError as error:
        return failure(error)
    return {'status': 'read', 'text': value[:MAX_BLOB].decode('utf-8', 'replace'),
            'truncated': len(value) > MAX_BLOB}


def identity(path):
    try:
        fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
        return {'ppid': int(fields[1]), 'starttime_ticks': int(fields[19])}
    except OSError as error:
        return failure(error)


def snapshot(proc=Path('/proc'), own_pid=None, requested_pids=None):
    own_pid = os.getpid() if own_pid is None else own_pid
    started = time.monotonic_ns()
    if requested_pids is None:
        pids = sorted(int(path.name) for path in proc.iterdir() if path.name.isdecimal())
        selected = sorted(set([own_pid] + [pid for pid in pids if pid != own_pid][:MAX_PIDS - 1]))
        truncated = len(pids) > MAX_PIDS
    else:
        pids = list(requested_pids)
        if not pids or len(pids) > MAX_PIDS - 1 or len(set(pids)) != len(pids) \
                or any(type(pid) is not int or pid <= 0 for pid in pids):
            raise ValueError('invalid bounded proc page')
        selected = sorted(set([own_pid] + pids))
        truncated = False
    rows = []
    for pid in selected:
        path = proc / str(pid)
        before = identity(path)
        row = {'pid': pid, 'identity_before': before,
               'cmdline': read_blob(path / 'cmdline'), 'environ': read_blob(path / 'environ')}
        try:
            row['fd'] = {'status': 'listed', 'entries': len(list((path / 'fd').iterdir()))}
        except OSError as error:
            row['fd'] = failure(error)
        row['identity_after'] = identity(path)
        row['identity_stable'] = before == row['identity_after'] and 'starttime_ticks' in before
        rows.append(row)
    result = {'schema_version': 1, 'actor_uid': os.getuid(), 'own_pid': own_pid,
              'started_monotonic_ns': started, 'ended_monotonic_ns': time.monotonic_ns(),
              'pid_set_truncated': truncated, 'records': rows}
    encoded = json.dumps(result, separators=(',', ':')).encode()
    if len(encoded) > MAX_OUTPUT:
        raise RuntimeError('proc snapshot exceeds private capture budget; not complete')
    return result


def summarize(result):
    own = next(row for row in result['records'] if row['pid'] == result['own_pid'])
    command = own['cmdline']
    environment = own['environ']
    controls = {'cmdline': command.get('status') == 'read' and CONTROL_VALUE in command['text'],
                'environ': environment.get('status') == 'read' and
                CONTROL_KEY + '=' + CONTROL_VALUE in environment['text'].split('\0'),
                'fd_list': own['fd']['status'] == 'listed'}
    streams = [row[name] for row in result['records'] for name in ('cmdline', 'environ')]
    errors = sum(item['status'] == 'error' for item in streams) + sum(row['fd']['status'] == 'error' for row in result['records'])
    truncated = sum(bool(item.get('truncated')) for item in streams)
    return {'passed': result['actor_uid'] == 1000 and own['identity_stable'] and all(controls.values())
                      and not result['pid_set_truncated'] and not truncated and not errors,
            'records': len(result['records']), 'positive_controls': controls,
            'stable_identities': sum(row['identity_stable'] for row in result['records']),
            'cmdline_status': dict(Counter(row['cmdline']['status'] for row in result['records'])),
            'environ_status': dict(Counter(row['environ']['status'] for row in result['records'])),
            'fd_status': dict(Counter(row['fd']['status'] for row in result['records'])),
            'truncated_streams': truncated, 'unexpected_errors': errors,
            'scope': 'bounded actor-readable proc snapshots; FD listing only, no FD contents or complete lifetime'}


if __name__ == '__main__':
    require_guest()
    print(json.dumps(snapshot(), separators=(',', ':')))
