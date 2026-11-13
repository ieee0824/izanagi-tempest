#!/usr/bin/python3 -I
"""Root mailbox helper: freeze the pinned RPC service and kill its descendants."""
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time

UNIT = 'izanagi-agent.service'
GROUP = Path('/sys/fs/cgroup/system.slice/izanagi-agent.service')
EXE = Path('/usr/local/bin/izanagi-agent')


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def identity():
    result = subprocess.run(['systemctl', 'show', UNIT, '--property=MainPID,InvocationID,ControlGroup,ActiveState,SubState'],
                            capture_output=True, text=True, timeout=5, check=True)
    fields = dict(line.split('=', 1) for line in result.stdout.splitlines())
    require(fields['ActiveState'] == 'active' and fields['SubState'] == 'running', 'daemon_not_running')
    require(fields['ControlGroup'] == '/system.slice/' + UNIT, 'unexpected_cgroup')
    pid = int(fields['MainPID'])
    require(pid > 1 and fields['InvocationID'], 'missing_daemon_identity')
    proc = Path('/proc') / str(pid)
    require((proc / 'exe').resolve() == EXE, 'unexpected_daemon_exe')
    status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines())
    require(set(status['Uid'].split()) == {'0'}, 'daemon_not_root')
    start = (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19]
    with (proc / 'exe').open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'pid': pid, 'start_ticks': start, 'invocation_id': fields['InvocationID'],
            'exe_sha256': digest, 'cgroup': fields['ControlGroup']}


def events(path):
    return dict(line.split() for line in (path / 'cgroup.events').read_text().splitlines())


def wait_for(test):
    deadline = time.monotonic() + 5
    while not test():
        require(time.monotonic() < deadline, 'cgroup_deadline')
        time.sleep(0.01)


def groups():
    return [GROUP, *sorted(p for p in GROUP.rglob('*') if p.is_dir())]


def quiesce(expected):
    require(identity() == expected, 'daemon_identity_changed')
    descriptor = os.pidfd_open(expected['pid'])
    try:
        require(not select.select([descriptor], [], [], 0)[0], 'daemon_exited')
        (GROUP / 'cgroup.freeze').write_text('1')
        wait_for(lambda: events(GROUP)['frozen'] == '1')
        frozen_guest_ns = time.time_ns()
        require(identity() == expected, 'daemon_identity_changed')
        target = GROUP / 'tempest-quiesce'
        target.mkdir()  # Never reuse a previous collection subgroup.
        moved = []
        for group in groups():
            if group == target:
                continue
            for pid in map(int, (group / 'cgroup.procs').read_text().split()):
                if pid != expected['pid']:
                    (target / 'cgroup.procs').write_text(str(pid))
                    moved.append(pid)
        # No task can fork while the whole service is frozen.
        (target / 'cgroup.kill').write_text('1')
        wait_for(lambda: events(target)['populated'] == '0')
        for group in groups():
            pids = set(map(int, (group / 'cgroup.procs').read_text().split()))
            require(pids == ({expected['pid']} if group == GROUP else set()), 'descendant_remains')
        require(identity() == expected and not select.select([descriptor], [], [], 0)[0], 'daemon_identity_changed')
        require(events(GROUP)['frozen'] == '1', 'service_not_frozen')
        return {'identity': expected, 'moved_pids': moved, 'descendants_empty': True, 'service_frozen': True,
                'frozen_guest_ns': frozen_guest_ns}
    finally:
        os.close(descriptor)


def main():
    require(os.geteuid() == 0, 'root_required')
    require(len(sys.argv) == 2, 'invalid_arguments')
    if sys.argv[1] == 'attest':
        result = identity()
    else:
        expected = json.load(sys.stdin)
        if sys.argv[1] == 'quiesce':
            result = quiesce(expected)
        else:
            require(sys.argv[1] == 'thaw', 'invalid_operation')
            require(identity() == expected, 'daemon_identity_changed')
            (GROUP / 'cgroup.freeze').write_text('0')
            wait_for(lambda: events(GROUP)['frozen'] == '0')
            result = {'thawed': True}
    print(json.dumps(result))


if __name__ == '__main__':
    main()
