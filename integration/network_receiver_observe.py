"""Fixed host-endpoint receiver observation; never accepts paths from ready JSON."""
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time

ROOT = Path('/var/lib/tempest-izanagi-host-endpoint-001')
UNIT = 'tempest-izanagi-host-endpoint-001.service'
FIELDS = {'schema_version', 'nonce', 'host_pid', 'address', 'port', 'socket_inode'}


def identity(value):
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError('receiver ready schema')
    if type(value['schema_version']) is not int or value['schema_version'] != 1 \
            or not isinstance(value['nonce'], str) or re.fullmatch('[0-9a-f]{32}', value['nonce']) is None \
            or value['address'] != '127.0.0.1':
        raise ValueError('receiver ready binding')
    for name in ('host_pid', 'port', 'socket_inode'):
        if type(value[name]) is not int or value[name] <= 0:
            raise ValueError('receiver ready integer')
    if not 1024 <= value['port'] <= 65535:
        raise ValueError('receiver port bound')
    return value


def private_json(path, owner=(999, 988, 0o600)):
    # Fixed ancestors must remain real directories, including runner-owned output.
    for parent in path.parents:
        if parent.is_symlink() or not stat.S_ISDIR(parent.lstat().st_mode):
            raise ValueError('receiver state parent changed')
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink not in (1, 2) \
                or (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) != owner:
            raise ValueError('receiver state owner/mode/type')
        publication_deadline = time.monotonic() + 1
        while before.st_nlink == 2:
            current = path.lstat()
            if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
                raise ValueError('receiver publication inode replaced')
            if time.monotonic() >= publication_deadline:
                raise ValueError('receiver publication did not become single-link')
            time.sleep(.01)
            before = os.fstat(stream.fileno())
        current = path.lstat()
        if before.st_nlink != 1 or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino) \
                or (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) != owner:
            raise ValueError('receiver publication identity changed')
        data = stream.read(4097)
        after = os.fstat(stream.fileno())
        if len(data) > 4096 or len(data) != before.st_size \
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != \
                   (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('receiver state changed or oversized')
    return json.loads(data)


def starttime(text):
    result = int(text.rsplit(')', 1)[1].split()[19])
    if result <= 0:
        raise ValueError('receiver process starttime')
    return result


def inspect_process(ready, proc=Path('/proc')):
    process = proc / str(ready['host_pid'])
    before = starttime((process / 'stat').read_text())
    metadata = process.stat()
    if (metadata.st_uid, metadata.st_gid) != (999, 988):
        raise ValueError('receiver process owner')
    if '0::/system.slice/' + UNIT not in (process / 'cgroup').read_text().splitlines():
        raise ValueError('receiver process cgroup')
    found = False
    for count, path in enumerate((process / 'fd').iterdir(), 1):
        if count > 4096:
            raise ValueError('receiver fd budget')
        try:
            found |= os.readlink(path) == 'socket:[' + str(ready['socket_inode']) + ']'
        except FileNotFoundError:
            continue
    if not found or starttime((process / 'stat').read_text()) != before:
        raise ValueError('receiver socket or process identity changed')
    return before


def listener_matches(ready, row):
    endpoint = '127.0.0.1:' + str(ready['port'])
    matches = [item for item in row['listeners'] if item['local'].rsplit(':', 1)[-1] == str(ready['port'])]
    if len(matches) != 1 or matches[0]['local'] != endpoint or matches[0]['pids'] != [ready['host_pid']]:
        raise ValueError('receiver listener ownership or endpoint changed')
    if str(ready['host_pid']) != row['unit'].get('MainPID') or ready['host_pid'] not in row['cgroup_pids']:
        raise ValueError('receiver not fixed unit MainPID')
    for vm in row['qemu_network']:
        if vm['pid'] == ready['host_pid']:
            raise ValueError('receiver and QEMU roles overlap')
        for key, value in vm['network_args']:
            if key == '-netdev' and ('hostfwd=tcp:' + endpoint + '-:9001') in value.split(','):
                raise ValueError('receiver port overlaps QEMU forward')


def publish_ack(path, value):
    data = (json.dumps(value, separators=(',', ':')) + '\n').encode()
    if len(data) > 4096:
        raise ValueError('receiver ack budget')
    temporary = path.with_name(path.name + '.pending-' + secrets.token_hex(8))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchown(stream.fileno(), 0, 988)
            os.fchmod(stream.fileno(), 0o440)
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
    finally:
        temporary.unlink(missing_ok=True)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class ReceiverLifetime:
    def __init__(self, root=ROOT):
        self.root = root
        self.ready = None
        self.ack = None
        self.closed = None

    def observe(self, row):
        ready_path = self.root / 'work/output/network-receiver.ready.json'
        if not ready_path.parent.exists():
            if self.ready is not None:
                raise ValueError('receiver output disappeared')
            return {'phase': 'waiting_ready'}
        ready = private_json(ready_path)
        if ready is None:
            if self.ready is not None:
                raise ValueError('receiver ready disappeared')
            return {'phase': 'waiting_ready'}
        identity(ready)
        if self.ready is not None and ready != self.ready:
            raise ValueError('receiver ready identity changed')
        self.ready = ready
        closed = private_json(self.root / 'work/output/network-receiver.closed.json')
        if closed is not None:
            if set(closed) != {'schema_version', 'identity', 'receiver_closed', 'host_monotonic_ns'} \
                    or type(closed['schema_version']) is not int or closed['schema_version'] != 1 \
                    or closed['identity'] != ready or closed['receiver_closed'] is not True \
                    or type(closed['host_monotonic_ns']) is not int or closed['host_monotonic_ns'] <= 0:
                raise ValueError('receiver closed binding')
            if self.ack is None or (self.closed is not None and self.closed != closed):
                raise ValueError('receiver closed without ack or changed')
            if any(item['local'].rsplit(':', 1)[-1] == str(ready['port']) for item in row['listeners']):
                raise ValueError('receiver listener remains after closed')
            self.closed = closed
            return {'phase': 'closed', 'identity': ready, 'ack': self.ack, 'closed': closed}
        if self.closed is not None:
            raise ValueError('receiver closed record disappeared')
        invocation = row['unit'].get('InvocationID', '')
        if re.fullmatch('[0-9a-f]{32}', invocation) is None:
            raise ValueError('receiver invocation missing')
        listener_matches(ready, row)
        ticks = inspect_process(ready)
        ack = {**ready, 'host_pid_starttime_ticks': ticks, 'invocation_id': invocation}
        if self.ack is None:
            publish_ack(self.root / 'work/evidence/network-receiver-observed.json', ack)
            self.ack = ack
        elif self.ack != ack:
            raise ValueError('receiver live identity changed')
        return {'phase': 'live', 'identity': ready, 'ack': self.ack}

    def require_complete(self):
        if self.ack is None or self.closed is None:
            raise ValueError('receiver acknowledgement/closure not observed')
