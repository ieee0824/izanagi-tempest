"""Read-only no-QEMU observation of the one fixed reservation unit."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path('/var/lib/tempest-izanagi-runtime-reservation-001')
UNIT = 'tempest-izanagi-runtime-reservation-001.service'


def qemu_pids():
    found = []
    for path in Path('/proc').glob('[0-9]*/comm'):
        try:
            name = path.read_text().strip()
        except (FileNotFoundError, ProcessLookupError):
            continue
        if name.startswith('qemu-system-') or name == 'qemu-kvm':
            found.append(int(path.parent.name))
    return sorted(found)



def publish_ready(root):
    # The final name must never expose an incomplete or unreadable marker.
    pending = root / 'observer-ready.pending'
    marker = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(marker, 'w') as ready:
        ready.write('ready\n')
        ready.flush()
        os.fchown(ready.fileno(), 0, 988)
        os.fchmod(ready.fileno(), 0o440)  # Explicitly restore group read after umask077.
        os.fsync(ready.fileno())
    os.link(pending, root / 'observer-ready', follow_symlinks=False)
    pending.unlink()
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main():
    assert os.geteuid() == 0
    spec = importlib.util.spec_from_file_location('bootstrap', ROOT / 'inputs/bootstrap_observe.py')
    bootstrap = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bootstrap)
    os.umask(0o077)
    fd = os.open(ROOT / 'observation.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    invocation = None
    start = time.monotonic()
    with os.fdopen(fd, 'w') as stream:
        while time.monotonic() - start < 110:
            row = bootstrap.sample(UNIT)
            pids = qemu_pids()
            stream.write(json.dumps({'sample': row, 'host_qemu_pids': pids}) + '\n')
            stream.flush()
            if pids or row['qemu_network']:
                subprocess.run(['/usr/bin/systemctl', 'stop', UNIT], check=False, timeout=15)
                raise RuntimeError('unexpected QEMU; stopped only reservation unit')
            if not (ROOT / 'observer-ready').exists():
                publish_ready(ROOT)
            current = row['unit'].get('InvocationID')
            if current:
                assert invocation is None or current == invocation
                invocation = current
            if invocation and row['unit'].get('ActiveState') in ('inactive', 'failed'):
                if row['unit'].get('LoadState') != 'loaded' or current != invocation:
                    raise RuntimeError('same-invocation terminal unknown after GC')
                assert not row['cgroup_pids']
                return
            time.sleep(0.1)
    raise RuntimeError('reservation observation deadline; inspect fixed unit')


if __name__ == '__main__':
    main()
