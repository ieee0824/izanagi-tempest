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
                marker = os.open(ROOT / 'observer-ready', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o440)
                os.fchown(marker, 0, 988)
                with os.fdopen(marker, 'w') as ready:
                    ready.write('ready\n')
                    ready.flush()
                    os.fsync(ready.fileno())
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
