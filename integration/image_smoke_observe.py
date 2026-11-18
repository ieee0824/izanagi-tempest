#!/usr/bin/env python3
"""Read-only observation of the first fixed Linux image smoke unit."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import time

SPEC = importlib.util.spec_from_file_location(
    'bootstrap_observe', Path(__file__).resolve().parent / 'izanagi-bootstrap/observe.py')
BOOTSTRAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOTSTRAP)
UNIT = 'tempest-izanagi-image-smoke-001.service'
ROOT = '/var/lib/tempest-izanagi-image-smoke-001'


def validate_runtime(row):
    if row['external_listener_observed']:
        raise RuntimeError('non-loopback listener in smoke unit')
    qemu = row['qemu_network']
    if len(qemu) > 1:
        raise RuntimeError('multiple QEMU processes in smoke unit')
    if not qemu:
        return False
    network = [value for key, value in qemu[0]['network_args'] if key == '-netdev']
    if len(network) != 1 or network[0].split(',')[0] != 'user' or 'restrict=on' not in network[0].split(','):
        raise RuntimeError('restricted user networking not observed')
    forwards = [part for part in network[0].split(',') if part.startswith('hostfwd=')]
    if len(forwards) != 1 or not re.fullmatch(r'hostfwd=tcp:127\.0\.0\.1:\d+-:9001', forwards[0]):
        raise RuntimeError('unexpected agent forwarding')
    storage = qemu[0]['storage_args']
    drives = [value for key, value in storage if key == '-drive']
    shares = [value for key, value in storage if key == '-fsdev']
    if len(drives) != 1 or not {'file=' + ROOT + '/inputs/image.qcow2', 'snapshot=on'} <= set(drives[0].split(',')):
        raise RuntimeError('fixed image snapshot protection not observed')
    if len(shares) != 1 or not {'path=' + ROOT + '/work/output/workspace',
                                'security_model=mapped-xattr', 'readonly=on'} <= set(shares[0].split(',')):
        raise RuntimeError('fixed read-only mapped share not observed')
    return True


class VmLifetime:
    """Bind observed QEMU samples to one PID/starttime within the fixed unit."""
    def __init__(self):
        self.identity = None

    def observe(self, row):
        if not validate_runtime(row):
            return
        qemu = row['qemu_network'][0]
        identity = (qemu.get('pid'), qemu.get('starttime_ticks'))
        if any(type(value) is not int or value <= 0 for value in identity):
            raise RuntimeError('QEMU process identity missing or invalid')
        if self.identity is not None and identity != self.identity:
            raise RuntimeError('QEMU process identity changed during smoke')
        self.identity = identity

    def require_observed(self):
        if self.identity is None:
            raise RuntimeError('smoke terminated without observing a QEMU identity')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('root required to observe socket ownership')
    invocation = None
    lifetime = VmLifetime()
    start = time.monotonic()
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        while time.monotonic() - start < 1870:
            row = BOOTSTRAP.sample(UNIT)
            current = row['unit'].get('InvocationID')
            if current:
                if invocation and current != invocation:
                    raise RuntimeError('smoke unit invocation changed')
                invocation = current
            stream.write(json.dumps(row) + '\n')
            stream.flush()
            lifetime.observe(row)
            if invocation and row['unit'].get('ActiveState') in ('inactive', 'failed'):
                if row['unit'].get('LoadState') != 'loaded' or current != invocation:
                    raise RuntimeError('same-invocation terminal attributes not captured')
                if row['cgroup_pids']:
                    raise RuntimeError('terminal smoke unit retains processes')
                lifetime.require_observed()
                return
            if not invocation and time.monotonic() - start > 60:
                raise RuntimeError('smoke unit not observed within startup window')
            time.sleep(1)
    raise RuntimeError('observation deadline exceeded; inspect fixed smoke unit')


if __name__ == '__main__':
    main()
