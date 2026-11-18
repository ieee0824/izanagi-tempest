#!/usr/bin/env python3
"""Read-only observation of fixed Linux image smoke attempts."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import time

SPEC = importlib.util.spec_from_file_location(
    'bootstrap_observe', Path(__file__).resolve().parent / 'izanagi-bootstrap/observe.py')
BOOTSTRAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOTSTRAP)
UNIT = 'tempest-izanagi-image-smoke-001.service'
ROOT = '/var/lib/tempest-izanagi-image-smoke-001-v2'
ATTEMPTS = {
    '001': (UNIT, ROOT),
    '002': ('tempest-izanagi-image-smoke-002.service', '/var/lib/tempest-izanagi-image-smoke-002'),
    'exec-exposure-001': ('tempest-izanagi-exec-exposure-001.service', '/var/lib/tempest-izanagi-exec-exposure-001'),
    'proc-exposure-001': ('tempest-izanagi-proc-exposure-001.service', '/var/lib/tempest-izanagi-proc-exposure-001'),
    'proc-exposure-002': ('tempest-izanagi-proc-exposure-002.service', '/var/lib/tempest-izanagi-proc-exposure-002'),
    'proc-exposure-003': ('tempest-izanagi-proc-exposure-003.service', '/var/lib/tempest-izanagi-proc-exposure-003'),
    'sidecar-001': ('tempest-izanagi-sidecar-001.service', '/var/lib/tempest-izanagi-sidecar-001'),
    'host-endpoint-001': ('tempest-izanagi-host-endpoint-001.service', '/var/lib/tempest-izanagi-host-endpoint-001'),
}


def validate_runtime(row, root=ROOT):
    if row['external_listener_observed']:
        raise RuntimeError('non-loopback listener in smoke unit')
    qemu = row['qemu_network']
    if len(qemu) > 1:
        raise RuntimeError('multiple QEMU processes in smoke unit')
    if not qemu:
        return False
    BOOTSTRAP.validate_qemu_policy(qemu[0], root + '/inputs/image.qcow2', root + '/work/output/workspace')
    return True


class VmLifetime:
    """Bind observed QEMU samples to one PID/starttime within the fixed unit."""
    def __init__(self, root=ROOT):
        self.root = root
        self.identity = None

    def observe(self, row):
        if not validate_runtime(row, self.root):
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
    parser.add_argument('--attempt', choices=tuple(ATTEMPTS), default='001')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('root required to observe socket ownership')
    invocation = None
    unit, root = ATTEMPTS[args.attempt]
    lifetime = VmLifetime(root)
    receiver = None
    if args.attempt == 'host-endpoint-001':
        spec = importlib.util.spec_from_file_location('network_receiver_observe', Path(__file__).resolve().parent / 'network_receiver_observe.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        receiver = module.ReceiverLifetime(Path(root))
    start = time.monotonic()
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        while time.monotonic() - start < 1870:
            row = BOOTSTRAP.sample(unit)
            try:
                current = row['unit'].get('InvocationID')
                if current:
                    if invocation and current != invocation:
                        raise RuntimeError('smoke unit invocation changed')
                    invocation = current
                lifetime.observe(row)
                if receiver is not None:
                    row['host_receiver'] = receiver.observe(row)
            except Exception as error:
                # Preserve the rejected sample without echoing arbitrary state data.
                row['observer_error'] = {'type': type(error).__name__, 'scope': 'runtime or receiver validation failed'}
                stream.write(json.dumps(row) + '\n')
                stream.flush()
                raise
            stream.write(json.dumps(row) + '\n')
            stream.flush()
            if invocation and row['unit'].get('ActiveState') in ('inactive', 'failed'):
                if row['unit'].get('LoadState') != 'loaded' or current != invocation:
                    raise RuntimeError('same-invocation terminal attributes not captured')
                if row['cgroup_pids']:
                    raise RuntimeError('terminal smoke unit retains processes')
                lifetime.require_observed()
                if receiver is not None:
                    receiver.require_complete()
                return
            if not invocation and time.monotonic() - start > 60:
                raise RuntimeError('smoke unit not observed within startup window')
            time.sleep(1)
    raise RuntimeError('observation deadline exceeded; inspect fixed smoke unit')


if __name__ == '__main__':
    main()
