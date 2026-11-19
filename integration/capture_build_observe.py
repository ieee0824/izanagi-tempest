"""Observe one fixed fixture image build; separate from runtime VM policy."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import time

SPEC = importlib.util.spec_from_file_location('build_sample', Path(__file__).resolve().parent / 'izanagi-bootstrap/observe.py')
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
ROOT = '/var/lib/tempest-izanagi-capture-build-001'
UNIT = 'tempest-izanagi-capture-build-001.service'


class BuildLifetime:
    def __init__(self):
        self.identity = None

    def observe(self, row):
        if row['external_listener_observed']:
            raise ValueError('external build listener')
        for listener in row['listeners']:
            if listener['local'] not in {'127.0.0.1:18082', '127.0.0.1:22222', '127.0.0.1:5902'}:
                raise ValueError('unexpected build listener endpoint')
        vms = row['qemu_network']
        if len(vms) > 1:
            raise ValueError('multiple build QEMU processes')
        if not vms:
            return
        vm = vms[0]
        identity = (vm.get('pid'), vm.get('starttime_ticks'))
        if any(type(value) is not int or value <= 0 for value in identity):
            raise ValueError('build QEMU identity unavailable')
        if self.identity is not None and identity != self.identity:
            raise ValueError('build QEMU replaced')
        if vm.get('cwd') != ROOT + '/work':
            raise ValueError('build QEMU cwd mismatch')
        # Installer networking is an explicit build-only policy, not runtime isolation.
        if sorted(vm['network_args']) != sorted([['-netdev', 'user,id=user.0,hostfwd=tcp:127.0.0.1:22222-:22'],
                                                  ['-vnc', '127.0.0.1:2']]):
            raise ValueError('build QEMU network policy mismatch')
        expected = [['-drive', 'file=output-debian/debian-x86_64.qcow2,if=virtio,cache=writeback,discard=ignore,format=qcow2'],
                    ['-drive', 'file=' + ROOT + '/inputs/base.iso,media=cdrom']]
        if sorted(vm['storage_args']) != sorted(expected):
            raise ValueError('build QEMU disk or ISO mismatch')
        for listener in row['listeners']:
            if listener['local'] in {'127.0.0.1:22222', '127.0.0.1:5902'} and listener['pids'] != [vm['pid']]:
                raise ValueError('build QEMU listener ownership mismatch')
        self.identity = identity

    def require_observed(self):
        if self.identity is None:
            raise ValueError('no build QEMU identity observed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('root required for socket/process observation')
    lifetime, invocation = BuildLifetime(), None
    started = time.monotonic()
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        while time.monotonic() - started < 3670:
            row = BASE.sample(UNIT)
            try:
                current = row['unit'].get('InvocationID')
                if current:
                    if invocation and invocation != current:
                        raise ValueError('build Invocation changed')
                    invocation = current
                lifetime.observe(row)
            except Exception as error:
                row['observer_error'] = {'type': type(error).__name__, 'scope': 'fixed build policy validation failed'}
                stream.write(json.dumps(row) + '\n');stream.flush()
                raise
            stream.write(json.dumps(row) + '\n');stream.flush()
            if invocation and row['unit'].get('ActiveState') in ('inactive', 'failed'):
                if row['unit'].get('LoadState') != 'loaded' or current != invocation:
                    raise ValueError('same-invocation build terminal attributes unavailable')
                if row['cgroup_pids']:
                    raise ValueError('build terminal retains processes')
                lifetime.require_observed()
                return
            if not invocation and time.monotonic() - started > 60:
                raise ValueError('build unit startup not observed')
            time.sleep(1)
    raise ValueError('build observation deadline exceeded; inspect fixed unit')


if __name__ == '__main__':
    main()
