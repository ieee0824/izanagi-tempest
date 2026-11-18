#!/usr/bin/env python3
"""Read-only samples of fixed runtime trial VM sessions; JSONL sample/binding records are separate."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import time

SPEC = importlib.util.spec_from_file_location(
    'bootstrap_observe', Path(__file__).resolve().parent / 'izanagi-bootstrap/observe.py')
BOOTSTRAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOTSTRAP)
ROOT = '/var/lib/tempest-izanagi-runtime-normal-001'
UNIT = 'tempest-izanagi-runtime-normal-001.service'
STAGES = [ROOT + '/work/runs/normal-' + str(run) + suffix + '/sandbox'
          for run in (1, 2) for suffix in ('', '/retest')]

SEED_ROOT = '/var/lib/tempest-izanagi-runtime-seed-loss-001'
PRESENCE_ROOT = '/var/lib/tempest-izanagi-runtime-presence-001'
PRESENCE_STAGES = tuple(
    PRESENCE_ROOT + '/work/runs/finding-' + str(finding) + '-retest-' + str(retest) + suffix + '/sandbox'
    for finding, retest in ((1, 1), (1, 0), (0, 1), (0, 0))
    for suffix in (('', '/retest') if retest else ('',)))
PROFILES = {
    'normal': (ROOT, UNIT, tuple(STAGES)),
    'presence': (PRESENCE_ROOT, 'tempest-izanagi-runtime-presence-001.service', PRESENCE_STAGES),
    'seed-loss': (SEED_ROOT, 'tempest-izanagi-runtime-seed-loss-001.service',
                  (SEED_ROOT + '/work/runs/seed-reply-loss/sandbox',)),
    'delivery-race-completed': (
        '/var/lib/tempest-izanagi-delivery-race-completed-001',
        'tempest-izanagi-delivery-race-completed-001.service',
        tuple('/var/lib/tempest-izanagi-delivery-race-completed-001/work/runs/forced-delivery-race'
              + suffix + '/sandbox' for suffix in ('', '/retest'))),
    'delivery-race-large': (
        '/var/lib/tempest-izanagi-delivery-race-large-001',
        'tempest-izanagi-delivery-race-large-001.service',
        ('/var/lib/tempest-izanagi-delivery-race-large-001/work/runs/forced-delivery-race/sandbox',)),
}


def read_launch(workspace):
    path = Path(workspace).parent / 'vm-launch.json'
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None  # The process may be sampled before the launch record exists.
    with os.fdopen(fd, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 999 \
                or metadata.st_gid != 988 or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise RuntimeError('runtime launch record is not private and owned')
        data = stream.read(16385)
    if len(data) > 16384:
        raise RuntimeError('runtime launch record exceeds limit')
    return json.loads(data)


class Sessions:
    def __init__(self, profile="normal"):
        self.root, self.unit, self.stages = PROFILES[profile]
        self.identities = []
        self.nonces = {}
        self.bindings = {}

    def observe(self, row):
        if row['external_listener_observed']:
            raise RuntimeError('non-loopback listener in runtime unit')
        qemu = row['qemu_network']
        if len(qemu) > 1:
            raise RuntimeError('multiple simultaneous runtime VMs')
        if not qemu:
            return None
        qemu = qemu[0]
        workspace = qemu.get('cwd')
        if workspace not in self.stages:
            raise RuntimeError('unexpected runtime workspace')
        index = self.stages.index(workspace)
        BOOTSTRAP.validate_qemu_policy(qemu, self.root + '/inputs/image.qcow2', workspace)
        identity = (qemu.get('pid'), qemu.get('starttime_ticks'))
        if any(type(value) is not int or value <= 0 for value in identity):
            raise RuntimeError('runtime VM identity missing or invalid')
        if index == len(self.identities):
            if identity in self.identities:
                raise RuntimeError('runtime VM reused across stages')
            self.identities.append(identity)
        elif index != len(self.identities) - 1 or self.identities[index] != identity:
            raise RuntimeError('runtime stage order or VM identity changed')
        return index

    def bind(self, index, launch):
        if launch is None:
            return
        nonce = launch.get('boot_nonce')
        if not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{32}', nonce):
            raise RuntimeError('runtime boot nonce missing or invalid')
        if index in self.nonces and self.nonces[index] != nonce:
            raise RuntimeError('runtime boot nonce changed within stage')
        if any(other != index and previous == nonce for other, previous in self.nonces.items()):
            raise RuntimeError('runtime boot nonce reused across stages')
        self.nonces[index] = nonce
        state = launch.get('state')
        if state in ('launching', 'spawned'):
            if index in self.bindings:
                raise RuntimeError('runtime launch state regressed')
            return
        if state != 'running':
            raise RuntimeError('unexpected runtime launch state')
        pid = launch.get('supervisor_pid')
        fingerprint = launch.get('session_fingerprint')
        if type(pid) is not int or pid <= 0 or not isinstance(fingerprint, str) \
                or not re.fullmatch('[0-9a-f]{64}', fingerprint):
            raise RuntimeError('runtime session binding missing or invalid')
        binding = {'boot_nonce': nonce, 'supervisor_pid': pid, 'session_fingerprint': fingerprint}
        if index in self.bindings and self.bindings[index] != binding:
            raise RuntimeError('runtime session changed within stage')
        if any(other != index and previous['session_fingerprint'] == fingerprint
               for other, previous in self.bindings.items()):
            raise RuntimeError('runtime session fingerprint reused')
        self.bindings[index] = binding

    def snapshot(self):
        return [{'workspace': self.stages[index], 'pid': identity[0], 'starttime_ticks': identity[1],
                 'binding': self.bindings.get(index)} for index, identity in enumerate(self.identities)]

    def require_complete(self):
        if len(self.identities) != len(self.stages) or len(self.bindings) != len(self.stages):
            raise RuntimeError('not all planned runtime sessions were observed and bound')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trial', choices=tuple(PROFILES), default='normal',
                        help='fixed unit/root/stages: normal=4, seed-loss=1, presence=6 VMs')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('root required to observe socket owners')
    start = time.monotonic()
    invocation = None
    sessions = Sessions(args.trial)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        while time.monotonic() - start < 1870:
            row = BOOTSTRAP.sample(sessions.unit)
            current = row['unit'].get('InvocationID')
            if current:
                if invocation and current != invocation:
                    raise RuntimeError('runtime unit invocation changed')
                invocation = current
            # Save the raw sample even when validation fails.
            stream.write(json.dumps({'sample': row}) + '\n')
            stream.flush()
            index = sessions.observe(row)
            if index is not None:
                sessions.bind(index, read_launch(sessions.stages[index]))
            stream.write(json.dumps({'observed_sessions': sessions.snapshot()}) + '\n')
            stream.flush()
            if invocation and row['unit'].get('ActiveState') in ('inactive', 'failed'):
                if row['unit'].get('LoadState') != 'loaded' or current != invocation:
                    raise RuntimeError('same-invocation runtime terminal attributes not captured')
                if row['cgroup_pids']:
                    raise RuntimeError('terminal runtime unit retains processes')
                sessions.require_complete()
                return
            if not invocation and time.monotonic() - start > 60:
                raise RuntimeError('runtime unit not observed within startup window')
            time.sleep(1)
    raise RuntimeError('runtime observation deadline exceeded; inspect fixed unit')


if __name__ == '__main__':
    main()
