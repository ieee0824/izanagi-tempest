"""Fixed same-ID refusal check. No scenario/seed is intended to execute."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import time

ROOT = Path('/var/lib/tempest-izanagi-runtime-reservation-001')
OLD = Path('/var/lib/tempest-izanagi-runtime-seed-loss-001')
COMMAND = [str(OLD / 'inputs/tempest'), 'run', str(OLD / 'inputs/repo/scenarios/s3-overread-001.yaml'),
           '--agent', 'mock', '--mock-script', str(OLD / 'inputs/repo/integration/mock-s3-overread.json'),
           '--izanagi', str(OLD / 'inputs/izanagi'), '--image', str(OLD / 'inputs/image.qcow2'),
           '--image-inputs', str(OLD / 'inputs/build-inputs.json'), '--mailbox-bridge',
           str(OLD / 'inputs/repo/image/host_bridge.py'), '--python', str(OLD / 'inputs/python/bin/python'),
           '--runs', str(OLD / 'work/runs'), '--run-id', 'seed-reply-loss']


def main():
    os.umask(0o077)
    assert os.getuid() == 999
    # Root observer publishes this outside the UID999-writable work tree.
    deadline = time.monotonic() + 30
    ready = ROOT / 'observer-ready'
    while not ready.exists():
        if time.monotonic() >= deadline:
            raise RuntimeError('observer readiness not established')
        time.sleep(0.05)
    metadata = ready.lstat()
    assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
    assert not metadata.st_mode & 0o022 and ready.read_text() == 'ready\n'
    result = subprocess.run(COMMAND, capture_output=True, text=True, timeout=30)
    for name, text in [('retry.stdout', result.stdout), ('retry.stderr', result.stderr)]:
        with (ROOT / 'work/evidence' / name).open('x') as stream:
            stream.write(text)
    spec = importlib.util.spec_from_file_location('faults', ROOT / 'inputs/runtime_faults.py')
    faults = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(faults)
    witness = faults.reservation_refusal(result)
    with (ROOT / 'work/evidence/reservation.json').open('x') as stream:
        json.dump(witness, stream, indent=2)
        stream.write('\n')
    # Permit a final live sample even when the CLI exits in milliseconds.
    time.sleep(2)
    print(json.dumps(witness))


if __name__ == '__main__':
    main()
