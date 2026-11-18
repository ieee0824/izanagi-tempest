"""Fixed single seed-response-loss case; no other fault or presence cases."""
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace


def main():
    os.umask(0o077)
    inputs = Path(__file__).resolve().parent
    assert inputs == Path('/var/lib/tempest-izanagi-runtime-seed-loss-001/inputs')
    spec = importlib.util.spec_from_file_location('runtime_faults', inputs / 'repo/integration/runtime_faults.py')
    faults = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(faults)
    args = SimpleNamespace(tempest=inputs / 'tempest', izanagi=inputs / 'izanagi',
                           image=inputs / 'image.qcow2', image_inputs=inputs / 'build-inputs.json',
                           python=inputs / 'python/bin/python', runs=inputs.parent / 'work/runs')
    args.runs.mkdir(mode=0o700, exist_ok=False)
    faults.seed_reply_loss(args)


if __name__ == '__main__':
    main()
