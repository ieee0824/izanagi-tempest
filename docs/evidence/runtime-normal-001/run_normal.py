"""Fixed normal-1/normal-2 reset trial; no boundary or fault cases."""
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace


def main():
    os.umask(0o077)
    inputs = Path(__file__).resolve().parent
    assert inputs == Path('/var/lib/tempest-izanagi-runtime-normal-001/inputs')
    spec = importlib.util.spec_from_file_location('runtime_smoke', inputs / 'repo/integration/runtime_smoke.py')
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    args = SimpleNamespace(tempest=inputs / 'tempest', izanagi=inputs / 'izanagi',
                           image=inputs / 'image.qcow2', image_inputs=inputs / 'build-inputs.json',
                           python=inputs / 'python/bin/python', runs=inputs.parent / 'work/runs')
    args.runs.mkdir(mode=0o700, exist_ok=False)
    reports = [smoke.run_once(args, 'normal-' + str(i)) for i in (1, 2)]
    bindings = []
    credentials = []
    for report in reports:
        for stage in ('primary', 'retest'):
            binding = report[stage]['vm_binding']
            bindings.append((binding['boot_nonce'], binding['session_fingerprint']))
            credentials.append(report[stage]['credentials']['access_key_sha256'])
            assert report[stage]['image_qcow_sha256'] == report['conditions']['image_sha256']
    assert len(set(bindings)) == 4 and len(set(credentials)) == 4, 'VM namespace or dummy credential reused'
    print(json.dumps({'normal_runs': 2, 'distinct_vm_bindings': 4, 'distinct_dummy_credentials': 4,
                      'reset_checks': 'passed', 'formal_metrics_eligible': False}))


if __name__ == '__main__':
    main()
