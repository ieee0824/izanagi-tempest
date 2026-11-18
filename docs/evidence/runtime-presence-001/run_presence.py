"""Fixed four-presence trial and aggregate denominator check; mock only."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    os.umask(0o077)
    inputs = Path(__file__).resolve().parent
    assert inputs == Path('/var/lib/tempest-izanagi-runtime-presence-001/inputs')
    script = inputs / 'repo/integration/runtime_presence.py'
    runs = inputs.parent / 'work/runs'
    sys.argv = [str(script), '--tempest', str(inputs / 'tempest'), '--izanagi', str(inputs / 'izanagi'),
                '--image', str(inputs / 'image.qcow2'), '--image-inputs', str(inputs / 'build-inputs.json'),
                '--python', str(inputs / 'python/bin/python'), '--runs', str(runs)]
    spec = importlib.util.spec_from_file_location('presence', script)
    presence = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(presence)
    presence.main()
    subprocess.run([str(inputs / 'tempest'), 'report', '--aggregate', str(runs)], check=True,
                   capture_output=True, text=True, timeout=60)
    aggregate = json.loads((runs / 'aggregate.json').read_text())
    assert aggregate['portfolio']['runs'] == 4
    for name in ('finding', 'retest'):
        assert aggregate['portfolio'][name] == {'configured_denominator': 2, 'not_configured': 2}
    assert aggregate['portfolio']['cross_condition_rates'] == 'not_computed'
    assert sum(group['runs']['formal_eligible'] for group in aggregate['groups']) == 0
    bindings = []
    credentials = []
    for finding, retest in ((1, 1), (1, 0), (0, 1), (0, 0)):
        report = json.loads((runs / f'finding-{finding}-retest-{retest}/run.json').read_text())
        for stage in (('primary', 'retest') if retest else ('primary',)):
            data = report[stage]
            binding = data['vm_binding']
            bindings.append((binding['boot_nonce'], binding['session_fingerprint']))
            credentials.append(data['credentials']['access_key_sha256'])
            assert data['image_qcow_sha256'] == report['conditions']['image_sha256']
            cleanup = data['cleanup']
            assert all(cleanup[key] for key in ('companion_stopped', 'management_stopped', 'down_succeeded', 'up_exited_successfully'))
            assert not cleanup['forced_group_stop'] and not cleanup['missing_logs']
    assert len(set(bindings)) == len(set(credentials)) == 6
    assert not list(runs.rglob('transport-hmac')) and not list(runs.rglob('__pycache__'))
    print(json.dumps({'presence_runs': 4, 'distinct_vm_bindings': 6, 'distinct_dummy_credentials': 6,
                      'finding_configured_denominator': 2, 'finding_not_configured': 2,
                      'retest_configured_denominator': 2, 'retest_not_configured': 2, 'formal_eligible': 0}))


if __name__ == '__main__':
    main()
