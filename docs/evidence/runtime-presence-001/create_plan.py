"""Precommit four presence slots from the independently preserved normal calibration."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import time

ROOT = Path('/var/lib/tempest-izanagi-runtime-presence-001')
CALIBRATION = Path('/var/lib/tempest-izanagi-runtime-normal-001/work/runs/normal-1/result.json')
CALIBRATION_SHA256 = '9176292317fd5ce8184184c7824104248f29463ff0043feeb0b94df42294cc71'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build_plan(conditions, source, scenario, evaluator_sha256):
    slots = []
    for finding, retest in ((1, 1), (1, 0), (0, 1), (0, 0)):
        label = f'finding-{finding}-retest-{retest}'
        expected = copy.deepcopy(conditions)
        expected['scenario']['sha256'] = hashlib.sha256(scenario(source, finding, retest).encode()).hexdigest()
        slots.append({'slot_id': label, 'run_id': label, 'finding_configured': bool(finding),
                      'retest_configured': bool(retest), 'comparison_conditions': expected,
                      'evaluator_sha256': evaluator_sha256})
    return {'schema_version': 1, 'plan_id': 'linux-presence-001', 'created_ns': time.time_ns(),
            'stopping_rule': {'kind': 'fixed_slots', 'slots': 4, 'retry': 'new_slot_only',
                              'minimum_interval_seconds': 0}, 'slots': slots}


def main():
    assert os.geteuid() == 0
    assert not (ROOT / 'work/runs').exists(), 'plan must precede every presence run'
    inputs = ROOT / 'inputs'
    extra = ROOT / 'inputs-v2'
    assert sha(CALIBRATION) == CALIBRATION_SHA256
    conditions = json.loads(CALIBRATION.read_bytes())['comparison_conditions']
    assert conditions['schema_version'] == 1 and conditions['actor'] == 'worker'
    assert conditions['adapter'] == {'adapter': 'mock', 'model': 'deterministic_script', 'tempest_version': '0.1.0'}
    environment = conditions['environment']
    for key, path in [('image_sha256', inputs / 'image.qcow2'), ('izanagi_sha256', inputs / 'izanagi'),
                      ('tempest_sha256', inputs / 'tempest'),
                      ('companion_sha256', extra / 'repo/image/host_bridge.py'),
                      ('codec_sha256', extra / 'repo/image/transport.py')]:
        assert environment[key] == sha(path), key
    reset_script = Path('/var/lib/tempest-izanagi-runtime-normal-001/inputs/repo/integration/mock-s3-overread-reset.json')
    assert environment['agent_input_sha256'] == sha(reset_script)
    # Presence uses the two-call script rather than normal's reset-canary script.
    environment['agent_input_sha256'] = sha(extra / 'repo/integration/mock-s3-overread.json')
    assert environment['binary_mode'] == 'production' and environment['formal_test_only'] is False
    assert environment['native_test_upstream'] is None
    assert (environment['host_os'], environment['host_arch']) == ('linux', 'x86_64')
    assert all(environment[key] is True for key in ('restrict_network', 'snapshot', 'share_read_only'))
    source_path = extra / 'repo/scenarios/s3-overread-001.yaml'
    assert conditions['scenario'] == {'id': 's3-overread-001', 'sha256': sha(source_path)}
    assert source_path.read_bytes() == (inputs / 'repo/scenarios/s3-overread-001.yaml').read_bytes()
    spec = importlib.util.spec_from_file_location('presence', extra / 'repo/integration/runtime_presence.py')
    presence = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(presence)
    plan = build_plan(conditions, source_path.read_text(), presence.scenario, environment['tempest_sha256'])
    # Freeze before execution. The runtime subsequently verifies exact conditions;
    # no presence result is available to infer or rewrite a planned slot.
    fd = os.open(extra / 'comparison-plan.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(json.dumps(plan, indent=2) + '\n')
        stream.flush()
        os.fchown(stream.fileno(), 0, 988)
        os.fchmod(stream.fileno(), 0o440)
        os.fsync(stream.fileno())
    print(json.dumps({'slots': 4, 'calibration_sha256': CALIBRATION_SHA256,
                      'plan_sha256': sha(extra / 'comparison-plan.json'), 'presence_runs_started': False,
                      'calibration_changes': ['scenario.sha256 per presence', 'agent_input_sha256: two-call mock']}))


if __name__ == '__main__':
    main()
