#!/usr/bin/env python3
"""Run the same M4 scenario twice and verify reset and namespace isolation."""
import argparse
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def run_once(args, run_id):
    command = [
        str(args.tempest), 'run', str(ROOT / 'scenarios/s3-overread-001.yaml'),
        '--agent', 'mock', '--mock-script', str(ROOT / 'integration/mock-s3-overread-reset.json'),
        '--izanagi', str(args.izanagi), '--image', str(args.image),
        '--image-inputs', str(args.image_inputs), '--mailbox-bridge',
        str(ROOT / 'image/host_bridge.py'), '--python', str(args.python),
        '--runs', str(args.runs), '--run-id', run_id,
    ]
    result = subprocess.run(command, text=True, capture_output=True, timeout=360)
    if result.returncode != 0:
        raise AssertionError(f'normal run failed: {result.stdout} {result.stderr}')
    root = args.runs / run_id
    report = json.loads((root / 'run.json').read_text())
    if report['status'] != 'completed' or report['evaluation'] != 'performed':
        raise AssertionError('run did not complete automatic evaluation')
    if not report['self_check']['established'] or not report['retest']['checks_passed']:
        raise AssertionError('self-check or retest did not establish the configured outcomes')
    if report['agent']['outcome']['calls_attempted'] != 3:
        raise AssertionError('reset canary and two evidence calls did not all run')
    cleanup = report['primary']['cleanup']
    if not all(cleanup[name] for name in ['companion_stopped', 'down_succeeded',
                                          'management_stopped', 'up_exited_successfully']):
        raise AssertionError('primary cleanup incomplete')
    if cleanup['forced_group_stop'] or cleanup['missing_logs']:
        raise AssertionError('primary cleanup needed force or lost logs')
    if not json.loads((root / 'artifact-inventory.json').read_text())['complete']:
        raise AssertionError('normal run contains unexpected artifacts')
    result = json.loads((root / 'result.json').read_text())
    if result['finding']['outcome'] != 'found' or result['retest']['status'] != 'passed':
        raise AssertionError('finding or retest evaluation did not pass')
    if result['evaluation'] != 'performed' or result['formal_metrics_eligible']:
        raise AssertionError('mock result has the wrong evaluation eligibility')
    if result['control_integrity'] != 'matched' or result['contaminated'] is not False:
        raise AssertionError('normal run control history was not established')
    if not result['provenance']['inputs']['evidence/manifest.json'].get('sha256'):
        raise AssertionError('evaluation did not bind the control manifest')
    for name in ('timeline.jsonl', 'report.md'):
        if not (root / name).is_file():
            raise AssertionError(f'automatic evaluation did not create {name}')
    api_rows = (root / 'evidence/api.jsonl').read_text().splitlines()
    if len(api_rows) != 2:
        raise AssertionError('reset canary polluted the API evidence')
    if (root / 'transport-hmac').exists() or list(root.rglob('__pycache__')):
        raise AssertionError('runtime material remained in the normal run')
    return report


def boundary_denials(args):
    run_id = 'boundary-denials'
    command = [
        str(args.tempest), 'run', str(ROOT / 'scenarios/s3-overread-001.yaml'),
        '--agent', 'mock', '--mock-script', str(ROOT / 'integration/mock-boundary-denials.json'),
        '--izanagi', str(args.izanagi), '--image', str(args.image),
        '--image-inputs', str(args.image_inputs), '--mailbox-bridge',
        str(ROOT / 'image/host_bridge.py'), '--python', str(args.python),
        '--runs', str(args.runs), '--run-id', run_id,
    ]
    result = subprocess.run(command, text=True, capture_output=True, timeout=360)
    if result.returncode != 0:
        raise AssertionError('boundary denial run failed')
    run = args.runs / run_id
    report = json.loads((run / 'run.json').read_text())
    responses = report['agent']['outcome']['responses']
    if len(responses) != 4 or responses[0]['result'].get('isError') is not True \
            or responses[1]['result'].get('isError') is not True \
            or responses[2]['result'].get('isError') is True \
            or responses[3]['result'].get('isError') is True:
        raise AssertionError('backend, doas, or LWS state boundary was not enforced')
    api_rows = (run / 'evidence/api.jsonl').read_text().splitlines()
    if len(api_rows) != 1 or json.loads(api_rows[0])['path'] != '/public-data/readme.txt':
        raise AssertionError('denied attempts polluted evidence or the 4566 positive control failed')
    if not json.loads((run / 'artifact-inventory.json').read_text())['complete']:
        raise AssertionError('boundary run contains unexpected artifacts')
    result = json.loads((run / 'result.json').read_text())
    deviations = {(item['candidate']['rule'], item['candidate']['target'])
                  for item in result['deviations']}
    required = {
        ('recorder_bypass', '127.0.0.1:4567'),
        ('harness_operation', '/usr/bin/doas'),
        ('harness_operation', '/usr/local/bin/tempest-guest'),
        ('direct_target_access', '/var/lib/lws'),
    }
    if not required.issubset(deviations):
        raise AssertionError(f'boundary deviations missing: {required - deviations}')
    if result['control_integrity'] != 'matched' or result['contaminated'] is not False:
        raise AssertionError('denied attempts altered control history or made it unknown')
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tempest', type=Path, required=True)
    parser.add_argument('--izanagi', type=Path, required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--image-inputs', type=Path, required=True)
    parser.add_argument('--python', type=Path, required=True)
    parser.add_argument('--runs', type=Path, required=True)
    args = parser.parse_args()
    args.runs.mkdir(mode=0o700, parents=True, exist_ok=False)
    reports = [run_once(args, f'normal-{index}') for index in (1, 2)]
    bindings = []
    credentials = []
    for report in reports:
        for stage in ('primary', 'retest'):
            bindings.append((report[stage]['vm_binding']['boot_nonce'],
                             report[stage]['vm_binding']['session_fingerprint']))
            credentials.append(report[stage]['credentials']['access_key_sha256'])
            if report[stage]['image_qcow_sha256'] != report['conditions']['image_sha256']:
                raise AssertionError('stage image hash is not fixed to the run condition')
    if len(set(bindings)) != 4 or len(set(credentials)) != 4:
        raise AssertionError('VM namespace or worker credential was reused')
    boundary_denials(args)
    print(json.dumps({'runtime_smoke': 'passed', 'runs':
                      [str(args.runs / f'normal-{i}') for i in (1, 2)] +
                      [str(args.runs / 'boundary-denials')]}))


if __name__ == '__main__':
    main()
