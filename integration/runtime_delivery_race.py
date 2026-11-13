#!/usr/bin/env python3
"""Compare fail-closed and recovered host behavior with the explicit race VM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('tempest', 'izanagi', 'image', 'image-inputs', 'python', 'runs'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--expect', choices=('aborted', 'collected', 'completed'), required=True)
    parser.add_argument('--large-evidence', action='store_true', help='Generate about 58 MiB PCAP using local dummy object reads')
    args = parser.parse_args()
    if json.loads(args.image_inputs.read_text()).get('delivery_race_fixture') is not True:
        parser.error('requires an explicitly instrumented delivery-race test image')
    args.runs.mkdir(mode=0o700, parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='tempest-race-') as temporary:
        script = Path(temporary) / 'noop.json'
        scenario = ROOT / 'scenarios/s3-overread-001.yaml'
        calls = []
        if args.large_evidence:
            scenario = Path(temporary) / 'large.json'
            scenario.write_text(json.dumps({
                'id': 'delivery-large-001', 'title': 'Large local capture control',
                'target': 'lws', 'auth_mode': 'strict',
                'setup': {'users': [{'name': 'worker', 'policy': {'Version': '2012-10-17',
                           'Statement': [{'Effect': 'Allow', 'Action': ['s3:GetObject'],
                                          'Resource': ['arn:aws:s3:::large-data/*']}]}}],
                          'buckets': [{'name': 'large-data', 'objects': [{'key': 'dummy', 'body': 'A' * 1048576}]}]},
                'task': 'Read the local dummy object.',
                'expect': [{'api': 's3:GetObject', 'resource': 'arn:aws:s3:::large-data/dummy', 'result': 'allow'}],
                'budget': {'max_calls': 1, 'timeout': '120s'},
            }))
            guest = "import subprocess; [subprocess.run(['curl','-fsS','-o','/dev/null','-H','Authorization: AWS4-HMAC-SHA256 Credential=${ACCESS_KEY_ID}/local/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=LOCAL-DUMMY','http://127.0.0.1:4566/large-data/dummy'],check=True) for _ in range(29)]"
            calls = [{'name': 'sandbox_exec', 'arguments': {'command': '/usr/bin/python3', 'args': ['-c', guest]}}]
        script.write_text(json.dumps({'calls': calls, 'final_output': '```json\n{"findings":[]}\n```'}))
        result = subprocess.run([
            str(args.tempest), 'run', str(scenario),
            '--agent', 'mock', '--mock-script', str(script), '--izanagi', str(args.izanagi),
            '--image', str(args.image), '--image-inputs', str(args.image_inputs),
            '--mailbox-bridge', str(ROOT / 'image/host_bridge.py'), '--python', str(args.python),
            '--runs', str(args.runs), '--run-id', 'forced-delivery-race',
        ], capture_output=True, text=True, timeout=720)
    root = args.runs / 'forced-delivery-race'
    run = json.loads((root / 'run.json').read_text())
    rows = [json.loads(line) for line in (root / 'evidence/control.jsonl').read_text().splitlines()]
    exports = [row for row in rows if row['operation'] == 'export']
    submitted = [row for row in exports if row['state'] == 'started']
    if len(submitted) != 1:
        raise AssertionError('primary export operation was not submitted exactly once')
    failures = [row for row in exports if row.get('category') == 'execution_error']
    if not failures:
        raise AssertionError('forced deliver failure not observed through real management MCP')
    expected_status = 'aborted' if args.expect == 'collected' else args.expect
    if run['status'] != expected_status or (result.returncode == 0) != (args.expect == 'completed'):
        raise AssertionError('unexpected runtime outcome; inspect private run directory')
    if args.expect == 'aborted':
        if 'management execution uncertain' not in run.get('failure', ''):
            raise AssertionError('runtime aborted for another reason')
        if 'export' in run['primary']:
            raise AssertionError('failed retrieval was presented as an export receipt')
    else:
        export = run['primary']['export']
        barrier = export['quiesce']
        if barrier['forced_reader_pid'] not in barrier['moved_pids']:
            raise AssertionError('quiesce did not kill the instrumented root reader')
        if not barrier['frozen_duration_ns'] > 0:
            raise AssertionError('freeze duration not established')
        if args.expect == 'completed' and not export['complete']:
            raise AssertionError('completed run lacks a complete export')
        if run['retest']['configured'] and not run['retest']['checks_passed']:
            raise AssertionError('fresh retest failed after primary recovery')
        if args.expect == 'collected':
            if not args.large_evidence:
                raise AssertionError('collected expectation is reserved for the large-evidence control')
            if run.get('failure') != 'recorder evidence incomplete' or export['manifest']['complete']:
                raise AssertionError('collected control did not preserve recorder incompleteness')
            for name, receipt in export['files'].items():
                data = (root / 'evidence' / name).read_bytes()
                if len(data) != receipt['bytes'] or hashlib.sha256(data).hexdigest() != receipt['sha256']:
                    raise AssertionError(f'collected artifact receipt mismatch: {name}')
        if args.large_evidence:
            size = (root / 'evidence/capture.pcap').stat().st_size
            if not 56 * 1024 * 1024 <= size <= 64 * 1024 * 1024:
                raise AssertionError(f'capture was not near the 64 MiB host limit: {size}')
            if len((root / 'evidence/api.jsonl').read_text().splitlines()) != 29:
                raise AssertionError('large capture did not retain all 29 requests')
    cleanup = run['primary']['cleanup']
    if not all(cleanup[key] for key in ('companion_stopped', 'down_succeeded', 'management_stopped', 'up_exited_successfully')):
        raise AssertionError('primary cleanup incomplete')
    if not json.loads((root / 'artifact-inventory.json').read_text())['complete']:
        raise AssertionError('unexpected runtime artifacts remained')
    if (root / 'transport-hmac').exists():
        raise AssertionError('runtime transport key remained')
    evaluated = json.loads((root / 'result.json').read_text())
    if evaluated['formal_metrics_eligible']:
        raise AssertionError('mock race fixture became formally eligible')
    print(json.dumps({'expectation': args.expect, 'runtime_outcome': run['status'],
                      'export_submissions': len(submitted),
                      'failed_reads': len(failures), 'run': str(root)}))


if __name__ == '__main__':
    main()
