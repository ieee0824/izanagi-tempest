#!/usr/bin/env python3
"""Exercise all expected_finding/retest presence combinations in disposable VMs."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def scenario(source, finding, retest):
    if not finding:
        source = re.sub(r'(?ms)^expected_finding:.*?(?=^retest:)', '', source)
    if not retest:
        source = re.sub(r'(?ms)^retest:.*?(?=^success_criteria:)', '', source)
    return source


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
    source = (ROOT / 'scenarios/s3-overread-001.yaml').read_text()
    completed = []
    with tempfile.TemporaryDirectory(prefix='tempest-presence-') as temporary:
        temporary = Path(temporary)
        for finding, retest in [(True, True), (True, False), (False, True), (False, False)]:
            label = f'finding-{int(finding)}-retest-{int(retest)}'
            path = temporary / f'{label}.yaml'
            path.write_text(scenario(source, finding, retest))
            command = [
                str(args.tempest), 'run', str(path), '--agent', 'mock',
                '--mock-script', str(ROOT / 'integration/mock-s3-overread.json'),
                '--izanagi', str(args.izanagi), '--image', str(args.image),
                '--image-inputs', str(args.image_inputs), '--mailbox-bridge',
                str(ROOT / 'image/host_bridge.py'), '--python', str(args.python),
                '--runs', str(args.runs), '--run-id', label,
            ]
            result = subprocess.run(command, text=True, capture_output=True, timeout=360)
            if result.returncode != 0:
                raise AssertionError(f'{label} failed: {result.stderr}')
            run = args.runs / label
            report = json.loads((run / 'run.json').read_text())
            if report['self_check']['configured'] is not finding:
                raise AssertionError(f'{label}: self-check presence changed')
            if report['finding']['configured'] is not finding or report['finding']['performed'] is not finding:
                raise AssertionError(f'{label}: finding evaluation presence changed')
            if report['retest']['configured'] is not retest \
                    or report['retest']['performed'] is not retest:
                raise AssertionError(f'{label}: retest presence changed')
            if retest and report['retest']['checks_passed'] is not True:
                raise AssertionError(f'{label}: configured retest failed')
            if not retest and (run / 'retest').exists():
                raise AssertionError(f'{label}: unconfigured retest directory was generated')
            if report['evaluation'] != 'performed':
                raise AssertionError(f'{label}: M5 evaluation missing')
            evaluated = json.loads((run / 'result.json').read_text())
            expected_finding = 'found' if finding else 'not_configured'
            if evaluated['finding']['outcome'] != expected_finding:
                raise AssertionError(f'{label}: wrong finding outcome')
            expected_retest = 'passed' if retest else 'not_performed'
            if evaluated['retest']['status'] != expected_retest:
                raise AssertionError(f'{label}: wrong retest outcome')
            if evaluated['formal_metrics_eligible']:
                raise AssertionError(f'{label}: mock eligible for formal metrics')
            if not (run / 'report.md').is_file():
                raise AssertionError(f'{label}: report missing')
            completed.append(str(run))
    print(json.dumps({'runtime_presence': 'passed', 'runs': completed}))


if __name__ == '__main__':
    main()
