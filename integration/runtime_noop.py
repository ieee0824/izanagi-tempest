#!/usr/bin/env python3
"""Record repeated no-tool mock controls without attributing background events."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ('tempest', 'izanagi', 'image', 'image-inputs', 'python', 'runs'):
        parser.add_argument('--' + flag, type=Path, required=True)
    parser.add_argument('--repeat', type=int, default=3)
    args = parser.parse_args()
    if args.repeat < 2:
        parser.error('--repeat must be at least 2')
    args.runs.mkdir(mode=0o700, parents=True, exist_ok=False)
    observations = []
    with tempfile.TemporaryDirectory(prefix='tempest-noop-') as temporary:
        script = Path(temporary) / 'noop.json'
        script.write_text(json.dumps({'calls': [], 'final_output': '```json\n{"findings":[]}\n```'}))
        for index in range(args.repeat):
            run_id = f'noop-{index + 1}'
            command = [str(args.tempest), 'run', str(ROOT / 'scenarios/s3-overread-001.yaml'),
                       '--agent', 'mock', '--mock-script', str(script), '--izanagi', str(args.izanagi),
                       '--image', str(args.image), '--image-inputs', str(args.image_inputs),
                       '--mailbox-bridge', str(ROOT / 'image/host_bridge.py'), '--python', str(args.python),
                       '--runs', str(args.runs), '--run-id', run_id]
            completed = subprocess.run(command, text=True, capture_output=True, timeout=360)
            if completed.returncode:
                raise AssertionError(f'{run_id}: failed; inspect private run directory')
            run = args.runs / run_id
            marker = json.loads((run / 'evaluation-state.json').read_text())
            if marker['state'] != 'committed':
                raise AssertionError(f'{run_id}: evaluation not committed')
            for name, digest in marker['artifacts'].items():
                if hashlib.sha256((run / name).read_bytes()).hexdigest() != digest['sha256']:
                    raise AssertionError(f'{run_id}: artifact digest mismatch')
            result = json.loads((run / 'result.json').read_text())
            metadata = json.loads((run / 'run.json').read_text())
            if metadata['status'] != 'completed' or result['attempts']['mcp_calls'] != 0:
                raise AssertionError(f'{run_id}: no-op contract failed')
            if result['attempts']['api_requests'] != 0 or result['finding']['outcome'] != 'not_found':
                raise AssertionError(f'{run_id}: no-op generated finding/API success')
            if result['formal_metrics_eligible']:
                raise AssertionError(f'{run_id}: mock accepted for formal comparison')
            candidates = Counter((row['candidate']['rule'], row['candidate']['target'], row['decision'])
                                 for row in result['deviations'])
            observations.append({'run_id': run_id, 'attempts': result['attempts'],
                                 'contaminated': result['contaminated'],
                                 'evaluation_id': marker['evaluation_id'],
                                 'candidates': [{'rule': key[0], 'target': key[1], 'decision': key[2],
                                                 'count': count} for key, count in sorted(candidates.items())]})
            print(json.dumps(observations[-1]), flush=True)
    summary = {'scope': 'no_tool_mock_background_control', 'attribution_proven': False,
               'subtract_from_model_candidates': False, 'runs': observations}
    (args.runs / 'noop-summary.json').write_text(json.dumps(summary, indent=2) + '\n')


if __name__ == '__main__':
    main()
