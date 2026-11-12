#!/usr/bin/env python3
"""Destructive-local M4 fault checks against the pinned disposable VM image."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assert_partial_evaluation(run):
    result = json.loads((run / 'result.json').read_text())
    if result['evaluation'] != 'partial' or result['formal_metrics_eligible']:
        raise AssertionError('aborted evidence was not evaluated as partial')
    if result['finding']['outcome'] != 'unknown' or result['contaminated'] is not None:
        raise AssertionError('missing evidence incorrectly proved a negative outcome')
    state = json.loads((run / 'evaluation-state.json').read_text())
    if state['state'] != 'committed' or not (run / 'report.md').is_file():
        raise AssertionError('partial evaluation artifacts were not finalized')


def seed_reply_loss(args):
    run_id = 'seed-reply-loss'
    run = args.runs / run_id
    with tempfile.TemporaryDirectory(prefix='tempest-seed-loss-') as temporary:
        companion = Path(temporary)
        source = (ROOT / 'image/host_bridge.py').read_text()
        needle = "                result = pending.decode(message['frame'])\n"
        replacement = needle + "                if pending.operation == 'seed':\n                    raise RuntimeError('injected reply loss')\n"
        if source.count(needle) != 1:
            raise AssertionError('host bridge injection point changed')
        (companion / 'host_bridge.py').write_text(source.replace(needle, replacement))
        shutil.copy2(ROOT / 'image/transport.py', companion / 'transport.py')
        command = [
            str(args.tempest), 'run', str(ROOT / 'scenarios/s3-overread-001.yaml'),
            '--agent', 'mock', '--mock-script', str(ROOT / 'integration/mock-s3-overread.json'),
            '--izanagi', str(args.izanagi), '--image', str(args.image),
            '--image-inputs', str(args.image_inputs), '--mailbox-bridge',
            str(companion / 'host_bridge.py'), '--python', str(args.python),
            '--runs', str(args.runs), '--run-id', run_id,
        ]
        first = subprocess.run(command, text=True, capture_output=True, timeout=360)
    if first.returncode == 0:
        raise AssertionError('lost seed response was accepted')
    report = json.loads((run / 'run.json').read_text())
    if report['status'] != 'aborted' or 'seed failed or response lost' not in report['failure']:
        raise AssertionError('lost seed response was not recorded as terminal')
    if report['agent']['performed'] or 'export' in report.get('primary', {}):
        raise AssertionError('agent or export started after lost seed response')
    owner = json.loads((run / 'vm-owner.json').read_text())
    try:
        os.kill(owner['supervisor_pid'], 0)
    except ProcessLookupError:
        pass
    else:
        raise AssertionError('discarded VM is still alive')
    if (run / 'transport-hmac').exists() or list(run.rglob('__pycache__')):
        raise AssertionError('transient runtime material remained')
    inventory = json.loads((run / 'artifact-inventory.json').read_text())
    if not inventory['complete']:
        raise AssertionError('unexpected artifact after seed loss')
    assert_partial_evaluation(run)
    before = digest(run / 'run.json')
    retry = subprocess.run(command, text=True, capture_output=True, timeout=30)
    if retry.returncode == 0 or digest(run / 'run.json') != before:
        raise AssertionError('reserved run ID was reused or mutated')
    print(json.dumps({'seed_reply_loss': 'passed', 'run': str(run)}))


def fetch_chunk_corruption(args):
    run_id = 'fetch-chunk-corruption'
    run = args.runs / run_id
    with tempfile.TemporaryDirectory(prefix='tempest-fetch-corrupt-') as temporary:
        companion = Path(temporary)
        source = (ROOT / 'image/host_bridge.py').read_text()
        needle = "                result = pending.decode(message['frame'])\n"
        replacement = needle + """                if pending.operation == 'fetch' and result.get('ok'):
                    fields = result['result']
                    raw = base64.b64decode(fields['data_base64'], validate=True)
                    fields['data_base64'] = base64.b64encode(bytes([raw[0] ^ 1]) + raw[1:]).decode()
"""
        if source.count(needle) != 1:
            raise AssertionError('host bridge injection point changed')
        (companion / 'host_bridge.py').write_text(source.replace(needle, replacement))
        shutil.copy2(ROOT / 'image/transport.py', companion / 'transport.py')
        command = [
            str(args.tempest), 'run', str(ROOT / 'scenarios/s3-overread-001.yaml'),
            '--agent', 'mock', '--mock-script', str(ROOT / 'integration/mock-s3-overread.json'),
            '--izanagi', str(args.izanagi), '--image', str(args.image),
            '--image-inputs', str(args.image_inputs), '--mailbox-bridge',
            str(companion / 'host_bridge.py'), '--python', str(args.python),
            '--runs', str(args.runs), '--run-id', run_id,
        ]
        result = subprocess.run(command, text=True, capture_output=True, timeout=360)
    if result.returncode == 0:
        raise AssertionError('corrupted chunk was accepted')
    report = json.loads((run / 'run.json').read_text())
    collection = json.loads((run / 'evidence/collection.json').read_text())
    reasons = {name: value.get('reason') for name, value in collection['files'].items()}
    if reasons != {'api.jsonl': 'chunk_hash_mismatch',
                   'capture.pcap': 'upstream_aborted',
                   'manifest.json': 'upstream_aborted'}:
        raise AssertionError('corruption was not isolated and classified')
    if report['status'] != 'aborted' or report['retest']['performed']:
        raise AssertionError('corrupted collection continued into retest')
    if list((run / 'evidence').glob('.*.partial')):
        raise AssertionError('partial evidence remained after corruption')
    if not json.loads((run / 'artifact-inventory.json').read_text())['complete']:
        raise AssertionError('unexpected artifact after fetch corruption')
    assert_partial_evaluation(run)
    print(json.dumps({'fetch_chunk_corruption': 'passed', 'run': str(run)}))


def active_sigterm(args):
    run_id = 'active-sigterm'
    run = args.runs / run_id
    command = [
        str(args.tempest), 'run', str(ROOT / 'scenarios/s3-overread-001.yaml'),
        '--agent', 'mock', '--mock-script', str(ROOT / 'integration/mock-sleep.json'),
        '--izanagi', str(args.izanagi), '--image', str(args.image),
        '--image-inputs', str(args.image_inputs), '--mailbox-bridge',
        str(ROOT / 'image/host_bridge.py'), '--python', str(args.python),
        '--runs', str(args.runs), '--run-id', run_id,
    ]
    process = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    deadline = time.monotonic() + 90
    log = run / 'evidence/mcp.jsonl'
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError('controller exited before active call')
        if log.exists():
            lines = [json.loads(line) for line in log.read_text().splitlines()]
            forwarded = any(line['event'] == 'forwarded' and line['data'].get('id') == 3 for line in lines)
            responded = any(line['event'] == 'response' and line['data'].get('id') == 3 for line in lines)
            if forwarded and not responded:
                break
        time.sleep(0.1)
    else:
        process.kill()
        raise AssertionError('active call was not observed')
    process.terminate()
    process.communicate(timeout=120)
    if process.returncode == 0:
        raise AssertionError('SIGTERM run completed')
    report = json.loads((run / 'run.json').read_text())
    cleanup = report['primary']['cleanup']
    if report.get('cancellation', {}).get('reason') != 'sigterm' or 'export' in report['primary']:
        raise AssertionError('SIGTERM was not recorded before export')
    if not all(cleanup[name] for name in ['companion_stopped', 'down_succeeded',
                                          'management_stopped', 'up_exited_successfully']):
        raise AssertionError('SIGTERM cleanup incomplete')
    owner = json.loads((run / 'vm-owner.json').read_text())
    try:
        os.kill(owner['supervisor_pid'], 0)
    except ProcessLookupError:
        pass
    else:
        raise AssertionError('SIGTERM VM is still alive')
    if (run / 'transport-hmac').exists() or list(run.rglob('__pycache__')):
        raise AssertionError('SIGTERM left runtime material')
    if not json.loads((run / 'artifact-inventory.json').read_text())['complete']:
        raise AssertionError('SIGTERM left unexpected artifacts')
    print(json.dumps({'active_sigterm': 'passed', 'run': str(run)}))


def crash_recovery(args):
    run_id = 'controller-sigkill'
    run = args.runs / run_id
    command = [
        str(args.tempest), 'run', str(ROOT / 'scenarios/s3-overread-001.yaml'),
        '--agent', 'mock', '--mock-script', str(ROOT / 'integration/mock-sleep.json'),
        '--izanagi', str(args.izanagi), '--image', str(args.image),
        '--image-inputs', str(args.image_inputs), '--mailbox-bridge',
        str(ROOT / 'image/host_bridge.py'), '--python', str(args.python),
        '--runs', str(args.runs), '--run-id', run_id,
    ]
    process = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    deadline = time.monotonic() + 90
    log = run / 'evidence/mcp.jsonl'
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError('controller exited before crash injection')
        if log.exists():
            lines = [json.loads(line) for line in log.read_text().splitlines()]
            if any(line['event'] == 'forwarded' and line['data'].get('id') == 3 for line in lines):
                break
        time.sleep(0.1)
    else:
        process.kill()
        raise AssertionError('active call was not observed before crash')
    live = subprocess.run([str(args.tempest), 'recover', str(run)], text=True,
                          capture_output=True, timeout=10)
    if live.returncode == 0 or 'still alive' not in live.stderr:
        raise AssertionError('recovery did not reject a living controller')
    process.kill()
    process.communicate(timeout=10)
    recovered = subprocess.run([str(args.tempest), 'recover', str(run)], text=True,
                               capture_output=True, timeout=120)
    if recovered.returncode != 0:
        raise AssertionError(f'explicit recovery failed: {recovered.stderr}')
    report = json.loads((run / 'run.json').read_text())
    owner = json.loads((run / 'controller-owner.json').read_text())
    vm_owner = json.loads((run / 'vm-owner.json').read_text())
    if report['status'] != 'aborted' or report['recovery']['status'] != 'recovered':
        raise AssertionError('recovered crash was not finalized as aborted')
    if owner['status'] != 'finished' or pid_exists(vm_owner['supervisor_pid']):
        raise AssertionError('recovery owner or VM remained active')
    for name in ('agent-owner.json', 'mcp-owner.json'):
        path = run / 'evidence' / name
        if path.exists() and pid_exists(json.loads(path.read_text())['process_group']):
            raise AssertionError(f'recovery left {name} process group alive')
    if (run / 'transport-hmac').exists() or list(run.rglob('__pycache__')):
        raise AssertionError('recovery left runtime material')
    if not json.loads((run / 'artifact-inventory.json').read_text())['complete']:
        raise AssertionError('recovery left unexpected artifacts')
    retry = subprocess.run(command, text=True, capture_output=True, timeout=30)
    if retry.returncode == 0:
        raise AssertionError('recovered run ID was reused')
    print(json.dumps({'crash_recovery': 'passed', 'run': str(run)}))


def pid_exists(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def seed_sigterm(args, operation, marker, expect_intent):
    run_id = f'{marker}-sigterm'
    run = args.runs / run_id
    with tempfile.TemporaryDirectory(prefix=f'tempest-{marker}-') as temporary:
        companion = Path(temporary)
        source = (ROOT / 'image/host_bridge.py').read_text()
        needle = "                result = pending.decode(message['frame'])\n"
        injected = needle + f"""                if pending.operation == '{operation}':
                    print('{marker}', file=sys.stderr, flush=True)
                    __import__('time').sleep(300)
"""
        if source.count(needle) != 1:
            raise AssertionError('host bridge injection point changed')
        (companion / 'host_bridge.py').write_text(source.replace(needle, injected))
        shutil.copy2(ROOT / 'image/transport.py', companion / 'transport.py')
        command = [
            str(args.tempest), 'run', str(ROOT / 'scenarios/s3-overread-001.yaml'),
            '--agent', 'mock', '--mock-script', str(ROOT / 'integration/mock-s3-overread.json'),
            '--izanagi', str(args.izanagi), '--image', str(args.image),
            '--image-inputs', str(args.image_inputs), '--mailbox-bridge',
            str(companion / 'host_bridge.py'), '--python', str(args.python),
            '--runs', str(args.runs), '--run-id', run_id,
        ]
        process = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 90
        companion_log = run / 'companion.stderr'
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError(f'{marker}: controller exited before injection')
            if companion_log.exists() and marker in companion_log.read_text():
                break
            time.sleep(0.1)
        else:
            process.kill()
            raise AssertionError(f'{marker}: injection point was not observed')
        intent = run / 'primary-seed-attempt.json'
        if intent.exists() is not expect_intent:
            process.kill()
            raise AssertionError(f'{marker}: seed intent boundary mismatch')
        process.terminate()
        process.communicate(timeout=120)
        report = json.loads((run / 'run.json').read_text())
        if report.get('cancellation', {}).get('reason') != 'sigterm':
            raise AssertionError(f'{marker}: SIGTERM was not recorded')
        if report['agent']['performed'] or 'export' in report.get('primary', {}):
            raise AssertionError(f'{marker}: work continued after SIGTERM')
        if (run / 'transport-hmac').exists() or list(run.rglob('__pycache__')):
            raise AssertionError(f'{marker}: transient runtime material remained')
        if pid_exists(json.loads((run / 'vm-owner.json').read_text())['supervisor_pid']):
            raise AssertionError(f'{marker}: VM remained alive')
        retry = subprocess.run(command, text=True, capture_output=True, timeout=30)
        if retry.returncode == 0:
            raise AssertionError(f'{marker}: run ID was reused')
    print(json.dumps({marker: 'passed', 'run': str(run)}))


def fetch_sigterm(args):
    run_id = 'fetch-midstream-sigterm'
    run = args.runs / run_id
    with tempfile.TemporaryDirectory(prefix='tempest-fetch-sigterm-') as temporary:
        fixture = Path(temporary)
        source = (ROOT / 'image/host_bridge.py').read_text()
        needle = "                result = pending.decode(message['frame'])\n"
        injected = needle + """                if pending.operation == 'fetch' and result.get('ok') and result['result']['offset'] > 0:
                    print('fetch-midstream', file=sys.stderr, flush=True)
                    __import__('time').sleep(300)
"""
        if source.count(needle) != 1:
            raise AssertionError('host bridge injection point changed')
        (fixture / 'host_bridge.py').write_text(source.replace(needle, injected))
        shutil.copy2(ROOT / 'image/transport.py', fixture / 'transport.py')
        call = {
            'name': 'sandbox_exec',
            'arguments': {
                'command': '/usr/bin/curl',
                'args': ['-fsS', '-H',
                         'Authorization: AWS4-HMAC-SHA256 Credential=${ACCESS_KEY_ID}/local/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=LOCAL-DUMMY',
                         'http://127.0.0.1:4566/public-data/readme.txt'],
            },
        }
        (fixture / 'mock.json').write_text(json.dumps({'calls': [call] * 50,
                                                       'final_output': 'bulk fixture'}))
        command = [
            str(args.tempest), 'run', str(ROOT / 'scenarios/s3-overread-001.yaml'),
            '--agent', 'mock', '--mock-script', str(fixture / 'mock.json'),
            '--izanagi', str(args.izanagi), '--image', str(args.image),
            '--image-inputs', str(args.image_inputs), '--mailbox-bridge',
            str(fixture / 'host_bridge.py'), '--python', str(args.python),
            '--runs', str(args.runs), '--run-id', run_id,
        ]
        process = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 120
        companion_log = run / 'companion.stderr'
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError('controller exited before mid-fetch injection')
            if companion_log.exists() and 'fetch-midstream' in companion_log.read_text():
                break
            time.sleep(0.1)
        else:
            process.kill()
            raise AssertionError('multi-chunk fetch was not reached')
        partials = list((run / 'evidence').glob('.*.partial'))
        if len(partials) != 1 or partials[0].stat().st_size == 0:
            process.kill()
            raise AssertionError('first fetch chunk was not durably distinguished')
        process.terminate()
        process.communicate(timeout=120)
        report = json.loads((run / 'run.json').read_text())
        collection = json.loads((run / 'evidence/collection.json').read_text())
        if report.get('cancellation', {}).get('reason') != 'sigterm' or collection['complete']:
            raise AssertionError('mid-fetch cancellation was not recorded as incomplete')
        if list((run / 'evidence').glob('.*.partial')):
            raise AssertionError('mid-fetch partial was not removed during shutdown')
        if not any(value.get('reason') == 'not_started'
                   for value in collection['files'].values()):
            raise AssertionError('unreached files were not explicitly marked')
        if pid_exists(json.loads((run / 'vm-owner.json').read_text())['supervisor_pid']):
            raise AssertionError('mid-fetch VM remained alive')
    print(json.dumps({'fetch_sigterm': 'passed', 'run': str(run)}))


def retest_crash_recovery(args):
    run_id = 'retest-controller-sigkill'
    run = args.runs / run_id
    with tempfile.TemporaryDirectory(prefix='tempest-retest-crash-') as temporary:
        fixture = Path(temporary)
        source = (ROOT / 'image/host_bridge.py').read_text()
        needle = "                result = pending.decode(message['frame'])\n"
        injected = needle + """                if pending.operation == 'probe' and workspace.parent.name == 'retest':
                    print('retest-probe-active', file=sys.stderr, flush=True)
                    __import__('time').sleep(300)
"""
        if source.count(needle) != 1:
            raise AssertionError('host bridge injection point changed')
        (fixture / 'host_bridge.py').write_text(source.replace(needle, injected))
        shutil.copy2(ROOT / 'image/transport.py', fixture / 'transport.py')
        command = [
            str(args.tempest), 'run', str(ROOT / 'scenarios/s3-overread-001.yaml'),
            '--agent', 'mock', '--mock-script', str(ROOT / 'integration/mock-s3-overread.json'),
            '--izanagi', str(args.izanagi), '--image', str(args.image),
            '--image-inputs', str(args.image_inputs), '--mailbox-bridge',
            str(fixture / 'host_bridge.py'), '--python', str(args.python),
            '--runs', str(args.runs), '--run-id', run_id,
        ]
        process = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 150
        marker = run / 'retest/companion.stderr'
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError('controller exited before retest crash injection')
            if marker.exists() and 'retest-probe-active' in marker.read_text():
                break
            time.sleep(0.1)
        else:
            process.kill()
            raise AssertionError('retest VM did not reach the injected probe')
        process.kill()
        process.communicate(timeout=10)
        recovered = subprocess.run([str(args.tempest), 'recover', str(run)], text=True,
                                   capture_output=True, timeout=120)
        if recovered.returncode != 0:
            raise AssertionError(f'retest recovery failed: {recovered.stderr}')
    report = json.loads((run / 'run.json').read_text())
    stages = {value['stage']: value for value in report['recovery']['stages']}
    if not stages['primary']['already_stopped'] or stages['retest']['already_stopped']:
        raise AssertionError('recovery did not distinguish primary and live retest VMs')
    for owner in (run / 'vm-owner.json', run / 'retest/vm-owner.json'):
        if pid_exists(json.loads(owner.read_text())['supervisor_pid']):
            raise AssertionError('a stage VM remained alive after recovery')
    if (run / 'transport-hmac').exists() or (run / 'retest/transport-hmac').exists():
        raise AssertionError('a stage transport key remained after recovery')
    if not json.loads((run / 'artifact-inventory.json').read_text())['complete']:
        raise AssertionError('retest recovery left unexpected artifacts')
    print(json.dumps({'retest_crash_recovery': 'passed', 'run': str(run)}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tempest', type=Path, required=True)
    parser.add_argument('--izanagi', type=Path, required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--image-inputs', type=Path, required=True)
    parser.add_argument('--python', type=Path, required=True)
    parser.add_argument('--runs', type=Path, required=True)
    parser.add_argument('--case', choices=['all', 'core', 'crash-recovery', 'seed-sigterm', 'fetch-sigterm', 'retest-recovery'], default='all')
    args = parser.parse_args()
    args.runs.mkdir(mode=0o700, parents=True, exist_ok=False)
    if args.case in ('all', 'core'):
        seed_reply_loss(args)
        fetch_chunk_corruption(args)
        active_sigterm(args)
        crash_recovery(args)
    if args.case == 'crash-recovery':
        crash_recovery(args)
    if args.case in ('all', 'seed-sigterm'):
        seed_sigterm(args, 'attest', 'before-seed-intent', False)
        seed_sigterm(args, 'seed', 'after-seed-apply', True)
    if args.case in ('all', 'fetch-sigterm'):
        fetch_sigterm(args)
    if args.case in ('all', 'retest-recovery'):
        retest_crash_recovery(args)


if __name__ == '__main__':
    main()
