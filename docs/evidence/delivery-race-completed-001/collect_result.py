"""Verify saved completed-trial artifacts and replay observers without starting a VM."""
from collections import Counter
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess

REPO = Path('/home/ubuntu/izanagi-tempest')
ROOT = Path('/var/lib/tempest-izanagi-delivery-race-completed-001')
UNIT = ROOT.name + '.service'
INVOCATION = '55a19055fed94911877b97fcf5be4437'
BOOT = '30389abc903c40ae89a5c6268ec1c432'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    os.umask(0o077)
    assert os.getuid() == 0
    base = module('normal_evidence', REPO / 'docs/evidence/runtime-normal-001/collect_result.py')
    snapshot = base.verify_snapshot(ROOT)
    for directory in snapshot['directories_mode0750_root_group']:
        s = Path(directory).lstat()
        assert stat.S_ISDIR(s.st_mode) and (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) == (0, 988, 0o750)
    for path, digest in snapshot['external_runtime_sha256'].items():
        assert base.sha(path) == digest
    for path, digest in json.loads((REPO / 'docs/LINUX_X86_DELIVERY_RACE_COMPLETED_SOURCE_001.json').read_text())['files'].items():
        assert base.sha(REPO / path) == digest
    previous = REPO / 'docs/evidence/host-endpoint-001/collect_result.py'
    code = previous.read_text().split("    output = ROOT / 'work/output'", 1)[0] + '\nmain()\n'
    exec(compile(code, str(previous), 'exec'), {'__name__': 'old_verification', '__file__': str(previous)})
    base.verify_snapshot(Path('/var/lib/tempest-izanagi-delivery-race-smoke-001'))
    for document in ('LINUX_X86_HOST_ENDPOINT_001_RESULT.json', 'LINUX_X86_DELIVERY_RACE_BUILD_001_RESULT.json', 'LINUX_X86_DELIVERY_RACE_SMOKE_001_RESULT.json'):
        for path, metadata in json.loads((REPO / 'docs' / document).read_text())['files'].items():
            assert base.sha(path) == metadata['sha256']
    for path in ('/var/lib/tempest-izanagi-host-endpoint-001/work/output/izanagi-hmac', '/var/lib/tempest-izanagi-delivery-race-smoke-001/work/output/izanagi-hmac'):
        assert not os.path.lexists(path)
    assert base.sha(ROOT / 'inputs/tempest') == '4354c40b7fba68ec03e4cbb8cd1407ce3ba7566816801b69dec09d85a984dc6f'

    observer_path = Path('/tmp/tempest-delivery-race-completed-observation-001.jsonl')
    envelopes = [json.loads(line) for line in observer_path.read_text().splitlines()]
    observer = module('fixed_runtime_observer', ROOT / 'inputs/repo/integration/runtime_normal_observe.py')
    replay = observer.Sessions('delivery-race-completed')
    samples = []
    last_saved = []
    invocations = set()
    for envelope in envelopes:
        if set(envelope) == {'sample'}:
            row = envelope['sample']
            samples.append(row)
            current = row['unit'].get('InvocationID')
            if current:
                invocations.add(current)
            replay.observe(row)
        elif set(envelope) == {'observed_sessions'}:
            last_saved = envelope['observed_sessions']
            assert len(last_saved) == len(replay.identities)
            for index, stage in enumerate(last_saved):
                assert (stage['pid'], stage['starttime_ticks']) == replay.identities[index]
                assert stage['workspace'] == replay.stages[index]
                if stage['binding'] is not None:
                    replay.bind(index, {'state': 'running', **stage['binding']})
        else:
            raise ValueError('unexpected observer envelope')
    replay.require_complete()
    assert replay.snapshot() == last_saved and invocations == {INVOCATION}
    assert [(s['pid'], s['starttime_ticks']) for s in last_saved] == [(317055, 38375020), (317378, 38378150)]

    run_root = ROOT / 'work/runs/forced-delivery-race'
    run = json.loads((run_root / 'run.json').read_text())
    result = json.loads((run_root / 'result.json').read_text())
    inventory = json.loads((run_root / 'artifact-inventory.json').read_text())
    assert run['status'] == 'completed' and run['evaluation'] == 'performed'
    assert run['self_check']['established'] is True
    assert run['retest']['configured'] is True and run['retest']['performed'] is True and run['retest']['checks_passed'] is True
    assert result['retest']['status'] == 'passed'
    assert result['formal_metrics_eligible'] is False and result['contaminated'] is False
    assert result['control_integrity'] == result['control_request_integrity'] == 'matched'
    assert result['failed_control_operations'] == {} and inventory['complete'] is True
    assert run['agent']['outcome']['calls_attempted'] == 0
    assert not list(run_root.rglob('transport-hmac')) and not list(run_root.rglob('__pycache__'))
    cleanups, bindings, credential_hashes = {}, [], []
    expected_agent = json.loads((ROOT / 'inputs/build-inputs.json').read_text())['input_sha256']['agent']
    for index, name in enumerate(('primary', 'retest')):
        stage = run[name]
        binding = {key: stage['vm_binding'][key] for key in ('boot_nonce', 'supervisor_pid', 'session_fingerprint')}
        assert binding == last_saved[index]['binding']
        bindings.append((binding['boot_nonce'], binding['session_fingerprint']))
        credential_hashes.append(stage['credentials']['access_key_sha256'])
        assert stage['daemon_identity']['exe_sha256'] == expected_agent
        cleanup = stage['cleanup']
        assert all(cleanup[key] for key in ('companion_stopped', 'down_succeeded', 'management_stopped', 'up_exited_successfully'))
        assert not cleanup['forced_group_stop'] and not cleanup['missing_logs']
        cleanups[name] = cleanup
    assert len(set(bindings)) == len(set(credential_hashes)) == 2

    controls = [json.loads(line) for line in (run_root / 'evidence/control.jsonl').read_text().splitlines()]
    exports = [row for row in controls if row['operation'] == 'export']
    started = [row for row in exports if row['state'] == 'started']
    assert len(started) == 1 and {row['id'] for row in exports} == {started[0]['id']}
    assert len([row for row in exports if row['state'] == 'completed']) == 1
    reads = [row for row in exports if row['state'] == 'delivery_read_observed']
    assert [row['attempt'] for row in reads] == [1, 2, 3]
    assert [row['category'] for row in reads] == ['reply_unavailable', 'execution_error', 'ciphertext_received']
    exported = run['primary']['export']
    barrier = exported['quiesce']
    assert exported['complete'] is True and exported['collection_complete'] is True
    assert barrier['forced_reader_pid'] == 1118 and 1118 in barrier['moved_pids']
    assert barrier['frozen_duration_ns'] > 0 and barrier['service_frozen'] and barrier['descendants_empty']
    manifest = json.loads((run_root / 'evidence/manifest.json').read_text())
    assert manifest == exported['manifest'] and manifest['complete'] is True
    assert manifest['control_operation_intents_overflow'] == 0
    expected = [(row['id'], row['operation']) for row in controls if row['state'] == 'started' and row['operation'] in ('claim', 'seed', 'probe', 'seal', 'export')]
    intents = manifest['control_operation_intents']
    assert all(row['authorized'] is True for row in intents)
    assert len(set(expected)) == len(expected)
    assert Counter(expected) == Counter((row['audit_id'], row['operation']) for row in intents)
    assert manifest['control_transitions'] == ['claimed', 'seeding', 'seeded', 'sealing', 'sealed', 'finalizing']
    export_index = json.loads((run_root / 'evidence/export-index.json').read_text())
    assert all(exported[key] == value for key, value in export_index.items())
    collection = json.loads((run_root / 'evidence/collection.json').read_text())
    assert collection['complete'] is True and collection['export_id'] == exported['export_id']
    assert set(exported['files']) == {'api.jsonl', 'capture.pcap', 'manifest.json'}
    receipt_projection = {}
    for name, receipt in exported['files'].items():
        path = run_root / 'evidence' / name
        assert path.stat().st_size == receipt['bytes'] and base.sha(path) == receipt['sha256']
        item = collection['files'][name]
        assert item['verified'] is True and item['received_bytes'] == item['expected_bytes'] == receipt['bytes']
        assert item['observed_sha256'] == item['expected_sha256'] == receipt['sha256']
        receipt_projection[name] = receipt
    api_rows = len((run_root / 'evidence/api.jsonl').read_text().splitlines())
    assert api_rows == manifest['api_rows']

    exited = json.loads((ROOT / 'work/evidence/exit-status.json').read_text())
    assert exited['unit_name'] == UNIT and exited['invocation_id'] == exited['unit']['InvocationID'] == INVOCATION
    assert exited['service_result'] == 'success' and exited['exit_code'] == 'exited' and exited['exit_status'] == '0'
    assert exited['unit']['ExecMainStatus'] == '0'
    journal = subprocess.check_output(['/usr/bin/journalctl', '-u', UNIT, '-o', 'json', '--no-pager'], text=True)
    with (ROOT / 'work/evidence/journal.private.jsonl').open('x') as stream:
        stream.write(journal)
    trusted = []
    for line in journal.splitlines():
        row = json.loads(line)
        if row.get('_PID') == '1' and row.get('_UID') == '0' and row.get('_BOOT_ID') == BOOT and row.get('UNIT') == UNIT and row.get('INVOCATION_ID') == INVOCATION:
            trusted.append({key: row.get(key) for key in ('UNIT', 'MESSAGE_ID', '__REALTIME_TIMESTAMP', '_BOOT_ID', '_PID', '_UID', 'INVOCATION_ID')})
    assert {'7d4958e842da4a758f6c1cdc7b36dcc5', '39f53479d3a045ac8e11786248231fbf', '7ad2d189f7e94e70a38c781354912448'} <= {row['MESSAGE_ID'] for row in trusted}
    assert not Path('/sys/fs/cgroup/system.slice', UNIT).exists()
    assert subprocess.run(['pgrep', '-u', '999'], capture_output=True).returncode == 1
    ports = {int(listener['local'].rsplit(':', 1)[1]) for row in samples for listener in row['listeners']}
    for port in ports:
        with socket.socket() as connection:
            connection.settimeout(1)
            assert connection.connect_ex(('127.0.0.1', port)) != 0
    files = {}
    paths = [run_root / name for name in ('run.json', 'result.json', 'artifact-inventory.json', 'evidence/control.jsonl', 'evidence/export-index.json', 'evidence/collection.json', 'evidence/manifest.json', 'evidence/api.jsonl', 'evidence/capture.pcap')]
    for path in paths:
        s = path.lstat()
        assert stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) == (999, 988, 0o600)
    paths += [observer_path, Path('/tmp/tempest-delivery-race-completed-001.log'), ROOT / 'work/evidence/exit-status.json', ROOT / 'work/evidence/journal.private.jsonl']
    for path in paths:
        files[str(path)] = {'sha256': base.sha(path), 'bytes': path.stat().st_size}
    output = {'status': 'completed_recovery_and_fresh_retest_passed_observer_terminal_unknown',
              'unit': UNIT, 'invocation_id': INVOCATION, 'host_boot_id': BOOT,
              'preflight_session': 70337, 'preflight_exit': 0, 'preflight_free_bytes': 10459947008,
              'caller_session': 99801, 'caller_exit': 0, 'observer_session': 91578, 'observer_exit': 1,
              'observer_terminal': 'unknown after unit GC; independent trusted terminal recorded separately',
              'observer_sample_count': len(samples), 'observer_replayed_with_fixed_validator': True,
              'observed_sessions': last_saved, 'distinct_vm_bindings': 2, 'distinct_dummy_credentials': 2,
              'host_control_operation_id': started[0]['id'], 'native_export_id': exported['export_id'],
              'export_submissions': 1, 'export_read_attempts': len(reads),
              'export_read_categories': [row['category'] for row in reads],
              'control_id_scope': 'host audit ID groups retries; native mailbox export ID is a distinct identifier',
              'guest_intents_reconciled_to_host_starts': True, 'control_transitions_recomputed': True,
              'authenticated_recovery_scope': 'fixed host CLI authenticated/decoded in-run; collector checks saved receipts and control intent without keys or reply decoding',
              'export_complete': True, 'collection_complete': True,
              'quiesce': {key: barrier[key] for key in ('forced_reader_pid', 'moved_pids', 'frozen_duration_ns', 'service_frozen', 'descendants_empty')},
              'export_file_receipts_verified': receipt_projection, 'api_rows': api_rows,
              'runtime_status': run['status'], 'evaluation': run['evaluation'], 'self_check_established': True,
              'finding_outcome': result['finding']['outcome'], 'agent_calls_attempted': 0,
              'retest_configured': True, 'retest_performed': True, 'retest_checks_passed': True,
              'formal_metrics_eligible': False, 'contaminated': False, 'failed_control_operations': {},
              'artifact_inventory_complete': True, 'cleanup': cleanups, 'transient_keys_absent': True,
              'exit_recorder': exited, 'trusted_lifecycle': trusted,
              'input_items_unchanged': len(snapshot['files']), 'old_inputs_evidence_unchanged': True,
              'external_runtime_unchanged': True, 'cgroup_absent': True, 'uid999_absent': True,
              'observed_ports_closed': sorted(ports), 'large_evidence_control_executed': False,
              'free_bytes': shutil.disk_usage(ROOT).free, 'files': files}
    with Path('/tmp/tempest-delivery-race-completed-result-001.json').open('x') as stream:
        json.dump(output, stream, indent=2)
        stream.write('\n')
    print('saved completed recovery/receipts/control intents/two-stage bindings and independent cleanup verified; private raw values not published')


if __name__ == '__main__':
    main()
