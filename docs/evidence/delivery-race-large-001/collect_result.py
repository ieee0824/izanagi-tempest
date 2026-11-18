"""Verify the failed large trial from saved artifacts only; never start a VM."""
from collections import Counter
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess

REPO = Path('/home/ubuntu/izanagi-tempest')
ROOT = Path('/var/lib/tempest-izanagi-delivery-race-large-001')
INVOCATION = '00226f94d15640be99b426f7c38ae5f2'
BOOT = '30389abc903c40ae89a5c6268ec1c432'
UNIT = ROOT.name + '.service'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    os.umask(0o077)
    assert os.getuid() == 0
    base = module('base_evidence', REPO / 'docs/evidence/runtime-normal-001/collect_result.py')
    snapshot = base.verify_snapshot(ROOT)
    assert len(snapshot['files']) == 1311
    for path, digest in snapshot['external_runtime_sha256'].items():
        assert base.sha(path) == digest
    sources = json.loads((REPO / 'docs/LINUX_X86_DELIVERY_RACE_LARGE_SOURCE_001.json').read_text())['files']
    for path, digest in sources.items():
        assert base.sha(REPO / path) == digest
    previous = REPO / 'docs/evidence/host-endpoint-001/collect_result.py'
    code = previous.read_text().split("    output = ROOT / 'work/output'", 1)[0] + '\nmain()\n'
    exec(compile(code, str(previous), 'exec'), {'__name__': 'old_verification', '__file__': str(previous)})
    for trial in ('smoke', 'completed'):
        base.verify_snapshot(Path('/var/lib/tempest-izanagi-delivery-race-' + trial + '-001'))
        document = REPO / ('docs/LINUX_X86_DELIVERY_RACE_' + trial.upper() + '_001_RESULT.json')
        for path, metadata in json.loads(document.read_text())['files'].items():
            assert base.sha(path) == metadata['sha256']
    retained = json.loads((REPO / 'docs/LINUX_X86_DELIVERY_RACE_RAW_CLEANUP_001.json').read_text())['retained_files_sha256']
    for path, digest in retained.items():
        assert base.sha(path) == digest
    assert not Path('/var/lib/tempest-izanagi-delivery-race-build-001/work/offline-proof/disk.raw').exists()
    observed_path = Path('/tmp/tempest-delivery-race-large-observation-001.jsonl')
    observer = module('fixed_observer', ROOT / 'inputs/repo/integration/runtime_normal_observe.py')
    replay = observer.Sessions('delivery-race-large')
    samples, saved, invocations = [], [], set()
    for line in observed_path.read_text().splitlines():
        envelope = json.loads(line)
        if set(envelope) == {'sample'}:
            row = envelope['sample']
            samples.append(row)
            if row['unit'].get('InvocationID'):
                invocations.add(row['unit']['InvocationID'])
            replay.observe(row)
        else:
            assert set(envelope) == {'observed_sessions'}
            saved = envelope['observed_sessions']
            assert len(saved) == len(replay.identities)
            for i, stage in enumerate(saved):
                assert (stage['pid'], stage['starttime_ticks']) == replay.identities[i]
                assert stage['workspace'] == replay.stages[i]
                if stage['binding'] is not None:
                    replay.bind(i, {'state': 'running', **stage['binding']})
    replay.require_complete()
    assert replay.snapshot() == saved and invocations == {INVOCATION}
    assert [(s['pid'], s['starttime_ticks']) for s in saved] == [(318657, 38603263)]
    assert samples[-1]['unit']['ActiveState'] == 'failed'
    assert samples[-1]['unit']['ExecMainStatus'] == '1'
    run_root = ROOT / 'work/runs/forced-delivery-race'
    def load(name):
        return json.loads((run_root / name).read_text())
    run, result = load('run.json'), load('result.json')
    assert run['status'] == 'aborted' and run['failure'] == 'recorder evidence incomplete'
    assert run['evaluation'] == 'partial' and run['agent']['outcome']['calls_attempted'] == 1
    assert run['retest']['configured'] is False and run['retest']['performed'] is False
    assert result['formal_metrics_eligible'] is False
    assert result['control_integrity'] == result['control_request_integrity'] == 'unavailable'
    assert result['contaminated'] is None and result['failed_control_operations'] is None
    assert load('artifact-inventory.json')['complete'] is True
    assert not list(run_root.rglob('transport-hmac'))
    scenario = load('scenario.yaml')
    assert base.sha(run_root / 'scenario.yaml') == run['scenario_sha256']
    assert scenario['id'] == 'delivery-large-001' and scenario['auth_mode'] == 'strict'
    assert scenario['budget'] == {'max_calls': 1, 'timeout': '120s'}
    assert scenario['expect'] == [{'api': 's3:GetObject', 'resource': 'arn:aws:s3:::large-data/dummy', 'result': 'allow'}]
    assert scenario['setup']['buckets'] == [{'name': 'large-data', 'objects': [{'key': 'dummy', 'body': 'A' * 1048576}]}]
    assert 'retest' not in scenario and 'expected_finding' not in scenario
    binding = {k: run['primary']['vm_binding'][k] for k in ('boot_nonce', 'supervisor_pid', 'session_fingerprint')}
    assert binding == saved[0]['binding']
    expected_agent = json.loads((ROOT / 'inputs/build-inputs.json').read_text())['input_sha256']['agent']
    assert run['primary']['daemon_identity']['exe_sha256'] == expected_agent
    cleanup = run['primary']['cleanup']
    assert cleanup == {'companion_stopped': True, 'down_succeeded': True, 'forced_group_stop': False,
                       'management_stopped': False, 'missing_logs': [], 'partial_files_removed': [], 'up_exited_successfully': True}
    exported, index, collection = run['primary']['export'], load('evidence/export-index.json'), load('evidence/collection.json')
    assert all(exported[k] == v for k, v in index.items())
    assert exported['complete'] is False and exported['collection_complete'] is False and collection['complete'] is False
    assert collection['export_id'] == index['export_id']
    manifest = index['manifest']
    assert manifest['complete'] is False and manifest['finalized'] is True
    assert manifest['failures'] == ['capture reports packets dropped by kernel']
    assert manifest['api_rows'] == 29 and manifest['incomplete_rows'] == 0
    assert manifest['capture_statistics'] == {'captured': 1930, 'dropped': 155, 'read_failed': False}
    assert manifest['capture_buffer_kib_requested'] == 4096 and manifest['capture_immediate_mode'] is True
    assert manifest['recorder_statistics'] == {'accepted_connections': 29, 'admission_rejected': 0, 'connection_errors': 0, 'http_parse_errors': 0, 'task_errors': 0}
    for name, receipt in index['files'].items():
        item = collection['files'][name]
        assert receipt['bytes'] == item['expected_bytes'] and receipt['sha256'] == item['expected_sha256']
    api = run_root / 'evidence/api.jsonl'
    assert api.stat().st_size == 16492 and base.sha(api) == index['files']['api.jsonl']['sha256']
    assert len(api.read_text().splitlines()) == 29
    assert collection['files']['api.jsonl']['verified'] is True
    assert collection['files']['api.jsonl']['observed_sha256'] == base.sha(api)
    pcap = collection['files']['capture.pcap']
    assert (pcap['received_bytes'], pcap['expected_bytes'], pcap['reason'], pcap['verified']) == (55607296, 59299901, 'transfer_deadline', False)
    assert collection['files']['manifest.json']['reason'] == 'upstream_aborted'
    assert collection['files']['manifest.json']['received_bytes'] == 0
    for name in ('capture.pcap', '.capture.pcap.partial', 'manifest.json'):
        assert not os.path.lexists(run_root / 'evidence' / name)
    controls = [json.loads(l) for l in (run_root / 'evidence/control.jsonl').read_text().splitlines()]
    exports = [r for r in controls if r['operation'] == 'export']
    starts = [r for r in exports if r['state'] == 'started']
    assert len(starts) == 1 and {r['id'] for r in exports} == {starts[0]['id']}
    reads = [r for r in exports if r['state'] == 'delivery_read_observed']
    assert [r['category'] for r in reads] == ['execution_error', 'ciphertext_received']
    expected = [(r['id'], r['operation']) for r in controls if r['state'] == 'started' and r['operation'] in ('claim', 'seed', 'probe', 'seal', 'export')]
    intents = manifest['control_operation_intents']
    assert all(r['authorized'] is True for r in intents)
    assert Counter(expected) == Counter((r['audit_id'], r['operation']) for r in intents)
    assert manifest['control_operation_intents_overflow'] == 0
    fetches = [r for r in controls if r['operation'] == 'fetch']
    counts = dict(Counter(r['state'] for r in fetches))
    assert counts == {'started': 1699, 'delivery_read_started': 2557, 'delivery_read_observed': 2556, 'completed': 1698}
    assert pcap['received_bytes'] == 1697 * 32768
    barrier = index['quiesce']
    assert barrier['forced_reader_pid'] == 1056 and 1056 in barrier['moved_pids']
    assert barrier['service_frozen'] and barrier['descendants_empty'] and barrier['frozen_duration_ns'] > 0
    exited = json.loads((ROOT / 'work/evidence/exit-status.json').read_text())
    assert exited['invocation_id'] == exited['unit']['InvocationID'] == INVOCATION
    assert exited['service_result'] == 'exit-code' and exited['exit_status'] == '1'
    journal = subprocess.check_output(['journalctl', '-u', UNIT, '-o', 'json', '--no-pager'], text=True)
    trusted = []
    keys = ('MESSAGE_ID', 'UNIT', 'INVOCATION_ID', '_BOOT_ID', '_PID', '_UID', 'EXIT_CODE', 'EXIT_STATUS', 'UNIT_RESULT', '__REALTIME_TIMESTAMP')
    for line in journal.splitlines():
        r = json.loads(line)
        if r.get('_PID') == '1' and r.get('_UID') == '0' and r.get('_BOOT_ID') == BOOT and r.get('UNIT') == UNIT and r.get('INVOCATION_ID') == INVOCATION:
            trusted.append({k: r[k] for k in keys if k in r})
    assert any(r.get('EXIT_CODE') == 'exited' and r.get('EXIT_STATUS') == '1' for r in trusted)
    assert any(r.get('UNIT_RESULT') == 'exit-code' for r in trusted)
    assert not Path('/sys/fs/cgroup/system.slice', UNIT).exists()
    assert subprocess.run(['pgrep', '-u', '999'], capture_output=True).returncode == 1
    ports = {int(l['local'].rsplit(':', 1)[1]) for r in samples for l in r['listeners']}
    for port in ports:
        with socket.socket() as connection:
            connection.settimeout(1)
            assert connection.connect_ex(('127.0.0.1', port)) != 0
    files = {}
    paths = [run_root / n for n in ('scenario.yaml', 'mock-script.json', 'run.json', 'result.json', 'artifact-inventory.json', 'evidence/control.jsonl', 'evidence/export-index.json', 'evidence/collection.json', 'evidence/api.jsonl')]
    paths += [observed_path, Path('/tmp/tempest-delivery-race-large-001.log'), ROOT / 'work/evidence/exit-status.json']
    for path in paths:
        files[str(path)] = {'sha256': base.sha(path), 'bytes': path.stat().st_size}
    output = {'status': 'failed_predeclared_completed_expectation', 'caller_session': 30779, 'caller_exit': 1,
              'observer_session': 13443, 'observer_exit': 0, 'observer_terminal': 'same Invocation failed terminal observed',
              'unit': UNIT, 'invocation_id': INVOCATION, 'host_boot_id': BOOT, 'observed_sessions': saved,
              'observer_sample_count': len(samples), 'fixed_observer_replay_passed': True,
              'input_items_unchanged': len(snapshot['files']), 'source_files_verified': len(sources),
              'retained_build_files_verified': len(retained), 'old_snapshots_and_results_verified': True,
              'runtime_status': run['status'], 'failure': run['failure'], 'evaluation': run['evaluation'],
              'formal_metrics_eligible': False, 'control_integrity': 'unavailable', 'control_request_integrity': 'unavailable',
              'contaminated': None, 'failed_control_operations': None, 'agent_calls_attempted': 1,
              'scenario': {'id': scenario['id'], 'dummy_object_bytes': 1048576, 'budget': scenario['budget'], 'retest_configured': False},
              'api_rows': 29, 'native_manifest_metadata': {k: manifest[k] for k in ('complete', 'finalized', 'failures', 'api_rows', 'incomplete_rows', 'capture_buffer_kib_requested', 'capture_immediate_mode', 'capture_statistics', 'recorder_statistics', 'capture_started', 'capture_stopped', 'recorder_started', 'recorder_stopped')},
              'collection': collection, 'indexed_file_receipts': index['files'], 'collected_verified_files': ['api.jsonl'],
              'pcap_whole_and_partial_absent': True, 'manifest_file_absent': True,
              'host_control_operation_id': starts[0]['id'], 'native_export_id': index['export_id'],
              'export_submissions': 1, 'export_read_categories': [r['category'] for r in reads],
              'embedded_manifest_intents_reconciled': True,
              'integrity_scope': 'Embedded metadata reconciled independently; runtime integrity remains unavailable because manifest file was not collected. No key recovery or reply decoding.',
              'fetch_state_counts': counts, 'fetch_recorded_span_ns': max(r['host_ns'] for r in fetches) - min(r['host_ns'] for r in fetches),
              'fetch_terminal_missing_count': 1, 'quiesce': {k: barrier[k] for k in ('forced_reader_pid', 'moved_pids', 'frozen_duration_ns', 'service_frozen', 'descendants_empty')},
              'cleanup_receipt': cleanup, 'actual_resources': {'uid999_absent': True, 'cgroup_absent': True, 'observed_ports_closed': sorted(ports)},
              'transient_keys_absent': True, 'artifact_inventory_complete': True, 'trusted_lifecycle': trusted,
              'files': files}
    with (ROOT / 'work/evidence/journal.private.jsonl').open('x') as stream:
        stream.write(journal)
    with Path('/tmp/tempest-delivery-race-large-result-001.json').open('x') as stream:
        json.dump(output, stream, indent=2)
        stream.write('\n')
    print('Saved failure evidence verified; completed expectation remains failed; no VM or trial rerun.')


if __name__ == '__main__':
    main()
