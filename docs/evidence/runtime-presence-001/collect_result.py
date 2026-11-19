"""Independently project committed presence slots and six-session isolation evidence."""
from pathlib import Path
import importlib.util
import json
import os
import shutil
import socket
import stat
import subprocess

REPO = Path('/home/ubuntu/izanagi-tempest')
ROOT = Path('/var/lib/tempest-izanagi-runtime-presence-001')
INVOCATION = '30121ae1574b4640bd5c0176d0a1bbb2'
BOOT = '30389abc903c40ae89a5c6268ec1c432'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    os.umask(0o077)
    base = module('normal_result', REPO / 'docs/evidence/runtime-normal-001/collect_result.py')
    projection = module('observer_projection', REPO / 'docs/evidence/runtime-normal-001/observer_projection.py')
    tree = module('tree', Path('/var/lib/tempest-izanagi-runtime-reservation-001/inputs/tree_manifest.py'))
    reservation = Path('/var/lib/tempest-izanagi-runtime-reservation-001')
    assert tree.inventory('/var/lib/tempest-izanagi-runtime-seed-loss-001') == json.loads((reservation / 'baseline.private.json').read_text())
    base.verify_snapshot(ROOT)
    snapshot = json.loads((ROOT / 'snapshot-v2.json').read_text())
    # Same verifier handles the v2 rows while preserving v1's original file.
    for row in snapshot['files']:
        path = Path(row['path'])
        metadata = path.lstat()
        assert (metadata.st_uid, metadata.st_gid) == (0, 988)
        if row['type'] == 'file':
            assert stat.S_IMODE(metadata.st_mode) == int(row['mode'], 8)
            assert base.sha(path) == row['sha256']
        else:
            assert os.readlink(path) == row['target']
    for directory in snapshot['directories_mode0750_root_group']:
        metadata = Path(directory).stat()
        assert (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) == (0, 988, 0o750)
    for path, digest in snapshot['external_runtime_sha256'].items():
        assert base.sha(path) == digest
    for name in ('001', '001-v2', '002'):
        base.verify_snapshot(Path('/var/lib/tempest-izanagi-image-smoke-' + name))
    base.verify_snapshot(Path('/var/lib/tempest-izanagi-runtime-normal-001'))
    for document in ('LINUX_X86_RUNTIME_NORMAL_001_RESULT.json', 'LINUX_X86_RUNTIME_RESERVATION_001_RESULT.json'):
        for path, metadata in json.loads((REPO / 'docs' / document).read_text())['files'].items():
            assert base.sha(path) == metadata['sha256']
    for number in ('001', '002', '003'):
        for row in json.loads((REPO / ('docs/LINUX_X86_FULL_SNAPSHOT_' + number + '.json')).read_text()):
            assert base.sha(row['path']) == row['sha256']
        for path, metadata in json.loads((REPO / ('docs/LINUX_X86_FULL_BUILD_' + number + '_RESULT.json')).read_text())['files'].items():
            assert base.sha(path) == metadata['sha256']
    runs = ROOT / 'work/runs'
    plan_path = ROOT / 'inputs-v2/comparison-plan.json'
    plan_sha = base.sha(plan_path)
    assert plan_sha == 'f3b85a85e907d5481687c11dbc6a1ced630915d35b4e41a235d6f1cc77ffcf67'
    assert (runs / 'aggregate-plan.json').read_bytes() == plan_path.read_bytes()
    plan = json.loads(plan_path.read_text())
    slots = {slot['slot_id']: slot for slot in plan['slots']}
    observed_path = Path('/tmp/tempest-runtime-presence-observation-001.jsonl')
    observed = projection.project(observed_path)
    assert len(observed['observed_sessions']) == 6 and not observed['external_listener_observed']
    bindings = []
    credentials = []
    results = []
    files = {}
    expected_agent = json.loads((ROOT / 'inputs/build-inputs.json').read_text())['input_sha256']['agent']
    for finding, retest in ((1, 1), (1, 0), (0, 1), (0, 0)):
        label = f'finding-{finding}-retest-{retest}'
        root = runs / label
        report = json.loads((root / 'run.json').read_text())
        result = json.loads((root / 'result.json').read_text())
        assert report['status'] == 'completed' and report['evaluation'] == 'performed'
        assert report['self_check']['configured'] is bool(finding) and report['self_check']['performed'] is bool(finding)
        if finding:
            assert report['self_check']['established'] is True
        else:
            assert report['self_check']['reason'] == 'not_configured' and report['self_check']['outcome'] == 'not_performed'
        controls = [json.loads(line) for line in (root / 'evidence/control.jsonl').read_text().splitlines()]
        probes = [row for row in controls if row['operation'] == 'probe']
        started = [row['id'] for row in probes if row['state'] == 'started']
        completed = [row['id'] for row in probes if row['state'] == 'completed']
        assert len(started) == finding and started == completed and not any(row['state'] == 'failed' for row in probes)
        assert report['retest']['configured'] is bool(retest) and report['retest']['performed'] is bool(retest)
        if retest:
            assert report['retest']['checks_passed'] is True
        else:
            assert report['retest']['reason'] == 'not_configured' and not (root / 'retest').exists()
        assert result['finding']['outcome'] == ('found' if finding else 'not_configured')
        assert result['retest']['status'] == ('passed' if retest else 'not_performed')
        assert not result['formal_metrics_eligible']
        binding = result['comparison_binding']
        assert binding['verified'] and binding['expected_conditions_match'] and binding['expected_evaluator_match']
        assert binding['plan_sha256'] == plan_sha and binding['slot_id'] == label
        assert result['comparison_conditions'] == slots[label]['comparison_conditions']
        assert report['agent']['outcome']['calls_attempted'] == 2
        assert result['control_integrity'] == result['control_request_integrity'] == 'matched'
        assert result['contaminated'] is False
        assert json.loads((root / 'artifact-inventory.json').read_text())['complete']
        cleanups = {}
        for stage in (('primary', 'retest') if retest else ('primary',)):
            data = report[stage]
            current = data['vm_binding']
            observed_stage = observed['observed_sessions'][len(bindings)]
            assert observed_stage['binding'] == {key: current[key] for key in ('boot_nonce', 'supervisor_pid', 'session_fingerprint')}
            bindings.append((current['boot_nonce'], current['session_fingerprint']))
            credentials.append(data['credentials']['access_key_sha256'])
            assert data['daemon_identity']['exe_sha256'] == expected_agent
            cleanup = data['cleanup']
            assert all(cleanup[key] for key in ('companion_stopped', 'management_stopped', 'down_succeeded', 'up_exited_successfully'))
            assert not cleanup['forced_group_stop'] and not cleanup['missing_logs']
            cleanups[stage] = cleanup
        assert not list(root.rglob('transport-hmac')) and not list(root.rglob('__pycache__'))
        results.append({'run_id': label, 'status': 'completed', 'evaluation': 'performed',
                        'finding_configured': bool(finding), 'retest_configured': bool(retest),
                        'self_check_performed': bool(finding), 'primary_probe_started': len(started), 'primary_probe_completed': len(completed),
                        'finding_outcome': result['finding']['outcome'], 'retest_status': result['retest']['status'],
                        'comparison_binding_verified': True, 'formal_metrics_eligible': False, 'cleanup': cleanups})
        for name in ('run.json', 'result.json', 'artifact-inventory.json', 'evidence/control.jsonl', 'evidence/manifest.json', 'evidence/api.jsonl', 'evidence/capture.pcap'):
            path = root / name
            files[str(path)] = {'sha256': base.sha(path), 'bytes': path.stat().st_size}
    assert len(set(bindings)) == len(set(credentials)) == 6
    aggregate = json.loads((runs / 'aggregate.json').read_text())
    assert aggregate['selection'] == {'rule': 'precommitted_plan_slots', 'planned': 4, 'discovered_directories': 4, 'committed': 4, 'unavailable': 0, 'unplanned': 0}
    for name in ('finding', 'retest'):
        assert aggregate['portfolio'][name] == {'configured_denominator': 2, 'not_configured': 2}
    assert aggregate['portfolio']['runs'] == 4 and aggregate['portfolio']['cross_condition_rates'] == 'not_computed'
    assert sum(group['runs']['formal_eligible'] for group in aggregate['groups']) == 0
    exited = json.loads((ROOT / 'work/evidence/exit-status.json').read_text())
    assert exited['invocation_id'] == INVOCATION and exited['exit_status'] == '0' and exited['service_result'] == 'success'
    journal = subprocess.check_output(['/usr/bin/journalctl', '-u', 'tempest-izanagi-runtime-presence-001.service', '-o', 'json', '--no-pager'], text=True)
    (ROOT / 'work/evidence/journal.private.jsonl').write_text(journal)
    trusted = []
    for line in journal.splitlines():
        row = json.loads(line)
        if row.get('_PID') == '1' and row.get('_UID') == '0' and row.get('_BOOT_ID') == BOOT and row.get('INVOCATION_ID') == INVOCATION and row.get('UNIT') == 'tempest-izanagi-runtime-presence-001.service':
            trusted.append({key: row.get(key) for key in ('UNIT', 'MESSAGE_ID', '__REALTIME_TIMESTAMP', '_BOOT_ID', '_PID', '_UID', 'INVOCATION_ID')})
    required = {'7d4958e842da4a758f6c1cdc7b36dcc5', '39f53479d3a045ac8e11786248231fbf', '7ad2d189f7e94e70a38c781354912448'}
    assert required <= {row['MESSAGE_ID'] for row in trusted}
    assert not Path('/sys/fs/cgroup/system.slice/tempest-izanagi-runtime-presence-001.service').exists()
    assert not subprocess.run(['ps', '-u', '999', '-o', 'pid='], capture_output=True, text=True).stdout.strip()
    ports = set()
    for line in observed_path.read_text().splitlines():
        row = json.loads(line)
        if 'sample' in row:
            ports.update(int(listener['local'].rsplit(':', 1)[1]) for listener in row['sample']['listeners'])
    for port in ports:
        with socket.socket() as connection:
            connection.settimeout(1)
            assert connection.connect_ex(('127.0.0.1', port)) != 0
    for path in (observed_path, ROOT / 'work/evidence/exit-status.json', runs / 'aggregate.json', runs / 'aggregate-plan.json', plan_path, Path('/tmp/tempest-runtime-presence-001.log')):
        files[str(path)] = {'sha256': base.sha(path), 'bytes': path.stat().st_size}
    public = {'status': 'four_presence_runs_passed_observer_terminal_unknown', 'caller_exit': 0, 'observer_exit': 1,
              'observer_failure': 'same-invocation terminal attributes not captured after GC',
              'unit': 'tempest-izanagi-runtime-presence-001.service', 'invocation_id': INVOCATION, 'host_boot_id': BOOT,
              'runs': results, 'distinct_vm_bindings': 6, 'distinct_dummy_credentials': 6, 'observer': observed,
              'precommitted_plan_sha256': plan_sha, 'aggregate_selection': aggregate['selection'], 'portfolio': aggregate['portfolio'],
              'formal_eligible': 0, 'exit_recorder': exited, 'trusted_lifecycle': trusted,
              'inputs_unchanged': len(snapshot['files']), 'input_ownership_modes_unchanged': True, 'v1_inputs_preserved': True, 'old_inputs_evidence_unchanged': True,
              'external_runtime_unchanged': True, 'cgroup_absent': True, 'uid999_absent': True,
              'observed_ports_closed': sorted(ports), 'transient_keys_absent': True, 'free_bytes': shutil.disk_usage(ROOT).free, 'files': files}
    Path('/tmp/tempest-runtime-presence-result-001.json').write_text(json.dumps(public, indent=2) + '\n')
    print('four committed presence slots, six bindings, denominators and preserved evidence verified')


if __name__ == '__main__':
    main()
