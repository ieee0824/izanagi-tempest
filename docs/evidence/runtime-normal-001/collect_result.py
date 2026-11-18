"""Read-only post-run verification and public metadata projection."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import shutil
import socket
import stat
import subprocess

ROOT = Path('/var/lib/tempest-izanagi-runtime-normal-001')
REPO = Path('/home/ubuntu/izanagi-tempest')
INVOCATION = 'd0bf251254d64f7890690c562193c493'
BOOT = '30389abc903c40ae89a5c6268ec1c432'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_snapshot(root):
    snapshot = json.loads((root / 'snapshot.json').read_text())
    for row in snapshot['files']:
        path = Path(row['path'])
        if row['type'] == 'file':
            assert sha(path) == row['sha256']
            assert stat.S_IMODE(path.stat().st_mode) == int(row['mode'], 8)
            assert (path.stat().st_uid, path.stat().st_gid) == (0, 988)
        else:
            assert path.is_symlink() and os.readlink(path) == row['target']
    return snapshot


def main():
    os.umask(0o077)
    snapshot = verify_snapshot(ROOT)
    for path, digest in snapshot['external_runtime_sha256'].items():
        assert sha(path) == digest
    for old in ('001', '001-v2', '002'):
        verify_snapshot(Path('/var/lib/tempest-izanagi-image-smoke-' + old))
    for number in ('001', '002', '003'):
        for row in json.loads((REPO / ('docs/LINUX_X86_FULL_SNAPSHOT_' + number + '.json')).read_text()):
            assert sha(row['path']) == row['sha256']
        result = json.loads((REPO / ('docs/LINUX_X86_FULL_BUILD_' + number + '_RESULT.json')).read_text())
        for path, metadata in result['files'].items():
            assert sha(path) == metadata['sha256']
    spec = importlib.util.spec_from_file_location('projection', REPO / 'docs/evidence/runtime-normal-001/observer_projection.py')
    projection = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(projection)
    observer_path = Path('/tmp/tempest-runtime-normal-observation-001.jsonl')
    observed = projection.project(observer_path)
    assert len(observed['observed_sessions']) == 4
    assert not observed['external_listener_observed']
    bindings = []
    credentials = []
    runs = []
    files = {}
    expected_agent = json.loads((ROOT / 'inputs/build-inputs.json').read_text())['input_sha256']['agent']
    for index in (1, 2):
        root = ROOT / 'work/runs' / ('normal-' + str(index))
        report = json.loads((root / 'run.json').read_text())
        result = json.loads((root / 'result.json').read_text())
        assert report['status'] == 'completed' and report['evaluation'] == 'performed'
        assert report['self_check']['established'] and report['retest']['checks_passed']
        assert result['finding']['outcome'] == 'found' and result['retest']['status'] == 'passed'
        assert not result['formal_metrics_eligible']
        assert result['control_integrity'] == result['control_request_integrity'] == 'matched'
        assert result['contaminated'] is False and result['failed_control_operations'] == {}
        assert json.loads((root / 'artifact-inventory.json').read_text())['complete']
        cleanups = {}
        for stage in ('primary', 'retest'):
            data = report[stage]
            binding = data['vm_binding']
            observed_stage = observed['observed_sessions'][len(bindings)]
            assert observed_stage['binding'] == {key: binding[key] for key in ('boot_nonce', 'supervisor_pid', 'session_fingerprint')}
            bindings.append((binding['boot_nonce'], binding['session_fingerprint']))
            credentials.append(data['credentials']['access_key_sha256'])
            assert data['daemon_identity']['exe_sha256'] == expected_agent
            cleanup = data['cleanup']
            assert all(cleanup[key] for key in ('companion_stopped', 'down_succeeded', 'management_stopped', 'up_exited_successfully'))
            assert not cleanup['forced_group_stop'] and not cleanup['missing_logs']
            cleanups[stage] = cleanup
        assert len((root / 'evidence/api.jsonl').read_text().splitlines()) == 2
        assert not list(root.rglob('transport-hmac')) and not list(root.rglob('__pycache__'))
        runs.append({'run_id': root.name, 'status': report['status'], 'evaluation': report['evaluation'],
                     'self_check_established': True, 'retest_checks_passed': True, 'finding': 'found',
                     'control_integrity': 'matched', 'control_request_integrity': 'matched',
                     'contaminated': False, 'failed_control_operations': {}, 'formal_metrics_eligible': False,
                     'agent_calls_attempted': report['agent']['outcome']['calls_attempted'], 'api_rows': 2,
                     'artifact_inventory_complete': True, 'cleanup': cleanups})
        for name in ('run.json', 'result.json', 'artifact-inventory.json', 'evidence/manifest.json', 'evidence/api.jsonl', 'evidence/capture.pcap'):
            path = root / name
            files[str(path)] = {'sha256': sha(path), 'bytes': path.stat().st_size}
    assert len(set(bindings)) == len(set(credentials)) == 4
    exited = json.loads((ROOT / 'work/evidence/exit-status.json').read_text())
    assert exited['invocation_id'] == INVOCATION and exited['exit_status'] == '0' and exited['service_result'] == 'success'
    journal = subprocess.check_output(['/usr/bin/journalctl', '-u', 'tempest-izanagi-runtime-normal-001.service', '-o', 'json', '--no-pager'], text=True)
    (ROOT / 'work/evidence/journal.private.jsonl').write_text(journal)
    trusted = []
    for line in journal.splitlines():
        row = json.loads(line)
        if row.get('_PID') == '1' and row.get('_UID') == '0' and row.get('_BOOT_ID') == BOOT and row.get('INVOCATION_ID') == INVOCATION and row.get('UNIT') == 'tempest-izanagi-runtime-normal-001.service':
            trusted.append({key: row.get(key) for key in ('UNIT', 'MESSAGE_ID', '__REALTIME_TIMESTAMP', '_BOOT_ID', '_PID', '_UID', 'INVOCATION_ID')})
    assert len(trusted) == 4
    assert not Path('/sys/fs/cgroup/system.slice/tempest-izanagi-runtime-normal-001.service').exists()
    assert not subprocess.run(['ps', '-u', '999', '-o', 'pid='], capture_output=True, text=True).stdout.strip()
    ports = set()
    for line in observer_path.read_text().splitlines():
        row = json.loads(line)
        if 'sample' in row:
            ports.update(int(listener['local'].rsplit(':', 1)[1]) for listener in row['sample']['listeners'])
    for port in ports:
        with socket.socket() as connection:
            connection.settimeout(1)
            assert connection.connect_ex(('127.0.0.1', port)) != 0
    for path in (observer_path, Path('/tmp/tempest-runtime-normal-001.log'), ROOT / 'work/evidence/exit-status.json'):
        files[str(path)] = {'sha256': sha(path), 'bytes': path.stat().st_size}
    output = {'status': 'normal_runs_passed_observer_terminal_unknown', 'caller_exit': 0, 'observer_exit': 1,
              'observer_failure': 'same-invocation runtime terminal attributes not captured after GC',
              'unit': 'tempest-izanagi-runtime-normal-001.service', 'invocation_id': INVOCATION, 'host_boot_id': BOOT,
              'runs': runs, 'distinct_vm_bindings': 4, 'distinct_dummy_credentials': 4,
              'observer': observed, 'exit_recorder': exited, 'trusted_lifecycle': trusted,
              'input_files_unchanged': len(snapshot['files']), 'old_inputs_evidence_unchanged': True,
              'external_runtime_unchanged': True, 'cgroup_absent': True, 'uid999_absent': True,
              'observed_ports_closed': sorted(ports), 'transient_keys_absent': True,
              'free_bytes': shutil.disk_usage(ROOT).free, 'files': files}
    Path('/tmp/tempest-runtime-normal-result-001.json').write_text(json.dumps(output, indent=2) + '\n')
    print('selected normal runtime evidence saved; private raw run data not published')


if __name__ == '__main__':
    main()
