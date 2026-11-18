"""Preserve the failed trial and distinguish seed-discard proof from retry uncertainty."""
from pathlib import Path
import importlib.util
import json
import os
import shutil
import socket
import subprocess

REPO = Path('/home/ubuntu/izanagi-tempest')
ROOT = Path('/var/lib/tempest-izanagi-runtime-seed-loss-001')
INVOCATION = '995c31fa97fa45c3aacac0409017bd85'
BOOT = '30389abc903c40ae89a5c6268ec1c432'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, REPO / path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    os.umask(0o077)
    base = module('normal_result', 'docs/evidence/runtime-normal-001/collect_result.py')
    seed = module('seed_projection', 'docs/evidence/runtime-seed-loss-001/seed_projection.py')
    observation = module('observer_projection', 'docs/evidence/runtime-normal-001/observer_projection.py')
    snapshot = base.verify_snapshot(ROOT)
    for path, digest in snapshot['external_runtime_sha256'].items():
        assert base.sha(path) == digest
    for old in [Path('/var/lib/tempest-izanagi-runtime-normal-001')] + [Path('/var/lib/tempest-izanagi-image-smoke-' + name) for name in ('001', '001-v2', '002')]:
        base.verify_snapshot(old)
    for number in ('001', '002', '003'):
        for row in json.loads((REPO / ('docs/LINUX_X86_FULL_SNAPSHOT_' + number + '.json')).read_text()):
            assert base.sha(row['path']) == row['sha256']
        for path, row in json.loads((REPO / ('docs/LINUX_X86_FULL_BUILD_' + number + '_RESULT.json')).read_text())['files'].items():
            assert base.sha(path) == row['sha256']
    run = ROOT / 'work/runs/seed-reply-loss'
    report = json.loads((run / 'run.json').read_text())
    result = json.loads((run / 'result.json').read_text())
    assert report['status'] == 'aborted' and 'seed failed or response lost' in report['failure']
    assert report['agent']['performed'] is False and report['retest']['performed'] is False
    assert 'export' not in report['primary'] and not (run / 'retest').exists()
    assert result['evaluation'] == 'partial' and result['finding']['outcome'] == 'unknown'
    assert result['contaminated'] is None and not result['formal_metrics_eligible']
    assert json.loads((run / 'artifact-inventory.json').read_text())['complete']
    assert not list(run.rglob('transport-hmac')) and not list(run.rglob('__pycache__'))
    controls = [json.loads(line) for line in (run / 'evidence/control.jsonl').read_text().splitlines()]
    witness_path = ROOT / 'work/runs/seed-reply-loss-applied.json'
    verified_seed = seed.project(json.loads(witness_path.read_text()), controls)
    observer_path = Path('/tmp/tempest-runtime-seed-loss-observation-001.jsonl')
    observed = observation.project(observer_path)
    assert len(observed['observed_sessions']) == 1 and not observed['external_listener_observed']
    binding = report['primary']['vm_binding']
    assert observed['observed_sessions'][0]['binding'] == {key: binding[key] for key in ('boot_nonce', 'supervisor_pid', 'session_fingerprint')}
    assert observed['last_observed_unit']['InvocationID'] == INVOCATION
    assert observed['last_observed_unit']['ActiveState'] == 'failed'
    exited = json.loads((ROOT / 'work/evidence/exit-status.json').read_text())
    assert exited['invocation_id'] == INVOCATION and exited['exit_status'] == '1'
    journal = subprocess.check_output(['/usr/bin/journalctl', '-u', 'tempest-izanagi-runtime-seed-loss-001.service', '-o', 'json', '--no-pager'], text=True)
    (ROOT / 'work/evidence/journal.private.jsonl').write_text(journal)
    trusted = []
    for line in journal.splitlines():
        row = json.loads(line)
        if row.get('_PID') == '1' and row.get('_UID') == '0' and row.get('_BOOT_ID') == BOOT and row.get('INVOCATION_ID') == INVOCATION and row.get('UNIT') == 'tempest-izanagi-runtime-seed-loss-001.service':
            trusted.append({key: row.get(key) for key in ('UNIT', 'MESSAGE_ID', '__REALTIME_TIMESTAMP', '_BOOT_ID', '_PID', '_UID', 'INVOCATION_ID')})
    assert len(trusted) >= 4
    assert not Path('/sys/fs/cgroup/system.slice/tempest-izanagi-runtime-seed-loss-001.service').exists()
    assert not subprocess.run(['ps', '-u', '999', '-o', 'pid='], capture_output=True, text=True).stdout.strip()
    ports = set()
    for line in observer_path.read_text().splitlines():
        row = json.loads(line)
        if 'sample' in row:
            ports.update(int(item['local'].rsplit(':', 1)[1]) for item in row['sample']['listeners'])
    for port in ports:
        with socket.socket() as connection:
            connection.settimeout(1)
            assert connection.connect_ex(('127.0.0.1', port)) != 0
    files = {}
    for path in [run / name for name in ('run.json', 'result.json', 'artifact-inventory.json', 'evidence/control.jsonl')] + [witness_path, observer_path, Path('/tmp/tempest-runtime-seed-loss-001.log'), ROOT / 'work/evidence/exit-status.json']:
        files[str(path)] = {'sha256': base.sha(path), 'bytes': path.stat().st_size}
    public = {'status': 'failed_retry_diagnostic_assertion', 'caller_exit': 1, 'observer_exit': 0,
              'failure': 'retry did not reach the existing run-ID reservation',
              'same_id_retry': 'not established; original retry stdout/stderr not retained; no rerun',
              'unit': 'tempest-izanagi-runtime-seed-loss-001.service', 'invocation_id': INVOCATION, 'host_boot_id': BOOT,
              'seed_evidence': verified_seed, 'run_status': report['status'], 'evaluation': result['evaluation'],
              'finding_outcome': 'unknown', 'formal_metrics_eligible': False, 'agent_export_retest_not_started': True,
              'cleanup': report['primary']['cleanup'], 'artifact_inventory_complete': True,
              'observer': observed, 'exit_recorder': exited, 'trusted_lifecycle': trusted,
              'inputs_unchanged': len(snapshot['files']), 'old_inputs_evidence_unchanged': True,
              'external_runtime_unchanged': True, 'cgroup_absent': True, 'uid999_absent': True,
              'observed_ports_closed': sorted(ports), 'transient_keys_absent': True,
              'free_bytes': shutil.disk_usage(ROOT).free, 'files': files}
    Path('/tmp/tempest-runtime-seed-loss-result-001.json').write_text(json.dumps(public, indent=2) + '\n')
    print('failed trial evidence preserved; seed-discard proof kept separate from retry uncertainty')


if __name__ == '__main__':
    main()
