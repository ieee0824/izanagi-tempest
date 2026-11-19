"""Preserve a capped guest proc snapshot without treating it as complete evidence."""
from collections import Counter
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess

REPO = Path('/home/ubuntu/izanagi-tempest')
ROOT = Path('/var/lib/tempest-izanagi-proc-exposure-001')
INVOCATION = 'ec197df910a34e42b0818f2d6333feba'
BOOT = '30389abc903c40ae89a5c6268ec1c432'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    os.umask(0o077)
    base = module('normal_result', REPO / 'docs/evidence/runtime-normal-001/collect_result.py')
    snapshot = base.verify_snapshot(ROOT)
    for directory in snapshot['directories_mode0750_root_group']:
        metadata = Path(directory).stat()
        assert (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) == (0, 988, 0o750)
    for path, digest in snapshot['external_runtime_sha256'].items():
        assert base.sha(path) == digest
    reservation = Path('/var/lib/tempest-izanagi-runtime-reservation-001')
    tree = module('tree', reservation / 'inputs/tree_manifest.py')
    assert tree.inventory('/var/lib/tempest-izanagi-runtime-seed-loss-001') == json.loads((reservation / 'baseline.private.json').read_text())
    for document in ('LINUX_X86_EXEC_EXPOSURE_001_RESULT.json', 'LINUX_X86_RUNTIME_PRESENCE_001_RESULT.json', 'LINUX_X86_RUNTIME_NORMAL_001_RESULT.json', 'LINUX_X86_RUNTIME_RESERVATION_001_RESULT.json'):
        for path, metadata in json.loads((REPO / 'docs' / document).read_text())['files'].items():
            assert base.sha(path) == metadata['sha256']
    assert not os.path.lexists('/var/lib/tempest-izanagi-exec-exposure-001/work/output/izanagi-hmac')
    for name in ('001', '001-v2', '002'):
        base.verify_snapshot(Path('/var/lib/tempest-izanagi-image-smoke-' + name))
    base.verify_snapshot(Path('/var/lib/tempest-izanagi-exec-exposure-001'))
    base.verify_snapshot(Path('/var/lib/tempest-izanagi-runtime-normal-001'))
    for row in json.loads(Path('/var/lib/tempest-izanagi-runtime-presence-001/snapshot-v2.json').read_text())['files']:
        if row['type'] == 'file':
            assert base.sha(row['path']) == row['sha256']
        else:
            assert os.readlink(row['path']) == row['target']
    for number in ('001', '002', '003'):
        for row in json.loads((REPO / ('docs/LINUX_X86_FULL_SNAPSHOT_' + number + '.json')).read_text()):
            assert base.sha(row['path']) == row['sha256']
        for path, metadata in json.loads((REPO / ('docs/LINUX_X86_FULL_BUILD_' + number + '_RESULT.json')).read_text())['files'].items():
            assert base.sha(path) == metadata['sha256']
    output = ROOT / 'work/output'
    summary = json.loads((output / 'summary.json').read_text())
    before = summary['checks']['proc_before_claim']
    assert summary['status'] == 'incomplete' and before['passed'] is False
    assert set(key for key in summary['checks'] if key.startswith('proc_')) == {'proc_before_claim'}
    assert 'exec_private_markers' not in summary['checks']
    proc = module('proc_summary_only', ROOT / 'inputs/repo/image/proc_evidence.py')
    evidence = output / 'exec-evidence'
    metadata = evidence.lstat()
    assert stat.S_ISDIR(metadata.st_mode) and (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) == (999, 988, 0o700)
    entries = list(evidence.iterdir())
    for path in entries:
        metadata = path.lstat()
        assert stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
        assert (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) == (999, 988, 0o600)
        assert re.fullmatch(r'exec-[0-9]{6}\.(stdout|stderr|json)', path.name)
    records = [json.loads(path.read_text()) for path in sorted(evidence.glob('*.json'))]
    assert [row['id'] for row in records] == list(range(1, len(records) + 1))
    expected_names = set()
    saved_proc = []
    for row in records:
        expected_names.add(f'exec-{row["id"]:06d}.json')
        assert len(row['streams']) == 2
        for item, kind in zip(row['streams'], ('stdout', 'stderr')):
            name = f'exec-{row["id"]:06d}.{kind}'
            assert item['file'] == name and (evidence / name).stat().st_size == item['bytes']
            expected_names.add(name)
        # Read only the saved guest JSON, never invoke snapshot() or host /proc.
        try:
            value = json.loads((evidence / row['streams'][0]['file']).read_bytes())
        except (ValueError, UnicodeError):
            continue
        if isinstance(value, dict) and 'pid_set_truncated' in value and 'records' in value:
            saved_proc.append(value)
    assert {path.name for path in entries} == expected_names
    assert len(saved_proc) == 1
    raw = saved_proc[0]
    assert raw['actor_uid'] == 1000 and raw['pid_set_truncated'] is True
    assert proc.summarize(raw) == before
    assert all(before['positive_controls'].values())
    assert before['records'] == 128 and before['truncated_streams'] == before['unexpected_errors'] == 0
    exited = json.loads((ROOT / 'work/evidence/exit-status.json').read_text())
    assert exited['invocation_id'] == INVOCATION and exited['exit_status'] == '1' and exited['service_result'] == 'exit-code'
    observer_path = Path('/tmp/tempest-proc-exposure-observation-001.jsonl')
    samples = [json.loads(line) for line in observer_path.read_text().splitlines()]
    assert samples and not any(row['external_listener_observed'] for row in samples)
    assert {(vm['pid'], vm['starttime_ticks'], vm['cwd']) for row in samples for vm in row['qemu_network']} == {(300385, 36179402, str(output / 'workspace'))}
    assert samples[-1]['unit']['InvocationID'] == INVOCATION and samples[-1]['unit']['ActiveState'] == 'failed'
    journal = subprocess.check_output(['/usr/bin/journalctl', '-u', 'tempest-izanagi-proc-exposure-001.service', '-o', 'json', '--no-pager'], text=True)
    (ROOT / 'work/evidence/journal.private.jsonl').write_text(journal)
    trusted = []
    for line in journal.splitlines():
        row = json.loads(line)
        if row.get('_PID') == '1' and row.get('_UID') == '0' and row.get('_BOOT_ID') == BOOT and row.get('INVOCATION_ID') == INVOCATION and row.get('UNIT') == 'tempest-izanagi-proc-exposure-001.service':
            trusted.append({key: row.get(key) for key in ('UNIT', 'MESSAGE_ID', '__REALTIME_TIMESTAMP', '_BOOT_ID', '_PID', '_UID', 'INVOCATION_ID')})
    assert {'7d4958e842da4a758f6c1cdc7b36dcc5', '39f53479d3a045ac8e11786248231fbf'} <= {row['MESSAGE_ID'] for row in trusted}
    assert not Path('/sys/fs/cgroup/system.slice/tempest-izanagi-proc-exposure-001.service').exists()
    assert not subprocess.run(['ps', '-u', '999', '-o', 'pid='], capture_output=True, text=True).stdout.strip()
    ports = {int(listener['local'].rsplit(':', 1)[1]) for row in samples for listener in row['listeners']}
    for port in ports:
        with socket.socket() as connection:
            connection.settimeout(1)
            assert connection.connect_ex(('127.0.0.1', port)) != 0
    files = {str(path): {'sha256': base.sha(path), 'bytes': path.stat().st_size} for path in
             (output / 'summary.json', observer_path, ROOT / 'work/evidence/exit-status.json', Path('/tmp/tempest-proc-exposure-001.log'))}
    public = {'status': 'failed_pid_set_cap_before_claim', 'caller_exit': 1, 'observer_exit': 0,
              'unit': 'tempest-izanagi-proc-exposure-001.service', 'invocation_id': INVOCATION, 'host_boot_id': BOOT,
              'guest_snapshot_stage': 'before_claim', 'saved_proc_summary': before, 'pid_set_truncated': True,
              'actor_uid': 1000, 'summary_recomputed_from_private_guest_json': True,
              'later_snapshots': 'not reached', 'final_exec_marker_scan': 'not reached; no overall leak-free claim',
              'capture_executions': len(records), 'capture_streams': sum(len(row['streams']) for row in records),
              'capture_operations': dict(Counter(row['operation'] for row in records)), 'capture_files_private_modes_verified': True,
              'collector_scope': 'summarize saved guest JSON only; host proc helper snapshot not invoked; markers not recovered or rescanned',
              'exit_recorder': exited, 'trusted_lifecycle': trusted, 'observer_samples': len(samples),
              'observed_qemu': {'pid': 300385, 'starttime_ticks': 36179402, 'cwd': str(output / 'workspace')},
              'inputs_unchanged': len(snapshot['files']), 'old_inputs_evidence_unchanged': True, 'external_runtime_unchanged': True,
              'exec001_key_remains_absent': True, 'cgroup_absent': True, 'uid999_absent': True,
              'observed_ports_closed': sorted(ports), 'dummy_transport_key': 'retained private pending failed-result review', 'files': files}
    Path('/tmp/tempest-proc-exposure-result-001.json').write_text(json.dumps(public, indent=2) + '\n')
    print('capped first-snapshot evidence and cleanup preserved; later stages/final scan remain unproven')


if __name__ == '__main__':
    main()
