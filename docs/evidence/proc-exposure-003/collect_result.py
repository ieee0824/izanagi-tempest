"""Verify saved exec scan metadata and isolation evidence without recovering markers."""
from collections import Counter
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess

REPO = Path('/home/ubuntu/izanagi-tempest')
ROOT = Path('/var/lib/tempest-izanagi-proc-exposure-003')
INVOCATION = '42b4754bbf1f48159eace8e9834f033a'
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
    for document in ('LINUX_X86_RUNTIME_PRESENCE_001_RESULT.json', 'LINUX_X86_RUNTIME_NORMAL_001_RESULT.json', 'LINUX_X86_RUNTIME_RESERVATION_001_RESULT.json'):
        for path, metadata in json.loads((REPO / 'docs' / document).read_text())['files'].items():
            assert base.sha(path) == metadata['sha256']
    for name in ('001', '001-v2', '002'):
        base.verify_snapshot(Path('/var/lib/tempest-izanagi-image-smoke-' + name))
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
    for attempt in ('exec-exposure-001', 'proc-exposure-001', 'proc-exposure-002'):
        base.verify_snapshot(Path('/var/lib/tempest-izanagi-' + attempt))
        assert not os.path.lexists('/var/lib/tempest-izanagi-' + attempt + '/work/output/izanagi-hmac')
    for document in ('LINUX_X86_EXEC_EXPOSURE_001_RESULT.json', 'LINUX_X86_PROC_EXPOSURE_001_RESULT.json', 'LINUX_X86_PROC_EXPOSURE_002_RESULT.json'):
        for path, metadata in json.loads((REPO / 'docs' / document).read_text())['files'].items():
            assert base.sha(path) == metadata['sha256']
    output = ROOT / 'work/output'
    summary = json.loads((output / 'summary.json').read_text())
    assert summary['status'] == 'collected_requires_review'
    scan = summary['checks']['exec_private_markers']
    assert scan['passed'] is True and scan['leaked_streams'] == []
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
    assert records and [row['id'] for row in records] == list(range(1, len(records) + 1))
    expected_names = set()
    for row in records:
        assert row['operation'] in {'exec', 'ping', 'claim', 'seed', 'probe', 'seal', 'attest', 'export', 'fetch'}
        assert type(row['expected_error']) is bool and type(row['timed_out']) is bool
        assert row['returncode'] is None if row['timed_out'] else type(row['returncode']) is int
        expected_names.add(f'exec-{row["id"]:06d}.json')
        assert len(row['streams']) == 2
        for item, kind in zip(row['streams'], ('stdout', 'stderr')):
            name = f'exec-{row["id"]:06d}.{kind}'
            assert item['file'] == name and type(item['bytes']) is int and item['bytes'] >= 0
            assert (evidence / name).stat().st_size == item['bytes']
            expected_names.add(name)
    assert {path.name for path in entries} == expected_names
    derived = {'executions': len(records), 'streams': 2 * len(records),
               'timed_out': sum(row['timed_out'] for row in records),
               'operations': dict(Counter(row['operation'] for row in records)),
               'expected_error_reads': sum(row['expected_error'] for row in records)}
    assert all(scan[key] == value for key, value in derived.items())
    assert scan['expected_error_reads'] > 0
    # Load only saved guest frames; never invoke guest helpers on host /proc.
    import sys
    sys.path.insert(0, str(ROOT / 'inputs/repo/image'))
    paging = module('saved_proc_paging', ROOT / 'inputs/repo/image/proc_paging.py')
    stages = {stage: {'enumeration': None, 'pages': [], 'wire_bytes': 0} for stage in paging.STAGES}
    for row in records:
        if row['operation'] != 'exec':
            continue
        stream = evidence / row['streams'][0]['file']
        if stream.stat().st_size > paging.core.MAX_OUTPUT:
            continue
        data = stream.read_bytes()
        try:
            value = json.loads(data)
        except (ValueError, UnicodeError):
            continue
        if not isinstance(value, dict) or value.get('kind') not in ('proc_enumeration', 'proc_page'):
            continue
        assert value['stage'] in stages and row['returncode'] == 0 and not row['timed_out']
        stage = stages[value['stage']]
        stage['wire_bytes'] += len(data)
        if value['kind'] == 'proc_enumeration':
            assert stage['enumeration'] is None and not stage['pages']
            stage['enumeration'] = value
        else:
            assert stage['enumeration'] is not None
            stage['pages'].append(value)
    recomputed = {}
    for name, stage in stages.items():
        assert stage['enumeration'] is not None
        value = paging.summarize_pages(stage['enumeration'], stage['pages'], stage['wire_bytes'])
        assert value['passed'] and value == summary['checks']['proc_' + name]
        recomputed[name] = value
    assert [recomputed[name]['enumerated_processes'] for name in paging.STAGES] == [132, 113, 116]
    assert [recomputed[name]['pages'] for name in paging.STAGES] == [2, 1, 1]

    assert summary['checks']['host_logs_private_markers']['passed'] is True
    assert summary['checks']['ebpf_trace_probe']['passed'] is True
    assert summary['checks']['running_agent_build_binding']['passed'] is True
    assert summary['checks']['installed_artifact_binding']['passed'] is True
    assert summary['checks']['recording_boundary']['passed'] is True
    helper_metadata = {}
    for name, source in (('proc_evidence.py', 'proc_evidence.py'), ('proc-probe.py', 'proc_paging.py')):
        path = output / 'workspace/readonly-check' / name
        metadata = path.lstat()
        assert stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
        assert (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) == (999, 988, 0o444)
        assert base.sha(path) == base.sha(ROOT / 'inputs/repo/image' / source)
        mapped = {field: int.from_bytes(os.getxattr(path, 'user.virtfs.' + field), 'little') for field in ('uid', 'gid', 'mode')}
        assert mapped == {'uid': 0, 'gid': 0, 'mode': stat.S_IFREG | 0o444}
        helper_metadata[name] = {'host_uid': 999, 'host_gid': 988, 'host_mode': '0444', 'mapped': mapped, 'source_hash_matches': True}
    exited = json.loads((ROOT / 'work/evidence/exit-status.json').read_text())
    assert exited['invocation_id'] == INVOCATION and exited['exit_status'] == '0' and exited['service_result'] == 'success'
    observer_path = Path('/tmp/tempest-proc-exposure-observation-003.jsonl')
    samples = [json.loads(line) for line in observer_path.read_text().splitlines()]
    assert samples and not any(row['external_listener_observed'] for row in samples)
    identities = {(vm['pid'], vm['starttime_ticks'], vm['cwd']) for row in samples for vm in row['qemu_network']}
    assert identities == {(302655, 36438214, str(output / 'workspace'))}
    journal = subprocess.check_output(['/usr/bin/journalctl', '-u', 'tempest-izanagi-proc-exposure-003.service', '-o', 'json', '--no-pager'], text=True)
    (ROOT / 'work/evidence/journal.private.jsonl').write_text(journal)
    trusted = []
    for line in journal.splitlines():
        row = json.loads(line)
        if row.get('_PID') == '1' and row.get('_UID') == '0' and row.get('_BOOT_ID') == BOOT and row.get('INVOCATION_ID') == INVOCATION and row.get('UNIT') == 'tempest-izanagi-proc-exposure-003.service':
            trusted.append({key: row.get(key) for key in ('UNIT', 'MESSAGE_ID', '__REALTIME_TIMESTAMP', '_BOOT_ID', '_PID', '_UID', 'INVOCATION_ID')})
    required = {'7d4958e842da4a758f6c1cdc7b36dcc5', '39f53479d3a045ac8e11786248231fbf', '7ad2d189f7e94e70a38c781354912448'}
    assert required <= {row['MESSAGE_ID'] for row in trusted}
    assert not Path('/sys/fs/cgroup/system.slice/tempest-izanagi-proc-exposure-003.service').exists()
    assert not subprocess.run(['ps', '-u', '999', '-o', 'pid='], capture_output=True, text=True).stdout.strip()
    ports = {int(listener['local'].rsplit(':', 1)[1]) for row in samples for listener in row['listeners']}
    for port in ports:
        with socket.socket() as connection:
            connection.settimeout(1)
            assert connection.connect_ex(('127.0.0.1', port)) != 0
    files = {str(path): {'sha256': base.sha(path), 'bytes': path.stat().st_size} for path in
             (output / 'summary.json', observer_path, ROOT / 'work/evidence/exit-status.json', Path('/tmp/tempest-proc-exposure-003.log'))}
    public = {'status': 'paged_proc_and_exec_scan_passed_observer_terminal_unknown', 'caller_exit': 0, 'observer_exit': 1,
              'observer_terminal': 'unknown after unit GC; not treated as success',
              'unit': 'tempest-izanagi-proc-exposure-003.service', 'invocation_id': INVOCATION, 'host_boot_id': BOOT,
              'public_helper_host_metadata': helper_metadata, 'individual_guest_helper_stat': 'not measured; host xattr/mode and successful guest reads do not prove individual guest stat',
              'saved_proc_checks': recomputed, 'proc_summary_recomputed_from_private_frames': True, 'proc_scope': 'enumerated identities in three bounded paged intervals; not complete lifetime, FD contents or short-lived native coverage',
              'saved_exec_scan': scan, 'capture_metadata_reconciled': True, 'capture_files': len(entries),
              'capture_directory_mode0700_files0600_uid999_verified': True,
              'collector_scan_scope': 'saved in-run scan results plus metadata/count/size/mode reconciliation; markers not recovered and raw streams not rescanned for markers; saved proc frames summarized separately',
              'host_timeout_scope': 'no host timeout occurred; partial-output behavior covered by unit fixture only' if not scan['timed_out'] else 'host timeout observed',
              'existing_log_scan_passed': True, 'actual_trace_probe_passed': True,
              'exit_recorder': exited, 'trusted_lifecycle': trusted, 'observer_samples': len(samples),
              'observed_qemu': {'pid': 302655, 'starttime_ticks': 36438214, 'cwd': str(output / 'workspace')},
              'inputs_unchanged': len(snapshot['files']), 'old_inputs_evidence_unchanged': True, 'external_runtime_unchanged': True,
              'cgroup_absent': True, 'uid999_absent': True, 'observed_ports_closed': sorted(ports),
              'dummy_transport_key': 'retained private pending result review; not read by collector',
              'free_bytes': shutil.disk_usage(ROOT).free, 'files': files}
    Path('/tmp/tempest-proc-exposure-result-003.json').write_text(json.dumps(public, indent=2) + '\n')
    print('saved proc frames and exec metadata reconciled; inputs/old evidence and cleanup verified; no marker recovery/rescan')


if __name__ == '__main__':
    main()
