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
ROOT = Path('/var/lib/tempest-izanagi-delivery-race-smoke-001')
INVOCATION = '332f962b2818418fba1f221e843f3777'
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
    previous = REPO / 'docs/evidence/host-endpoint-001/collect_result.py'
    code = previous.read_text().split("    output = ROOT / 'work/output'", 1)[0] + '\nmain()\n'
    exec(compile(code, str(previous), 'exec'), {'__name__': 'old_verification', '__file__': str(previous)})
    for document in ('LINUX_X86_HOST_ENDPOINT_001_RESULT.json', 'LINUX_X86_DELIVERY_RACE_BUILD_001_RESULT.json'):
        for path, metadata in json.loads((REPO / 'docs' / document).read_text())['files'].items():
            assert base.sha(path) == metadata['sha256']
    assert not os.path.lexists('/var/lib/tempest-izanagi-host-endpoint-001/work/output/izanagi-hmac')
    build = Path('/var/lib/tempest-izanagi-delivery-race-build-001')
    for row in json.loads((build / 'snapshot.json').read_text())['files']:
        assert base.sha(row['path']) == row['sha256']
    for path, digest in json.loads((REPO / 'docs/LINUX_X86_DELIVERY_RACE_SMOKE_SOURCE_001.json').read_text())['files'].items():
        assert base.sha(REPO / path) == digest
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
    assert scan['expected_error_reads'] == 6 and scan['timed_out'] == 0
    checks = summary['checks']
    forced = checks['forced_delivery_race']
    exported = checks['export']
    quiesce = exported['quiesce']
    assert forced['passed'] and forced['operation_submissions'] == 1
    assert forced['forced_reader_pid'] == quiesce['forced_reader_pid'] == 1496
    assert quiesce['forced_reader_pid'] in quiesce['moved_pids']
    assert quiesce['descendants_empty'] and quiesce['service_frozen'] and exported['complete']
    reads = summary['export_delivery_reads'][exported['export_id']]
    assert reads[0]['category'] == 'execution_error' and reads[0]['returncode'] != 0
    assert reads[-1]['category'] == 'reply' and reads[-1]['returncode'] == 0
    # Reconcile saved read metadata against captured stream digests, without
    # recovering private markers, keys, plaintext requests or decoding replies again.
    expected_reads = Counter((row['returncode'], row['stdout_sha256'], row['stderr_sha256'])
                             for group in summary['export_delivery_reads'].values() for row in group)
    actual_reads = Counter((row['returncode'], base.sha(evidence / row['streams'][0]['file']),
                           base.sha(evidence / row['streams'][1]['file']))
                          for row in records if row['operation'] == 'export')
    assert expected_reads == actual_reads
    assert checks['image_manifest']['stdout']
    manifest = json.loads(checks['image_manifest']['stdout'])
    expected_manifest = json.loads((build / 'inputs/definition/packer/image.json').read_text())
    assert manifest['delivery_race_fixture'] is True
    assert all(manifest[key] == value for key, value in expected_manifest.items())
    assert all(row.get('passed', True) for row in checks.values() if isinstance(row, dict))
    assert checks['build_guest_binding']['passed']
    assert checks['cgroup_detached_descendant_killed']['passed']
    assert summary['checks']['host_logs_private_markers']['passed'] is True
    assert summary['checks']['ebpf_trace_probe']['passed'] is True
    assert summary['checks']['running_agent_build_binding']['passed'] is True
    assert summary['checks']['installed_artifact_binding']['passed'] is True
    assert summary['checks']['recording_boundary']['passed'] is True
    exited = json.loads((ROOT / 'work/evidence/exit-status.json').read_text())
    assert exited['unit_name'] == ROOT.name + '.service' and exited['unit']['InvocationID'] == INVOCATION
    assert exited['exit_code'] == 'exited' and exited['unit']['ExecMainStatus'] == '0'
    assert exited['invocation_id'] == INVOCATION and exited['exit_status'] == '0' and exited['service_result'] == 'success'
    observer_path = Path('/tmp/tempest-delivery-race-smoke-observation-001.jsonl')
    samples = [json.loads(line) for line in observer_path.read_text().splitlines()]
    assert samples and not any(row['external_listener_observed'] for row in samples)
    assert not any('observer_error' in row for row in samples)
    assert {row['unit']['InvocationID'] for row in samples if row['unit'].get('InvocationID')} == {INVOCATION}
    identities = {(vm['pid'], vm['starttime_ticks'], vm['cwd']) for row in samples for vm in row['qemu_network']}
    assert identities == {(314914, 38232597, str(output / 'workspace'))}
    journal = subprocess.check_output(['/usr/bin/journalctl', '-u', 'tempest-izanagi-delivery-race-smoke-001.service', '-o', 'json', '--no-pager'], text=True)
    with (ROOT / 'work/evidence/journal.private.jsonl').open('x') as stream:
        stream.write(journal)
    trusted = []
    for line in journal.splitlines():
        row = json.loads(line)
        if row.get('_PID') == '1' and row.get('_UID') == '0' and row.get('_BOOT_ID') == BOOT and row.get('INVOCATION_ID') == INVOCATION and row.get('UNIT') == 'tempest-izanagi-delivery-race-smoke-001.service':
            trusted.append({key: row.get(key) for key in ('UNIT', 'MESSAGE_ID', '__REALTIME_TIMESTAMP', '_BOOT_ID', '_PID', '_UID', 'INVOCATION_ID')})
    required = {'7d4958e842da4a758f6c1cdc7b36dcc5', '39f53479d3a045ac8e11786248231fbf', '7ad2d189f7e94e70a38c781354912448'}
    assert required <= {row['MESSAGE_ID'] for row in trusted}
    assert not Path('/sys/fs/cgroup/system.slice/tempest-izanagi-delivery-race-smoke-001.service').exists()
    assert not subprocess.run(['ps', '-u', '999', '-o', 'pid='], capture_output=True, text=True).stdout.strip()
    ports = {int(listener['local'].rsplit(':', 1)[1]) for row in samples for listener in row['listeners']}
    for port in ports:
        with socket.socket() as connection:
            connection.settimeout(1)
            assert connection.connect_ex(('127.0.0.1', port)) != 0
    files = {str(path): {'sha256': base.sha(path), 'bytes': path.stat().st_size} for path in
             (output / 'summary.json', observer_path, ROOT / 'work/evidence/exit-status.json', ROOT / 'work/evidence/journal.private.jsonl', Path('/tmp/tempest-delivery-race-smoke-001.log'))}
    public = {'status': 'forced_reader_M3_checks_passed_observer_terminal_unknown', 'caller_exit': 0, 'observer_exit': 1,
              'observer_terminal': 'unknown after unit GC; not treated as success',
              'unit': 'tempest-izanagi-delivery-race-smoke-001.service', 'invocation_id': INVOCATION, 'host_boot_id': BOOT,
              'preflight_session': 79957, 'preflight_exit': 0, 'preflight_free_bytes': 12605267968,
              'caller_session': 20069, 'observer_session': 70362,
              'forced_delivery_race': forced, 'export_id': exported['export_id'],
              'export_complete': exported['complete'],
              'quiesce': {key: quiesce[key] for key in ('forced_reader_pid', 'moved_pids', 'descendants_empty', 'service_frozen')},
              'primary_export_read_categories': [row['category'] for row in reads],
              'saved_export_read_metadata_reconciled_to_private_stream_digests': True,
              'authenticated_recovery_scope': 'fixed smoke decoded and authenticated the reply in-run; collector reconciles saved hashes and metadata, without decoding again',
              'fixture_guest_manifest_matches_fixed_input': True,
              'build_guest_binding_passed': True, 'installed_artifact_binding_passed': True,
              'recording_boundary_passed': True, 'M3_checks_executed': sorted(checks),
              'host_completed_or_large_control_executed': False,
              'saved_exec_scan': scan, 'capture_metadata_reconciled': True, 'capture_files': len(entries),
              'capture_directory_mode0700_files0600_uid999_verified': True,
              'collector_scan_scope': 'saved in-run marker scan plus metadata/count/size/mode reconciliation and export stream digests; markers not recovered and raw streams not rescanned for markers',
              'host_timeout_scope': 'no host timeout occurred; partial-output behavior covered by unit fixture only' if not scan['timed_out'] else 'host timeout observed',
              'existing_log_scan_passed': True, 'actual_trace_probe_passed': True,
              'exit_recorder': exited, 'trusted_lifecycle': trusted, 'observer_samples': len(samples),
              'observed_qemu': {'pid': 314914, 'starttime_ticks': 38232597, 'cwd': str(output / 'workspace')},
              'inputs_unchanged': len(snapshot['files']), 'old_inputs_evidence_unchanged': True, 'external_runtime_unchanged': True,
              'cgroup_absent': True, 'uid999_absent': True, 'observed_ports_closed': sorted(ports),
              'dummy_transport_key': 'retained private pending result review; not read by collector',
              'free_bytes': shutil.disk_usage(ROOT).free, 'files': files}
    with Path('/tmp/tempest-delivery-race-smoke-result-001.json').open('x') as stream:
        stream.write(json.dumps(public, indent=2) + '\n')
    print('saved exec/export digest/count/mode and independent cleanup verified; no marker recovery or rescan')


if __name__ == '__main__':
    main()
