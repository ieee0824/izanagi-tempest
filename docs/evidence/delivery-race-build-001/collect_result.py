"""Collect the one build's saved evidence; never boots or retries a build."""
from pathlib import Path
import hashlib
import json
import os
import socket
import stat
import subprocess

REPO = Path('/home/ubuntu/izanagi-tempest')
ROOT = Path('/var/lib/tempest-izanagi-delivery-race-build-001')
UNIT = 'tempest-izanagi-delivery-race-build-001.service'
INVOCATION = 'f5ff6db2e2714f8fa265e8e95d3399b7'
BOOT = '30389abc903c40ae89a5c6268ec1c432'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    os.umask(0o077)
    assert os.getuid() == 0
    assert not Path('/sys/fs/cgroup/system.slice', UNIT).exists()
    assert subprocess.run(['pgrep', '-u', '999'], capture_output=True).returncode == 1
    for port in (18082, 22222, 5902):
        with socket.socket() as sock:
            assert sock.connect_ex(('127.0.0.1', port)) != 0
    snapshot = json.loads((ROOT / 'snapshot.json').read_text())
    for row in snapshot['files']:
        path = Path(row['path'])
        metadata = path.lstat()
        assert stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
        assert (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) == (0, 988, int(row['mode'], 8))
        assert sha(path) == row['sha256']
    for path, digest in snapshot['external_runtime_sha256'].items():
        assert sha(path) == digest
    # The prefix verifies immutable historical inputs/evidence only. It stops before
    # the old collector's output reads or journal writes and keeps its original ROOT.
    previous = REPO / 'docs/evidence/host-endpoint-001/collect_result.py'
    code = previous.read_text().split("    output = ROOT / 'work/output'", 1)[0] + '\nmain()\n'
    exec(compile(code, str(previous), 'exec'), {'__name__': 'old_verification', '__file__': str(previous)})
    assert not os.path.lexists('/var/lib/tempest-izanagi-host-endpoint-001/work/output/izanagi-hmac')
    exited = json.loads((ROOT / 'work/evidence/exit-status.json').read_text())
    assert exited['unit_name'] == UNIT and exited['invocation_id'] == INVOCATION
    assert exited['service_result'] == 'success' and exited['exit_code'] == 'exited' and exited['exit_status'] == '0'
    assert exited['unit']['InvocationID'] == INVOCATION
    assert exited['unit']['ExecMainStatus'] == '0' and exited['unit']['Result'] == 'success'
    observed = [json.loads(line) for line in Path('/tmp/tempest-delivery-race-build-observation-001.jsonl').read_text().splitlines()]
    assert observed and not any(row.get('observer_error') for row in observed)
    assert all(not row['external_listener_observed'] for row in observed)
    assert {row['unit']['InvocationID'] for row in observed if row['unit'].get('InvocationID')} == {INVOCATION}
    identities = {(vm['pid'], vm['starttime_ticks'], vm['cwd']) for row in observed for vm in row['qemu_network']}
    assert identities == {(310225, 37156503, str(ROOT / 'work'))}
    journal = subprocess.check_output(['/usr/bin/journalctl', '-u', UNIT, '-o', 'json', '--no-pager'], text=True)
    target = ROOT / 'work/evidence/journal.private.jsonl'
    with target.open('x') as stream:
        stream.write(journal)
    trusted = []
    for line in journal.splitlines():
        row = json.loads(line)
        if row.get('_PID') == '1' and row.get('_UID') == '0' and row.get('_BOOT_ID') == BOOT and row.get('UNIT') == UNIT and row.get('INVOCATION_ID') == INVOCATION:
            trusted.append({key: row.get(key) for key in ('UNIT', 'MESSAGE_ID', '__REALTIME_TIMESTAMP', '_BOOT_ID', '_PID', '_UID', 'INVOCATION_ID')})
    assert {'7d4958e842da4a758f6c1cdc7b36dcc5', '39f53479d3a045ac8e11786248231fbf', '7ad2d189f7e94e70a38c781354912448'} <= {row['MESSAGE_ID'] for row in trusted}
    image = ROOT / 'work/output-debian/debian-x86_64.qcow2'
    info = json.loads(subprocess.check_output(['/usr/bin/qemu-img', 'info', '--output=json', str(image)], text=True))
    assert info['format'] == 'qcow2' and info['virtual-size'] == 4294967296
    assert not info.get('backing-filename') and not info.get('dirty-flag', False)
    assert not info.get('format-specific', {}).get('data', {}).get('corrupt', False)
    log = Path('/tmp/tempest-delivery-race-build-001.log').read_text(errors='replace')
    assert 'Builds finished' in log and 'IZANAGI_IMAGE_SECURITY_OK' in log
    expected = json.loads((ROOT / 'inputs/definition/packer/image.json').read_text())
    assert expected['delivery_race_fixture'] is True
    for name in ('dispatcher.py', 'quiesce.py'):
        assert sha(ROOT / 'inputs/definition/packer' / name) == expected['derivation_sha256'][name]
    files = {}
    for path in (image, Path('/tmp/tempest-delivery-race-build-001.log'), Path('/tmp/tempest-delivery-race-build-observation-001.jsonl'), ROOT / 'work/packer-debug.log', ROOT / 'work/installer-serial.log', ROOT / 'work/evidence/exit-status.json', target):
        metadata = path.lstat()
        assert stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
        files[str(path)] = {'bytes': metadata.st_size, 'sha256': sha(path), 'uid': metadata.st_uid, 'gid': metadata.st_gid, 'mode': format(stat.S_IMODE(metadata.st_mode), '04o')}
    result = {'unit': UNIT, 'invocation_id': INVOCATION, 'boot_id': BOOT,
              'caller_session': 34339, 'observer_session': 87131,
              'caller_exit': 0, 'observer_exit': 1,
              'observer_terminal': 'unknown: same-invocation terminal attributes unavailable after unit GC',
              'exit_recorder': exited, 'trusted_lifecycle': trusted,
              'observations': len(observed), 'observer_last': observed[-1],
              'qemu_identity': {'pid': 310225, 'starttime_ticks': 37156503, 'cwd': str(ROOT / 'work')},
              'observer_errors': 0, 'external_listener_observed': False,
              'inputs_unchanged': len(snapshot['files']), 'old_inputs_evidence_unchanged': True,
              'external_runtime_unchanged': True, 'cgroup_absent': True, 'uid999_processes_absent': True,
              'ports_closed': True, 'image_info': info, 'files': files,
              'fixture_expected_manifest': expected, 'install_security_marker_observed': True,
              'installed_fixture_bytes': 'not yet verified; separate offline proof required',
              'fixture_runtime_executed': False}
    with (ROOT / 'work/evidence/result.json').open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'result_saved': True, 'inputs_unchanged': len(snapshot['files']), 'observations': len(observed), 'image_sha256': files[str(image)]['sha256']}))


if __name__ == '__main__':
    main()
