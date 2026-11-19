"""Collect the one build's saved evidence; never boots or retries a build."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import socket
import stat
import subprocess

REPO = Path('/home/ubuntu/izanagi-tempest')
ROOT = Path('/var/lib/tempest-izanagi-capture-build-001')
UNIT = 'tempest-izanagi-capture-build-001.service'
INVOCATION = '19bf093edd7743d08154172eb63abf50'
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
    observed = [json.loads(line) for line in Path('/tmp/tempest-capture-build-observation-001.jsonl').read_text().splitlines()]
    assert observed and not any(row.get('observer_error') for row in observed)
    assert all(not row['external_listener_observed'] for row in observed)
    assert {row['unit']['InvocationID'] for row in observed if row['unit'].get('InvocationID')} == {INVOCATION}
    identities = {(vm['pid'], vm['starttime_ticks'], vm['cwd']) for row in observed for vm in row['qemu_network']}
    assert identities == {(327995, 39020414, str(ROOT / 'work'))}
    spec = importlib.util.spec_from_file_location('fixed_capture_build_observer', ROOT / 'inputs/repo/integration/capture_build_observe.py')
    observer = importlib.util.module_from_spec(spec); spec.loader.exec_module(observer)
    replay = observer.BuildLifetime()
    for row in observed: replay.observe(row)
    replay.require_observed()
    for name,digest in snapshot['provenance']['source_hashes'].items(): assert sha(REPO/name)==digest
    binding=json.loads((REPO/'docs/LINUX_X86_CAPTURE_COMPILE_BINDING_001.json').read_text())['parent_compile']
    image_metadata=json.loads((ROOT/'inputs/definition/packer/image.json').read_text())
    assert all(image_metadata[k]==v for k,v in binding.items())
    hardlink=json.loads((REPO/'docs/LINUX_X86_IMAGE_HARDLINK_001_RESULT.json').read_text())
    for row in hardlink['after']:
        metadata=Path(row['path']).lstat()
        assert (metadata.st_dev,metadata.st_ino,metadata.st_nlink)==(row['file']['device'],row['file']['inode'],8)
    guest=json.loads((REPO/'docs/LINUX_X86_CAPTURE_GUEST_BUILD_001_RESULT.json').read_text())
    assert sha(ROOT/'inputs/guest')==guest['binary']['sha256']==image_metadata['input_sha256']['guest']
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
    log = Path('/tmp/tempest-capture-build-001.log').read_text(errors='replace')
    assert 'Builds finished' in log and 'IZANAGI_IMAGE_SECURITY_OK' in log
    expected = json.loads((ROOT / 'inputs/definition/packer/image.json').read_text())
    assert expected['delivery_race_fixture'] is True
    for name in ('dispatcher.py', 'quiesce.py'):
        assert sha(ROOT / 'inputs/definition/packer' / name) == expected['derivation_sha256'][name]
    files = {}
    for path in (image, Path('/tmp/tempest-capture-build-001.log'), Path('/tmp/tempest-capture-build-observation-001.jsonl'), ROOT / 'work/packer-debug.log', ROOT / 'work/installer-serial.log', ROOT / 'work/evidence/exit-status.json', target):
        metadata = path.lstat()
        assert stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
        files[str(path)] = {'bytes': metadata.st_size, 'sha256': sha(path), 'uid': metadata.st_uid, 'gid': metadata.st_gid, 'mode': format(stat.S_IMODE(metadata.st_mode), '04o')}
    result = {'unit': UNIT, 'invocation_id': INVOCATION, 'boot_id': BOOT,
              'caller_session': 40711, 'observer_session': 39683,
              'caller_exit': 0, 'observer_exit': 1,
              'observer_terminal': 'unknown: same-invocation terminal attributes unavailable after unit GC',
              'exit_recorder': exited, 'trusted_lifecycle': trusted,
              'observations': len(observed), 'observer_last': observed[-1],
              'qemu_identity': {'pid': 327995, 'starttime_ticks': 39020414, 'cwd': str(ROOT / 'work')},
              'fixed_observer_replay_passed': True, 'new_guest_build_report_sha256': sha(REPO/'docs/LINUX_X86_CAPTURE_GUEST_BUILD_001_RESULT.json'), 'hardlink_exception_report_sha256': sha(REPO/'docs/LINUX_X86_IMAGE_HARDLINK_001_RESULT.json'), 'observer_errors': 0, 'external_listener_observed': False,
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
