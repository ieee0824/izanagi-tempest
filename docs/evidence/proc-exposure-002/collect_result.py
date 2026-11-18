"""Preserve the pre-VM helper setup failure without claiming a proc observation."""
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
ROOT = Path('/var/lib/tempest-izanagi-proc-exposure-002')
INVOCATION = 'dd6e5cb56b4640ba922e548b3c984f37'
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
    base.verify_snapshot(Path('/var/lib/tempest-izanagi-proc-exposure-001'))
    for path, metadata in json.loads((REPO / 'docs/LINUX_X86_PROC_EXPOSURE_001_RESULT.json').read_text())['files'].items():
        assert base.sha(path) == metadata['sha256']
    assert not os.path.lexists('/var/lib/tempest-izanagi-proc-exposure-001/work/output/izanagi-hmac')
    output = ROOT / 'work/output'
    assert not (output / 'summary.json').exists() and not (output / 'exec-evidence').exists()
    helper = output / 'workspace/readonly-check/proc_evidence.py'
    metadata = helper.lstat()
    assert stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
    assert (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) == (999, 988, 0o444)
    assert base.sha(helper) == base.sha(ROOT / 'inputs/repo/image/proc_evidence.py')
    assert not (helper.parent / 'proc-probe.py').exists()
    log = Path('/tmp/tempest-proc-exposure-002.log')
    text = log.read_text()
    assert 'PermissionError: [Errno 13] Permission denied:' in text and str(helper) in text
    assert 'mapped_metadata' in text and 'os.setxattr' in text
    observer = Path('/tmp/tempest-proc-exposure-observation-002.jsonl')
    rows = [json.loads(line) for line in observer.read_text().splitlines()]
    assert rows and not any(row['qemu_network'] or row['listeners'] or row['external_listener_observed'] for row in rows)
    assert rows[-1]['unit']['InvocationID'] == INVOCATION and rows[-1]['unit']['ActiveState'] == 'failed'
    exited_path = ROOT / 'work/evidence/exit-status.json'
    exited = json.loads(exited_path.read_text())
    assert exited['invocation_id'] == INVOCATION and exited['exit_status'] == '1' and exited['service_result'] == 'exit-code'
    assert not Path('/sys/fs/cgroup/system.slice/tempest-izanagi-proc-exposure-002.service').exists()
    assert not subprocess.run(['ps', '-u', '999', '-o', 'pid='], capture_output=True, text=True).stdout.strip()
    journal = subprocess.check_output(['/usr/bin/journalctl', '-u', 'tempest-izanagi-proc-exposure-002.service', '-o', 'json', '--no-pager'], text=True)
    (ROOT / 'work/evidence/journal.private.jsonl').write_text(journal)
    trusted = []
    for line in journal.splitlines():
        row = json.loads(line)
        if row.get('_PID') == '1' and row.get('_UID') == '0' and row.get('_BOOT_ID') == BOOT and row.get('INVOCATION_ID') == INVOCATION and row.get('UNIT') == 'tempest-izanagi-proc-exposure-002.service':
            trusted.append({key: row.get(key) for key in ('UNIT', 'MESSAGE_ID', '__REALTIME_TIMESTAMP', '_BOOT_ID', '_PID', '_UID', 'INVOCATION_ID')})
    assert {'7d4958e842da4a758f6c1cdc7b36dcc5', '39f53479d3a045ac8e11786248231fbf'} <= {row['MESSAGE_ID'] for row in trusted}
    key = output / 'izanagi-hmac'
    metadata = key.lstat()
    assert stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
    assert (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) == (999, 988, 0o600)
    public = {'status': 'failed_helper_xattr_setup_before_vm', 'caller_exit': 1, 'observer_exit': 1,
              'observer_failure': 'same-invocation terminal captured, but no QEMU identity observed',
              'unit': 'tempest-izanagi-proc-exposure-002.service', 'invocation_id': INVOCATION,
              'snapshot_source': snapshot['source_commit'], 'inputs_unchanged': len(snapshot['files']),
              'old_inputs_evidence_unchanged': True, 'external_runtime_unchanged': True,
              'observer_samples': len(rows), 'qemu_samples': 0, 'listener_samples': 0,
              'failure_location': 'os.setxattr after chmod0444 of first public helper',
              'summary': 'not created', 'proc_observations': 'not reached', 'exec_marker_scan': 'not reached',
              'cgroup_absent': True, 'uid999_absent': True, 'exit_recorder': exited, 'trusted_lifecycle': trusted,
              'dummy_transport_key': 'retained private pending result review; value/hash unread',
              'scope': 'pre-boot source failure plus sampled no-QEMU; no proc or VM acceptance evidence',
              'files': {str(path): {'sha256': base.sha(path), 'bytes': path.stat().st_size} for path in (log, observer, exited_path)}}
    Path('/tmp/tempest-proc-exposure-result-002.json').write_text(json.dumps(public, indent=2) + '\n')
    print('pre-VM failure preserved; inputs and old evidence unchanged; cleanup verified')


if __name__ == '__main__':
    main()
