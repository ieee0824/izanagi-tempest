"""Select no-VM reservation proof while preserving the historical failed trial."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
from types import SimpleNamespace

ROOT = Path('/var/lib/tempest-izanagi-runtime-reservation-001')
OLD = Path('/var/lib/tempest-izanagi-runtime-seed-loss-001')
INVOCATION = '67f4f9378e49423fb349662d5ec35326'
BOOT = '30389abc903c40ae89a5c6268ec1c432'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    os.umask(0o077)
    tree = module('tree', ROOT / 'inputs/tree_manifest.py')
    baseline = json.loads((ROOT / 'baseline.private.json').read_text())
    after = tree.inventory(OLD)
    assert after == baseline
    (ROOT / 'after.private.json').write_text(json.dumps(after, sort_keys=True) + '\n')
    snapshot = json.loads((ROOT / 'snapshot-v2.json').read_text())
    for row in snapshot['files']:
        path = Path(row['path'])
        assert sha(path) == row['sha256']
        metadata = path.stat()
        assert (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) == (0, 988, 0o440)
    for path, digest in snapshot['external_runtime_sha256'].items():
        assert sha(path) == digest
    stdout_path = ROOT / 'work/evidence/retry.stdout'
    stderr_path = ROOT / 'work/evidence/retry.stderr'
    faults = module('faults', ROOT / 'inputs/runtime_faults.py')
    witness = faults.reservation_refusal(SimpleNamespace(returncode=1, stdout=stdout_path.read_text(), stderr=stderr_path.read_text()))
    assert witness == json.loads((ROOT / 'work/evidence/reservation.json').read_text())
    exited = json.loads((ROOT / 'work/evidence/exit-status.json').read_text())
    assert exited['invocation_id'] == INVOCATION and exited['exit_status'] == '0' and exited['service_result'] == 'success'
    rows = [json.loads(line) for line in (ROOT / 'observation.jsonl').read_text().splitlines()]
    assert rows and all(not row['host_qemu_pids'] and not row['sample']['qemu_network'] for row in rows)
    observer = module('observer', ROOT / 'inputs/observe_v2.py')
    assert not observer.qemu_pids()
    assert not subprocess.run(['ps', '-u', '999', '-o', 'pid='], capture_output=True, text=True).stdout.strip()
    assert not Path('/sys/fs/cgroup/system.slice/tempest-izanagi-runtime-reservation-001.service').exists()
    journal = subprocess.check_output(['/usr/bin/journalctl', '-u', 'tempest-izanagi-runtime-reservation-001.service', '-o', 'json', '--no-pager'], text=True)
    (ROOT / 'journal.private.jsonl').write_text(journal)
    trusted = []
    for line in journal.splitlines():
        row = json.loads(line)
        if row.get('_PID') == '1' and row.get('_UID') == '0' and row.get('_BOOT_ID') == BOOT and row.get('INVOCATION_ID') == INVOCATION and row.get('UNIT') == 'tempest-izanagi-runtime-reservation-001.service':
            trusted.append({key: row.get(key) for key in ('UNIT', 'MESSAGE_ID', '__REALTIME_TIMESTAMP', '_BOOT_ID', '_PID', '_UID', 'INVOCATION_ID')})
    required_lifecycle = {'7d4958e842da4a758f6c1cdc7b36dcc5', '39f53479d3a045ac8e11786248231fbf', '7ad2d189f7e94e70a38c781354912448'}
    assert required_lifecycle <= {row['MESSAGE_ID'] for row in trusted}
    source = Path('/tmp/tempest-host-cli-build-001/source/crates/tempest/src/run_cli.rs')
    text = source.read_text()
    assert text.index('SeedController::create(&runs, &options.id') < text.index('result=Vm::boot(', text.index('async fn execute('))
    files = {str(path): {'sha256': sha(path), 'bytes': path.stat().st_size} for path in
             (stdout_path, stderr_path, ROOT / 'work/evidence/reservation.json', ROOT / 'work/evidence/exit-status.json',
              ROOT / 'observation.jsonl', Path('/tmp/tempest-runtime-reservation-001.log'))}
    public = {'status': 'reservation_refusal_established_separately', 'historical_seed_loss_trial': 'still failed; not retroactively changed',
              'cli_returncode': 1, 'check_caller_exit': 0, 'observer_exit': 1,
              'observer_terminal': 'unknown after unit GC; not treated as success', 'witness': witness,
              'unit': 'tempest-izanagi-runtime-reservation-001.service', 'invocation_id': INVOCATION, 'host_boot_id': BOOT,
              'old_full_tree_before_sha256': baseline['sha256'], 'old_full_tree_after_sha256': after['sha256'],
              'old_full_tree_entries': after['entries'], 'old_full_tree_unchanged': True, 'input_files_unchanged': len(snapshot['files']),
              'external_runtime_unchanged': True, 'samples': len(rows), 'qemu_observed': False, 'qemu_absent_after': True,
              'sampling_scope': 'sampled non-observation; not a proof of absence between samples',
              'source_order': {'path': str(source), 'sha256': sha(source), 'exclusive_reservation_precedes_vm_boot': True},
              'exit_recorder': exited, 'trusted_lifecycle': trusted, 'cgroup_absent': True, 'uid999_absent': True, 'files': files}
    Path('/tmp/tempest-runtime-reservation-result-001.json').write_text(json.dumps(public, indent=2) + '\n')
    print('reservation witness and unchanged1537-entry old tree verified; private streams retained')


if __name__ == '__main__':
    main()
