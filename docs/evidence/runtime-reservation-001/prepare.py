"""Create a new immutable standard-library-only reservation check environment."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess

ROOT = Path('/var/lib/tempest-izanagi-runtime-reservation-001')
OLD = Path('/var/lib/tempest-izanagi-runtime-seed-loss-001')
REPO = Path('/home/ubuntu/izanagi-tempest')


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    assert os.geteuid() == 0 and not os.path.lexists(ROOT)
    os.umask(0o077)
    for path in (OLD / 'work/runs', OLD / 'work/runs/seed-reply-loss'):
        metadata = path.lstat()
        assert stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 999 and metadata.st_gid == 988
        assert stat.S_IMODE(metadata.st_mode) == 0o700
    old_snapshot = json.loads((OLD / 'snapshot.json').read_text())
    for row in old_snapshot['files']:
        path = Path(row['path'])
        if row['type'] == 'file':
            assert sha(path) == row['sha256']
            assert (path.stat().st_uid, path.stat().st_gid, stat.S_IMODE(path.stat().st_mode)) == (0, 988, int(row['mode'], 8))
        else:
            assert path.is_symlink() and os.readlink(path) == row['target']
    for path, digest in old_snapshot['external_runtime_sha256'].items():
        assert sha(path) == digest
    assert sha(OLD / 'inputs/tempest') == '4354c40b7fba68ec03e4cbb8cd1407ce3ba7566816801b69dec09d85a984dc6f'
    ROOT.mkdir(mode=0o750)
    os.chown(ROOT, 0, 988)
    ROOT.chmod(0o750)
    inputs = ROOT / 'inputs'
    inputs.mkdir(mode=0o750)
    os.chown(inputs, 0, 988)
    inputs.chmod(0o750)
    work = ROOT / 'work'
    work.mkdir(mode=0o700)
    os.chown(work, 999, 988)
    for name in ('home', 'tmp', 'evidence'):
        path = work / name
        path.mkdir(mode=0o700)
        os.chown(path, 999, 988)
    sources = {name: REPO / 'docs/evidence/runtime-reservation-001' / name
               for name in ('check_once.py', 'tree_manifest.py', 'observe.py', 'run_once.py')}
    sources.update({'runtime_faults.py': REPO / 'integration/runtime_faults.py',
                    'bootstrap_observe.py': REPO / 'integration/izanagi-bootstrap/observe.py'})
    for name, source in sources.items():
        assert source.is_file() and not source.is_symlink()
        shutil.copyfile(source, inputs / name)
    recorder = (REPO / 'integration/izanagi-bootstrap/record_exit.py').read_text()
    recorder = recorder.replace('tempest-izanagi-bootstrap-boot-002.service', 'tempest-izanagi-runtime-reservation-001.service')
    recorder = recorder.replace('/run/tempest-izanagi-bootstrap-002/evidence/exit-status.json', str(work / 'evidence/exit-status.json'))
    (inputs / 'record_exit.py').write_text(recorder)
    rows = []
    for path in sorted(inputs.iterdir()):
        path.chmod(0o440)
        os.chown(path, 0, 988)
        rows.append({'path': str(path), 'sha256': sha(path), 'uid': 0, 'gid': 988, 'mode': '0440'})
    spec = importlib.util.spec_from_file_location('tree', inputs / 'tree_manifest.py')
    tree = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tree)
    baseline = tree.inventory(OLD)
    (ROOT / 'baseline.private.json').write_text(json.dumps(baseline, sort_keys=True) + '\n')
    public = {'source_commit': subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], text=True).strip(),
              'root': str(ROOT), 'unit': 'tempest-izanagi-runtime-reservation-001.service', 'files': rows,
              'external_runtime_sha256': old_snapshot['external_runtime_sha256'],
              'old_tree_sha256': baseline['sha256'], 'old_tree_entries': baseline['entries'],
              'baseline_file_sha256': sha(ROOT / 'baseline.private.json'),
              'existing_runs_and_run_owned_0700': True, 'old_inputs_verified': True,
              'vm_executed': False, 'reservation_cli_executed': False, 'free_bytes': shutil.disk_usage(ROOT).free}
    (ROOT / 'snapshot.json').write_text(json.dumps(public, indent=2) + '\n')
    (ROOT / 'snapshot.json').chmod(0o440)
    os.chown(ROOT / 'snapshot.json', 0, 988)
    Path('/tmp/tempest-runtime-reservation-preparation-001.json').write_text(json.dumps(public, indent=2) + '\n')
    print(json.dumps({'input_files': len(rows), 'baseline_entries': baseline['entries'], 'baseline_tree_sha256': baseline['sha256']}))


if __name__ == '__main__':
    main()
