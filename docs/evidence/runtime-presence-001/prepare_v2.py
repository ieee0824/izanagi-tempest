"""Add precommitted presence slots and updated code without changing v1 inputs."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import stat
import subprocess

ROOT = Path('/var/lib/tempest-izanagi-runtime-presence-001')
REPO = Path('/home/ubuntu/izanagi-tempest')


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    assert os.geteuid() == 0
    os.umask(0o077)
    assert not os.path.lexists(ROOT / 'work/runs')
    snapshot = json.loads((ROOT / 'snapshot.json').read_text())
    for row in snapshot['files']:
        path = Path(row['path'])
        if row['type'] == 'file':
            assert sha(path) == row['sha256']
        else:
            assert os.readlink(path) == row['target']
    extra = ROOT / 'inputs-v2'
    assert not os.path.lexists(extra)
    extra.mkdir(mode=0o750)
    extra.chmod(0o750)
    os.chown(extra, 0, 988)
    for name in ('integration/runtime_presence.py', 'integration/mock-s3-overread.json',
                 'scenarios/s3-overread-001.yaml', 'image/host_bridge.py', 'image/transport.py'):
        source = REPO / name
        assert source.is_file() and not source.is_symlink()
        dest = extra / 'repo' / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, dest)
    for source, name in [('run_presence.py', 'run_presence.py'), ('run_once_v2.py', 'run_once.py'),
                         ('create_plan.py', 'create_plan.py')]:
        shutil.copyfile(REPO / 'docs/evidence/runtime-presence-001' / source, extra / name)
    command = ['/usr/bin/python3', '-I', '-B', str(extra / 'create_plan.py')]
    completed = subprocess.run(command, capture_output=True, text=True, check=True, timeout=60)
    creation = json.loads(completed.stdout)
    (ROOT / 'plan-creation.private.log').write_text(completed.stdout + completed.stderr)
    rows = list(snapshot['files'])
    directories = list(snapshot['directories_mode0750_root_group'])
    for path in [extra, *sorted(extra.rglob('*'))]:
        assert not path.is_symlink()
        os.chown(path, 0, 988)
        if path.is_dir():
            path.chmod(0o750)
            directories.append(str(path))
        else:
            path.chmod(0o440)
            rows.append({'path': str(path), 'type': 'file', 'sha256': sha(path), 'mode': '0440', 'owner': 'root:tempest-kvm'})
    plan = json.loads((extra / 'comparison-plan.json').read_text())
    assert len(plan['slots']) == 4 and creation['plan_sha256'] == sha(extra / 'comparison-plan.json')
    revised = {**snapshot, 'preparation_version': 2,
               'v1_source_commit': snapshot['source_commit'],
               'source_commit': subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], text=True).strip(),
               'files': rows, 'directories_mode0750_root_group': directories,
               'input_rows_sha256': hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
               'plan_creation': creation, 'plan_creation_argv': command,
               'v1_inputs_preserved': True, 'run_script': str(extra / 'run_presence.py')}
    path = ROOT / 'snapshot-v2.json'
    with path.open('x') as stream:
        stream.write(json.dumps(revised, indent=2) + '\n')
    os.chown(path, 0, 988)
    path.chmod(0o440)
    Path('/tmp/tempest-runtime-presence-snapshot-001-v2.json').write_text(json.dumps(revised, indent=2) + '\n')
    print(json.dumps({'input_files': len(rows), 'v1_inputs_preserved': True,
                      'input_rows_sha256': revised['input_rows_sha256'], 'plan_creation': creation}))


if __name__ == '__main__':
    main()
