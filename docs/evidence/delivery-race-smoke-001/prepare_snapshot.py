"""Prepare one reviewed fixture smoke snapshot; does not start a VM."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import stat
import subprocess

REPO = Path('/home/ubuntu/izanagi-tempest')
ROOT = Path('/var/lib/tempest-izanagi-delivery-race-smoke-001')
BUILD = Path('/var/lib/tempest-izanagi-delivery-race-build-001')
IMAGE_SHA = '4c2a101c929547c422ce5f7709e4d52db69dbc2032bb7408fc4a4ce16aefe236'
SOURCES = ['integration/image_smoke.py', 'integration/image_smoke_observe.py',
           'integration/izanagi-bootstrap/observe.py', 'integration/izanagi-bootstrap/record_exit.py',
           'image/transport.py', 'image/trace_evidence.py', 'image/artifact_evidence.py',
           'image/exec_evidence.py', 'image/proc_evidence.py', 'image/proc_paging.py',
           'image/sidecar_probe.py', 'image/sidecar_evidence.py', 'image/network_evidence.py',
           'image/network_probe.py', 'tools/m0/izanagi.example.toml']


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    os.umask(0o077)
    assert os.geteuid() == 0 and not os.path.lexists(ROOT)
    pinned = json.loads((REPO / 'docs/LINUX_X86_DELIVERY_RACE_SMOKE_SOURCE_001.json').read_text())
    assert set(SOURCES) <= set(pinned['files'])
    for name, digest in pinned['files'].items():
        path = REPO / name
        assert not path.is_symlink() and sha(path) == digest
    assert subprocess.check_output(['id', '-u', 'tempest-kvm'], text=True).strip() == '999'
    assert subprocess.check_output(['id', '-g', 'tempest-kvm'], text=True).strip() == '988'
    assert subprocess.run(['pgrep', '-u', '999'], capture_output=True).returncode == 1
    state = subprocess.check_output(['systemctl', 'show', ROOT.name + '.service', '-p', 'LoadState', '-p', 'ActiveState', '-p', 'InvocationID'], text=True)
    assert 'LoadState=not-found' in state and 'ActiveState=inactive' in state and 'InvocationID=\n' in state
    assert not os.path.lexists('/tmp/tempest-delivery-race-smoke-001.log')
    assert not os.path.lexists('/tmp/tempest-delivery-race-smoke-observation-001.jsonl')
    assert shutil.disk_usage(ROOT.parent).free >= 12 * 1024**3
    previous = REPO / 'docs/evidence/host-endpoint-001/collect_result.py'
    code = previous.read_text().split("    output = ROOT / 'work/output'", 1)[0] + '\nmain()\n'
    exec(compile(code, str(previous), 'exec'), {'__name__': 'old_verification', '__file__': str(previous)})
    for document in ('LINUX_X86_HOST_ENDPOINT_001_RESULT.json', 'LINUX_X86_DELIVERY_RACE_BUILD_001_RESULT.json'):
        for path, metadata in json.loads((REPO / 'docs' / document).read_text())['files'].items():
            assert sha(path) == metadata['sha256']
    assert not os.path.lexists('/var/lib/tempest-izanagi-host-endpoint-001/work/output/izanagi-hmac')
    source_image = BUILD / 'work/output-debian/debian-x86_64.qcow2'
    assert sha(source_image) == IMAGE_SHA
    native = REPO / 'docs/LINUX_X86_DELIVERY_RACE_NATIVE_ARTIFACTS_001.json'
    assert sha(native) == sha(BUILD / 'work/offline-proof/native-report.json')
    manifest = BUILD / 'inputs/definition/inputs.json'
    assert json.loads(manifest.read_text())['delivery_race_fixture'] is True
    for repository, revision in (('/tmp/tempest-izanagi-upstream-review', '16d0b55947006a166cfa29dcb8bfe71f65f8c36a'), ('/tmp/tempest-lws-upstream-review', '2c0ea463f334f10a562e54f1cdc7ba8a474029e2')):
        assert subprocess.check_output(['git', '-C', repository, 'rev-parse', 'HEAD'], text=True).strip() == revision
        assert not subprocess.check_output(['git', '-C', repository, 'status', '--porcelain'])
    kvm = Path('/dev/kvm').stat()
    assert stat.S_ISCHR(kvm.st_mode) and (kvm.st_uid, kvm.st_gid, stat.S_IMODE(kvm.st_mode), os.major(kvm.st_rdev), os.minor(kvm.st_rdev)) == (0, 993, 0o660, 10, 232)
    ROOT.mkdir(mode=0o750)
    os.chown(ROOT, 0, 988)
    ROOT.chmod(0o750)
    inputs, work = ROOT / 'inputs', ROOT / 'work'
    inputs.mkdir(mode=0o750)
    os.chown(inputs, 0, 988)
    inputs.chmod(0o750)
    work.mkdir(mode=0o700)
    os.chown(work, 999, 988)
    for name in ('home', 'tmp', 'evidence'):
        path = work / name
        path.mkdir(mode=0o700)
        os.chown(path, 999, 988)
    shutil.copyfile(source_image, inputs / 'image.qcow2')
    cli = Path('/tmp/tempest-izanagi-bootstrap-host-target/release/izanagi')
    assert sha(cli) == '088a5ca1fcf6f78501fabb329ff41a6318935e4971d86ef23e98626df5c3b0f8'
    shutil.copyfile(cli, inputs / 'izanagi')
    (inputs / 'izanagi').chmod(0o550)
    shutil.copyfile(manifest, inputs / 'build-inputs.json')
    shutil.copyfile(native, inputs / 'offline-artifacts.json')
    for name in SOURCES:
        target = inputs / 'repo' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / name, target)
    recorder = (REPO / 'integration/izanagi-bootstrap/record_exit.py').read_text().replace('tempest-izanagi-bootstrap-boot-002.service', ROOT.name + '.service').replace('/run/tempest-izanagi-bootstrap-002/evidence/exit-status.json', str(work / 'evidence/exit-status.json'))
    (inputs / 'record_exit.py').write_text(recorder)
    wheels = json.loads((REPO / 'docs/LINUX_X86_PYTHON_WHEELS.json').read_text())
    wheelhouse = inputs / 'wheelhouse'
    wheelhouse.mkdir()
    for row in wheels['wheels']:
        source = Path('/tmp/tempest-x86-full-python-002/wheelhouse') / row['filename']
        assert not source.is_symlink() and sha(source) == row['sha256']
        shutil.copyfile(source, wheelhouse / source.name)
    shutil.copyfile(REPO / 'docs/locks/python-x86-full-002.txt', inputs / 'requirements.lock')
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'PIP_CONFIG_FILE': '/dev/null', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
    with (ROOT / 'venv-install.log').open('xb') as log:
        subprocess.run(['/usr/bin/python3', '-I', '-B', '-m', 'venv', str(inputs / 'python')], env=env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=120)
        subprocess.run([str(inputs / 'python/bin/python'), '-I', '-B', '-m', 'pip', '--disable-pip-version-check', '--no-cache-dir', 'install', '--no-index', '--find-links', str(wheelhouse), '--only-binary=:all:', '--require-hashes', '--requirement', str(inputs / 'requirements.lock')], env=env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=120)
    rows, directories = [], [str(ROOT), str(inputs)]
    for path in sorted(inputs.rglob('*')):
        if path.is_symlink():
            assert path.resolve().is_relative_to(inputs) or path.resolve() == Path('/usr/bin/python3.12')
            os.lchown(path, 0, 988)
            rows.append({'path': str(path), 'type': 'symlink', 'target': os.readlink(path), 'owner': 'root:tempest-kvm'})
            continue
        os.chown(path, 0, 988)
        if path.is_dir():
            path.chmod(0o750)
            directories.append(str(path))
            continue
        path.chmod(0o550 if path.stat().st_mode & 0o111 else 0o440)
        rows.append({'path': str(path), 'type': 'file', 'sha256': sha(path), 'mode': format(stat.S_IMODE(path.stat().st_mode), '04o'), 'owner': 'root:tempest-kvm'})
    assert sha(inputs / 'image.qcow2') == IMAGE_SHA
    assert shutil.disk_usage(ROOT).free >= 10 * 1024**3
    external = {name: sha(name) for name in ('/usr/bin/python3.12', '/usr/bin/qemu-system-x86_64', '/usr/bin/qemu-img', '/usr/bin/tcpdump', '/usr/bin/ss', '/usr/bin/systemctl', '/lib64/ld-linux-x86-64.so.2', '/lib/x86_64-linux-gnu/libc.so.6', '/lib/x86_64-linux-gnu/libgcc_s.so.1')}
    meta = {'schema_version': 1, 'source_commit': subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], text=True).strip(),
            'unit': ROOT.name + '.service', 'root': str(ROOT), 'files': rows, 'directories_mode0750_root_group': directories,
            'external_runtime_sha256': external, 'wheel_versions_hashes': wheels['wheels'], 'old_build_inputs_and_evidence_unchanged': True,
            'input_rows_sha256': hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'vm_boot_executed': False, 'free_bytes_after_copy': shutil.disk_usage(ROOT).free,
            'dummy_transport_key': 'not created; fresh per-run key generated by smoke output'}
    with (ROOT / 'snapshot.json').open('x') as stream:
        json.dump(meta, stream, indent=2)
        stream.write('\n')
    os.chown(ROOT / 'snapshot.json', 0, 988)
    (ROOT / 'snapshot.json').chmod(0o440)
    print(json.dumps({'snapshot_created': True, 'files': len(rows), 'tree': meta['input_rows_sha256'], 'vm_boot_executed': False}))


if __name__ == '__main__':
    main()
