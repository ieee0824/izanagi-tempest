"""Read the finished fixture image without mounting, booting, or executing its files."""
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys

ROOT = Path('/var/lib/tempest-izanagi-delivery-race-build-001')


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(argv):
    result = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=180)
    return result.stdout


def main():
    os.umask(0o077)
    assert os.getuid() == 999
    expected_sha = sys.argv[1]
    assert re.fullmatch('[0-9a-f]{64}', expected_sha)
    image = ROOT / 'work/output-debian/debian-x86_64.qcow2'
    assert sha(image) == expected_sha
    assert shutil.disk_usage(ROOT).free >= 12 * 1024**3
    work = ROOT / 'work/offline-proof'
    work.mkdir(mode=0o700)
    raw = work / 'disk.raw'
    commands = [['/usr/bin/qemu-img', 'convert', '-f', 'qcow2', '-O', 'raw', str(image), str(raw)]]
    run(commands[-1])
    assert raw.stat().st_size == 4294967296
    commands.append(['/usr/sbin/sfdisk', '--json', str(raw)])
    table = json.loads(run(commands[-1]))
    (work / 'partition-table.json').write_text(json.dumps(table, indent=2) + '\n')
    t = table['partitiontable']
    assert t['label'] == 'dos' and t['unit'] == 'sectors' and t['sectorsize'] == 512
    parts = t['partitions']
    assert len({p['node'] for p in parts}) == len(parts)
    containers = [p for p in parts if p['type'].lower() in ('5', '05', 'f', '0f', '85')]
    data = [p for p in parts if p not in containers]
    for p in parts:
        assert p['start'] >= 0 and p['size'] > 0 and (p['start'] + p['size']) * 512 <= raw.stat().st_size
    spans = sorted((p['start'], p['start'] + p['size']) for p in data)
    assert all(a[1] <= b[0] for a, b in zip(spans, spans[1:]))
    for p in data:
        assert p['node'].startswith(t['device'])
        if int(p['node'][len(t['device']):]) > 4:
            assert sum(c['start'] <= p['start'] and p['start'] + p['size'] <= c['start'] + c['size'] for c in containers) == 1
    candidates = []
    with raw.open('rb') as stream:
        for p in data:
            stream.seek(p['start'] * 512 + 1024 + 56)
            if stream.read(2) == b'\x53\xef':
                candidates.append(p)
        assert len(candidates) == 1
        selected = candidates[0]
        stream.seek(selected['start'] * 512)
        remaining = selected['size'] * 512
        partition = work / 'root.partition'
        with partition.open('xb') as dest:
            while remaining:
                chunk = stream.read(min(16 * 1024**2, remaining))
                assert chunk
                assert dest.write(chunk) == len(chunk)
                remaining -= len(chunk)
    metadata = json.loads((ROOT / 'inputs/definition/packer/image.json').read_text())
    paths = {'image_metadata': '/etc/tempest/image.json', 'dispatcher': '/usr/local/bin/tempest-guest',
             'mailbox': '/usr/local/libexec/tempest-mailbox', 'quiesce': '/usr/local/libexec/tempest-quiesce',
             'guest': '/usr/local/libexec/tempest-guest-native', 'lws': '/usr/local/bin/lws'}
    results = {}
    for name, guest in paths.items():
        commands.append(['/usr/sbin/debugfs', '-R', 'stat ' + guest, str(partition)])
        output = run(commands[-1])
        (work / (name + '.stat.txt')).write_text(output)
        kind = re.search(r'Type:\s*(\w+)', output)
        mode = re.search(r'Mode:\s*([0-7]+)', output)
        uid = re.search(r'User:\s*(\d+)', output)
        gid = re.search(r'Group:\s*(\d+)', output)
        size = re.search(r'\bSize:\s*(\d+)', output)
        assert kind and kind[1] == 'regular' and mode and uid and gid and size
        assert uid[1] == gid[1] == '0' and 0 < int(size[1]) < 128 * 1024**2
        dest = work / name
        assert not dest.exists()
        commands.append(['/usr/sbin/debugfs', '-R', 'dump ' + guest + ' ' + str(dest), str(partition)])
        run(commands[-1])
        s = dest.lstat()
        assert stat.S_ISREG(s.st_mode) and s.st_size == int(size[1]) and not s.st_mode & 0o111
        digest = sha(dest)
        expected = metadata['derivation_sha256']['dispatcher.py' if name in ('dispatcher', 'mailbox') else 'quiesce.py'] if name in ('dispatcher', 'mailbox', 'quiesce') else metadata['input_sha256'].get(name)
        if expected is not None:
            assert digest == expected
        assert int(mode[1], 8) == (0o644 if name == 'image_metadata' else 0o755)
        results[name] = {'guest_path': guest, 'guest_mode': mode[1], 'guest_uid': 0, 'guest_gid': 0, 'bytes': s.st_size, 'sha256': digest}
    actual = json.loads((work / 'image_metadata').read_text())
    assert actual['delivery_race_fixture'] is True
    assert all(actual[key] == value for key, value in metadata.items())
    assert all(actual['installed_sha256'][paths[name]] == results[name]['sha256'] for name in paths if name != 'image_metadata')
    assert sha(image) == expected_sha
    report = {'source_image': str(image), 'source_image_sha256_before': expected_sha,
              'source_image_sha256_after': expected_sha, 'raw_bytes': raw.stat().st_size,
              'raw_sha256': sha(raw), 'partition': selected, 'partition_sha256': sha(partition),
              'data_partitions_nonoverlapping': True, 'extended_logical_containment_verified': True,
              'commands': commands, 'artifacts': results, 'installed_manifest': actual,
              'fixture_manifest_and_installed_scripts_match': True,
              'mounted': False, 'debugfs_write_flag_used': False, 'vm_boot_executed': False,
              'extracted_files_executed': False, 'runtime_race_test_executed': False}
    (work / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'fixture_install_verified': True, 'artifacts': results, 'source_image_unchanged': True}))


if __name__ == '__main__':
    main()
