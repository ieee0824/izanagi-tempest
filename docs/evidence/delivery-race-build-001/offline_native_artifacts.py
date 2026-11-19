"""Extend the saved read-only partition proof with the runtime's three native artifacts."""
from pathlib import Path
import hashlib
import json
import os
import re
import stat
import subprocess

ROOT = Path('/var/lib/tempest-izanagi-delivery-race-build-001')


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    os.umask(0o077)
    assert os.getuid() == 999
    work = ROOT / 'work/offline-proof'
    previous = json.loads((work / 'report.json').read_text())
    image = Path(previous['source_image'])
    assert image == ROOT / 'work/output-debian/debian-x86_64.qcow2'
    expected_sha = '4c2a101c929547c422ce5f7709e4d52db69dbc2032bb7408fc4a4ce16aefe236'
    assert previous['source_image_sha256_before'] == previous['source_image_sha256_after'] == expected_sha
    assert sha(image) == expected_sha
    partition = work / 'root.partition'
    assert sha(partition) == previous['partition_sha256']
    inputs = json.loads((ROOT / 'inputs/definition/inputs.json').read_text())
    paths = {'agent': '/usr/local/bin/izanagi-agent', 'http': '/usr/local/bin/izanagi-http-capture', 'ebpf': '/opt/izanagi/izanagi-ebpf.o'}
    modes = {'agent': '0551', 'http': '0755', 'ebpf': '0440'}
    artifacts = {}
    commands = []
    for name, guest in paths.items():
        dest = work / ('native-' + name)
        assert not os.path.lexists(dest)
        commands.append(['/usr/sbin/debugfs', '-R', 'stat ' + guest, str(partition)])
        result = subprocess.run(commands[-1], capture_output=True, text=True, check=True, timeout=30)
        with (work / ('native-' + name + '.stat.txt')).open('x') as stream:
            stream.write(result.stdout)
        output = result.stdout
        kind = re.search(r'Type:\s*(\w+)', output)
        mode = re.search(r'Mode:\s*([0-7]+)', output)
        uid = re.search(r'User:\s*(\d+)', output)
        gid = re.search(r'Group:\s*(\d+)', output)
        size = re.search(r'\bSize:\s*(\d+)', output)
        assert kind and kind[1] == 'regular' and mode and mode[1] == modes[name]
        assert uid and gid and uid[1] == gid[1] == '0' and size and 0 < int(size[1]) < 128 * 1024**2
        commands.append(['/usr/sbin/debugfs', '-R', 'dump ' + guest + ' ' + str(dest), str(partition)])
        subprocess.run(commands[-1], capture_output=True, text=True, check=True, timeout=30)
        s = dest.lstat()
        assert stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_size == int(size[1]) and not s.st_mode & 0o111
        digest = sha(dest)
        assert digest == inputs['input_sha256'][name]
        with dest.open('rb') as stream:
            header = stream.read(20)
        assert header[:6] == b'\x7fELF\x02\x01'
        machine = int.from_bytes(header[18:20], 'little')
        assert machine == (247 if name == 'ebpf' else 62)
        artifacts[name] = {'guest_path': guest, 'guest_uid': 0, 'guest_gid': 0, 'guest_mode': mode[1], 'bytes': s.st_size, 'sha256': digest, 'elf_machine': machine}
    assert sha(image) == expected_sha and sha(partition) == previous['partition_sha256']
    report = {'schema_version': 1, 'source_image': str(image), 'source_image_sha256_before': expected_sha,
              'source_image_sha256_after': expected_sha, 'partition_sha256': previous['partition_sha256'],
              'prior_fixture_report_sha256': sha(work / 'report.json'), 'artifacts': artifacts,
              'commands': commands, 'debugfs_write_flag_used': False, 'vm_boot_executed': False,
              'mounted': False, 'extracted_files_executed': False}
    with (work / 'native-report.json').open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'source_image_unchanged': True, 'native_artifacts_verified': artifacts}))


if __name__ == '__main__':
    main()
