#!/usr/bin/env python3
"""Derive pinned upstream Debian Packer configuration without modifying upstream."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tomllib

IZANAGI = '16d0b55947006a166cfa29dcb8bfe71f65f8c36a'
LWS = '2c0ea463f334f10a562e54f1cdc7ba8a474029e2'
ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def source_commit(path, expected):
    actual = subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()
    dirty = subprocess.check_output(['git', '-C', str(path), 'status', '--porcelain'], text=True)
    if actual != expected or dirty:
        raise ValueError('upstream checkout must be clean and match the pinned commit')
    return actual


def linux_elf(path, machine=183):
    with path.open('rb') as stream:
        header = stream.read(20)
    if len(header) < 20 or header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != machine:
        raise ValueError(f'expected little-endian ELF64 machine={machine}: {path.name}')


def helper_source():
    paths = subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '-z',
                                     'Cargo.toml', 'Cargo.lock', 'crates'], text=True).split('\0')
    digest = hashlib.sha256()
    for name in sorted(filter(None, paths)):
        digest.update(name.encode() + b'\0' + (ROOT / name).read_bytes() + b'\0')
    dirty = subprocess.check_output(['git', '-C', str(ROOT), 'status', '--porcelain', '--',
                                     'Cargo.toml', 'Cargo.lock', 'crates'], text=True)
    return {'tempest_guest_source_tree_sha256': digest.hexdigest(),
            'tempest_guest_source_dirty': bool(dirty)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['izanagi-source', 'lws-source', 'iso', 'agent', 'ebpf', 'http', 'lws', 'guest', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        source = args.izanagi_source.resolve()
        source_commit(source, IZANAGI)
        source_commit(args.lws_source.resolve(), LWS)
        template = (source / 'packer/debian.pkr.hcl').read_text()
        iso_hash = re.search(r'default = "sha256:([0-9a-f]{64})"', template).group(1)
        if sha(args.iso) != iso_hash:
            raise ValueError('ISO does not match pinned upstream SHA-256')
        assets = {name: getattr(args, name).resolve() for name in ['agent', 'ebpf', 'http', 'lws', 'guest']}
        for name, path in assets.items():
            linux_elf(path, 247 if name == 'ebpf' else 183)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    shutil.copytree(source / 'packer', output / 'packer')
    start = template.index('      # Homebrew (Linuxbrew)')
    end = template.index('      "chmod +x /usr/local/bin/izanagi-agent",', start)
    template = template[:start] + template[end:]
    template = template.replace('apt-get install -y curl git build-essential procps file',
                                'apt-get install -y curl python3 python3-cryptography tcpdump iptables awscli opendoas procps file ca-certificates')
    template = template.replace('iso_url      = local.iso_url', 'iso_url      = ' + json.dumps(str(args.iso.resolve())))
    own = Path(__file__).resolve().parent
    metadata = {**helper_source(), 'schema_version': 1, 'izanagi_commit': IZANAGI, 'lws_commit': LWS,
                'tempest_guest_version': tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']['version'],
                'tempest_guest_source_commit': subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
                'built_at': datetime.now(timezone.utc).isoformat(),
                'iso_sha256': iso_hash, 'input_sha256': {name: sha(path) for name, path in assets.items()},
                'derivation_sha256': {name: sha(own / name) for name in ['prepare.py', 'provision.sh', 'dispatcher.py', 'quiesce.py']}}
    (output / 'packer/image.json').write_text(json.dumps(metadata, indent=2) + '\n')
    for name in ['provision.sh', 'dispatcher.py', 'quiesce.py']:
        shutil.copyfile(own / name, output / 'packer' / name)
    extra = '\n  provisioner "shell" { inline = ["install -d -m 0700 /tmp/tempest-m3"] }\n'
    for path, destination in [(assets['lws'], 'lws'), (assets['guest'], 'tempest-guest'),
                              ('${path.root}/dispatcher.py', 'dispatcher.py'), ('${path.root}/image.json', 'image.json'),
                              ('${path.root}/provision.sh', 'provision.sh'), ('${path.root}/quiesce.py', 'quiesce.py')]:
        extra += '  provisioner "file" {\n    source = ' + json.dumps(str(path)) + '\n    destination = ' + json.dumps('/tmp/tempest-m3/' + destination) + '\n  }\n'
    extra += '  provisioner "shell" { inline = ["sh /tmp/tempest-m3/provision.sh"] }\n'
    position = template.rfind('\n}')
    template = template[:position] + extra + template[position:]
    (output / 'packer/debian.pkr.hcl').write_text(template)
    (output / 'packer/tempest.pkrvars.json').write_text(json.dumps({
        'agent_binary': str(assets['agent']), 'ebpf_binary': str(assets['ebpf']), 'http_binary': str(assets['http'])}, indent=2) + '\n')
    (output / 'inputs.json').write_text(json.dumps({**metadata, 'inputs': {name: str(path) for name, path in assets.items()},
                                                 'template_sha256': hashlib.sha256(template.encode()).hexdigest()}, indent=2) + '\n')
    print(output / 'packer')


if __name__ == '__main__':
    main()
