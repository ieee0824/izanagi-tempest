#!/usr/bin/env python3
"""Prepare an M0 Packer derivation without modifying the upstream checkout."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--izanagi-source', type=Path, required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--iso', type=Path, required=True)
    parser.add_argument('--agent', type=Path, required=True)
    parser.add_argument('--ebpf', type=Path, required=True)
    parser.add_argument('--http', type=Path, required=True)
    parser.add_argument('--lws', type=Path, help='Pinned LWS binary for the root-only backend connection probe')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = args.izanagi_source.resolve()
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
    dirty = subprocess.check_output(['git', 'status', '--porcelain'], cwd=source, text=True)
    if commit != args.commit or dirty:
        parser.error('Upstream checkout must be clean and match --commit exactly')
    template = (source / 'packer/debian.pkr.hcl').read_text()
    expected_iso = re.search(r'default = "sha256:([0-9a-f]{64})"', template).group(1)
    if digest(args.iso) != expected_iso:
        parser.error('ISO digest does not match the pinned upstream template')
    assets = {name: path.resolve() for name, path in
              [('agent', args.agent), ('ebpf', args.ebpf), ('http', args.http)]}
    if args.lws:
        assets['lws'] = args.lws.resolve()
    manifest = {'izanagi_commit': commit, 'iso_sha256': expected_iso,
                'inputs': {name: {'path': str(path), 'sha256': digest(path)}
                           for name, path in assets.items()}}
    manifest['cargo_locks'] = {str(path.relative_to(source)): digest(path)
                              for path in source.glob('**/Cargo.lock')}
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    shutil.copytree(source / 'packer', output / 'packer')
    # Keep upstream installation, service and lock-down paths. Omit unrelated language managers.
    start = template.index('      # Homebrew (Linuxbrew)')
    end = template.index('      "chmod +x /usr/local/bin/izanagi-agent",', start)
    template = template[:start] + template[end:]
    template = template.replace('apt-get install -y curl git build-essential procps file',
                                'apt-get install -y curl python3 tcpdump iptables awscli procps file')
    template = template.replace('iso_url      = local.iso_url',
                                'iso_url      = ' + json.dumps(str(args.iso.resolve())))
    # Run M0 provisioning after the upstream setup and before its shutdown lock-down.
    position = template.rfind('\n}')
    if args.lws:
        addition = '\n  provisioner "file" {\n    source = ' + json.dumps(str(assets['lws'])) + '''
    destination = "/usr/local/bin/tempest-m0-lws"
  }
'''
        template = template[:position] + addition + template[position:]
        position = template.rfind('\n}')
    template = template[:position] + '''
  provisioner "file" {
    source = "${path.root}/m0-provision.sh"
    destination = "/tmp/tempest-m0-provision.sh"
  }
  provisioner "shell" {
    inline = ["sh /tmp/tempest-m0-provision.sh"]
  }
''' + template[position:]
    provision = Path(__file__).resolve().parent / 'image/provision.sh'
    shutil.copyfile(provision, output / 'packer/m0-provision.sh')
    manifest['provision_sha256'] = digest(provision)
    (output / 'packer/debian.pkr.hcl').write_text(template)
    (output / 'packer/m0.pkrvars.json').write_text(json.dumps({
        'agent_binary': str(assets['agent']), 'ebpf_binary': str(assets['ebpf']),
        'http_binary': str(assets['http'])}, indent=2) + '\n')
    manifest['template_sha256'] = hashlib.sha256(template.encode()).hexdigest()
    (output / 'inputs.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(output / 'packer')


if __name__ == '__main__':
    main()
