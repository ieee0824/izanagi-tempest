import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'image' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def fixture_module():
    result = module('x86_template')
    # Only tests substitute the sanitized fixture digest; production continues
    # to require the exact pinned upstream template digest.
    result.TEMPLATE_SHA256 = hashlib.sha256(
        (ROOT / 'tests/fixtures/izanagi-16d-debian.pkr.hcl').read_bytes()).hexdigest()
    return result


class X86ImageTests(unittest.TestCase):
    def test_prepare_wires_x86_elf_template_and_manifest(self):
        self.prepare_architecture('x86_64')

    def test_prepare_default_remains_arm64(self):
        self.prepare_architecture('aarch64')

    def test_fixed_receiver_provisioning_is_explicit_in_image_metadata(self):
        self.prepare_architecture('x86_64', fixed_receiver=True)

    def prepare_architecture(self, architecture, fixed_receiver=False):
        prepare = module('prepare')
        x86 = fixture_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            packer = source / 'packer'
            packer.mkdir(parents=True)
            (packer / 'http').mkdir()
            (packer / 'debian.pkr.hcl').write_bytes(
                (ROOT / 'tests/fixtures/izanagi-16d-debian.pkr.hcl').read_bytes())
            iso = root / 'fixture.iso'
            iso.write_bytes(b'fixture ISO; no VM is started')
            args = ['prepare', '--izanagi-source', str(source),
                    '--lws-source', str(source), '--iso', str(iso), '--output', str(root / 'out')]
            if architecture == 'x86_64':
                args += ['--architecture', architecture]
            if fixed_receiver:
                args += ['--fixed-vm-receiver-fixture']
            iso_hash = x86.ISO_SHA256 if architecture == 'x86_64' else '6e93fa1759bd9d4b0fc11e938987de6967ee7de5297dac1be27c3a75cc17024b'
            machine = 62 if architecture == 'x86_64' else 183
            for name in ['agent', 'ebpf', 'http', 'lws', 'guest']:
                path = root / name
                header = bytearray(20)
                header[:6] = b'\x7fELF\x02\x01'
                header[18:20] = (247 if name == 'ebpf' else machine).to_bytes(2, 'little')
                path.write_bytes(header)
                args += ['--' + name, str(path)]
            real_sha = prepare.sha
            with patch('sys.argv', args), patch.dict('sys.modules', {'x86_template': x86}), \
                 patch.object(prepare, 'source_commit'), \
                 patch.object(prepare, 'helper_source', return_value={}), \
                 patch.object(prepare, 'sha', side_effect=lambda p: iso_hash if p == iso else real_sha(p)):
                prepare.main()
            manifest = json.loads((root / 'out/inputs.json').read_text())
            guest_metadata = json.loads((root / 'out/packer/image.json').read_text())
            for metadata in (manifest, guest_metadata):
                if fixed_receiver:
                    self.assertIs(metadata['fixed_vm_receiver_fixture'], True)
                else:
                    self.assertNotIn('fixed_vm_receiver_fixture', metadata)
            self.assertEqual(manifest['architecture'], architecture)
            self.assertEqual(manifest['iso_sha256'], iso_hash)
            self.assertEqual('x86_template.py' in manifest['derivation_sha256'], architecture == 'x86_64')
            template = (root / 'out/packer/debian.pkr.hcl').read_text()
            self.assertIn('vm_name          = "debian-' + architecture + '.qcow2"', template)
            self.assertIn('boot_wait         = "' + ('10s' if architecture == 'x86_64' else '60s') + '"', template)
            self.assertIn('tempest-m3/provision.sh', template)
            self.assertNotIn('Homebrew (Linuxbrew)', template)
            self.assertIn(str(iso), template)

    def test_pinned_derivation_has_only_x86_platform_and_loopback_build_endpoints(self):
        # Upstream 16d0b559 fixture with the build-only SSH password line removed.
        source = (ROOT / 'tests/fixtures/izanagi-16d-debian.pkr.hcl').read_text()
        derived = fixture_module().derive(source)
        for forbidden in ['aarch64', 'install.a64', '"hvf"', '/opt/homebrew', '{{ .HTTPIP }}']:
            self.assertNotIn(forbidden, derived)
        for required in ['machine_type = "q35"', 'accelerator  = "kvm"',
                         '"/usr/bin/qemu-system-x86_64"', '/install.amd/vmlinuz',
                         'initrd=/install.amd/initrd.gz', 'hostfwd=tcp:127.0.0.1:',
                         'http_bind_address = "127.0.0.1"', 'vnc_bind_address = "127.0.0.1"',
                         'ssh_host = "127.0.0.1"', 'http://10.0.2.2:{{ .HTTPPort }}',
                         '["-serial", "file:installer-serial.log"]',
                         'console=tty0 console=ttyS0,115200n8 auto=true priority=critical',
                         'boot_wait         = "10s"',
                         'version = "= 1.1.8"']:
            self.assertIn(required, derived)
        self.assertEqual(source, (ROOT / 'tests/fixtures/izanagi-16d-debian.pkr.hcl').read_text())

    def test_even_small_upstream_template_change_is_rejected(self):
        source = (ROOT / 'tests/fixtures/izanagi-16d-debian.pkr.hcl').read_text()
        with self.assertRaisesRegex(ValueError, 'unexpected pinned Debian template bytes'):
            fixture_module().derive(source + '\n')

    def test_architecture_check_rejects_arm_and_non_bpf_objects_for_x86_inputs(self):
        prepare = module('prepare')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'artifact'
            for actual in [62, 183, 247]:
                header = bytearray(20)
                header[:6] = b'\x7fELF\x02\x01'
                header[18:20] = actual.to_bytes(2, 'little')
                path.write_bytes(header)
                for expected in [62, 183, 247]:
                    if actual == expected:
                        prepare.linux_elf(path, expected)
                    else:
                        with self.assertRaises(ValueError):
                            prepare.linux_elf(path, expected)


if __name__ == '__main__':
    unittest.main()
