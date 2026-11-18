"""Derive the fixed x86 Debian build definition without modifying upstream."""
import hashlib

TEMPLATE_SHA256 = 'f72851d5869da005224ca134b8caf0e9e357cdf41fc05c8524e4cac0ea0b1143'
ISO_SHA256 = 'a7ef94ac2fb9a7fec454552abd629b7cc9d5155c886165a45649f5ce6167e355'


def derive(template):
    if hashlib.sha256(template.encode()).hexdigest() != TEMPLATE_SHA256:
        raise ValueError('unexpected pinned Debian template bytes')

    def replace(old, new):
        nonlocal template
        if template.count(old) != 1:
            raise ValueError('unexpected pinned Debian template layout')
        template = template.replace(old, new)

    replace('version = "~> 1"', 'version = "= 1.1.8"')
    replace('sha256:6e93fa1759bd9d4b0fc11e938987de6967ee7de5297dac1be27c3a75cc17024b',
            'sha256:' + ISO_SHA256)
    replace('/arm64/iso-cd/debian-${var.debian_version}-arm64-netinst.iso',
            '/amd64/iso-cd/debian-${var.debian_version}-amd64-netinst.iso')
    replace('vm_name          = "debian-aarch64.qcow2"',
            'vm_name          = "debian-x86_64.qcow2"')
    replace('qemu_binary  = "qemu-system-aarch64"',
            'qemu_binary  = "/usr/bin/qemu-system-x86_64"')
    replace('machine_type = "virt"', 'machine_type = "q35"')
    replace('accelerator  = "hvf"', 'accelerator  = "kvm"')
    replace('  # aarch64 では -boot once=d が使えないため無効化',
            '  # BIOS installer uses the default CD boot order; no injected CD files.')
    start = template.index('  qemuargs = [\n')
    end = template.index('\n  ]', start) + len('\n  ]')
    template = template[:start] + '''  qemuargs = [
    ["-netdev", "user,id=user.0,hostfwd=tcp:127.0.0.1:{{ .SSHHostPort }}-:22"]
  ]''' + template[end:]
    replace('  http_directory = "http"', '''  http_directory = "${path.root}/http"
  http_bind_address = "127.0.0.1"
  http_port_min = 18082
  http_port_max = 18082
  vnc_bind_address = "127.0.0.1"
  vnc_port_min = 5902
  vnc_port_max = 5902
  host_port_min = 22222
  host_port_max = 22222
  ssh_host = "127.0.0.1"''')
    start = template.index('  boot_command = [\n')
    end = template.index('\n  ]', start) + len('\n  ]')
    # BIOS/ISOLINUX: enter a kernel command at the boot prompt. This derived
    # installer path still requires validation on the actual fixed amd64 ISO.
    template = template[:start] + '''  boot_command = [
    "<esc><wait3>",
    "/install.amd/vmlinuz auto=true priority=critical preseed/url=http://10.0.2.2:{{ .HTTPPort }}/preseed.cfg initrd=/install.amd/initrd.gz --- quiet<enter>",
  ]''' + template[end:]
    return template.replace('aarch64-unknown-linux-gnu', 'x86_64-unknown-linux-gnu')
