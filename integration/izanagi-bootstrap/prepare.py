#!/usr/bin/env python3
"""Derive a fixed bootstrap definition; never build or start a VM."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

COMMIT = "16d0b55947006a166cfa29dcb8bfe71f65f8c36a"
TEMPLATE_SHA = "77c17773d03badbcce8b95e94222b2d750b730ffc8a1aa5746307e17c5d6f531"
ORIGINAL_ISO_SHA = "366285bfa4d25429e0a9d1c5cbe3c2e35e84e1ad5e0620e8b5a20b5e39e7e02b"
ISO_SHA = "d91fb5c7a73528c89e0a1aa9a7d959f9deb9ca3dc5211e39bd73fd7df0d9070e"


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("source", "iso", "agent", "output"):
        parser.add_argument("--" + arg, type=Path, required=True)
    args = parser.parse_args()
    source, iso, agent = (p.resolve(strict=True) for p in (args.source, args.iso, args.agent))
    output = args.output.absolute()
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    clean = subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"], text=True)
    if revision != COMMIT or clean:
        raise SystemExit("source must be the clean pinned commit")
    template_path = source / "packer/alpine-x86_64.pkr.hcl"
    if digest(template_path) != TEMPLATE_SHA or digest(iso) != ISO_SHA:
        raise SystemExit("template or ISO hash mismatch")
    with agent.open("rb") as stream:
        elf = stream.read(20)
    if len(elf) != 20 or elf[:6] != b"\x7fELF\x02\x01" or int.from_bytes(elf[18:20], "little") != 62:
        raise SystemExit("agent must be a little-endian ELF64 x86_64 artifact")
    template = template_path.read_text()
    anchor = "  # agent のセットアップ\n"
    if template.count(anchor) != 1 or template.count('version = "~> 1"') != 1:
        raise SystemExit("unexpected template layout")
    template = template.replace('version = "~> 1"', 'version = "= 1.1.8"')
    network_anchor = '  http_directory = "http"'
    if template.count(network_anchor) != 1 or template.count("{{ .HTTPIP }}") != 2:
        raise SystemExit("unexpected HTTP configuration")
    template = template.replace(network_anchor, '''  http_directory = "${path.root}/http"
  http_bind_address = "127.0.0.1"
  http_port_min = 18081
  http_port_max = 18081
  vnc_bind_address = "127.0.0.1"
  vnc_port_min = 5901
  vnc_port_max = 5901
  host_port_min = 22221
  host_port_max = 22221
  ssh_host = "127.0.0.1"
  qemu_binary = "/usr/bin/qemu-system-x86_64"
  machine_type = "q35"
  qemuargs = [
    ["-netdev", "user,id=user.0,hostfwd=tcp:127.0.0.1:{{ .SSHHostPort }}-:22"]
  ]''')
    # Plugin 1.1.8 reports a specific bind address as HTTPIP. Guest loopback
    # differs from host loopback; use the fixed slirp host alias in boot commands.
    template = template.replace("{{ .HTTPIP }}", "10.0.2.2")
    extra = '''  provisioner "file" {
    source = "${path.root}/guest-bootstrap.sh"
    destination = "/tmp/tempest-bootstrap.sh"
  }
  provisioner "shell" {
    inline = ["sh /tmp/tempest-bootstrap.sh", "rm /tmp/tempest-bootstrap.sh"]
  }

'''
    template = template.replace(anchor, extra + anchor)
    # Refuse existing destinations, including dangling symlinks.
    output.mkdir(mode=0o700)
    inputs = {}
    for name in ("http/setup.sh", "http/answers", "lock-down.sh", "verify-image.sh"):
        src = source / "packer" / name
        dst = output / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        inputs[name] = digest(src)
    helper = Path(__file__).with_name("guest-bootstrap.sh")
    shutil.copyfile(helper, output / helper.name)
    (output / "bootstrap.pkr.hcl").write_text(template)
    variables = {"iso_url": str(iso), "iso_checksum": "sha256:" + ISO_SHA, "agent_binary": str(agent)}
    (output / "bootstrap.pkrvars.json").write_text(json.dumps(variables, indent=2) + "\n")
    manifest = {
        "source_commit": COMMIT, "upstream_template_sha256": TEMPLATE_SHA,
        "original_iso_sha256": ORIGINAL_ISO_SHA, "override_iso_sha256": ISO_SHA,
        "iso_signature_primary_fingerprint": "0482D84022F52DF1C4E7CD43293ACD0907D9495A",
        "iso_override_review_room_post": 16352,
        "agent_sha256": digest(agent), "upstream_inputs_sha256": inputs,
        "guest_bootstrap_sha256": digest(helper),
        "derived_template_sha256": digest(output / "bootstrap.pkr.hcl"),
        "variables_sha256": digest(output / "bootstrap.pkrvars.json"),
        "generator_sha256": digest(Path(__file__)), "guest_uid": 1000,
        "qemu_plugin_version": "1.1.8", "image_built": False,
        "build_host_bind": "127.0.0.1", "build_guest_http_host": "10.0.2.2",
        "build_ports": {"http": 18081, "ssh_forward": 22221, "vnc": 5901},
    }
    (output / "inputs.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"prepared": True, "image_built": False}))


if __name__ == "__main__":
    main()
