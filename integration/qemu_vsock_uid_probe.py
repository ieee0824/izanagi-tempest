"""Observe UID999 vsock reachability in init and isolated guest network namespaces.

Uses the existing dedicated non-login KVM user. No NIC or external connection.
The result is an observation, not an assertion that the boundary is sufficient.
"""
import argparse
import gzip
import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', required=True, type=Path)
    parser.add_argument('--kernel-release', required=True)
    parser.add_argument('--manual-libtest', type=Path)
    args = parser.parse_args()
    user = pwd.getpwnam('tempest-kvm')
    group = grp.getgrnam('kvm').gr_gid
    if os.geteuid() != 0 or user.pw_uid == 0 or user.pw_shell != '/usr/sbin/nologin':
        raise RuntimeError('requires administrator orchestration and dedicated non-login KVM user')
    with tempfile.TemporaryDirectory(prefix='tempest-vsock-uid-', dir='/var/lib') as temporary:
        root = Path(temporary)
        root.chmod(0o750)
        os.chown(root, 0, user.pw_gid)
        guest = root / 'guest'
        for name in ('bin', 'dev', 'proc', 'sys', 'modules'):
            (guest / name).mkdir(parents=True)
        shutil.copyfile('/usr/bin/busybox', guest / 'bin/busybox')
        (guest / 'bin/busybox').chmod(0o755)
        subprocess.run(['cc', '-static', '-O2', '-Wall', '-Wextra', '-Werror',
            str(Path(__file__).parent / 'fixtures/vsock_uid_probe.c'), '-o', str(guest / 'bin/probe')], check=True)
        dependencies = subprocess.check_output(['modprobe', '-S', args.kernel_release,
            '--show-depends', 'vmw_vsock_virtio_transport'], text=True)
        modules = []
        for line in dependencies.splitlines():
            if not line.startswith('insmod '):
                continue
            source = Path(line.split()[1])
            name = source.name.removesuffix('.zst')
            modules.append(name)
            data = subprocess.check_output(['zstd', '-dc', str(source)]) if source.suffix == '.zst' else source.read_bytes()
            (guest / 'modules' / name).write_bytes(data)
        init = '#!/bin/busybox sh\nset -eu\n'
        init += ''.join(f'/bin/busybox mount -t {kind} {kind} /{path}\n' for kind, path in
                        (('proc', 'proc'), ('sysfs', 'sys'), ('devtmpfs', 'dev')))
        init += ''.join('/bin/busybox insmod /modules/' + name + '\n' for name in modules)
        init += '/bin/probe\n'
        if args.manual_libtest:
            shutil.copyfile(args.manual_libtest, guest / 'bin/verify')
            (guest / 'bin/verify').chmod(0o755)
            dependencies = subprocess.check_output(['ldd', str(args.manual_libtest)], text=True)
            for token in dependencies.split():
                if token.startswith('/'):
                    target = guest / token.lstrip('/')
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(token, target)
                    target.chmod(0o755)
            init += '/bin/busybox mkdir -p /var/lib\n/bin/verify --ignored --exact claude_offline::tests::manual_child_vsock_is_denied --quiet --nocapture\n'
        init += '/bin/busybox poweroff -f\n'
        (guest / 'init').write_text(init)
        (guest / 'init').chmod(0o755)
        names = ['.'] + [str(path.relative_to(guest)) for path in guest.rglob('*')]
        archive = subprocess.check_output(['cpio', '-o', '-H', 'newc', '--quiet'], cwd=guest,
            input=('\n'.join(names) + '\n').encode())
        image = root / 'initrd.gz'
        image.write_bytes(gzip.compress(archive))
        kernel = root / 'kernel'
        shutil.copyfile(args.kernel, kernel)
        for path in (image, kernel):
            os.chown(path, 0, user.pw_gid)
            path.chmod(0o440)
        log_path = root / 'serial.log'
        accepted = []
        with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as listener, log_path.open('wb') as log:
            listener.bind((socket.VMADDR_CID_HOST, 23104))
            listener.listen(2)
            listener.settimeout(0.2)
            vm = subprocess.Popen(['qemu-system-x86_64', '-machine', 'q35,accel=kvm', '-m', '256',
                '-nodefaults', '-display', 'none', '-serial', 'stdio', '-no-reboot', '-net', 'none',
                '-kernel', str(kernel), '-initrd', str(image), '-append', 'console=ttyS0 panic=-1 quiet',
                '-device', 'vhost-vsock-pci,id=boundary,guest-cid=235'],
                user=user.pw_uid, group=user.pw_gid, extra_groups=[group], stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 30
                while vm.poll() is None and time.monotonic() < deadline:
                    try:
                        connection, peer = listener.accept()
                    except TimeoutError:
                        continue
                    with connection:
                        accepted.append(peer[0])
                if vm.poll() is None:
                    raise TimeoutError('dedicated-user KVM probe exceeded 30 seconds')
                if vm.wait() != 0:
                    raise RuntimeError('dedicated-user QEMU failed; no root/TCG fallback')
            finally:
                if vm.poll() is None:
                    vm.kill()
                    vm.wait()
                print(log_path.read_text(errors='replace')[-5000:])
        output = log_path.read_text(errors='replace')
        results = [json.loads(line.split('VSOCK_UID_RESULT ', 1)[1]) for line in output.splitlines()
                   if line.startswith('VSOCK_UID_RESULT ')]
        if args.manual_libtest and 'MANUAL_CHILD_VSOCK_DENIED' not in output:
            raise RuntimeError('actual manual child did not confirm denial')
        if 'VSOCK_UID_PROBE_COMPLETE' not in output or len(results) != 2:
            raise RuntimeError('missing boundary observations')
        if any(cid != 235 for cid in accepted) or len(accepted) != sum(result['connected'] for result in results):
            raise RuntimeError('guest observations disagree with actual host vsock accepts')
        print(json.dumps(dict(qemu_user=user.pw_uid, acceleration='kvm', host_peer_cids=accepted,
                              observations=results, external_connections=False)))


if __name__ == '__main__':
    main()
